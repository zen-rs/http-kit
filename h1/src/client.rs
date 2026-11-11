//! Sending HTTP/1.1 requests on one connection.
//!
//! [`handshake`] splits a connection into a [`SendRequest`] handle and the
//! [`Connection`] that owns the socket. The connection must be driven —
//! awaited, or spawned on the thread's local executor — for any request to
//! make progress; it answers requests in the order they were sent and keeps
//! the socket alive between them while the server allows.
//!
//! The handle is `Clone` and `Send`, so a connection pool can hold it while
//! the connection itself, like every future here, stays on one thread.

use std::{cell::Cell, fmt, time::Duration};

use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use http::{Method, StatusCode};
use http_kit::{Body, Request, Response};
use http_kit_io::{Read, SendFile, SpliceRead, SpliceWrite, Split, Timer, Write};

use crate::{
    ClientConfig, Error, ParseError, Timeout, Upgraded, body,
    conn::{Outbox, Pumped, Recv, deadline_after, pump_body, send_message, until, while_driving},
    proto::{BodyDecoder, BodyKind, ResponseHead, encode_request_head, parse_response_head},
};

/// A request on its way to the connection.
///
/// One that is dropped before the connection took it (the connection ended
/// while it waited in the queue) hands its request back to the caller that
/// sent it: nothing of it was written.
struct Exchange {
    request: Option<Request>,
    respond: Sender<Result<Response, TrySendError>>,
}

impl Exchange {
    fn new(request: Request, respond: Sender<Result<Response, TrySendError>>) -> Self {
        Self {
            request: Some(request),
            respond,
        }
    }

    /// The request and where its answer goes; the connection has taken it.
    fn take(mut self) -> (Request, Sender<Result<Response, TrySendError>>) {
        let request = self
            .request
            .take()
            .expect("an exchange holds its request until taken");
        (request, self.respond.clone())
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            self.respond
                .try_send(Err(TrySendError::unsent(Error::ConnectionClosed, request)))
                .ok();
        }
    }
}

/// A request that failed, and the request itself if nothing of it was
/// written.
///
/// Like hyper's `TrySendError`: when the connection had stopped taking
/// requests, or ended before it took this one, [`take_request`](Self::take_request)
/// returns the request as it was handed in, and it can be sent on another
/// connection whatever its method or body. Once the connection took the
/// request, a failure leaves nothing to give back.
pub struct TrySendError {
    error: Error,
    /// Boxed: a request is large, and an error is returned by value.
    request: Option<Box<Request>>,
}

impl TrySendError {
    fn unsent(error: Error, request: Request) -> Self {
        Self {
            error,
            request: Some(Box::new(request)),
        }
    }

    /// Why the request failed.
    #[must_use]
    pub const fn error(&self) -> &Error {
        &self.error
    }

    /// Why the request failed, dropping the request.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.error
    }

    /// The request, if none of it was written. It is returned once.
    pub fn take_request(&mut self) -> Option<Request> {
        self.request.take().map(|request| *request)
    }
}

impl From<Error> for TrySendError {
    fn from(error: Error) -> Self {
        Self {
            error,
            request: None,
        }
    }
}

impl From<TrySendError> for Error {
    fn from(error: TrySendError) -> Self {
        error.error
    }
}

impl fmt::Debug for TrySendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrySendError")
            .field("error", &self.error)
            .field("unsent", &self.request.is_some())
            .finish()
    }
}

impl fmt::Display for TrySendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for TrySendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Sends requests on a connection.
#[derive(Clone)]
pub struct SendRequest {
    exchanges: Sender<Exchange>,
}

impl fmt::Debug for SendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendRequest")
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl SendRequest {
    /// Sends `request` and waits for the head of its response. The response
    /// body streams from the connection as it is read.
    ///
    /// A request with `Expect: 100-continue` holds its body back until the
    /// server answers `100 Continue`, or
    /// [`expect_continue_timeout`](ClientConfig::expect_continue_timeout)
    /// passes and the body is sent anyway; a final response before either
    /// leaves the body unsent and closes the connection after the response.
    ///
    /// # Errors
    ///
    /// The request cannot be sent as given, or the connection failed or
    /// closed before the response head arrived.
    pub async fn send(&self, request: Request) -> Result<Response, Error> {
        self.try_send(request).await.map_err(Error::from)
    }

    /// As [`send`](Self::send), but a failure that left the request unwritten
    /// gives it back: the connection had stopped taking requests, or ended
    /// while this one waited for its turn. A pool can send it again on
    /// another connection, whatever its method or body.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send), with the request in the [`TrySendError`]
    /// when it can be recovered.
    pub async fn try_send(&self, request: Request) -> Result<Response, TrySendError> {
        let (respond, response) = async_channel::bounded(1);
        if let Err(refused) = self.exchanges.send(Exchange::new(request, respond)).await {
            let mut exchange = refused.into_inner();
            let request = exchange
                .request
                .take()
                .expect("a refused exchange holds its request");
            return Err(TrySendError::unsent(Error::ConnectionClosed, request));
        }
        response
            .recv()
            .await
            .map_err(|_| TrySendError::from(Error::ConnectionClosed))?
    }

    /// Whether the connection has stopped taking requests.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.exchanges.is_closed()
    }
}

/// How a client connection ended.
pub enum ClientOutcome<R, W> {
    /// The connection is finished and its write side shut down.
    Closed,
    /// The server switched protocols (a `101`, or a `2xx` to `CONNECT`).
    /// The response was delivered to the request that asked for it.
    Upgraded(Upgraded<R, W>),
}

impl<R, W> fmt::Debug for ClientOutcome<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => f.write_str("Closed"),
            Self::Upgraded(upgraded) => f.debug_tuple("Upgraded").field(upgraded).finish(),
        }
    }
}

/// The requests waiting for the connection. Whatever is still queued when
/// the connection is dropped, by whatever path it ended, goes back to the
/// callers, unwritten: a queue that outlived its receiver (the handles hold
/// the channel) would keep them waiting forever.
struct Queue(Receiver<Exchange>);

impl Queue {
    async fn recv(&self) -> Result<Exchange, async_channel::RecvError> {
        self.0.recv().await
    }

    fn close(&self) {
        self.0.close();
    }
}

impl Drop for Queue {
    fn drop(&mut self) {
        self.0.close();
        while self.0.try_recv().is_ok() {}
    }
}

/// The socket side of a client connection: drive it with
/// [`run`](Self::run).
pub struct Connection<R, W, T> {
    recv: Recv<R>,
    writer: W,
    timer: T,
    exchanges: Queue,
    config: ClientConfig,
}

impl<R, W, T> fmt::Debug for Connection<R, W, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("buffered", &self.recv.buf.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Starts a client connection over a socket's read and write halves, with
/// its deadlines (see [`ClientConfig`]) driven by `timer`.
pub fn handshake<R, W, T>(
    reader: R,
    writer: W,
    timer: T,
    config: ClientConfig,
) -> (SendRequest, Connection<R, W, T>)
where
    R: Read + SpliceRead,
    W: Write + SendFile + SpliceWrite,
    T: Timer,
{
    let (send, exchanges) = async_channel::bounded(1);
    (
        SendRequest { exchanges: send },
        Connection {
            recv: Recv::new(reader, config.read_buffer_size),
            writer,
            timer,
            exchanges: Queue(exchanges),
            config,
        },
    )
}

/// Starts a client connection over a whole socket, split into halves so
/// that request and response bodies flow at the same time.
pub fn handshake_stream<S, T>(
    stream: S,
    timer: T,
    config: ClientConfig,
) -> (SendRequest, Connection<S::ReadHalf, S::WriteHalf, T>)
where
    S: Split,
    S::ReadHalf: SpliceRead,
    S::WriteHalf: SendFile + SpliceWrite,
    T: Timer,
{
    let (reader, writer) = stream.split();
    handshake(reader, writer, timer, config)
}

enum Next {
    KeepAlive,
    Close,
    Upgrade,
}

impl<R, W, T> Connection<R, W, T>
where
    R: Read + SpliceRead,
    W: Write + SendFile + SpliceWrite,
    T: Timer,
{
    /// Answers requests until every [`SendRequest`] is dropped, the
    /// connection cannot persist, or the server switches protocols.
    ///
    /// An error is delivered to the request it affected, as the result of
    /// [`SendRequest::send`] or through its response body, and returned here
    /// too.
    ///
    /// # Errors
    ///
    /// The transport failed or the server sent an invalid response.
    pub async fn run(mut self) -> Result<ClientOutcome<R, W>, Error> {
        loop {
            let Ok(exchange) = self.exchanges.recv().await else {
                return self.close().await;
            };
            match self.exchange(exchange).await? {
                Next::KeepAlive => {}
                Next::Close => return self.close().await,
                Next::Upgrade => {
                    self.exchanges.close();
                    return Ok(ClientOutcome::Upgraded(Upgraded {
                        read_buf: self.recv.buf.split().freeze(),
                        read: self.recv.reader,
                        write: self.writer,
                    }));
                }
            }
        }
    }

    async fn exchange(&mut self, exchange: Exchange) -> Result<Next, Error> {
        let (request, respond) = exchange.take();
        let (parts, body) = request.into_parts();
        let mut head = BytesMut::with_capacity(256);
        let encoded = encode_request_head(
            &parts,
            self.config.request_target,
            body.len().map(|len| len as u64),
            &mut head,
        );
        let mut plan = match encoded {
            Ok(plan) => plan,
            Err(error) => {
                // Nothing was written: the connection is still usable.
                respond.send(Err(error.into())).await.ok();
                return Ok(Next::KeepAlive);
            }
        };
        let method = parts.method;
        let expect_continue = plan.expect_continue;
        let requested_upgrade = plan.upgrade;
        let limits = &self.config.limits;
        let continue_timeout = self.config.expect_continue_timeout;
        let read_timeout = self.config.read_timeout;
        let timer = &self.timer;

        // A message once the server answered `100 Continue`; closed once a
        // final response made the body moot.
        let (go_ahead, proceed) = async_channel::bounded::<()>(1);
        // Closed once the request is fully written.
        let (written_tx, written) = async_channel::bounded::<()>(1);
        let delivered = Cell::new(false);

        let writer = &mut self.writer;
        let send = async {
            let _written = written_tx;
            let mut outbox = Outbox::default();
            outbox.push(head.freeze());
            if expect_continue {
                outbox.flush(writer).await?;
                match until(timer, deadline_after(continue_timeout), proceed.recv()).await {
                    Some(Ok(())) => {}
                    // Withheld: the head announced a body that never follows,
                    // so the connection closes after the response.
                    Some(Err(_)) => return Ok(false),
                    // The server stayed silent; send the body anyway.
                    None => tracing::debug!("no 100 Continue in time, sending the body"),
                }
            }
            send_message(writer, &mut outbox, Some(body), &mut plan.encoder).await?;
            Ok::<_, Error>(true)
        };

        let recv = &mut self.recv;
        let receive = async {
            let head = loop {
                let head = read_head(recv, limits, &method, timer, read_timeout).await?;
                if !head.is_interim() {
                    break head;
                }
                if head.parts.status == StatusCode::CONTINUE {
                    go_ahead.try_send(()).ok();
                }
            };
            // A final response without `100 Continue` first: withhold the body.
            go_ahead.close();
            if head.upgrade && !requested_upgrade {
                return Err(Error::UnrequestedUpgrade);
            }
            let (response, pump) = match head.body {
                BodyKind::Empty => (Response::from_parts(head.parts, Body::empty()), None),
                kind => {
                    let (sender, incoming) = body::channel();
                    (
                        Response::from_parts(head.parts, Body::from_source(incoming)),
                        Some((sender, BodyDecoder::new(kind))),
                    )
                }
            };
            delivered.set(true);
            respond.send(Ok(response)).await.ok();
            if head.upgrade {
                // The new protocol starts after the whole request.
                written.recv().await.ok();
                return Ok(Received::Upgrade);
            }
            let pumped = match pump {
                None => Pumped::Complete,
                Some((sender, decoder)) => {
                    pump_body(recv, decoder, limits, sender, timer, read_timeout, async {}).await?
                }
            };
            Ok(Received::Response {
                keep_alive: head.keep_alive && pumped == Pumped::Complete,
            })
        };

        let (received, sent) = while_driving(receive, send).await;
        let received = match received {
            Ok(received) => received,
            Err(error) => {
                if !delivered.get() {
                    respond.send(Err(error.clone().into())).await.ok();
                }
                return Err(error);
            }
        };
        match received {
            Received::Upgrade => match sent {
                Some(Ok(true)) => Ok(Next::Upgrade),
                Some(Err(error)) => Err(error),
                Some(Ok(false)) | None => Err(Error::UpgradeBeforeBodyRead),
            },
            Received::Response { keep_alive } => {
                let sent = match sent {
                    Some(Ok(sent_body)) => sent_body,
                    Some(Err(error)) => {
                        tracing::debug!(%error, "request write failed after its response");
                        false
                    }
                    None => false,
                };
                Ok(if keep_alive && sent && plan.keep_alive {
                    Next::KeepAlive
                } else {
                    Next::Close
                })
            }
        }
    }

    async fn close(mut self) -> Result<ClientOutcome<R, W>, Error> {
        self.exchanges.close();
        self.writer.shutdown().await?;
        Ok(ClientOutcome::Closed)
    }
}

enum Received {
    Response { keep_alive: bool },
    Upgrade,
}

/// Reads one response head, each wait for bytes bounded by `read_timeout`.
async fn read_head<R: Read, T: Timer>(
    recv: &mut Recv<R>,
    limits: &crate::Limits,
    method: &Method,
    timer: &T,
    read_timeout: Option<Duration>,
) -> Result<ResponseHead, Error> {
    loop {
        if let Some(head) = parse_response_head(&mut recv.buf, limits, method)? {
            tracing::trace!(status = %head.parts.status, "response");
            return Ok(head);
        }
        let read = until(timer, deadline_after(read_timeout), recv.fill())
            .await
            .ok_or(Error::Timeout(Timeout::HeadRead))??;
        if read == 0 {
            return Err(if recv.buf.is_empty() {
                Error::ConnectionClosed
            } else {
                ParseError::Incomplete.into()
            });
        }
    }
}
