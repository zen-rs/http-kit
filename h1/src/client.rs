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

use std::{cell::Cell, fmt};

use async_channel::{Receiver, Sender};
use bytes::BytesMut;
use http::{Method, StatusCode};
use http_kit::{Body, Request, Response};
use http_kit_io::{Read, SendFile, Split, Write};

use crate::{
    ClientConfig, Error, ParseError, Upgraded, body,
    conn::{Outbox, Pumped, Recv, pump_body, send_message, while_driving},
    proto::{BodyDecoder, BodyKind, ResponseHead, encode_request_head, parse_response_head},
};

struct Exchange {
    request: Request,
    respond: Sender<Result<Response, Error>>,
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
    /// server answers `100 Continue`; a final response before that leaves the
    /// body unsent and closes the connection after the response.
    ///
    /// # Errors
    ///
    /// The request cannot be sent as given, or the connection failed or
    /// closed before the response head arrived.
    pub async fn send(&self, request: Request) -> Result<Response, Error> {
        let (respond, response) = async_channel::bounded(1);
        self.exchanges
            .send(Exchange { request, respond })
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        response.recv().await.map_err(|_| Error::ConnectionClosed)?
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

/// The socket side of a client connection: drive it with
/// [`run`](Self::run).
pub struct Connection<R, W> {
    recv: Recv<R>,
    writer: W,
    exchanges: Receiver<Exchange>,
    config: ClientConfig,
}

impl<R, W> fmt::Debug for Connection<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("buffered", &self.recv.buf.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Starts a client connection over a socket's read and write halves.
pub fn handshake<R, W>(
    reader: R,
    writer: W,
    config: ClientConfig,
) -> (SendRequest, Connection<R, W>)
where
    R: Read,
    W: Write + SendFile,
{
    let (send, exchanges) = async_channel::bounded(1);
    (
        SendRequest { exchanges: send },
        Connection {
            recv: Recv::new(reader, config.read_buffer_size),
            writer,
            exchanges,
            config,
        },
    )
}

/// Starts a client connection over a whole socket, split into halves so
/// that request and response bodies flow at the same time.
pub fn handshake_stream<T>(
    stream: T,
    config: ClientConfig,
) -> (SendRequest, Connection<T::ReadHalf, T::WriteHalf>)
where
    T: Split,
    T::WriteHalf: SendFile,
{
    let (reader, writer) = stream.split();
    handshake(reader, writer, config)
}

enum Next {
    KeepAlive,
    Close,
    Upgrade,
}

impl<R, W> Connection<R, W>
where
    R: Read,
    W: Write + SendFile,
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
        let Exchange { request, respond } = exchange;
        let (parts, body) = request.into_parts();
        let mut head = BytesMut::with_capacity(256);
        let mut plan =
            match encode_request_head(&parts, body.len().map(|len| len as u64), &mut head) {
                Ok(plan) => plan,
                Err(error) => {
                    // Nothing was written: the connection is still usable.
                    respond.send(Err(error)).await.ok();
                    return Ok(Next::KeepAlive);
                }
            };
        let method = parts.method;
        let expect_continue = plan.expect_continue;
        let requested_upgrade = plan.upgrade;
        let limits = &self.config.limits;

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
                if proceed.recv().await.is_err() {
                    // Withheld: the head announced a body that never follows,
                    // so the connection closes after the response.
                    return Ok(false);
                }
            }
            send_message(writer, &mut outbox, Some(body), &mut plan.encoder).await?;
            Ok::<_, Error>(true)
        };

        let recv = &mut self.recv;
        let receive = async {
            let head = loop {
                let head = read_head(recv, limits, &method).await?;
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
                        Response::from_parts(head.parts, Body::from_frames(incoming)),
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
                    pump_body(recv, decoder, limits, sender, async {}).await?
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
                    respond.send(Err(error.clone())).await.ok();
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

async fn read_head<R: Read>(
    recv: &mut Recv<R>,
    limits: &crate::Limits,
    method: &Method,
) -> Result<ResponseHead, Error> {
    loop {
        if let Some(head) = parse_response_head(&mut recv.buf, limits, method)? {
            tracing::trace!(status = %head.parts.status, "response");
            return Ok(head);
        }
        if recv.fill().await? == 0 {
            return Err(if recv.buf.is_empty() {
                Error::ConnectionClosed
            } else {
                ParseError::Incomplete.into()
            });
        }
    }
}
