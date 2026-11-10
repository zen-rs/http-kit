//! Serving HTTP/1.1 on one connection.
//!
//! [`ServerConnection`] reads requests, hands each to a [`Service`] and
//! writes its response, for as long as the connection persists. Requests
//! are answered strictly in order, so pipelined requests need nothing
//! special: the next one waits in the receive buffer until the current
//! response is written.
//!
//! The request body streams from the socket while the service runs, and the
//! response body streams to it; the two run concurrently, so a service can
//! answer with a body computed from the request body as it arrives. No
//! future here is required to be `Send`: a connection lives on the thread
//! that accepted it.

use std::{
    cell::Cell,
    future::{Future, pending},
    pin::pin,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::{Bytes, BytesMut};
use futures_lite::future::{or, poll_once};
use http::{HeaderValue, Method, StatusCode, Version, response};
use http_kit::{Body, Request, Response};
use http_kit_io::{Read, SendFile, Split, Timer, Write};

use crate::{
    Error, ParseError, ServerConfig, Timeout, Upgraded, body,
    conn::{Outbox, Pumped, Recv, deadline_after, pump_body, send_message, until, while_driving},
    proto::{
        BodyDecoder, BodyKind, RequestHead, RequestInfo, encode_response_head, parse_request_head,
    },
};

/// Answers requests.
///
/// Implemented for every `Fn(Request) -> impl Future<Output = Response>`.
/// Errors are the service's to turn into responses; nothing here is `Send`.
pub trait Service {
    /// Answers one request.
    fn call(&self, request: Request) -> impl Future<Output = Response>;
}

impl<F, Fut> Service for F
where
    F: Fn(Request) -> Fut,
    Fut: Future<Output = Response>,
{
    fn call(&self, request: Request) -> impl Future<Output = Response> {
        self(request)
    }
}

/// How a served connection ended.
pub enum ServerOutcome<R, W> {
    /// The connection is finished and its write side shut down.
    Closed,
    /// The connection switched protocols: a `101` was sent, or a `2xx` to
    /// `CONNECT`. The socket now belongs to whatever speaks the new protocol.
    Upgraded {
        /// The socket and any bytes the client sent after its request.
        upgraded: Upgraded<R, W>,
        /// The head of the response that switched protocols, with the
        /// extensions the service put on it, to tell the new protocol's
        /// handler what was agreed.
        response: response::Parts,
    },
}

impl<R, W> std::fmt::Debug for ServerOutcome<R, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => f.write_str("Closed"),
            Self::Upgraded { upgraded, response } => f
                .debug_struct("Upgraded")
                .field("upgraded", upgraded)
                .field("response", response)
                .finish(),
        }
    }
}

/// One server connection.
pub struct ServerConnection<R, W, T> {
    recv: Recv<R>,
    writer: W,
    timer: T,
    config: ServerConfig,
    date: DateCache,
    /// Queued writes, kept so each message reuses the allocation.
    outbox: Outbox,
    /// Where response heads are encoded; each is split off as `Bytes`, and
    /// the space comes back once those are written and dropped.
    head_buf: BytesMut,
}

/// Room reserved for a response head.
const RESPONSE_HEAD_CAPACITY: usize = 256;

impl<R, W, T> std::fmt::Debug for ServerConnection<R, W, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConnection")
            .field("buffered", &self.recv.buf.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<R, W, T> ServerConnection<R, W, T>
where
    R: Read,
    W: Write + SendFile,
    T: Timer,
{
    /// A connection over a socket's read and write halves, with its
    /// deadlines (see [`ServerConfig`]) driven by `timer`.
    pub fn new(reader: R, writer: W, timer: T, config: ServerConfig) -> Self {
        Self {
            recv: Recv::new(reader, config.read_buffer_size),
            writer,
            timer,
            config,
            date: DateCache::default(),
            outbox: Outbox::default(),
            head_buf: BytesMut::with_capacity(RESPONSE_HEAD_CAPACITY),
        }
    }

    /// Serves requests until the connection closes or switches protocols.
    ///
    /// # Errors
    ///
    /// The transport failed, the client sent an invalid request (answered
    /// with its status code first, where one applies), a response could
    /// not be sent as the service produced it, or a configured deadline
    /// passed ([`Error::Timeout`]).
    pub async fn serve<S: Service>(self, service: &S) -> Result<ServerOutcome<R, W>, Error> {
        self.serve_until(service, pending()).await
    }

    /// Serves requests like [`serve`](Self::serve) until `shutdown`
    /// completes, then finishes gracefully: an idle connection closes at
    /// once, and a request already arriving is answered with
    /// `Connection: close`.
    ///
    /// # Errors
    ///
    /// As [`serve`](Self::serve).
    pub async fn serve_until<S: Service, F: Future<Output = ()>>(
        mut self,
        service: &S,
        shutdown: F,
    ) -> Result<ServerOutcome<R, W>, Error> {
        let mut shutdown = pin!(shutdown);
        let mut stopping = false;
        let mut served = false;
        loop {
            let head = match self.next_head(&mut shutdown, &mut stopping, served).await {
                Ok(Some(head)) => head,
                Ok(None) => return self.close().await,
                Err(Error::Parse(error)) => {
                    self.reject(&error).await;
                    return Err(error.into());
                }
                Err(error) => return Err(error),
            };
            if !stopping && poll_once(shutdown.as_mut()).await.is_some() {
                stopping = true;
            }
            match self.exchange(service, head, stopping).await? {
                Next::KeepAlive => served = true,
                Next::Close => return self.close().await,
                Next::Upgrade(response) => {
                    return Ok(ServerOutcome::Upgraded {
                        upgraded: Upgraded {
                            read_buf: self.recv.buf.split().freeze(),
                            read: self.recv.reader,
                            write: self.writer,
                        },
                        response,
                    });
                }
            }
        }
    }

    /// Reads the next request head; `None` when the connection should close
    /// without one (end of stream, or shutdown while idle).
    ///
    /// Waiting for the first byte is bounded by the keep-alive timeout once a
    /// request was served and by the header timeout before that; from the
    /// first byte on, the whole head is bounded by the header timeout. A
    /// timeout with part of a head received is answered with `408`.
    async fn next_head<F: Future<Output = ()>>(
        &mut self,
        shutdown: &mut std::pin::Pin<&mut F>,
        stopping: &mut bool,
        served: bool,
    ) -> Result<Option<RequestHead>, Error> {
        let header_timeout = self.config.header_read_timeout;
        // Waiting idle between keep-alive requests ends the connection
        // normally at its deadline; any other wait is for a head.
        let (mut deadline, mut idle_wait) = if self.recv.buf.is_empty() && served {
            (deadline_after(self.config.keep_alive_timeout), true)
        } else {
            (deadline_after(header_timeout), false)
        };
        loop {
            if let Some(head) = parse_request_head(&mut self.recv.buf, &self.config.limits)? {
                tracing::trace!(method = %head.parts.method, uri = %head.parts.uri, "request");
                return Ok(Some(head));
            }
            let idle = self.recv.buf.is_empty();
            let fill = until(&self.timer, deadline, self.recv.fill());
            let read = if idle && !*stopping {
                let fill = async { Some(fill.await) };
                let stop = async {
                    shutdown.as_mut().await;
                    None
                };
                match or(fill, stop).await {
                    Some(read) => read,
                    None => {
                        *stopping = true;
                        return Ok(None);
                    }
                }
            } else {
                fill.await
            };
            let Some(read) = read else {
                if idle_wait {
                    tracing::debug!("keep-alive connection idle; closing");
                    return Ok(None);
                }
                tracing::debug!("request head not received in time; closing");
                if !idle {
                    self.send_status(StatusCode::REQUEST_TIMEOUT).await;
                }
                return Err(Error::Timeout(Timeout::HeadRead));
            };
            let read = read?;
            if idle && read > 0 {
                // The head's own clock starts at its first byte.
                deadline = deadline_after(header_timeout);
                idle_wait = false;
            }
            if read == 0 {
                return if self.recv.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(ParseError::Incomplete.into())
                };
            }
        }
    }

    async fn exchange<S: Service>(
        &mut self,
        service: &S,
        head: RequestHead,
        stopping: bool,
    ) -> Result<Next, Error> {
        let info = head.info();
        let limits = &self.config.limits;
        let body_timeout = self.config.body_read_timeout;
        let timer = &self.timer;
        let expect_continue = head.expect_continue && head.body != BodyKind::Empty;
        let (body, pump) = match head.body {
            BodyKind::Empty => (Body::empty(), None),
            kind => {
                let (sender, incoming) = body::channel();
                (
                    Body::from_frames(incoming),
                    Some((sender, BodyDecoder::new(kind))),
                )
            }
        };
        let has_body = pump.is_some();
        let request = Request::from_parts(head.parts, body);

        // Whether the body has been asked for, and whether it was read to its end.
        let demanded = Cell::new(false);
        // The pump asks for `100 Continue` here, and waits until it was sent
        // or a final response made it moot (the channel closes).
        // Only a request that asked for it gets the channels.
        let handshake = expect_continue.then(ContinueHandshake::new);

        let recv = &mut self.recv;
        let pump = async {
            let Some((sender, decoder)) = pump else {
                return Ok(Pumped::Complete);
            };
            let first_read = async {
                demanded.set(true);
                if let Some(handshake) = &handshake {
                    // The responder may already have committed to a final
                    // response and closed both channels; either way, read.
                    if handshake.want_continue.send(()).await.is_ok() {
                        handshake.continued.recv().await.ok();
                    }
                }
            };
            pump_body(
                recv,
                decoder,
                limits,
                sender,
                timer,
                body_timeout,
                first_read,
            )
            .await
        };

        let writer = &mut self.writer;
        let outbox = &mut self.outbox;
        let head_buf = &mut self.head_buf;
        let date = self.config.date_header.then(|| self.date.get()).cloned();
        let respond = async {
            let mut call = pin!(service.call(request));
            let response = if let Some(handshake) = &handshake {
                let answered = async { Some(call.as_mut().await) };
                let wants = async {
                    match handshake.continue_wanted.recv().await {
                        Ok(()) => None,
                        Err(_) => pending().await,
                    }
                };
                match or(answered, wants).await {
                    Some(response) => response,
                    None => {
                        outbox.push(Bytes::from_static(b"HTTP/1.1 100 Continue\r\n\r\n"));
                        outbox.flush(writer).await?;
                        handshake.continued_tx.close();
                        call.await
                    }
                }
            } else {
                call.await
            };
            // From here no `100 Continue` is sent; the pump reads without it.
            if let Some(handshake) = &handshake {
                handshake.continue_wanted.close();
                handshake.continued_tx.close();
            }

            let (parts, body) = response.into_parts();
            // A body nobody asked for is unread: the connection cannot be
            // reused, since the client may or may not still send it.
            let unread = has_body && !demanded.get();
            // The previous head's bytes are gone by now, so this reclaims
            // the connection's allocation instead of making a new one.
            head_buf.clear();
            head_buf.reserve(RESPONSE_HEAD_CAPACITY);
            let mut plan = encode_response_head(
                &info,
                &parts,
                body.len().map(|len| len as u64),
                stopping || unread,
                date.as_ref(),
                head_buf,
            )?;
            if plan.upgrade && has_body && !demanded.get() {
                return Err(Error::UpgradeBeforeBodyRead);
            }
            outbox.push(head_buf.split().freeze());
            send_message(writer, outbox, Some(body), &mut plan.encoder).await?;
            Ok::<_, Error>((plan, parts))
        };

        let (responded, pumped) = while_driving(respond, pump).await;
        let (plan, parts) = responded?;
        let complete = match pumped {
            Some(Ok(Pumped::Complete)) => true,
            Some(Ok(Pumped::Abandoned)) | None => false,
            Some(Err(error)) => return Err(error),
        };
        if plan.upgrade {
            if !complete {
                return Err(Error::UpgradeBeforeBodyRead);
            }
            return Ok(Next::Upgrade(parts));
        }
        Ok(if plan.keep_alive && complete {
            Next::KeepAlive
        } else {
            Next::Close
        })
    }

    /// Answers an invalid request with its status, where one applies.
    async fn reject(&mut self, error: &ParseError) {
        tracing::debug!(%error, "rejecting an invalid request");
        if let Some(status) = error.status() {
            self.send_status(status).await;
        }
    }

    /// Sends an empty response with `status` that closes the connection,
    /// and shuts the write side down.
    async fn send_status(&mut self, status: StatusCode) {
        self.outbox.push(rejection(status));
        if let Err(error) = self.outbox.flush(&mut self.writer).await {
            tracing::debug!(%error, "could not send the rejection");
        }
        if let Err(error) = self.writer.shutdown().await {
            tracing::debug!(%error, "could not shut the connection down");
        }
    }

    async fn close(mut self) -> Result<ServerOutcome<R, W>, Error> {
        self.writer.shutdown().await?;
        Ok(ServerOutcome::Closed)
    }
}

impl<R, W, T> ServerConnection<R, W, T>
where
    R: Read,
    W: Write + SendFile,
    T: Timer,
{
    /// A connection over a whole socket, split into halves so that request
    /// and response bodies flow at the same time.
    pub fn from_stream<S>(stream: S, timer: T, config: ServerConfig) -> Self
    where
        S: Split<ReadHalf = R, WriteHalf = W>,
    {
        let (reader, writer) = stream.split();
        Self::new(reader, writer, timer, config)
    }
}

enum Next {
    KeepAlive,
    Close,
    Upgrade(response::Parts),
}

/// An empty response with `status` that closes the connection.
fn rejection(status: StatusCode) -> Bytes {
    let mut parts = http::Response::new(()).into_parts().0;
    parts.status = status;
    let request = RequestInfo {
        method: Method::GET,
        version: Version::HTTP_11,
        keep_alive: false,
        upgrade: false,
    };
    let mut head = BytesMut::new();
    encode_response_head(&request, &parts, Some(0), true, None, &mut head)
        .expect("an empty final response is always valid");
    head.freeze()
}

/// The `Date` value, formatted once per second.
#[derive(Debug, Default)]
struct DateCache {
    second: u64,
    value: Option<HeaderValue>,
}

impl DateCache {
    fn get(&mut self) -> &HeaderValue {
        let now = SystemTime::now();
        let second = now
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after 1970")
            .as_secs();
        if self.value.is_none() || self.second != second {
            self.second = second;
            self.value = Some(
                HeaderValue::from_str(&httpdate::fmt_http_date(now))
                    .expect("an HTTP date is a valid field value"),
            );
        }
        self.value.as_ref().expect("set above")
    }
}

/// The channels of one `Expect: 100-continue` exchange.
struct ContinueHandshake {
    /// The pump asks for `100 Continue` here...
    want_continue: async_channel::Sender<()>,
    /// ...and the responder hears it here.
    continue_wanted: async_channel::Receiver<()>,
    /// The responder closes this once the interim response was sent...
    continued_tx: async_channel::Sender<()>,
    /// ...which releases the pump waiting on it.
    continued: async_channel::Receiver<()>,
}

impl ContinueHandshake {
    fn new() -> Self {
        let (want_continue, continue_wanted) = async_channel::bounded(1);
        let (continued_tx, continued) = async_channel::bounded(1);
        Self {
            want_continue,
            continue_wanted,
            continued_tx,
            continued,
        }
    }
}
