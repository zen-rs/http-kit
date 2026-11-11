//! Sending HTTP/3 requests on one connection.
//!
//! [`Client::connect`] splits a connection into a [`SendRequest`] handle and
//! the [`Connection`] that owns its socket. The connection must be driven —
//! awaited, or spawned on the thread's local executor — for anything to make
//! progress: the handshake, and every request on it, which run concurrently
//! as QUIC streams. Requests sent before the handshake completes wait for it.
//!
//! The handle is `Clone` and `Send`, so a connection pool can hold it while
//! the connection itself, like every future here, stays on one thread.

use std::{
    collections::VecDeque,
    fmt,
    net::SocketAddr,
    pin::pin,
    sync::{Arc, OnceLock},
    task::Poll,
    time::Instant,
};

use async_channel::{Receiver, Sender};
use futures_lite::Stream as _;
use http::{Method, StatusCode};
use http_kit::{Body, Deadlines, Request, Response};
use http_kit_io::{BufResult, DatagramSocket, Timer, datagram::MAX_COALESCED_BYTES};
use quiche::h3::{self, Header, WireErrorCode};

use crate::{
    ClientConfig, Error, TrySendError,
    body::{self, Command},
    config::H3Settings,
    conn::{Bounds, Conn, Outgoing, Recv, Send, Stream, StreamRef, code},
    driver::{Sources, Transmit, peer_error},
    fields,
};

/// A prepared client configuration: TLS context and QUIC settings, built
/// once and used for each connection.
pub struct Client {
    quic: quiche::Config,
    h3: H3Settings,
    read_size: usize,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").finish_non_exhaustive()
    }
}

impl Client {
    /// Prepares `config`.
    ///
    /// # Errors
    ///
    /// The trust roots cannot be loaded, or quiche rejects a setting.
    pub fn new(config: &ClientConfig) -> Result<Self, Error> {
        let (quic, h3) = config.quiche()?;
        Ok(Self {
            quic,
            h3,
            read_size: config.read_size,
        })
    }

    /// Starts a connection to `peer` over `socket`, verifying the server's
    /// certificate for `server_name` (also sent as SNI, and the name a
    /// [`Verifier`](crate::Verifier) is given). Its QUIC timers are driven by
    /// `timer`.
    ///
    /// # Errors
    ///
    /// The socket cannot report its address, or quiche cannot start the
    /// connection (an invalid server name, among others).
    pub fn connect<S: DatagramSocket, T: Timer>(
        &mut self,
        socket: S,
        timer: T,
        server_name: &str,
        peer: SocketAddr,
    ) -> Result<(SendRequest, Connection<S, T>), Error> {
        let local = socket.local_addr()?;
        let mut id = vec![0; quiche::MAX_CONN_ID_LEN];
        boring::rand::rand_bytes(&mut id).expect("BoringSSL's random generator does not fail");
        let scid = quiche::ConnectionId::from_vec(id);
        let quic = Box::new(quiche::connect(
            Some(server_name),
            &scid,
            local,
            peer,
            &mut self.quic,
        )?);
        let (send, exchanges) = async_channel::bounded(1);
        let (mailbox, inbox) = async_channel::unbounded();
        let (ready, handshake) = Readiness::new();
        Ok((
            SendRequest {
                exchanges: send,
                handshake,
            },
            Connection {
                socket,
                timer,
                conn: Conn::new(0, quic, local, peer, self.read_size),
                h3: self.h3,
                exchanges,
                mailbox,
                inbox,
                ready,
            },
        ))
    }
}

/// A request on its way to the connection.
///
/// One that is dropped before the connection took it (the connection ended
/// while it waited in the queue) hands its request back to the caller that
/// sent it: nothing of it was sent.
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

    /// Answers with `error`, handing the request back.
    fn refuse(mut self, error: Error) {
        if let Some(request) = self.request.take() {
            self.respond
                .try_send(Err(TrySendError::unsent(error, request)))
                .ok();
        }
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

/// Sends requests on a connection.
#[derive(Clone)]
pub struct SendRequest {
    exchanges: Sender<Exchange>,
    handshake: Handshake,
}

impl fmt::Debug for SendRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SendRequest")
            .field("closed", &self.is_closed())
            .finish()
    }
}

impl SendRequest {
    /// Sends `request` and waits for the head of its response. The request
    /// body streams to the server while the response body streams back, as
    /// each is read.
    ///
    /// The URI's authority, or else its `Host` field, becomes `:authority`;
    /// its scheme `:scheme` (`https` when absent).
    ///
    /// # Errors
    ///
    /// The request cannot be sent as given, the server reset or refused it
    /// ([`Error::RequestRejected`] is safe to retry), or the connection
    /// failed or closed before the response head arrived. Once the server's
    /// GOAWAY has been read the handle is closed, and a request fails with
    /// [`Error::ConnectionClosed`] without being sent.
    pub async fn send(&self, request: Request) -> Result<Response, Error> {
        self.try_send(request).await.map_err(Error::from)
    }

    /// As [`send`](Self::send), but a failure that left the request unsent
    /// gives it back, its body unread: the handle was closed (the
    /// connection ended, or the server's GOAWAY was read), the connection
    /// ended or read a GOAWAY before it opened a stream for the request
    /// (including a handshake that failed), or the server refused the
    /// request unprocessed ([`Error::RequestRejected`]). A pool can send it
    /// again on another connection, whatever its method or body.
    ///
    /// A request refused after its stream opened is given back only when its
    /// body is known to be empty: a body that may hold data was handed to
    /// the stream as soon as it opened, and is not recoverable.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send), with the request in the [`TrySendError`]
    /// when it can be recovered.
    pub async fn try_send(&self, request: Request) -> Result<Response, TrySendError> {
        let (respond, response) = async_channel::bounded(1);
        if let Err(refused) = self.exchanges.send(Exchange::new(request, respond)).await {
            refused.into_inner().refuse(Error::ConnectionClosed);
        }
        response
            .recv()
            .await
            .map_err(|_| TrySendError::from(Error::ConnectionClosed))?
    }

    /// Resolves when the connection's handshake completes: the server's
    /// certificate was accepted and requests can be answered. Until then
    /// they wait. It fails with the handshake's error (a refused chain
    /// closes the connection with the TLS alert's code) or, if the
    /// connection ends first, [`Error::ConnectionClosed`].
    ///
    /// The [`Connection`] must be driven for it to resolve. Every clone of
    /// the handle may wait, and each gets the same answer, also after the
    /// fact.
    ///
    /// # Errors
    ///
    /// As above.
    pub async fn ready(&self) -> Result<(), Error> {
        self.handshake.done.recv().await.ok();
        self.handshake
            .outcome
            .get()
            .cloned()
            .expect("the connection reports before it closes the channel")
    }

    /// Whether the connection has stopped taking requests: it closed, or
    /// the server sent GOAWAY.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.exchanges.is_closed()
    }
}

/// The socket side of a client connection: drive it with
/// [`run`](Self::run).
pub struct Connection<S, T> {
    socket: S,
    timer: T,
    conn: Conn,
    h3: H3Settings,
    exchanges: Receiver<Exchange>,
    mailbox: Sender<Command>,
    inbox: Receiver<Command>,
    ready: Readiness,
}

impl<S, T> fmt::Debug for Connection<S, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.conn.info.peer_addr())
            .field("streams", &self.conn.streams.len())
            .finish_non_exhaustive()
    }
}

/// A request waiting for a stream.
struct Queued {
    fields: Vec<Header>,
    fin: bool,
    declared: Option<u64>,
    head: bool,
    /// The request's receive deadlines, applied once a stream opens.
    deadlines: Deadlines,
    /// The request, until a stream took it. Dropped queued, it goes back to
    /// the caller: nothing of it was sent.
    request: Option<(http::request::Parts, Body)>,
    respond: Sender<Result<Response, TrySendError>>,
}

impl Queued {
    fn new(exchange: Exchange) -> Option<Self> {
        let (request, respond) = exchange.take();
        let (parts, body) = request.into_parts();
        let len = body.len().map(|len| len as u64);
        let deadlines = parts
            .extensions
            .get::<Deadlines>()
            .copied()
            .unwrap_or_default();
        match fields::encode_request(&parts, len) {
            Ok(fields) => {
                let fin = body.is_empty() == Some(true);
                Some(Self {
                    fields,
                    fin,
                    declared: (!fin)
                        .then(|| fields::declared_length(&parts.headers).or(len))
                        .flatten(),
                    head: parts.method == Method::HEAD,
                    deadlines,
                    request: Some((parts, body)),
                    respond,
                })
            }
            Err(error) => {
                respond.try_send(Err(error.into())).ok();
                None
            }
        }
    }

    /// Fails the request with `error`, handing it back.
    fn refuse(mut self, error: Error) {
        if let Some((parts, body)) = self.request.take() {
            self.respond
                .try_send(Err(TrySendError::unsent(
                    error,
                    Request::from_parts(parts, body),
                )))
                .ok();
        }
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        if let Some((parts, body)) = self.request.take() {
            self.respond
                .try_send(Err(TrySendError::unsent(
                    Error::ConnectionClosed,
                    Request::from_parts(parts, body),
                )))
                .ok();
        }
    }
}

/// Feeds a request body to the driver.
async fn pump(body: Body, stream: StreamRef, mailbox: Sender<Command>, credit: Receiver<()>) {
    body::pump(body, stream, &mailbox, &credit).await;
}

impl<S: DatagramSocket, T: Timer> Connection<S, T> {
    /// Runs the connection until every [`SendRequest`] is dropped (or the
    /// server sent GOAWAY) and every exchange has finished, then closes it
    /// with `H3_NO_ERROR`. An idle timeout closes it too.
    ///
    /// An error is delivered to each request it affected, as the result of
    /// [`SendRequest::send`] or through its response body.
    ///
    /// The returned future is a pointer to the driver's state, which lives
    /// on the heap as long as the connection runs, so a caller that wraps it
    /// in futures of its own does not carry that state inline in each.
    ///
    /// # Errors
    ///
    /// The socket failed, the handshake failed, or either side closed the
    /// connection with an error.
    pub fn run(self) -> impl Future<Output = Result<(), Error>> {
        Box::pin(self.drive())
    }

    async fn drive(self) -> Result<(), Error> {
        let Self {
            socket,
            timer,
            mut conn,
            h3: settings,
            exchanges,
            mailbox,
            inbox,
            ready,
        } = self;
        let recv = pin!(socket.recv_from(Vec::with_capacity(MAX_COALESCED_BYTES)));
        let sleep = pin!(timer.sleep_until(Instant::now()));
        let inbox = pin!(inbox);
        let mut exchanges = pin!(exchanges);
        let mut sources = Sources::new(recv, sleep, inbox);
        let mut transmit = Transmit::new(socket.max_send_segments(), conn.info.local_addr());
        let mut commands = Vec::new();
        let mut waiting: VecDeque<Queued> = VecDeque::new();
        let mut accepting = true;
        let mut closing = false;
        let mut dirty = true;
        loop {
            let woken = sources
                .wait(&mut commands, dirty, |cx| {
                    if !accepting || !waiting.is_empty() {
                        return None;
                    }
                    match exchanges.as_mut().poll_next(cx) {
                        Poll::Ready(exchange) => Some(exchange),
                        Poll::Pending => None,
                    }
                })
                .await;
            dirty = false;
            match woken.extra {
                Some(Some(exchange)) => waiting.extend(Queued::new(exchange)),
                Some(None) => accepting = false,
                None => {}
            }
            if let Some(BufResult(received, mut buf)) = woken.received {
                match received {
                    Ok(meta) => {
                        let info = quiche::RecvInfo {
                            from: meta.from(),
                            to: conn.info.local_addr(),
                        };
                        for range in meta.segments() {
                            match conn.quic.recv(&mut buf[range], info) {
                                Ok(_) | Err(quiche::Error::Done) => {}
                                Err(error) => tracing::debug!(%error, "packet rejected"),
                            }
                        }
                    }
                    Err(error) if peer_error(&error) => {
                        tracing::debug!(%error, "receive reported the server's error");
                    }
                    Err(error) => {
                        let error = Error::from(error);
                        ready.report(Err(error.clone()));
                        return Err(error);
                    }
                }
                sources.rearm_recv(socket.recv_from(buf));
            }
            for command in commands.drain(..) {
                conn.apply(command);
            }

            conn.on_timer(Instant::now());
            conn.expire(Instant::now());
            if conn.quic.is_established() {
                ready.report(Ok(()));
            }
            if conn.h3.is_none() && conn.quic.is_established() {
                match h3::Connection::with_transport(&mut conn.quic, &settings.build()) {
                    Ok(h3) => conn.h3 = Some(h3),
                    Err(error) => tracing::debug!(%error, "HTTP/3 setup failed"),
                }
            }
            while let Some(opened) = open_next(&mut conn, &mut waiting, &mailbox) {
                sources.tasks.extend(opened);
            }
            if events(&mut conn, &mailbox) {
                // GOAWAY: nothing new will be processed.
                accepting = false;
                exchanges.close();
                for queued in waiting.drain(..) {
                    queued.refuse(Error::RequestRejected);
                }
                // Sent before the handle closed, and not yet taken.
                while let Ok(exchange) = exchanges.try_recv() {
                    exchange.refuse(Error::RequestRejected);
                }
            }
            conn.write_unblocked();
            // Checked on every pass, which also forgets delivered streams.
            let delivered = conn.delivered();
            if !accepting && waiting.is_empty() && conn.streams.is_empty() && delivered && !closing
            {
                closing = true;
                conn.quic
                    .close(true, code(WireErrorCode::NoError), b"")
                    .ok();
            }

            transmit.flush(&socket, &mut conn).await;
            if conn.quic.is_closed() {
                let outcome = conn.outcome();
                let error = outcome.clone().err().unwrap_or(Error::ConnectionClosed);
                ready.report(Err(error.clone()));
                conn.fail_all(&error);
                for queued in waiting.drain(..) {
                    queued.refuse(error.clone());
                }
                exchanges.close();
                while let Ok(exchange) = exchanges.try_recv() {
                    exchange.refuse(error.clone());
                }
                return outcome;
            }
            sources.arm_timer(
                [conn.next_deadline(), conn.stream_deadline()]
                    .into_iter()
                    .flatten()
                    .min(),
                |at| timer.sleep_until(at),
            );
        }
    }
}

/// Opens a stream for the first waiting request, which leaves the queue
/// unless no stream can be opened yet (`None`). Otherwise returns the
/// request body's pump, when there is one to run.
fn open_next(
    conn: &mut Conn,
    waiting: &mut VecDeque<Queued>,
    mailbox: &Sender<Command>,
) -> Option<Option<impl Future<Output = ()> + use<>>> {
    let queued = waiting.front()?;
    let h3 = conn.h3.as_mut()?;
    match h3.send_request(&mut conn.quic, &queued.fields, queued.fin) {
        Ok(id) => {
            let mut queued = waiting.pop_front().expect("looked at above");
            let (parts, body) = queued
                .request
                .take()
                .expect("a queued request holds its request until a stream takes it");
            let stream = conn.stream_ref(id);
            tracing::trace!(stream = id, "request");
            let (credit, credits) = async_channel::bounded(1);
            // A body known to be empty is never read, so it stays whole for
            // the caller if the server rejects the stream unprocessed.
            let (unsent, body) = if queued.fin {
                (Some((parts, body)), None)
            } else {
                (None, Some(body))
            };
            conn.streams.insert(
                id,
                Stream {
                    recv: None,
                    send: if queued.fin {
                        Send::Done
                    } else {
                        Send::Body(Outgoing::new(queued.declared))
                    },
                    credit: (!queued.fin).then_some(credit),
                    respond: Some(queued.respond.clone()),
                    unsent,
                    head_request: queued.head,
                    bounds: Bounds {
                        // Counted from when the stream opens.
                        head_at: queued
                            .deadlines
                            .response_head
                            .and_then(|head| Instant::now().checked_add(head)),
                        body_idle: queued.deadlines.body_idle,
                    },
                },
            );
            let Some(body) = body else {
                return Some(None);
            };
            conn.write(id);
            Some(Some(pump(body, stream, mailbox.clone(), credits)))
        }
        Err(h3::Error::StreamBlocked | h3::Error::TransportError(quiche::Error::StreamLimit)) => {
            None
        }
        Err(error) => {
            let queued = waiting.pop_front().expect("looked at above");
            queued.refuse(error.into());
            Some(None)
        }
    }
}

/// Handles the connection's HTTP/3 events; `true` when the server sent
/// GOAWAY.
fn events(conn: &mut Conn, mailbox: &Sender<Command>) -> bool {
    let mut goaway = false;
    while let Some(h3) = conn.h3.as_mut() {
        let (id, event) = match h3.poll(&mut conn.quic) {
            Ok(event) => event,
            Err(h3::Error::Done) => break,
            Err(error) => {
                // quiche has closed the connection with the matching code.
                tracing::debug!(%error, "HTTP/3 connection error");
                break;
            }
        };
        match event {
            h3::Event::Headers { list, more_frames } => {
                headers(conn, mailbox, id, &list, more_frames);
            }
            h3::Event::Data => conn.on_data(id),
            h3::Event::Finished => conn.on_finished(id),
            h3::Event::Reset(reset) => {
                let error = if reset == code(WireErrorCode::RequestRejected) {
                    Error::RequestRejected
                } else {
                    Error::StreamReset(reset)
                };
                conn.on_reset(id, &error);
            }
            h3::Event::PriorityUpdate => {}
            h3::Event::GoAway => {
                tracing::debug!(first_refused = id, "server sent GOAWAY");
                conn.reject_from(id);
                goaway = true;
            }
        }
    }
    goaway
}

/// A response head, an interim response, or trailers.
fn headers(
    conn: &mut Conn,
    mailbox: &Sender<Command>,
    id: u64,
    list: &[Header],
    more_frames: bool,
) {
    let key = conn.stream_ref(id);
    let Some(stream) = conn.streams.get_mut(&id) else {
        return;
    };
    if stream.respond.is_none() {
        if stream.recv.is_some() {
            conn.on_trailers(id, list, more_frames);
        }
        return;
    }
    let (parts, expected) = match fields::decode_response(list) {
        Ok(decoded) => decoded,
        Err(malformed) => return conn.malformed(id, malformed),
    };
    if parts.status.is_informational() {
        tracing::trace!(stream = id, status = %parts.status, "interim response");
        return;
    }
    tracing::trace!(stream = id, status = %parts.status, "response");
    // A response to HEAD, a 204 and a 304 describe a body they do not carry.
    let bodiless = stream.head_request
        || parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED;
    let expected = expected.filter(|_| !bodiless);
    let body = if more_frames {
        let (frames, body) = body::incoming(key, mailbox.clone());
        let mut recv = Recv::new(frames, expected);
        recv.idle = stream.bounds.body_idle;
        stream.recv = Some(recv);
        body
    } else {
        Body::empty()
    };
    let respond = stream.respond.take().expect("checked above");
    respond.try_send(Ok(Response::from_parts(parts, body))).ok();
    if !more_frames && expected.is_some_and(|len| len > 0) {
        conn.malformed(id, crate::Malformed::ContentLengthMismatch);
        return;
    }
    conn.settle(id);
}

/// The handshake's outcome, shared between a connection and the handles to
/// it: set once, then the channel closes to wake whoever waits.
#[derive(Clone)]
struct Handshake {
    outcome: Arc<OnceLock<Result<(), Error>>>,
    done: Receiver<()>,
}

/// The connection's end of a [`Handshake`]. A connection dropped before it
/// reported fails it as closed.
struct Readiness {
    outcome: Arc<OnceLock<Result<(), Error>>>,
    done: Sender<()>,
}

impl Readiness {
    fn new() -> (Self, Handshake) {
        let outcome = Arc::new(OnceLock::new());
        let (done, waiting) = async_channel::bounded(1);
        (
            Self {
                outcome: outcome.clone(),
                done,
            },
            Handshake {
                outcome,
                done: waiting,
            },
        )
    }

    /// Records the outcome unless one was recorded already: the first is the
    /// handshake's.
    fn report(&self, outcome: Result<(), Error>) {
        if self.outcome.set(outcome).is_ok() {
            self.done.close();
        }
    }
}

impl Drop for Readiness {
    fn drop(&mut self) {
        self.report(Err(Error::ConnectionClosed));
    }
}
