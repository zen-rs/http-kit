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

use std::{collections::VecDeque, fmt, net::SocketAddr, pin::pin, task::Poll, time::Instant};

use async_channel::{Receiver, Sender};
use futures_lite::Stream as _;
use http::{Method, StatusCode};
use http_kit::{Body, Request, Response};
use http_kit_io::{BufResult, DatagramSocket, Timer, datagram::MAX_COALESCED_BYTES};
use quiche::h3::{self, Header, WireErrorCode};

use crate::{
    ClientConfig, Error,
    body::{self, Command},
    config::H3Settings,
    conn::{Conn, Outgoing, Recv, Send, Stream, StreamRef, code},
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
    /// certificate for `server_name` (also sent as SNI). Its QUIC timers are
    /// driven by `timer`.
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
        Ok((
            SendRequest { exchanges: send },
            Connection {
                socket,
                timer,
                conn: Conn::new(0, quic, local, peer, self.read_size),
                h3: self.h3,
                exchanges,
                mailbox,
                inbox,
            },
        ))
    }
}

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
        let (respond, response) = async_channel::bounded(1);
        self.exchanges
            .send(Exchange { request, respond })
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        response.recv().await.map_err(|_| Error::ConnectionClosed)?
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
    body: Body,
    fin: bool,
    declared: Option<u64>,
    head: bool,
    respond: Sender<Result<Response, Error>>,
}

impl Queued {
    fn new(exchange: Exchange) -> Option<Self> {
        let Exchange { request, respond } = exchange;
        let (parts, body) = request.into_parts();
        let len = body.len().map(|len| len as u64);
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
                    body,
                    respond,
                })
            }
            Err(error) => {
                respond.try_send(Err(error)).ok();
                None
            }
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
        } = self;
        let recv = pin!(socket.recv_from(Vec::with_capacity(MAX_COALESCED_BYTES)));
        let sleep = pin!(timer.sleep_until(Instant::now()));
        let inbox = pin!(inbox);
        let mut exchanges = pin!(exchanges);
        let mut sources = Sources::new(recv, sleep, inbox);
        let mut transmit = Transmit::new(socket.max_send_segments());
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
                    Err(error) => return Err(error.into()),
                }
                sources.rearm_recv(socket.recv_from(buf));
            }
            for command in commands.drain(..) {
                conn.apply(command);
            }

            conn.on_timer(Instant::now());
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
                    queued.respond.try_send(Err(Error::RequestRejected)).ok();
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
                conn.fail_all(&error);
                for queued in waiting.drain(..) {
                    queued.respond.try_send(Err(error.clone())).ok();
                }
                exchanges.close();
                while let Ok(exchange) = exchanges.try_recv() {
                    exchange.respond.try_send(Err(error.clone())).ok();
                }
                return outcome;
            }
            sources.arm_timer(conn.next_deadline(), |at| timer.sleep_until(at));
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
            let queued = waiting.pop_front().expect("looked at above");
            let stream = conn.stream_ref(id);
            tracing::trace!(stream = id, "request");
            let (credit, credits) = async_channel::bounded(1);
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
                    respond: Some(queued.respond),
                    head_request: queued.head,
                },
            );
            if queued.fin {
                return Some(None);
            }
            conn.write(id);
            Some(Some(pump(queued.body, stream, mailbox.clone(), credits)))
        }
        Err(h3::Error::StreamBlocked | h3::Error::TransportError(quiche::Error::StreamLimit)) => {
            None
        }
        Err(error) => {
            let queued = waiting.pop_front().expect("looked at above");
            queued.respond.try_send(Err(error.into())).ok();
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
        stream.recv = Some(Recv::new(frames, expected));
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
