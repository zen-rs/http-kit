//! Serving HTTP/3 on one UDP socket.
//!
//! [`Server`] is an endpoint: one socket, every connection that reaches it,
//! and every request on those connections, driven by one future on one
//! thread. Datagrams are routed to connections by destination connection
//! ID; an Initial packet for an unknown ID opens a connection, once its
//! source address is validated with a stateless Retry when
//! [`ServerConfig::retry`] requires it. Each request
//! runs its [`Service`] call as a task inside that future, its request body
//! streaming from the peer while its response body streams back.

use std::{
    collections::HashMap,
    future::{Future, pending},
    mem,
    net::SocketAddr,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime},
};

use async_channel::{Receiver, Sender};
use futures_lite::future::or;
use http::Method;
use http_kit::{Body, Request, Response};
use http_kit_io::{BufResult, DatagramSocket, Timer, datagram::MAX_COALESCED_BYTES};
use quiche::{
    ConnectionId, Shutdown,
    h3::{self, WireErrorCode},
};

use crate::{
    Error, ServerConfig,
    body::{self, Command},
    config::H3Settings,
    conn::{Conn, ConnKey, Recv, Send, Stream, StreamRef, code},
    driver::{Sources, Timers, Transmit, peer_error},
    fields,
    retry::{Refused, RetryConfig, Validator},
};

/// Answers requests.
///
/// Implemented for every `Fn(Request) -> impl Future<Output = Response>`.
/// Errors are the service's to turn into responses; nothing here is `Send`.
/// Each request carries a [`ConnectionInfo`](crate::ConnectionInfo) in its
/// extensions.
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

/// Counters of a [`Server`]'s connection setup, readable from any thread
/// while it serves.
///
/// Every clone reads the same counters; [`Server::stats`] hands one out.
#[derive(Debug, Clone, Default)]
pub struct ServerStats(Arc<Counters>);

#[derive(Debug, Default)]
struct Counters {
    accepted: AtomicU64,
    retries: AtomicU64,
    invalid_tokens: AtomicU64,
    expired_tokens: AtomicU64,
}

impl ServerStats {
    /// Connections opened.
    #[must_use]
    pub fn connections_accepted(&self) -> u64 {
        self.0.accepted.load(Ordering::Relaxed)
    }

    /// Retry packets written in answer to an Initial without a token.
    #[must_use]
    pub fn retries_sent(&self) -> u64 {
        self.0.retries.load(Ordering::Relaxed)
    }

    /// Initials dropped because their token was not one this server minted
    /// for that client address and connection ID.
    #[must_use]
    pub fn invalid_tokens(&self) -> u64 {
        self.0.invalid_tokens.load(Ordering::Relaxed)
    }

    /// Initials dropped because their token was authentic but older than
    /// [`RetryConfig::validity`](crate::RetryConfig::validity).
    #[must_use]
    pub fn expired_tokens(&self) -> u64 {
        self.0.expired_tokens.load(Ordering::Relaxed)
    }

    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// An HTTP/3 server endpoint on one socket.
pub struct Server<S, T> {
    socket: S,
    timer: T,
    quic: quiche::Config,
    h3: H3Settings,
    read_size: usize,
    local: SocketAddr,
    retry: Option<RetryConfig>,
    stats: ServerStats,
}

impl<S, T> std::fmt::Debug for Server<S, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl<S: DatagramSocket, T: Timer> Server<S, T> {
    /// A server on `socket`, its QUIC timers driven by `timer`.
    ///
    /// # Errors
    ///
    /// The identity cannot be loaded, quiche rejects a setting, or the
    /// socket cannot report its address.
    pub fn new(socket: S, timer: T, config: &ServerConfig) -> Result<Self, Error> {
        let (quic, h3) = config.quiche()?;
        let local = socket.local_addr()?;
        Ok(Self {
            socket,
            timer,
            quic,
            h3,
            read_size: config.read_size,
            local,
            retry: config.retry.clone(),
            stats: ServerStats::default(),
        })
    }

    /// The address the socket is bound to.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// A handle on this server's counters.
    #[must_use]
    pub fn stats(&self) -> ServerStats {
        self.stats.clone()
    }

    /// Serves until the socket fails.
    ///
    /// # Errors
    ///
    /// The socket failed. Errors on one connection or stream end only that
    /// connection or stream, and are logged.
    pub async fn serve<Svc: Service>(self, service: &Svc) -> Result<(), Error> {
        self.serve_until(service, pending()).await
    }

    /// Serves like [`serve`](Self::serve) until `shutdown` completes, then
    /// drains gracefully: every connection gets a GOAWAY naming the requests
    /// it will still answer, those requests finish, and each connection
    /// closes with `H3_NO_ERROR` once it has none left. New connections are
    /// refused meanwhile. Returns once every connection has closed; drop the
    /// future to stop at once instead.
    ///
    /// # Errors
    ///
    /// As [`serve`](Self::serve).
    pub async fn serve_until<Svc: Service, F: Future<Output = ()>>(
        mut self,
        service: &Svc,
        shutdown: F,
    ) -> Result<(), Error> {
        let (mailbox, inbox) = async_channel::unbounded();
        let mut endpoint = Endpoint {
            quic: &mut self.quic,
            h3: self.h3,
            read_size: self.read_size,
            local: self.local,
            mailbox: mailbox.clone(),
            conns: HashMap::new(),
            cids: HashMap::new(),
            next_key: 0,
            timers: Timers::default(),
            dirty: Vec::new(),
            stopping: false,
            retry: self
                .retry
                .take()
                .map(|config| Validator::new(config, Instant::now())),
            stats: self.stats.clone(),
        };
        let socket = &self.socket;
        let timer = &self.timer;
        let recv = pin!(socket.recv_from(Vec::with_capacity(MAX_COALESCED_BYTES)));
        let sleep = pin!(timer.sleep_until(Instant::now()));
        let inbox = pin!(inbox);
        let mut shutdown = pin!(shutdown);
        let mut awaiting_shutdown = true;
        let mut sources = Sources::new(recv, sleep, inbox);
        let mut transmit = Transmit::new(socket.max_send_segments());
        let mut commands = Vec::new();
        let mut spawns = Vec::new();
        let mut replies = Vec::new();
        loop {
            let woken = sources
                .wait(&mut commands, !endpoint.dirty.is_empty(), |cx| {
                    (awaiting_shutdown && shutdown.as_mut().poll(cx).is_ready()).then_some(())
                })
                .await;
            if woken.extra.is_some() {
                awaiting_shutdown = false;
                endpoint.drain();
            }
            if let Some(BufResult(received, mut buf)) = woken.received {
                match received {
                    Ok(meta) => {
                        for range in meta.segments() {
                            endpoint.datagram(&mut buf[range], meta.from(), &mut replies);
                        }
                    }
                    Err(error) if peer_error(&error) => {
                        tracing::debug!(%error, "receive reported a peer's error");
                    }
                    Err(error) => return Err(error.into()),
                }
                sources.rearm_recv(socket.recv_from(buf));
            }
            for (reply, to) in replies.drain(..) {
                let BufResult(sent, _) = socket.send_to(reply, to).await;
                if let Err(error) = sent {
                    tracing::debug!(%error, %to, "stateless reply send failed");
                }
            }
            if woken.timer {
                endpoint.expire(Instant::now());
            }
            for command in commands.drain(..) {
                endpoint.command(command);
            }
            for key in mem::take(&mut endpoint.dirty) {
                endpoint.service(key, &mut spawns);
                if let Some(served) = endpoint.conns.get_mut(&key) {
                    transmit.flush(socket, &mut served.conn).await;
                }
                endpoint.settle(key);
            }
            for spawn in spawns.drain(..) {
                sources.tasks.push(respond(service, spawn, mailbox.clone()));
            }
            sources.arm_timer(endpoint.timers.next(), |at| timer.sleep_until(at));
            if endpoint.stopping && endpoint.conns.is_empty() {
                tracing::debug!("drained; every connection closed");
                return Ok(());
            }
        }
    }
}

/// A request to hand to the service.
struct Spawn {
    request: Request,
    stream: StreamRef,
    head: bool,
    credit: Receiver<()>,
}

/// Runs one request: the service call, then the response body's pump. The
/// call is dropped if the stream is reset or its connection closes first.
async fn respond<Svc: Service>(service: &Svc, spawn: Spawn, mailbox: Sender<Command>) {
    let Spawn {
        request,
        stream,
        head,
        credit,
    } = spawn;
    let call = async { Some(service.call(request).await) };
    let withdrawn = async {
        body::cancelled(&credit).await;
        None
    };
    let Some(response) = or(call, withdrawn).await else {
        return;
    };
    let (parts, body) = response.into_parts();
    let body_len = body.len().map(|len| len as u64);
    let has_body = !head && body.is_empty() != Some(true);
    mailbox
        .try_send(Command::Respond {
            stream,
            parts,
            body_len,
            has_body,
        })
        .ok();
    if has_body {
        body::pump(body, stream, &mailbox, &credit).await;
    }
}

/// One connection, with what the server keeps about it.
struct Served {
    conn: Conn,
    /// The connection IDs routed to it.
    cids: Vec<ConnectionId<'static>>,
    /// The highest request stream ID received.
    max_request: Option<u64>,
    /// The first request stream ID a GOAWAY refused.
    goaway: Option<u64>,
}

struct Endpoint<'c> {
    quic: &'c mut quiche::Config,
    h3: H3Settings,
    read_size: usize,
    local: SocketAddr,
    mailbox: Sender<Command>,
    conns: HashMap<ConnKey, Served>,
    cids: HashMap<ConnectionId<'static>, ConnKey>,
    next_key: ConnKey,
    timers: Timers,
    dirty: Vec<ConnKey>,
    stopping: bool,
    retry: Option<Validator>,
    stats: ServerStats,
}

impl Endpoint<'_> {
    fn touch(&mut self, key: ConnKey) {
        if let Some(served) = self.conns.get_mut(&key)
            && !served.conn.dirty
        {
            served.conn.dirty = true;
            self.dirty.push(key);
        }
    }

    /// Routes one received datagram.
    fn datagram(
        &mut self,
        packet: &mut [u8],
        from: SocketAddr,
        replies: &mut Vec<(Vec<u8>, SocketAddr)>,
    ) {
        let header = match quiche::Header::from_slice(packet, quiche::MAX_CONN_ID_LEN) {
            Ok(header) => header,
            Err(error) => {
                tracing::trace!(%error, %from, "not a QUIC packet");
                return;
            }
        };
        let key = if let Some(&key) = self.cids.get(&header.dcid) {
            key
        } else {
            if header.ty != quiche::Type::Initial {
                tracing::trace!(%from, "packet for an unknown connection");
                return;
            }
            if !quiche::version_is_supported(header.version) {
                let mut reply = vec![0; quiche::MIN_CLIENT_INITIAL_LEN];
                match quiche::negotiate_version(&header.scid, &header.dcid, &mut reply) {
                    Ok(len) => {
                        reply.truncate(len);
                        replies.push((reply, from));
                    }
                    Err(error) => tracing::debug!(%error, %from, "version negotiation failed"),
                }
                return;
            }
            if self.stopping {
                tracing::debug!(%from, "draining; refusing a new connection");
                return;
            }
            // A client's first datagram is padded to this size, which bounds
            // what a spoofed source can make the server send (RFC 9000 §14.1).
            if packet.len() < quiche::MIN_CLIENT_INITIAL_LEN {
                tracing::trace!(%from, len = packet.len(), "Initial in a short datagram");
                return;
            }
            let Some(admission) = self.validate(&header, from, replies) else {
                return;
            };
            let Some(key) = self.accept(&header.dcid, admission, from) else {
                return;
            };
            key
        };
        let local = self.local;
        let served = self
            .conns
            .get_mut(&key)
            .expect("every routed ID has a connection");
        match served
            .conn
            .quic
            .recv(packet, quiche::RecvInfo { from, to: local })
        {
            Ok(_) | Err(quiche::Error::Done) => {}
            Err(error) => tracing::debug!(%error, %from, "packet rejected"),
        }
        self.touch(key);
    }

    /// Decides whether a new connection's Initial may open one, or `None`
    /// when it is answered with a Retry or dropped; neither allocates
    /// connection state.
    ///
    /// A token that fails its check is dropped rather than answered with
    /// `INVALID_TOKEN` (RFC 9000 §8.1.3 permits either): closing needs
    /// Initial keys and a TLS session per packet, work a flood of forged
    /// tokens could then make the server do, and a reply a spoofed source
    /// could aim at a victim. An honest client with a stale token times out.
    fn validate(
        &mut self,
        header: &quiche::Header<'_>,
        from: SocketAddr,
        replies: &mut Vec<(Vec<u8>, SocketAddr)>,
    ) -> Option<Admission> {
        let Some(retry) = self.retry.as_mut() else {
            return Some(Admission::Unvalidated);
        };
        match header.token.as_deref() {
            Some(token) if !token.is_empty() => {
                match retry.check(token, from, &header.dcid, SystemTime::now()) {
                    Ok(odcid) => Some(Admission::Validated { odcid }),
                    Err(refused) => {
                        tracing::debug!(%from, ?refused, "Initial with a refused token");
                        ServerStats::count(match refused {
                            Refused::Invalid => &self.stats.0.invalid_tokens,
                            Refused::Expired => &self.stats.0.expired_tokens,
                        });
                        None
                    }
                }
            }
            _ if retry.requires(Instant::now()) => {
                let scid = random_cid();
                let token = retry.mint(from, &header.dcid, &scid, SystemTime::now());
                let mut reply = vec![0; quiche::MIN_CLIENT_INITIAL_LEN];
                match quiche::retry(
                    &header.scid,
                    &header.dcid,
                    &scid,
                    &token,
                    header.version,
                    &mut reply,
                ) {
                    Ok(len) => {
                        reply.truncate(len);
                        replies.push((reply, from));
                        ServerStats::count(&self.stats.0.retries);
                        tracing::trace!(%from, "Retry");
                    }
                    Err(error) => tracing::debug!(%error, %from, "Retry failed"),
                }
                None
            }
            _ => Some(Admission::Unvalidated),
        }
    }

    /// Opens a connection for an Initial sent to `dcid`. After a Retry,
    /// `dcid` is the Retry's source ID, minted here and authenticated by the
    /// token, and becomes the connection's, as the client's transport
    /// parameter check expects.
    fn accept(
        &mut self,
        dcid: &ConnectionId<'_>,
        admission: Admission,
        from: SocketAddr,
    ) -> Option<ConnKey> {
        let (scid, odcid) = match admission {
            Admission::Validated { odcid } => (dcid.clone().into_owned(), Some(odcid)),
            Admission::Unvalidated => (random_cid(), None),
        };
        let quic = match quiche::accept(&scid, odcid.as_ref(), self.local, from, self.quic) {
            Ok(quic) => quic,
            Err(error) => {
                tracing::debug!(%error, %from, "connection refused");
                return None;
            }
        };
        let key = self.next_key;
        self.next_key += 1;
        ServerStats::count(&self.stats.0.accepted);
        tracing::debug!(%from, key, validated = odcid.is_some(), "new connection");
        // Until it switches to the server's ID, the client keeps sending to
        // the ID it chose; after a Retry, that is the Retry's, now `scid`.
        let mut cids = vec![scid.clone()];
        if odcid.is_none() {
            cids.push(dcid.clone().into_owned());
        }
        for cid in &cids {
            self.cids.insert(cid.clone(), key);
        }
        self.conns.insert(
            key,
            Served {
                conn: Conn::new(key, quic, self.local, from, self.read_size),
                cids,
                max_request: None,
                goaway: None,
            },
        );
        Some(key)
    }

    fn expire(&mut self, now: Instant) {
        let expired: Vec<ConnKey> = self.timers.expired(now).collect();
        for key in expired {
            self.touch(key);
        }
    }

    fn command(&mut self, command: Command) {
        let key = command.stream().conn;
        if let Some(served) = self.conns.get_mut(&key) {
            served.conn.apply(command);
            self.touch(key);
        }
    }

    /// Starts the graceful drain.
    fn drain(&mut self) {
        tracing::debug!(connections = self.conns.len(), "draining");
        self.stopping = true;
        let keys: Vec<ConnKey> = self.conns.keys().copied().collect();
        for key in keys {
            if let Some(served) = self.conns.get_mut(&key) {
                goaway(served);
            }
            self.touch(key);
        }
    }

    /// Runs one connection's timers and HTTP/3 events, and moves its
    /// streams' output into quiche.
    fn service(&mut self, key: ConnKey, spawns: &mut Vec<Spawn>) {
        let Some(served) = self.conns.get_mut(&key) else {
            return;
        };
        served.conn.dirty = false;
        let now = Instant::now();
        served.conn.on_timer(now);
        if served.conn.h3.is_none() && served.conn.quic.is_established() {
            match h3::Connection::with_transport(&mut served.conn.quic, &self.h3.build()) {
                Ok(h3) => {
                    served.conn.h3 = Some(h3);
                    if self.stopping {
                        goaway(served);
                    }
                }
                Err(error) => tracing::debug!(%error, "HTTP/3 setup failed"),
            }
        }
        while let Some(h3) = served.conn.h3.as_mut() {
            let (id, event) = match h3.poll(&mut served.conn.quic) {
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
                    if let Some(stream) = served.conn.streams.get(&id) {
                        if stream.recv.is_some() {
                            served.conn.on_trailers(id, &list, more_frames);
                        }
                    } else if let Some(spawn) =
                        self::request(served, &self.mailbox, id, &list, more_frames)
                    {
                        spawns.push(spawn);
                    }
                }
                h3::Event::Data => served.conn.on_data(id),
                h3::Event::Finished => served.conn.on_finished(id),
                h3::Event::Reset(code) => served.conn.on_reset(id, &Error::StreamReset(code)),
                h3::Event::PriorityUpdate => {
                    // Streams are served in arrival order; take the update
                    // so quiche reports the next one.
                    h3.take_last_priority_update(id).ok();
                }
                h3::Event::GoAway => {}
            }
        }
        served.conn.write_unblocked();
        // The alarm is the round trip a GOAWAY waits out; once it passed it
        // is cleared, so it cannot keep the timer firing.
        if served.conn.alarm.is_some_and(|at| at <= now) {
            served.conn.alarm = None;
        }
        // Checked on every pass, which also forgets delivered streams.
        let delivered = served.conn.delivered();
        if served.goaway.is_some()
            && served.conn.alarm.is_none()
            && served.conn.streams.is_empty()
            && delivered
        {
            served
                .conn
                .quic
                .close(true, code(WireErrorCode::NoError), b"")
                .ok();
        }
    }

    /// Forgets a closed connection, or files its next deadline.
    fn settle(&mut self, key: ConnKey) {
        let Some(served) = self.conns.get_mut(&key) else {
            return;
        };
        if !served.conn.quic.is_closed() {
            self.timers.update(&mut served.conn);
            return;
        }
        let mut served = self.conns.remove(&key).expect("looked up above");
        self.timers.remove(&served.conn);
        for cid in &served.cids {
            self.cids.remove(cid);
        }
        match served.conn.outcome() {
            Ok(()) => tracing::debug!(key, "connection closed"),
            Err(error) => tracing::debug!(key, %error, "connection closed"),
        }
        served.conn.fail_all(&Error::ConnectionClosed);
    }
}

/// How a new connection's Initial was admitted.
enum Admission {
    /// No validation was required.
    Unvalidated,
    /// It echoed a valid token naming the client's original destination ID.
    Validated { odcid: ConnectionId<'static> },
}

/// A fresh server connection ID, as long as QUIC allows.
fn random_cid() -> ConnectionId<'static> {
    let mut id = vec![0; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut id).expect("BoringSSL's random generator does not fail");
    ConnectionId::from_vec(id)
}

/// Sends a connection its GOAWAY, or closes one that has not reached
/// HTTP/3 yet.
///
/// The GOAWAY names the stream after the highest request received, so every
/// request the client sent before it reads the frame is either answered or
/// rejected as safe to retry. A request below that ID may still be in flight
/// out of order, so the connection waits a round trip before it closes.
fn goaway(served: &mut Served) {
    let conn = &mut served.conn;
    let Some(h3) = conn.h3.as_mut() else {
        conn.quic
            .close(true, code(WireErrorCode::NoError), b"")
            .ok();
        return;
    };
    if served.goaway.is_some() {
        return;
    }
    let first_refused = served.max_request.map_or(0, |id| id + 4);
    match h3.send_goaway(&mut conn.quic, first_refused) {
        Ok(()) => {
            served.goaway = Some(first_refused);
            let rtt = conn
                .quic
                .path_stats()
                .next()
                .map(|path| path.rtt)
                .unwrap_or_default();
            conn.alarm = Some(Instant::now() + rtt);
        }
        Err(error) => {
            tracing::debug!(%error, "GOAWAY failed; closing");
            conn.quic
                .close(true, code(WireErrorCode::InternalError), b"")
                .ok();
        }
    }
}

/// Opens a request stream, or refuses it.
fn request(
    served: &mut Served,
    mailbox: &Sender<Command>,
    id: u64,
    list: &[h3::Header],
    more_frames: bool,
) -> Option<Spawn> {
    let conn = &mut served.conn;
    if served
        .goaway
        .is_some_and(|first_refused| id >= first_refused)
    {
        tracing::debug!(stream = id, "request after GOAWAY; rejecting");
        let rejected = code(WireErrorCode::RequestRejected);
        conn.quic.stream_shutdown(id, Shutdown::Read, rejected).ok();
        conn.quic
            .stream_shutdown(id, Shutdown::Write, rejected)
            .ok();
        return None;
    }
    served.max_request = Some(served.max_request.map_or(id, |max| max.max(id)));
    let (mut parts, expected) = match fields::decode_request(list) {
        Ok(decoded) => decoded,
        Err(malformed) => {
            tracing::debug!(stream = id, %malformed, "malformed request");
            let error = code(WireErrorCode::MessageError);
            conn.quic.stream_shutdown(id, Shutdown::Read, error).ok();
            conn.quic.stream_shutdown(id, Shutdown::Write, error).ok();
            return None;
        }
    };
    tracing::trace!(stream = id, method = %parts.method, uri = %parts.uri, "request");
    // The peer as quiche validated it: the active path's address, which
    // follows a migration and ignores datagrams that failed to decrypt.
    if let Some(path) = conn.quic.path_stats().find(|path| path.active) {
        conn.info.set_peer(path.peer_addr);
    }
    parts.extensions.insert(conn.info);
    let stream = conn.stream_ref(id);
    let (body, recv) = if more_frames {
        let (frames, body) = body::incoming(stream, mailbox.clone());
        (body, Some(Recv::new(frames, expected)))
    } else {
        (Body::empty(), None)
    };
    let (credit, credits) = async_channel::bounded(1);
    let head = parts.method == Method::HEAD;
    conn.streams.insert(
        id,
        Stream {
            recv,
            send: Send::Waiting,
            credit: Some(credit),
            respond: None,
            head_request: false,
        },
    );
    if !more_frames && expected.is_some_and(|len| len > 0) {
        conn.malformed(id, crate::Malformed::ContentLengthMismatch);
        return None;
    }
    Some(Spawn {
        request: Request::from_parts(parts, body),
        stream,
        head,
        credit: credits,
    })
}

#[cfg(test)]
mod tests {
    use super::Response;

    // The service bound is the same as HTTP/1.1's: a closure from request to
    // response future.
    #[test]
    fn closures_are_services() {
        fn assert_service<S: super::Service>(_: &S) {}
        assert_service(&|_request: http_kit::Request| async {
            Response::new(http_kit::Body::empty())
        });
    }
}
