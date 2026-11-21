//! Serving HTTP/2 requests multiplexed over one connection.
//!
//! [`ServerConnection`] drives the sans-IO [`ProtoConn`](crate::proto::ProtoConn)
//! state machine over owned-buffer read and write halves, running concurrent
//! [`Service`] futures on the accepting thread without `Send` bounds or locks.
//! Request and response bodies stream concurrently in full duplex, supporting
//! bidirectional streaming, standard `CONNECT` tunnels (RFC 9113 §8.5), and
//! Extended `CONNECT` (`:protocol`, RFC 8441).

use std::{
    collections::HashMap,
    fmt,
    future::{Future, pending, poll_fn},
    pin::{Pin, pin},
    task::Poll,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use async_channel::Sender;
use futures_lite::Stream as _;
use http::{HeaderValue, Method, StatusCode, response};
use http_kit::{Body, Request, Response};
use http_kit_io::{ReadOwned, SendFile, SpliceRead, SpliceWrite, Split, Timer, Write};

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use crate::splice::{SpliceOutcome, can_splice_read, reader_can_splice};
use crate::{
    Error, Reason, ServerConfig, Timeout,
    body::{self, BodyCommand, RecvStream},
    conn::{
        Outbox, OutgoingStreams, ReadDone, ReadMode, Recv, Slot, best_effort_error_close,
        deadline_after, flush_and_shutdown, step_read, step_write,
    },
    proto::{ProtoConn, ProtoEvent, ServerSide, StreamId},
};

/// Answers HTTP/2 requests on the connection's thread.
///
/// Implemented automatically for every `Fn(Request) -> impl Future<Output = Response>`.
/// Neither the service nor its returned future need be `Send`.
pub trait Service {
    /// Computes the response for `request`.
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

/// One server-side HTTP/2 connection over owned-buffer stream halves.
pub struct ServerConnection<R, W, T> {
    recv: Recv<R>,
    writer: W,
    timer: T,
    config: ServerConfig,
}

impl<R, W, T> fmt::Debug for ServerConnection<R, W, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConnection")
            .field("buffered", &self.recv.buf.len())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<R, W, T> ServerConnection<R, W, T>
where
    R: ReadOwned + SpliceRead,
    W: Write + SendFile + SpliceWrite,
    T: Timer,
{
    /// Creates an HTTP/2 server connection over split read and write halves.
    pub fn new(reader: R, writer: W, timer: T, config: ServerConfig) -> Self {
        Self {
            recv: Recv::new(reader, config.read_buffer_size),
            writer,
            timer,
            config,
        }
    }

    /// Creates an HTTP/2 server connection over a whole stream socket, split
    /// into concurrent read and write halves.
    pub fn from_stream<S>(stream: S, timer: T, config: ServerConfig) -> Self
    where
        S: Split<ReadHalf = R, WriteHalf = W>,
    {
        let (reader, writer) = stream.split();
        Self::new(reader, writer, timer, config)
    }

    /// Serves HTTP/2 requests until the peer closes the connection or a fatal
    /// connection error occurs.
    ///
    /// # Errors
    ///
    /// Returns transport, handshake, or connection-level HTTP/2 protocol errors
    /// after flushing the corresponding `GOAWAY` frame.
    pub async fn serve<S: Service>(self, service: &S) -> Result<(), Error> {
        self.serve_until(service, pending()).await
    }

    /// Serves HTTP/2 requests until `shutdown` resolves, then performs RFC 9113
    /// §6.8 two-phase graceful `GOAWAY` shutdown (`GOAWAY(2^31 - 1)` + RTT
    /// `PING`, followed by `GOAWAY(last_stream_id)`) and drains active streams.
    ///
    /// # Errors
    ///
    /// As [`serve`](Self::serve).
    pub async fn serve_until<S: Service, F: Future<Output = ()>>(
        self,
        service: &S,
        shutdown: F,
    ) -> Result<(), Error> {
        let Self {
            recv,
            writer,
            timer,
            config,
        } = self;

        let mut proto = ProtoConn::<ServerSide>::new_server(&config, Instant::now());
        let mut recv_slot = Some(recv);
        let mut read_task = Slot::default();
        let mut write_slot = Some((writer, Outbox::default()));
        let mut write_task = Slot::default();
        let mut outgoing = OutgoingStreams::default();
        let mut streams: HashMap<StreamId, ServerStream> = HashMap::new();
        let mut in_flight: Vec<(StreamId, Pin<Box<_>>)> = Vec::new();
        let mut date_cache = DateCache::default();
        let (mailbox, inbox) = async_channel::unbounded::<BodyCommand>();

        let mut inbox_rx = pin!(inbox);
        let mut shutdown = pin!(shutdown);
        let mut shutting_down = false;
        let mut peer_eof = false;
        let mut max_peer_stream = StreamId::CONNECTION;

        let mut sleep = pin!(timer.sleep_until(Instant::now()));
        let mut sleep_at: Option<Instant> = None;
        let mut idle_since: Option<Instant> = None;

        let mut commands: Vec<BodyCommand> = Vec::new();
        let mut ready_responses: Vec<(StreamId, Response)> = Vec::new();
        let mut failed_outgoing: Vec<(StreamId, Error)> = Vec::new();
        let mut pending_requests: Vec<(StreamId, Request)> = Vec::new();

        loop {
            let now = Instant::now();

            // 1. Parse all frames currently buffered in `recv.buf`.
            if let Some(recv) = recv_slot.as_mut() {
                loop {
                    match proto.poll_recv(&mut recv.buf, now) {
                        Ok(Some(event)) => {
                            idle_since = None;
                            handle_server_event(
                                event,
                                &config,
                                &mut proto,
                                &mut streams,
                                &mut outgoing,
                                &mut in_flight,
                                &mut pending_requests,
                                &mailbox,
                                &mut max_peer_stream,
                            );
                        }
                        Ok(None) => break,
                        Err(error) => {
                            return abort_server(
                                error,
                                &mut proto,
                                &mut recv_slot,
                                &mut write_slot,
                                &mut write_task,
                                &timer,
                                &mut streams,
                                &mut outgoing,
                                &mut in_flight,
                            )
                            .await;
                        }
                    }
                }
            }

            // Spawn `Service` futures for newly decoded requests.
            for (stream_id, request) in pending_requests.drain(..) {
                in_flight.push((stream_id, Box::pin(call_service(service, request))));
            }

            // 2. Check protocol, body-idle, and connection keep-alive deadlines.
            match proto.poll_timeout(now) {
                Ok(()) => {}
                Err(Error::Timeout(Timeout::KeepAlive))
                    if streams.is_empty() && in_flight.is_empty() && outgoing.is_empty() =>
                {
                    if let Some((w, o, res)) = write_task.finish().await {
                        write_slot = Some((w, o));
                        res?;
                    }
                    if let Some((mut writer, mut outbox)) = write_slot.take() {
                        proto.send_goaway(max_peer_stream, Reason::NO_ERROR, b"");
                        flush_and_shutdown(&mut proto, &mut writer, &mut outbox).await?;
                    }
                    return Ok(());
                }
                Err(error) => {
                    return abort_server(
                        error,
                        &mut proto,
                        &mut recv_slot,
                        &mut write_slot,
                        &mut write_task,
                        &timer,
                        &mut streams,
                        &mut outgoing,
                        &mut in_flight,
                    )
                    .await;
                }
            }
            expire_server_bodies(now, &mut proto, &mut streams);
            settle_server_streams(&mut proto, &mut streams, &outgoing);

            // Track idle connection keep-alive deadline when handshake is done and no stream is active.
            let is_idle = proto.is_handshake_complete()
                && !shutting_down
                && streams.is_empty()
                && in_flight.is_empty()
                && outgoing.is_empty()
                && recv_slot.as_ref().is_none_or(|r| r.buf.is_empty());
            if is_idle {
                let start = *idle_since.get_or_insert(now);
                if let Some(limit) = config.keep_alive_timeout
                    && now.saturating_duration_since(start) >= limit
                {
                    if let Some((w, o, res)) = write_task.finish().await {
                        write_slot = Some((w, o));
                        res?;
                    }
                    if let Some((mut writer, mut outbox)) = write_slot.take() {
                        proto.send_goaway(max_peer_stream, Reason::NO_ERROR, b"");
                        flush_and_shutdown(&mut proto, &mut writer, &mut outbox).await?;
                    }
                    return Ok(());
                }
            } else {
                idle_since = None;
            }

            // 3. Check clean completion (client EOF while idle, peer/local close, or graceful drain finished).
            let drained = (shutting_down && (proto.is_gracefully_drained() || peer_eof))
                || (peer_eof && proto.active_stream_count() == 0)
                || (proto.is_closing() && proto.active_stream_count() == 0);
            if drained && streams.is_empty() && in_flight.is_empty() && outgoing.is_empty() {
                if let Some((w, o, res)) = write_task.finish().await {
                    write_slot = Some((w, o));
                    res?;
                }
                if let Some((mut writer, mut outbox)) = write_slot.take() {
                    flush_and_shutdown(&mut proto, &mut writer, &mut outbox).await?;
                }
                return Ok(());
            }

            // 4. Arm earliest timer across protocol, body-idle, and idle keep-alive deadlines.
            let idle_deadline =
                idle_since.and_then(|start| deadline_after(start, config.keep_alive_timeout));
            let next_at = earliest_server_deadline(proto.next_deadline(), idle_deadline, &streams);
            if next_at != sleep_at {
                if let Some(at) = next_at {
                    sleep.set(timer.sleep_until(at));
                }
                sleep_at = next_at;
            }

            // 5. Poll every event source together without cancelling active socket I/O.
            let wake = poll_fn(|cx| {
                let mut progressed = false;

                if !shutting_down && shutdown.as_mut().poll(cx).is_ready() {
                    shutting_down = true;
                    idle_since = None;
                    proto.initiate_graceful_shutdown(Instant::now());
                    progressed = true;
                }

                // Poll active `Service` futures first so responses queue into `outbox` in the same pass.
                let mut idx = 0;
                while idx < in_flight.len() {
                    if let Poll::Ready(response) = in_flight[idx].1.as_mut().poll(cx) {
                        let (stream_id, _) = in_flight.swap_remove(idx);
                        ready_responses.push((stream_id, response));
                        progressed = true;
                    } else {
                        idx += 1;
                    }
                }

                if !ready_responses.is_empty() {
                    for (stream_id, response) in ready_responses.drain(..) {
                        submit_response(
                            stream_id,
                            response,
                            config.date_header,
                            &mut date_cache,
                            &mut proto,
                            &mut streams,
                            &mut outgoing,
                        );
                    }
                    settle_server_streams(&mut proto, &mut streams, &outgoing);
                }

                while let Poll::Ready(Some(cmd)) = inbox_rx.as_mut().poll_next(cx) {
                    commands.push(cmd);
                    progressed = true;
                }

                if !commands.is_empty() {
                    let tick_now = Instant::now();
                    for cmd in commands.drain(..) {
                        apply_server_body_command(cmd, tick_now, &mut proto, &mut streams);
                    }
                    settle_server_streams(&mut proto, &mut streams, &outgoing);
                }

                if !write_task.is_active()
                    && let Some((writer, mut outbox)) = write_slot.take()
                {
                    if let Some(op) = outgoing.poll_ready(
                        cx,
                        &mut proto,
                        &writer,
                        &mut outbox,
                        &mut failed_outgoing,
                    ) {
                        settle_server_streams(&mut proto, &mut streams, &outgoing);
                        write_task.start(step_write(writer, outbox, op));
                    } else {
                        write_slot = Some((writer, outbox));
                    }
                }

                // Drain any `BodyCommand`s emitted synchronously while `outgoing.poll_ready`
                // polled an echoed `IncomingBody` (such as parking a `PipeOffer`) before
                // choosing the next socket read mode.
                while let Poll::Ready(Some(cmd)) = inbox_rx.as_mut().poll_next(cx) {
                    commands.push(cmd);
                    progressed = true;
                }

                if !commands.is_empty() {
                    let tick_now = Instant::now();
                    for cmd in commands.drain(..) {
                        apply_server_body_command(cmd, tick_now, &mut proto, &mut streams);
                    }
                    settle_server_streams(&mut proto, &mut streams, &outgoing);
                }

                if !failed_outgoing.is_empty() {
                    for (stream_id, error) in failed_outgoing.drain(..) {
                        tracing::debug!(stream = %stream_id.get(), %error, "response body failed");
                        if let Some(mut stream) = streams.remove(&stream_id)
                            && let Some(mut recv_body) = stream.recv_body.take()
                        {
                            let (unconsumed, _) = recv_body.discard();
                            if unconsumed > 0 {
                                proto.release_recv_capacity(stream_id, unconsumed);
                            }
                        }
                    }
                    progressed = true;
                }

                // Arm next socket read after `Service` responses and `outgoing.poll_ready`
                // have parked any `PipeOffer`s on incoming streams.
                if !peer_eof
                    && !read_task.is_active()
                    && let Some(recv) = recv_slot.take()
                {
                    let write_busy = write_task.is_active() && !outgoing.is_empty();
                    let mode = choose_server_read_mode(&proto, &recv, &mut streams, write_busy);
                    read_task.start(step_read(recv, mode));
                }

                if let Poll::Ready((recv, result)) = read_task.poll(cx) {
                    recv_slot = Some(recv);
                    return Poll::Ready(ServerWake::Read(result));
                }

                if let Poll::Ready((writer, outbox, result)) = write_task.poll(cx) {
                    write_slot = Some((writer, outbox));
                    return Poll::Ready(ServerWake::Write(result));
                }

                if sleep_at.is_some() && sleep.as_mut().poll(cx).is_ready() {
                    sleep_at = None;
                    return Poll::Ready(ServerWake::Timer);
                }

                if progressed || (!write_task.is_active() && proto.has_pending_send()) {
                    return Poll::Ready(ServerWake::Activity);
                }

                Poll::Pending
            })
            .await;

            match wake {
                ServerWake::Write(Ok(())) | ServerWake::Timer | ServerWake::Activity => {}
                ServerWake::Write(Err(error)) => {
                    return abort_server(
                        error,
                        &mut proto,
                        &mut recv_slot,
                        &mut write_slot,
                        &mut write_task,
                        &timer,
                        &mut streams,
                        &mut outgoing,
                        &mut in_flight,
                    )
                    .await;
                }
                ServerWake::Read(Err(error)) => {
                    return abort_server(
                        error,
                        &mut proto,
                        &mut recv_slot,
                        &mut write_slot,
                        &mut write_task,
                        &timer,
                        &mut streams,
                        &mut outgoing,
                        &mut in_flight,
                    )
                    .await;
                }
                ServerWake::Read(Ok(done)) => {
                    idle_since = None;
                    if let Err(error) = handle_server_read_done(
                        done,
                        Instant::now(),
                        &mut proto,
                        recv_slot.as_mut().expect("returned above"),
                        &mut streams,
                        &in_flight,
                        &outgoing,
                        &mut peer_eof,
                    ) {
                        return abort_server(
                            error,
                            &mut proto,
                            &mut recv_slot,
                            &mut write_slot,
                            &mut write_task,
                            &timer,
                            &mut streams,
                            &mut outgoing,
                            &mut in_flight,
                        )
                        .await;
                    }
                }
            }
        }
    }
}

async fn call_service<S: Service>(service: &S, request: Request) -> Response {
    service.call(request).await
}

struct ServerStream {
    head_method: bool,
    peer_recv_ended: bool,
    response_started: bool,
    response_finished: bool,
    recv_body: Option<RecvStream>,
}

enum ServerWake {
    Read(Result<ReadDone, Error>),
    Write(Result<(), Error>),
    Timer,
    Activity,
}

fn choose_server_read_mode<R: SpliceRead>(
    proto: &ProtoConn<ServerSide>,
    recv: &Recv<R>,
    streams: &mut HashMap<StreamId, ServerStream>,
    write_busy: bool,
) -> ReadMode {
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    {
        if let Some(pending_data) = proto.pending_data_run()
            && can_splice_read(recv)
            && let Some(offer) = streams
                .get_mut(&pending_data.stream_id)
                .and_then(|s| s.recv_body.as_mut())
                .and_then(RecvStream::take_pipe_offer)
        {
            return ReadMode::Splice {
                stream_id: pending_data.stream_id,
                remaining: pending_data.remaining,
                offer,
            };
        }
        if proto.is_handshake_complete()
            && proto.pending_data_run().is_none()
            && recv.buf.len() < 9
            && reader_can_splice(&recv.reader)
            && streams.values().any(|s| {
                s.recv_body
                    .as_ref()
                    .is_some_and(|b| b.wants_pipe() || (write_busy && b.may_want_pipe()))
            })
        {
            return ReadMode::FrameHeader;
        }
    }
    #[cfg(not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))))]
    {
        let _ = (proto, recv, streams, write_busy);
    }
    ReadMode::Normal
}

#[allow(clippy::too_many_arguments)]
fn handle_server_read_done<R, SFut>(
    done: ReadDone,
    #[cfg_attr(
        not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))),
        allow(unused_variables)
    )]
    now: Instant,
    proto: &mut ProtoConn<ServerSide>,
    recv: &mut Recv<R>,
    streams: &mut HashMap<StreamId, ServerStream>,
    in_flight: &[(StreamId, Pin<Box<SFut>>)],
    outgoing: &OutgoingStreams,
    peer_eof: &mut bool,
) -> Result<(), Error> {
    match done {
        ReadDone::Bytes { read: 0, .. } => {
            *peer_eof = true;
            // Clean client disconnect on an idle connection before or after exchanges.
            if recv.buf.is_empty()
                && streams.is_empty()
                && in_flight.is_empty()
                && outgoing.is_empty()
                && proto.active_stream_count() == 0
            {
                return Ok(());
            }
            proto.on_eof(recv.buf.is_empty())?;
            if streams.values().any(|s| !s.peer_recv_ended) {
                return Err(Error::ConnectionClosed);
            }
            Ok(())
        }
        ReadDone::Bytes {
            owned: Some(mut bytes),
            ..
        } => {
            if recv.buf.is_empty()
                && !bytes.is_empty()
                && let Some(run) = proto.pending_data_run()
            {
                let take = run.remaining.min(bytes.len());
                let chunk = bytes.split_to(take);
                let end_stream = proto.consume_external_data(take)?;
                if let Some(stream) = streams.get_mut(&run.stream_id) {
                    if end_stream {
                        stream.peer_recv_ended = true;
                    }
                    if let Some(recv_body) = stream.recv_body.as_mut() {
                        let released = recv_body.push_data(chunk, end_stream);
                        if released > 0 {
                            proto.release_recv_capacity(run.stream_id, released);
                        }
                    } else {
                        proto.release_recv_capacity(run.stream_id, take);
                    }
                } else {
                    proto.release_recv_capacity(run.stream_id, take);
                }
                settle_server_streams(proto, streams, outgoing);
            }
            if !bytes.is_empty() {
                recv.buf.extend_from_slice(&bytes);
            }
            Ok(())
        }
        ReadDone::Bytes { owned: None, .. } => Ok(()),
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        ReadDone::Spliced { stream_id, outcome } => match outcome {
            SpliceOutcome::Filled(filled) => {
                let len = filled.len();
                let end_stream = proto.consume_external_data(len)?;
                proto.release_recv_capacity(stream_id, len);
                if let Some(stream) = streams.get_mut(&stream_id) {
                    if end_stream {
                        stream.peer_recv_ended = true;
                    }
                    if let Some(recv_body) = stream.recv_body.as_mut() {
                        recv_body.deliver_pipe(filled, end_stream);
                    }
                }
                settle_server_streams(proto, streams, outgoing);
                Ok(())
            }
            SpliceOutcome::Eof(offer) => {
                if let Some(stream) = streams.get_mut(&stream_id)
                    && let Some(recv_body) = stream.recv_body.as_mut()
                {
                    recv_body.restore_pipe_offer(offer, now);
                }
                *peer_eof = true;
                proto.on_eof(recv.buf.is_empty())?;
                Err(Error::ConnectionClosed)
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_server_event<SFut>(
    event: ProtoEvent,
    config: &ServerConfig,
    proto: &mut ProtoConn<ServerSide>,
    streams: &mut HashMap<StreamId, ServerStream>,
    outgoing: &mut OutgoingStreams,
    in_flight: &mut Vec<(StreamId, Pin<Box<SFut>>)>,
    pending_requests: &mut Vec<(StreamId, Request)>,
    mailbox: &Sender<BodyCommand>,
    max_peer_stream: &mut StreamId,
) {
    match event {
        ProtoEvent::PrefaceComplete | ProtoEvent::SendWindowAvailable { .. } => {}
        ProtoEvent::Request {
            stream_id,
            parts,
            end_stream,
            ..
        } => {
            if stream_id.get() > max_peer_stream.get() {
                *max_peer_stream = stream_id;
            }
            let head_method = parts.method == Method::HEAD;
            let (recv_body, body) = if end_stream {
                (None, Body::empty())
            } else {
                let (recv_stream, body) =
                    body::channel(stream_id, mailbox.clone(), config.body_read_timeout);
                (Some(recv_stream), body)
            };
            streams.insert(
                stream_id,
                ServerStream {
                    head_method,
                    peer_recv_ended: end_stream,
                    response_started: false,
                    response_finished: false,
                    recv_body,
                },
            );
            pending_requests.push((stream_id, Request::from_parts(parts, body)));
        }
        ProtoEvent::Data {
            stream_id,
            data,
            end_stream,
        } => {
            if let Some(stream) = streams.get_mut(&stream_id) {
                if end_stream {
                    stream.peer_recv_ended = true;
                }
                if let Some(recv_body) = stream.recv_body.as_mut() {
                    let released = recv_body.push_data(data, end_stream);
                    if released > 0 {
                        proto.release_recv_capacity(stream_id, released);
                    }
                } else if !data.is_empty() {
                    proto.release_recv_capacity(stream_id, data.len());
                }
            } else if !data.is_empty() {
                proto.release_recv_capacity(stream_id, data.len());
            }
        }
        ProtoEvent::Trailers {
            stream_id,
            trailers,
        } => {
            if let Some(stream) = streams.get_mut(&stream_id) {
                stream.peer_recv_ended = true;
                if let Some(recv_body) = stream.recv_body.as_mut() {
                    recv_body.push_trailers(trailers);
                }
            }
        }
        ProtoEvent::StreamReset { stream_id, reason } => {
            cancel_server_stream(
                stream_id,
                Error::StreamReset(reason),
                proto,
                streams,
                outgoing,
                in_flight,
                pending_requests,
            );
        }
        ProtoEvent::StreamError { stream_id, error } => {
            cancel_server_stream(
                stream_id,
                error,
                proto,
                streams,
                outgoing,
                in_flight,
                pending_requests,
            );
        }
        ProtoEvent::GoAway { .. } => {}
        ProtoEvent::InformationalResponse { .. } | ProtoEvent::Response { .. } => {
            unreachable!("server never receives HTTP responses")
        }
    }
}

fn submit_response(
    stream_id: StreamId,
    response: Response,
    add_date: bool,
    date_cache: &mut DateCache,
    proto: &mut ProtoConn<ServerSide>,
    streams: &mut HashMap<StreamId, ServerStream>,
    outgoing: &mut OutgoingStreams,
) {
    let Some(stream) = streams.get_mut(&stream_id) else {
        return;
    };
    let (parts, body): (response::Parts, Body) = response.into_parts();
    let bodiless = stream.head_method
        || parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED;
    let body_len = body.len().map(|len| len as u64);
    let end_stream = bodiless || body.is_empty() == Some(true);
    let date = add_date.then(|| date_cache.get());

    match proto.send_response(stream_id, &parts, body_len, end_stream, date) {
        Ok(()) => {
            stream.response_started = true;
            if end_stream {
                stream.response_finished = true;
            } else {
                outgoing.insert(stream_id, body);
            }
        }
        Err(error) => {
            tracing::debug!(stream = %stream_id.get(), %error, "cannot encode HTTP/2 response");
            proto.send_reset(stream_id, Reason::INTERNAL_ERROR);
            if let Some(mut removed) = streams.remove(&stream_id)
                && let Some(mut recv_body) = removed.recv_body.take()
            {
                let (unconsumed, _) = recv_body.discard();
                if unconsumed > 0 {
                    proto.release_recv_capacity(stream_id, unconsumed);
                }
            }
        }
    }
}

fn apply_server_body_command(
    cmd: BodyCommand,
    now: Instant,
    proto: &mut ProtoConn<ServerSide>,
    streams: &mut HashMap<StreamId, ServerStream>,
) {
    match cmd {
        BodyCommand::Demand { stream_id, offer } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(recv_body) = stream.recv_body.as_mut()
            {
                let released = recv_body.on_demand(offer, now);
                if released > 0 {
                    proto.release_recv_capacity(stream_id, released);
                }
            }
        }
        BodyCommand::Discard { stream_id } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(recv_body) = stream.recv_body.as_mut()
            {
                let (unconsumed, _) = recv_body.discard();
                if unconsumed > 0 {
                    proto.release_recv_capacity(stream_id, unconsumed);
                }
            }
        }
    }
}

fn expire_server_bodies(
    now: Instant,
    proto: &mut ProtoConn<ServerSide>,
    streams: &mut HashMap<StreamId, ServerStream>,
) {
    let mut expired = Vec::new();
    for (&stream_id, stream) in streams.iter() {
        if stream
            .recv_body
            .as_ref()
            .and_then(RecvStream::idle_deadline)
            .is_some_and(|at| now >= at)
        {
            expired.push(stream_id);
        }
    }
    for stream_id in expired {
        proto.send_reset(stream_id, Reason::CANCEL);
        if let Some(stream) = streams.get_mut(&stream_id) {
            stream.peer_recv_ended = true;
            if let Some(recv_body) = stream.recv_body.as_mut() {
                recv_body.fail(Error::Timeout(Timeout::BodyIdle));
            }
        }
    }
}

fn settle_server_streams(
    proto: &mut ProtoConn<ServerSide>,
    streams: &mut HashMap<StreamId, ServerStream>,
    outgoing: &OutgoingStreams,
) {
    streams.retain(|&stream_id, stream| {
        if stream.response_started && !stream.response_finished && !outgoing.contains(stream_id) {
            stream.response_finished = true;
        }
        let recv_done = stream.recv_body.as_ref().is_none_or(RecvStream::is_done);
        if stream.response_finished && recv_done {
            // RFC 9113 §8.1: once a complete response has been sent and the
            // handler is done with the request body, stop any remaining client
            // upload with `RST_STREAM(NO_ERROR)`.
            if !stream.peer_recv_ended {
                proto.send_reset(stream_id, Reason::NO_ERROR);
                stream.peer_recv_ended = true;
            }
            return false;
        }
        true
    });
}

fn cancel_server_stream<SFut>(
    stream_id: StreamId,
    error: Error,
    proto: &mut ProtoConn<ServerSide>,
    streams: &mut HashMap<StreamId, ServerStream>,
    outgoing: &mut OutgoingStreams,
    in_flight: &mut Vec<(StreamId, Pin<Box<SFut>>)>,
    pending_requests: &mut Vec<(StreamId, Request)>,
) {
    in_flight.retain(|(id, _)| *id != stream_id);
    pending_requests.retain(|(id, _)| *id != stream_id);
    outgoing.remove(stream_id);
    if let Some(mut stream) = streams.remove(&stream_id)
        && let Some(mut recv_body) = stream.recv_body.take()
    {
        let unconsumed = recv_body.fail(error);
        if unconsumed > 0 {
            proto.release_recv_capacity(stream_id, unconsumed);
        }
        if !recv_body.is_done() {
            stream.response_started = true;
            stream.response_finished = true;
            stream.peer_recv_ended = true;
            stream.recv_body = Some(recv_body);
            streams.insert(stream_id, stream);
        }
    }
}

fn earliest_server_deadline(
    proto_deadline: Option<Instant>,
    idle_deadline: Option<Instant>,
    streams: &HashMap<StreamId, ServerStream>,
) -> Option<Instant> {
    let mut earliest = match (proto_deadline, idle_deadline) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    for stream in streams.values() {
        if let Some(at) = stream
            .recv_body
            .as_ref()
            .and_then(RecvStream::idle_deadline)
        {
            earliest = Some(earliest.map_or(at, |cur| cur.min(at)));
        }
    }
    earliest
}

#[allow(clippy::too_many_arguments)]
async fn abort_server<R, W, T, WFut, SFut>(
    error: Error,
    proto: &mut ProtoConn<ServerSide>,
    recv_slot: &mut Option<Recv<R>>,
    write_slot: &mut Option<(W, Outbox)>,
    write_task: &mut Slot<WFut>,
    timer: &T,
    streams: &mut HashMap<StreamId, ServerStream>,
    outgoing: &mut OutgoingStreams,
    in_flight: &mut Vec<(StreamId, Pin<Box<SFut>>)>,
) -> Result<(), Error>
where
    R: ReadOwned + SpliceRead,
    W: Write,
    T: Timer,
    WFut: Future<Output = (W, Outbox, Result<(), Error>)>,
{
    in_flight.clear();
    let ids: Vec<StreamId> = streams.keys().copied().collect();
    for stream_id in ids {
        outgoing.remove(stream_id);
        if let Some(mut stream) = streams.remove(&stream_id)
            && let Some(mut recv_body) = stream.recv_body.take()
        {
            recv_body.fail(error.clone());
        }
    }

    if let Some((w, o, _)) = write_task.finish().await {
        *write_slot = Some((w, o));
    }
    if matches!(error, Error::Protocol { .. })
        && let Some((mut writer, mut outbox)) = write_slot.take()
    {
        best_effort_error_close(proto, recv_slot.as_mut(), &mut writer, &mut outbox, timer).await;
    }
    Err(error)
}

/// Per-second IMF-fixdate (`RFC 9110 §5.6.7`) cache for server `date` headers.
#[derive(Debug, Default)]
struct DateCache {
    second: u64,
    value: Option<HeaderValue>,
}

impl DateCache {
    fn get(&mut self) -> &HeaderValue {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if self.value.is_none() || self.second != secs {
            self.second = secs;
            self.value = Some(fmt_imf_fixdate(secs));
        }
        self.value.as_ref().expect("populated above")
    }
}

/// Formats `epoch_secs` (seconds since `1970-01-01T00:00:00Z`) as an RFC 9110
/// §5.6.7 `IMF-fixdate`, e.g. `Sun, 06 Nov 1994 08:49:37 GMT`.
fn fmt_imf_fixdate(epoch_secs: u64) -> HeaderValue {
    const WDAYS: [[u8; 3]; 7] = [
        *b"Thu", *b"Fri", *b"Sat", *b"Sun", *b"Mon", *b"Tue", *b"Wed",
    ];
    const MONTHS: [[u8; 3]; 12] = [
        *b"Jan", *b"Feb", *b"Mar", *b"Apr", *b"May", *b"Jun", *b"Jul", *b"Aug", *b"Sep", *b"Oct",
        *b"Nov", *b"Dec",
    ];

    let days = epoch_secs / 86_400;
    let rem = epoch_secs % 86_400;
    let hour = (rem / 3_600) as u8;
    let min = ((rem % 3_600) / 60) as u8;
    let sec = (rem % 60) as u8;
    let wday = &WDAYS[(days % 7) as usize];

    // Howard Hinnant's civil-from-days algorithm shifted to 0000-03-01 epoch.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as usize;
    let year = (y + u64::from(m <= 2)) as u32;
    let month = &MONTHS[m - 1];

    let mut out = [0u8; 29];
    out[0..3].copy_from_slice(wday);
    out[3..5].copy_from_slice(b", ");
    write_two(&mut out[5..7], d);
    out[7] = b' ';
    out[8..11].copy_from_slice(month);
    out[11] = b' ';
    out[12] = b'0' + ((year / 1000) % 10) as u8;
    out[13] = b'0' + ((year / 100) % 10) as u8;
    out[14] = b'0' + ((year / 10) % 10) as u8;
    out[15] = b'0' + (year % 10) as u8;
    out[16] = b' ';
    write_two(&mut out[17..19], hour);
    out[19] = b':';
    write_two(&mut out[20..22], min);
    out[22] = b':';
    write_two(&mut out[23..25], sec);
    out[25..29].copy_from_slice(b" GMT");

    HeaderValue::from_bytes(&out).expect("IMF-fixdate is valid visible ASCII")
}

fn write_two(dst: &mut [u8], val: u8) {
    dst[0] = b'0' + (val / 10);
    dst[1] = b'0' + (val % 10);
}

#[cfg(test)]
mod tests {
    use super::{Response, Service, fmt_imf_fixdate};

    #[test]
    fn closures_implement_service() {
        fn assert_service<S: Service>(_: &S) {}
        assert_service(&|_request: http_kit::Request| async {
            Response::new(http_kit::Body::empty())
        });
    }

    #[test]
    fn imf_fixdate_matches_rfc_examples() {
        assert_eq!(fmt_imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            fmt_imf_fixdate(784_111_777),
            "Sun, 06 Nov 1994 08:49:37 GMT"
        );
        assert_eq!(
            fmt_imf_fixdate(951_782_400),
            "Tue, 29 Feb 2000 00:00:00 GMT"
        );
        assert_eq!(
            fmt_imf_fixdate(1_709_251_199),
            "Thu, 29 Feb 2024 23:59:59 GMT"
        );
    }
}
