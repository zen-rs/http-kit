//! Sending HTTP/2 requests multiplexed over one connection.
//!
//! [`handshake`] and [`handshake_stream`] split a connection into a cloneable,
//! thread-safe [`SendRequest`] handle and the single-threaded [`Connection`]
//! driver that owns the socket halves. Drive [`Connection::run`] on the local
//! executor so the connection preface, flow control, timers, and concurrent
//! request/response streams make progress.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::{Future, poll_fn},
    pin::pin,
    task::Poll,
    time::{Duration, Instant},
};

use async_channel::{Receiver, Sender};
use futures_lite::Stream as _;
use http::request;
use http_kit::{Body, Deadlines, Request, Response};
use http_kit_io::{ReadOwned, SendFile, SpliceRead, SpliceWrite, Split, Timer, Write};

pub use crate::TrySendError;
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use crate::splice::{SpliceOutcome, can_splice_read, reader_can_splice};
use crate::{
    ClientConfig, Error, Protocol, Reason, Timeout,
    body::{self, BodyCommand, RecvStream},
    conn::{
        Outbox, OutgoingStreams, ReadDone, ReadMode, Recv, Slot, best_effort_error_close,
        deadline_after, flush_and_shutdown, step_read, step_write,
    },
    proto::{ClientSide, ProtoConn, ProtoEvent, StreamId},
};

/// One request submitted through [`SendRequest`], returning its request if
/// dropped before a stream took it.
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

    fn has_extended_connect(&self) -> bool {
        self.request
            .as_ref()
            .is_some_and(|req| req.extensions().get::<Protocol>().is_some())
    }

    fn take(mut self) -> (Request, Sender<Result<Response, TrySendError>>) {
        let request = self
            .request
            .take()
            .expect("an exchange holds its request until taken");
        (request, self.respond.clone())
    }

    fn refuse(mut self, error: Error) {
        if let Some(request) = self.request.take() {
            let _ = self
                .respond
                .try_send(Err(TrySendError::unsent(error, request)));
        }
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        if let Some(request) = self.request.take() {
            let _ = self
                .respond
                .try_send(Err(TrySendError::unsent(Error::ConnectionClosed, request)));
        }
    }
}

struct Queue(Receiver<Exchange>);

impl Queue {
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

/// Cloneable, `Send + Sync` handle for submitting HTTP/2 requests to a [`Connection`].
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
    /// Sends `request` and awaits its final response head; request and response
    /// bodies stream concurrently in full duplex.
    ///
    /// # Errors
    ///
    /// Fails if the request is invalid for HTTP/2, the stream is reset or
    /// rejected, a configured [`Deadlines`] expires, or the connection closes.
    pub async fn send(&self, request: Request) -> Result<Response, Error> {
        self.try_send(request).await.map_err(Error::from)
    }

    /// Sends `request` like [`send`](Self::send), returning the original
    /// [`Request`] inside [`TrySendError::take_request`] whenever the server
    /// is guaranteed not to have processed it and its body is still intact.
    ///
    /// # Errors
    ///
    /// As [`send`](Self::send), carrying the recoverable [`Request`] when unsent
    /// or rejected unprocessed.
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

    /// Whether the connection has stopped accepting new requests (closed or
    /// peer `GOAWAY` received).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.exchanges.is_closed()
    }
}

/// Starts an HTTP/2 client connection over split read and write halves.
pub fn handshake<R, W, T>(
    reader: R,
    writer: W,
    timer: T,
    config: ClientConfig,
) -> (SendRequest, Connection<R, W, T>)
where
    R: ReadOwned + SpliceRead,
    W: Write + SendFile + SpliceWrite,
    T: Timer,
{
    let (send, recv) = async_channel::unbounded();
    (
        SendRequest { exchanges: send },
        Connection {
            recv: Recv::new(reader, config.read_buffer_size),
            writer,
            timer,
            exchanges: Queue(recv),
            config,
        },
    )
}

/// Starts an HTTP/2 client connection over a stream socket, splitting it into
/// concurrent read and write halves.
pub fn handshake_stream<S, T>(
    stream: S,
    timer: T,
    config: ClientConfig,
) -> (SendRequest, Connection<S::ReadHalf, S::WriteHalf, T>)
where
    S: Split,
    S::ReadHalf: ReadOwned + SpliceRead,
    S::WriteHalf: SendFile + SpliceWrite,
    T: Timer,
{
    let (reader, writer) = stream.split();
    handshake(reader, writer, timer, config)
}

/// Single-threaded driver of an HTTP/2 client connection.
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

struct ClientStream {
    respond: Option<Sender<Result<Response, TrySendError>>>,
    unsent_parts: Option<request::Parts>,
    empty_mime: Option<Body>,
    head_deadline: Option<Instant>,
    body_idle: Option<Duration>,
    recv_body: Option<RecvStream>,
}

enum Wake {
    Read(Result<ReadDone, Error>),
    Write(Result<(), Error>),
    Timer,
    Activity,
}

impl<R, W, T> Connection<R, W, T>
where
    R: ReadOwned + SpliceRead,
    W: Write + SendFile + SpliceWrite,
    T: Timer,
{
    /// Drives the HTTP/2 connection until all [`SendRequest`] handles are
    /// dropped (or the server sends `GOAWAY`) and all active exchanges complete.
    ///
    /// # Errors
    ///
    /// Returns transport, handshake/protocol, keep-alive, or error-`GOAWAY`
    /// failures.
    pub async fn run(self) -> Result<(), Error> {
        let Self {
            recv,
            writer,
            timer,
            exchanges,
            config,
        } = self;

        let mut proto = ProtoConn::<ClientSide>::new_client(&config, Instant::now());
        let mut recv_slot = Some(recv);
        let mut read_task = Slot::default();
        let mut write_slot = Some((writer, Outbox::default()));
        let mut write_task = Slot::default();
        let mut outgoing = OutgoingStreams::new_client();
        let mut streams: HashMap<StreamId, ClientStream> = HashMap::new();
        let mut waiting: VecDeque<Exchange> = VecDeque::new();
        let (mailbox, inbox) = async_channel::unbounded::<BodyCommand>();

        let mut exchanges_rx = pin!(exchanges.0.clone());
        let mut inbox_rx = pin!(inbox);
        let mut sleep = pin!(timer.sleep_until(Instant::now()));
        let mut sleep_at: Option<Instant> = None;

        let mut accepting = true;
        let mut peer_eof = false;
        let mut write_error: Option<Error> = None;
        let mut peer_goaway_error: Option<Error> = None;
        let mut eof_error: Option<Error> = None;
        let mut commands: Vec<BodyCommand> = Vec::new();
        let mut failed_outgoing: Vec<(StreamId, Error)> = Vec::new();

        loop {
            let now = Instant::now();

            // 1. Parse all frames currently buffered in `recv.buf`.
            if let Some(recv) = recv_slot.as_mut() {
                loop {
                    match proto.poll_recv(&mut recv.buf, now) {
                        Ok(Some(event)) => {
                            handle_proto_event(
                                event,
                                &mut proto,
                                &mut streams,
                                &mut outgoing,
                                &mut waiting,
                                &exchanges,
                                &mailbox,
                                &mut accepting,
                                &mut peer_goaway_error,
                            );
                        }
                        Ok(None) => break,
                        Err(error) => {
                            return abort_connection(
                                error,
                                &mut proto,
                                &mut recv_slot,
                                &mut write_slot,
                                &mut write_task,
                                &timer,
                                &mut streams,
                                &mut outgoing,
                                &mut waiting,
                                &exchanges,
                            )
                            .await;
                        }
                    }
                }
            }

            // 2. Check protocol and per-stream deadlines while the peer socket is open.
            if !peer_eof {
                if let Err(error) = proto.poll_timeout(now) {
                    return abort_connection(
                        error,
                        &mut proto,
                        &mut recv_slot,
                        &mut write_slot,
                        &mut write_task,
                        &timer,
                        &mut streams,
                        &mut outgoing,
                        &mut waiting,
                        &exchanges,
                    )
                    .await;
                }
                expire_streams(now, &mut proto, &mut streams, &mut outgoing);
            }

            // 3. Open streams for queued requests while concurrency allows.
            if !peer_eof && write_error.is_none() {
                open_waiting(now, &mut proto, &mut streams, &mut outgoing, &mut waiting);
            }
            settle_streams(&mut streams, &outgoing);

            // 4. Clean completion once no new requests can arrive and all active streams finished.
            if (!accepting || proto.is_closing() || peer_eof || write_error.is_some())
                && waiting.is_empty()
                && streams.is_empty()
                && outgoing.is_empty()
            {
                exchanges.close();
                if peer_eof || write_error.is_some() {
                    if let Some((w, o, _)) = write_task.finish().await {
                        write_slot = Some((w, o));
                    }
                    if let Some((mut writer, _)) = write_slot.take() {
                        let _ = writer.shutdown().await;
                    }
                    return match peer_goaway_error.or(eof_error) {
                        Some(err) => Err(err),
                        None => Ok(()),
                    };
                }
                if let Some((w, o, res)) = write_task.finish().await {
                    write_slot = Some((w, o));
                    res?;
                }
                if let Some((mut writer, mut outbox)) = write_slot.take() {
                    if peer_goaway_error.is_none() && !proto.is_closing() {
                        proto.send_goaway(StreamId::CONNECTION, Reason::NO_ERROR, b"");
                    }
                    flush_and_shutdown(&mut proto, &mut writer, &mut outbox).await?;
                }
                return match peer_goaway_error {
                    Some(err) => Err(err),
                    None => Ok(()),
                };
            }

            // 5. Arm the earliest timer across protocol and stream deadlines.
            let next_at = if peer_eof {
                None
            } else {
                earliest_deadline(proto.next_deadline(), &streams)
            };
            if next_at != sleep_at {
                if let Some(at) = next_at {
                    sleep.set(timer.sleep_until(at));
                }
                sleep_at = next_at;
            }

            // 6. Poll every source once per wakeup without cancelling active I/O.
            let wake = poll_fn(|cx| {
                let mut progressed = false;

                while let Poll::Ready(Some(cmd)) = inbox_rx.as_mut().poll_next(cx) {
                    commands.push(cmd);
                    progressed = true;
                }

                if accepting {
                    loop {
                        match exchanges_rx.as_mut().poll_next(cx) {
                            Poll::Ready(Some(exchange)) => {
                                waiting.push_back(exchange);
                                progressed = true;
                            }
                            Poll::Ready(None) => {
                                accepting = false;
                                progressed = true;
                                break;
                            }
                            Poll::Pending => break,
                        }
                    }
                }

                // Apply body demand/discard commands immediately so `PipeOffer`s and
                // `WINDOW_UPDATE`s take effect in the same tick.
                let write_dead = peer_eof || write_error.is_some();
                if !commands.is_empty() {
                    let tick_now = Instant::now();
                    for cmd in commands.drain(..) {
                        apply_body_command(
                            cmd,
                            tick_now,
                            write_dead,
                            &mut proto,
                            &mut streams,
                            &mut outgoing,
                        );
                    }
                }

                // Start a write if idle and either control or outgoing stream frames are ready.
                if !write_dead
                    && !write_task.is_active()
                    && let Some((writer, mut outbox)) = write_slot.take()
                {
                    if let Some(op) = outgoing.poll_ready(
                        cx,
                        &mut proto,
                        &writer,
                        &mut outbox,
                        &mut failed_outgoing,
                    ) {
                        write_task.start(step_write(writer, outbox, op));
                    } else {
                        write_slot = Some((writer, outbox));
                    }
                }

                while let Poll::Ready(Some(cmd)) = inbox_rx.as_mut().poll_next(cx) {
                    commands.push(cmd);
                    progressed = true;
                }

                if !commands.is_empty() {
                    let tick_now = Instant::now();
                    for cmd in commands.drain(..) {
                        apply_body_command(
                            cmd,
                            tick_now,
                            write_dead,
                            &mut proto,
                            &mut streams,
                            &mut outgoing,
                        );
                    }
                }

                if !failed_outgoing.is_empty() {
                    for (stream_id, error) in failed_outgoing.drain(..) {
                        fail_client_stream(stream_id, error, false, &mut streams, &mut outgoing);
                    }
                    progressed = true;
                }

                // Arm the next socket read after outgoing body polls have parked any `PipeOffer`s.
                if !peer_eof
                    && !read_task.is_active()
                    && let Some(recv) = recv_slot.take()
                {
                    let write_busy = write_task.is_active() && !outgoing.is_empty();
                    let mode = choose_read_mode(&proto, &recv, &mut streams, write_busy);
                    read_task.start(step_read(recv, mode));
                }

                // Poll `read_task` ahead of `write_task` so frames sent by a closing peer
                // are ingested before a concurrent write error (`BrokenPipe`/`ConnectionReset`).
                if let Poll::Ready((recv, result)) = read_task.poll(cx) {
                    recv_slot = Some(recv);
                    return Poll::Ready(Wake::Read(result));
                }

                if let Poll::Ready((writer, outbox, result)) = write_task.poll(cx) {
                    write_slot = Some((writer, outbox));
                    return Poll::Ready(Wake::Write(result));
                }

                if sleep_at.is_some() && sleep.as_mut().poll(cx).is_ready() {
                    sleep_at = None;
                    return Poll::Ready(Wake::Timer);
                }

                if progressed
                    || (!write_dead && !write_task.is_active() && proto.has_pending_send())
                {
                    return Poll::Ready(Wake::Activity);
                }

                Poll::Pending
            })
            .await;

            match wake {
                Wake::Write(Ok(())) | Wake::Timer | Wake::Activity => {}
                Wake::Write(Err(error)) => {
                    accepting = false;
                    exchanges.close();
                    let refuse_err = peer_goaway_error.clone().unwrap_or_else(|| error.clone());
                    for queued in waiting.drain(..) {
                        queued.refuse(refuse_err.clone());
                    }
                    while let Ok(queued) = exchanges.0.try_recv() {
                        queued.refuse(refuse_err.clone());
                    }
                    outgoing.clear();
                    if peer_eof {
                        settle_peer_disconnect(
                            error,
                            true,
                            &mut streams,
                            &mut outgoing,
                            &mut eof_error,
                        );
                    } else {
                        // Keep reading until the read half reaches EOF/error so any
                        // response + GOAWAY frames already sent by the peer are delivered.
                        write_error.get_or_insert(error);
                    }
                }
                Wake::Read(Err(error)) => {
                    let clean_goaway =
                        proto.is_closing() && recv_slot.as_ref().is_some_and(|r| r.buf.is_empty());
                    let has_complete = streams.values().any(|s| {
                        s.respond.is_none()
                            && s.recv_body.as_ref().is_some_and(RecvStream::has_end_stream)
                    });
                    if clean_goaway || has_complete {
                        peer_eof = true;
                        accepting = false;
                        exchanges.close();
                        let close_err = peer_goaway_error.clone().unwrap_or(error);
                        for queued in waiting.drain(..) {
                            queued.refuse(close_err.clone());
                        }
                        while let Ok(queued) = exchanges.0.try_recv() {
                            queued.refuse(close_err.clone());
                        }
                        settle_peer_disconnect(
                            close_err,
                            clean_goaway,
                            &mut streams,
                            &mut outgoing,
                            &mut eof_error,
                        );
                    } else {
                        return abort_connection(
                            error,
                            &mut proto,
                            &mut recv_slot,
                            &mut write_slot,
                            &mut write_task,
                            &timer,
                            &mut streams,
                            &mut outgoing,
                            &mut waiting,
                            &exchanges,
                        )
                        .await;
                    }
                }
                Wake::Read(Ok(done)) => {
                    if let Err(error) = handle_read_done(
                        done,
                        Instant::now(),
                        &mut proto,
                        recv_slot.as_mut().expect("returned above"),
                        &mut streams,
                        &mut outgoing,
                        &mut waiting,
                        &exchanges,
                        &mut accepting,
                        &mut peer_eof,
                        &write_error,
                        &peer_goaway_error,
                        &mut eof_error,
                    ) {
                        return abort_connection(
                            error,
                            &mut proto,
                            &mut recv_slot,
                            &mut write_slot,
                            &mut write_task,
                            &timer,
                            &mut streams,
                            &mut outgoing,
                            &mut waiting,
                            &exchanges,
                        )
                        .await;
                    }
                }
            }
        }
    }
}

fn choose_read_mode<R: SpliceRead>(
    proto: &ProtoConn<ClientSide>,
    recv: &Recv<R>,
    streams: &mut HashMap<StreamId, ClientStream>,
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
fn handle_read_done<R>(
    done: ReadDone,
    #[cfg_attr(
        not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))),
        allow(unused_variables)
    )]
    now: Instant,
    proto: &mut ProtoConn<ClientSide>,
    recv: &mut Recv<R>,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
    waiting: &mut VecDeque<Exchange>,
    exchanges: &Queue,
    accepting: &mut bool,
    peer_eof: &mut bool,
    write_error: &Option<Error>,
    peer_goaway_error: &Option<Error>,
    eof_error: &mut Option<Error>,
) -> Result<(), Error> {
    match done {
        ReadDone::Bytes { read: 0, .. } => {
            *peer_eof = true;
            *accepting = false;
            exchanges.close();
            proto.on_eof(recv.buf.is_empty())?;

            let close_err = peer_goaway_error
                .clone()
                .or_else(|| write_error.clone())
                .unwrap_or(Error::ConnectionClosed);
            for queued in waiting.drain(..) {
                queued.refuse(close_err.clone());
            }
            while let Ok(queued) = exchanges.0.try_recv() {
                queued.refuse(close_err.clone());
            }

            settle_peer_disconnect(close_err, true, streams, outgoing, eof_error);
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
                if let Some(stream) = streams.get_mut(&run.stream_id)
                    && let Some(recv_body) = stream.recv_body.as_mut()
                {
                    let released = recv_body.push_data(chunk, end_stream);
                    if released > 0 {
                        proto.release_recv_capacity(run.stream_id, released);
                    }
                } else {
                    proto.release_recv_capacity(run.stream_id, take);
                }
                settle_streams(streams, outgoing);
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
                if let Some(stream) = streams.get_mut(&stream_id)
                    && let Some(recv_body) = stream.recv_body.as_mut()
                {
                    recv_body.deliver_pipe(filled, end_stream);
                }
                settle_streams(streams, outgoing);
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
                Err(peer_goaway_error.clone().unwrap_or(Error::ConnectionClosed))
            }
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_proto_event(
    event: ProtoEvent,
    proto: &mut ProtoConn<ClientSide>,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
    waiting: &mut VecDeque<Exchange>,
    exchanges: &Queue,
    mailbox: &Sender<BodyCommand>,
    accepting: &mut bool,
    peer_goaway_error: &mut Option<Error>,
) {
    match event {
        ProtoEvent::PrefaceComplete | ProtoEvent::SendWindowAvailable { .. } => {}
        ProtoEvent::InformationalResponse { stream_id, parts } => {
            tracing::trace!(stream = %stream_id.get(), status = %parts.status, "interim response");
        }
        ProtoEvent::Response {
            stream_id,
            parts,
            end_stream,
            ..
        } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(respond) = stream.respond.take()
            {
                outgoing.clear_recoverable(stream_id);
                stream.head_deadline = None;
                stream.unsent_parts = None;
                stream.empty_mime = None;
                let body = if end_stream {
                    Body::empty()
                } else {
                    let (recv_stream, body) =
                        body::channel(stream_id, mailbox.clone(), stream.body_idle);
                    stream.recv_body = Some(recv_stream);
                    body
                };
                let _ = respond.try_send(Ok(Response::from_parts(parts, body)));
            }
        }
        ProtoEvent::Data {
            stream_id,
            data,
            end_stream,
        } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(recv_body) = stream.recv_body.as_mut()
            {
                let released = recv_body.push_data(data, end_stream);
                if released > 0 {
                    proto.release_recv_capacity(stream_id, released);
                }
            } else if !data.is_empty() {
                proto.release_recv_capacity(stream_id, data.len());
            }
        }
        ProtoEvent::Trailers {
            stream_id,
            trailers,
        } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(recv_body) = stream.recv_body.as_mut()
            {
                recv_body.push_trailers(trailers);
            }
        }
        ProtoEvent::StreamReset { stream_id, reason } => {
            let rejected = reason == Reason::REFUSED_STREAM;
            let error = if rejected {
                Error::RequestRejected
            } else {
                Error::StreamReset(reason)
            };
            fail_client_stream(stream_id, error, rejected, streams, outgoing);
        }
        ProtoEvent::StreamError { stream_id, error } => {
            fail_client_stream(stream_id, error, false, streams, outgoing);
        }
        ProtoEvent::GoAway {
            last_stream_id,
            reason,
            debug_data,
            rejected_streams,
        } => {
            *accepting = false;
            exchanges.close();
            for stream_id in rejected_streams {
                fail_client_stream(stream_id, Error::RequestRejected, true, streams, outgoing);
            }
            for queued in waiting.drain(..) {
                queued.refuse(Error::RequestRejected);
            }
            while let Ok(queued) = exchanges.0.try_recv() {
                queued.refuse(Error::RequestRejected);
            }
            if reason != Reason::NO_ERROR {
                *peer_goaway_error = Some(Error::PeerGoAway {
                    last_stream_id,
                    reason,
                    debug_data,
                });
            }
        }
        ProtoEvent::Request { .. } => unreachable!("client never receives requests"),
    }
}

fn open_waiting(
    now: Instant,
    proto: &mut ProtoConn<ClientSide>,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
    waiting: &mut VecDeque<Exchange>,
) {
    let mut deferred_extended = VecDeque::new();
    while let Some(exchange) = waiting.pop_front() {
        if exchange.has_extended_connect() {
            if !proto.is_handshake_complete() {
                deferred_extended.push_back(exchange);
                continue;
            }
            if !proto.can_send_extended_connect() {
                exchange.refuse(Error::UnsupportedExtendedConnect);
                continue;
            }
        }
        if !proto.can_open_stream() {
            waiting.push_front(exchange);
            break;
        }

        let (request, respond) = exchange.take();
        let (parts, body) = request.into_parts();
        let deadlines = parts
            .extensions
            .get::<Deadlines>()
            .copied()
            .unwrap_or_default();
        let body_len = body.len().map(|len| len as u64);
        let end_stream = body.is_empty() == Some(true);

        match proto.open_request(&parts, body_len, end_stream) {
            Ok(stream_id) => {
                let empty_mime = if end_stream {
                    let mut empty = Body::empty();
                    if let Some(mime) = body.mime().cloned() {
                        empty = empty.with_mime(mime);
                    }
                    Some(empty)
                } else {
                    outgoing.insert(stream_id, body);
                    None
                };
                streams.insert(
                    stream_id,
                    ClientStream {
                        respond: Some(respond),
                        unsent_parts: Some(parts),
                        empty_mime,
                        head_deadline: deadline_after(now, deadlines.response_head),
                        body_idle: deadlines.body_idle,
                        recv_body: None,
                    },
                );
            }
            Err(error @ (Error::RequestRejected | Error::StreamsExhausted)) => {
                let _ = respond.try_send(Err(TrySendError::unsent(
                    error,
                    Request::from_parts(parts, body),
                )));
            }
            Err(error) => {
                let _ = respond.try_send(Err(TrySendError::from(error)));
            }
        }
    }
    while let Some(deferred) = deferred_extended.pop_back() {
        waiting.push_front(deferred);
    }
}

fn apply_body_command(
    cmd: BodyCommand,
    now: Instant,
    peer_eof: bool,
    proto: &mut ProtoConn<ClientSide>,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
) {
    match cmd {
        BodyCommand::Demand { stream_id, offer } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(recv_body) = stream.recv_body.as_mut()
            {
                let released = recv_body.on_demand(offer, now);
                if released > 0 && !peer_eof {
                    proto.release_recv_capacity(stream_id, released);
                }
            }
            settle_streams(streams, outgoing);
        }
        BodyCommand::Discard { stream_id } => {
            if let Some(stream) = streams.get_mut(&stream_id)
                && let Some(recv_body) = stream.recv_body.as_mut()
            {
                let (unconsumed, peer_open) = recv_body.discard();
                if unconsumed > 0 && !peer_eof {
                    proto.release_recv_capacity(stream_id, unconsumed);
                }
                if peer_open && !peer_eof && !outgoing.contains(stream_id) {
                    proto.send_reset(stream_id, Reason::CANCEL);
                }
            }
            settle_streams(streams, outgoing);
        }
    }
}

fn expire_streams(
    now: Instant,
    proto: &mut ProtoConn<ClientSide>,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
) {
    let mut head_expired = Vec::new();
    let mut body_expired = Vec::new();
    for (&stream_id, stream) in streams.iter() {
        if stream.head_deadline.is_some_and(|at| now >= at) {
            head_expired.push(stream_id);
        } else if stream
            .recv_body
            .as_ref()
            .and_then(RecvStream::idle_deadline)
            .is_some_and(|at| now >= at)
        {
            body_expired.push(stream_id);
        }
    }
    for stream_id in head_expired {
        proto.send_reset(stream_id, Reason::CANCEL);
        fail_client_stream(
            stream_id,
            Error::Timeout(Timeout::ResponseHead),
            false,
            streams,
            outgoing,
        );
    }
    for stream_id in body_expired {
        proto.send_reset(stream_id, Reason::CANCEL);
        fail_client_stream(
            stream_id,
            Error::Timeout(Timeout::BodyIdle),
            false,
            streams,
            outgoing,
        );
    }
}

fn earliest_deadline(
    proto_deadline: Option<Instant>,
    streams: &HashMap<StreamId, ClientStream>,
) -> Option<Instant> {
    let mut earliest = proto_deadline;
    for stream in streams.values() {
        for candidate in [
            stream.head_deadline,
            stream
                .recv_body
                .as_ref()
                .and_then(RecvStream::idle_deadline),
        ]
        .into_iter()
        .flatten()
        {
            earliest = Some(earliest.map_or(candidate, |cur| cur.min(candidate)));
        }
    }
    earliest
}

fn fail_client_stream(
    stream_id: StreamId,
    error: Error,
    unprocessed: bool,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
) {
    let recovered_outgoing = if unprocessed {
        outgoing.take_recoverable(stream_id)
    } else {
        outgoing.remove(stream_id);
        None
    };
    let Some(mut stream) = streams.remove(&stream_id) else {
        return;
    };
    if let Some(respond) = stream.respond.take() {
        let send_err = if unprocessed && let Some(parts) = stream.unsent_parts.take() {
            let recovered_body = stream.empty_mime.take().or(recovered_outgoing);
            match recovered_body {
                Some(body) => TrySendError::unsent(error, Request::from_parts(parts, body)),
                None => TrySendError::from(error),
            }
        } else {
            TrySendError::from(error)
        };
        let _ = respond.try_send(Err(send_err));
    } else if let Some(mut recv_body) = stream.recv_body.take() {
        recv_body.fail(error);
        if !recv_body.is_done() {
            stream.recv_body = Some(recv_body);
            streams.insert(stream_id, stream);
        }
    }
}

fn settle_peer_disconnect(
    close_err: Error,
    clean_close: bool,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
    eof_error: &mut Option<Error>,
) {
    let ids: Vec<StreamId> = streams.keys().copied().collect();
    let mut had_incomplete = false;
    for stream_id in ids {
        let complete_recv = streams.get(&stream_id).is_some_and(|s| {
            s.respond.is_none() && s.recv_body.as_ref().is_some_and(RecvStream::has_end_stream)
        });
        if complete_recv {
            outgoing.remove(stream_id);
        } else {
            had_incomplete = true;
            fail_client_stream(stream_id, close_err.clone(), false, streams, outgoing);
        }
    }
    if (had_incomplete || !clean_close) && eof_error.is_none() {
        *eof_error = Some(close_err);
    }
    settle_streams(streams, outgoing);
}

fn settle_streams(streams: &mut HashMap<StreamId, ClientStream>, outgoing: &OutgoingStreams) {
    streams.retain(|&stream_id, stream| {
        stream.respond.is_some()
            || outgoing.contains(stream_id)
            || stream.recv_body.as_ref().is_some_and(|b| !b.is_done())
    });
}

#[allow(clippy::too_many_arguments)]
async fn abort_connection<R, W, T, WFut>(
    error: Error,
    proto: &mut ProtoConn<ClientSide>,
    recv_slot: &mut Option<Recv<R>>,
    write_slot: &mut Option<(W, Outbox)>,
    write_task: &mut Slot<WFut>,
    timer: &T,
    streams: &mut HashMap<StreamId, ClientStream>,
    outgoing: &mut OutgoingStreams,
    waiting: &mut VecDeque<Exchange>,
    exchanges: &Queue,
) -> Result<(), Error>
where
    R: ReadOwned + SpliceRead,
    W: Write,
    T: Timer,
    WFut: Future<Output = (W, Outbox, Result<(), Error>)>,
{
    exchanges.close();
    for queued in waiting.drain(..) {
        queued.refuse(error.clone());
    }
    while let Ok(queued) = exchanges.0.try_recv() {
        queued.refuse(error.clone());
    }
    let ids: Vec<StreamId> = streams.keys().copied().collect();
    for stream_id in ids {
        fail_client_stream(stream_id, error.clone(), false, streams, outgoing);
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
