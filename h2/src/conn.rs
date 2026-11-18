//! Shared owned-buffer I/O machinery for HTTP/2 client and server connections.
//!
//! Neither `futures_io` nor `CopyingPoll` appears here: socket reads go through
//! [`ReadOwned`] (with [`SpliceRead`] when an incoming stream offers a kernel
//! pipe), and socket writes gather control frames, `HEADERS`, and `DATA` slices
//! into [`Write::write_all_owned`], stepping aside for [`SendFile`] and
//! [`SpliceWrite`] on file-region and pipe body frames.
//!
//! Every in-flight read or write owns its buffer inside a [`Slot`] until the
//! kernel completes it, so waking on a channel, timer, or body stream never
//! cancels an active `io_uring` or IOCP submission mid-flight.

use std::{
    collections::{HashMap, VecDeque},
    future::{Future, pending},
    io, mem,
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use futures_lite::future::or;
use http::HeaderMap;
use http_kit::{Body, BodyFrame, PipeOffer};
use http_kit_io::{
    BufResult, IntoInner as _, IoBuf as _, ReadOwned, Received, SendFile, SpliceRead, SpliceWrite,
    Timer, Write,
};

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
use crate::splice::{SpliceOutcome, splice_data};
use crate::{
    Error, Reason,
    proto::{ProtoConn, Side, StreamId},
};

/// Maximum `Bytes` buffers batched into one vectored write (`IOV_MAX` is 1024
/// on Linux and Darwin; 64 amortises syscalls while leaving room for TLS).
const MAX_WRITE_BUFFERS: usize = 64;

/// Maximum time spent draining trailing peer bytes before closing after an
/// error `GOAWAY`, preventing unread `SO_RCVBUF` bytes from turning our `FIN`
/// into a TCP `RST` before the peer reads `GOAWAY`.
const ERROR_DRAIN_TIMEOUT: Duration = Duration::from_millis(50);

/// Instant `timeout` from `now`, or `None` when unbounded or unrepresentable.
pub(crate) fn deadline_after(now: Instant, timeout: Option<Duration>) -> Option<Instant> {
    now.checked_add(timeout?)
}

/// Owned-buffer reader over half of a stream socket.
pub(crate) struct Recv<R> {
    pub(crate) reader: R,
    pub(crate) buf: BytesMut,
    read_size: usize,
}

impl<R: ReadOwned> Recv<R> {
    pub(crate) fn new(reader: R, read_size: usize) -> Self {
        Self {
            reader,
            buf: BytesMut::new(),
            read_size: read_size.max(1024),
        }
    }

    /// Receives bytes from the socket, lending from a ring buffer when
    /// available or reading into `self.buf`'s spare capacity.
    pub(crate) async fn receive(&mut self) -> Result<(usize, Option<Bytes>), Error> {
        loop {
            match self.reader.read_owned().await {
                Ok(Received::Lent(bytes)) => {
                    self.buf.extend_from_slice(&bytes);
                    return Ok((bytes.len(), None));
                }
                Ok(Received::Owned(bytes)) => return Ok((bytes.len(), Some(bytes))),
                Ok(Received::End) => return Ok((0, None)),
                Ok(Received::ReadInstead) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.buf.reserve(self.read_size);
        let mut buf = mem::take(&mut self.buf);
        loop {
            let len = buf.len();
            let BufResult(result, slice) = self.reader.read(buf.slice(len..)).await;
            buf = slice.into_inner();
            match result {
                Ok(n) => {
                    self.buf = buf;
                    return Ok((n, None));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.buf = buf;
                    return Err(error.into());
                }
            }
        }
    }

    /// Reads at most `target - self.buf.len()` bytes into `self.buf` so a 9-byte
    /// `DATA` frame header leaves its payload untouched in the socket for `splice(2)`.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) async fn read_up_to(&mut self, target: usize) -> Result<usize, Error> {
        let len = self.buf.len();
        if len >= target {
            return Ok(0);
        }
        let needed = target - len;
        self.buf.reserve(needed);
        let mut buf = mem::take(&mut self.buf);
        loop {
            let BufResult(result, slice) = self.reader.read(buf.slice(len..target)).await;
            buf = slice.into_inner();
            match result {
                Ok(n) => {
                    self.buf = buf;
                    return Ok(n);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.buf = buf;
                    return Err(error.into());
                }
            }
        }
    }

    /// Briefly drains peer EOF after shutting down writes on a connection error
    /// so the kernel delivers our `GOAWAY` + `FIN` cleanly instead of `RST`.
    pub(crate) async fn drain_eof<T: Timer>(&mut self, timer: &T) {
        let deadline = Instant::now().checked_add(ERROR_DRAIN_TIMEOUT);
        let drain = async {
            for _ in 0..4 {
                self.buf.clear();
                match self.receive().await {
                    Ok((0, _)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        };
        let timeout = async {
            match deadline {
                Some(at) => timer.sleep_until(at).await,
                None => pending().await,
            }
        };
        or(drain, timeout).await;
    }
}

/// Queued outgoing frame buffers for vectored writes, plus the connection's
/// reusable kernel pipe.
#[derive(Default)]
pub(crate) struct Outbox {
    pub(crate) bufs: Vec<Bytes>,
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pipe: Option<http_kit_io::splice::Pipe>,
}

impl Outbox {
    pub(crate) fn is_empty(&self) -> bool {
        self.bufs.is_empty()
    }

    pub(crate) fn is_full(&self) -> bool {
        self.bufs.len() >= MAX_WRITE_BUFFERS
    }

    pub(crate) async fn flush<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        if self.bufs.is_empty() {
            return Ok(());
        }
        let bufs = mem::take(&mut self.bufs);
        let BufResult(result, returned) = writer.write_all_owned(bufs).await;
        if let Some(mut bufs) = returned {
            bufs.clear();
            self.bufs = bufs;
        }
        result.map_err(Error::from)
    }

    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn take_offer<W: SpliceWrite>(
        &mut self,
        writer: &W,
        max: usize,
    ) -> Option<PipeOffer> {
        (max > 0 && SpliceWrite::can_splice(writer)).then(|| match self.pipe.take() {
            Some(pipe) => PipeOffer::with_pipe(max, pipe),
            None => PipeOffer::new(max),
        })
    }

    #[cfg(not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))))]
    pub(crate) const fn take_offer<W>(&mut self, _writer: &W, _max: usize) -> Option<PipeOffer> {
        None
    }

    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn restore_offer(&mut self, offer: Option<PipeOffer>) {
        if self.pipe.is_none()
            && let Some(mut offer) = offer
        {
            self.pipe = offer.take_pipe();
        }
    }

    #[cfg(not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))))]
    pub(crate) fn restore_offer(&mut self, _offer: Option<PipeOffer>) {}

    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pub(crate) fn return_pipe(&mut self, pipe: http_kit_io::splice::Pipe) {
        if self.pipe.is_none() {
            self.pipe = Some(pipe);
        }
    }
}

/// Pinned slot holding at most one concrete in-flight I/O future.
pub(crate) struct Slot<F>(Option<Pin<Box<F>>>);

impl<F> Default for Slot<F> {
    fn default() -> Self {
        Self(None)
    }
}

impl<F: Future> Slot<F> {
    pub(crate) const fn is_active(&self) -> bool {
        self.0.is_some()
    }

    pub(crate) fn start(&mut self, fut: F) {
        debug_assert!(self.0.is_none(), "slot started while already active");
        self.0 = Some(Box::pin(fut));
    }

    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<F::Output> {
        let Some(fut) = self.0.as_mut() else {
            return Poll::Pending;
        };
        let out = fut.as_mut().poll(cx);
        if out.is_ready() {
            self.0 = None;
        }
        out
    }

    pub(crate) async fn finish(&mut self) -> Option<F::Output> {
        let fut = self.0.take()?;
        Some(fut.await)
    }
}

/// Which read operation [`step_read`] performs next.
pub(crate) enum ReadMode {
    /// Standard `ReadOwned` / `Read` into `Recv`.
    Normal,
    /// Read at most up to the 9-byte frame header so a `DATA` payload stays in the socket.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    FrameHeader,
    /// Splice an active unpadded `DATA` frame payload straight into `offer`'s pipe.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    Splice {
        stream_id: StreamId,
        remaining: usize,
        offer: PipeOffer,
    },
}

/// Outcome of one [`step_read`] completion.
pub(crate) enum ReadDone {
    /// Read `read` bytes (`0` = EOF), with optional zero-copy `owned` slice.
    Bytes { read: usize, owned: Option<Bytes> },
    /// Completed a `splice_to_pipe` attempt on `stream_id`.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    Spliced {
        stream_id: StreamId,
        outcome: SpliceOutcome,
    },
}

/// Executes one cancellation-safe socket read step, returning ownership of `recv`.
pub(crate) async fn step_read<R: ReadOwned + SpliceRead>(
    mut recv: Recv<R>,
    mode: ReadMode,
) -> (Recv<R>, Result<ReadDone, Error>) {
    let result = match mode {
        ReadMode::Normal => recv
            .receive()
            .await
            .map(|(read, owned)| ReadDone::Bytes { read, owned }),
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        ReadMode::FrameHeader => recv
            .read_up_to(9)
            .await
            .map(|read| ReadDone::Bytes { read, owned: None }),
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        ReadMode::Splice {
            stream_id,
            remaining,
            offer,
        } => splice_data(&mut recv, remaining, offer)
            .await
            .map(|outcome| ReadDone::Spliced { stream_id, outcome }),
    };
    (recv, result)
}

/// Which write operation [`step_write`] performs next.
pub(crate) enum WriteOp {
    /// Flush `outbox` vectored buffers and flush the writer.
    Flush,
    /// Flush `outbox` (ending with the 9-byte `DATA` header), then `send_file_all`.
    #[cfg(feature = "fs")]
    SendFile {
        file: std::sync::Arc<std::fs::File>,
        offset: u64,
        len: usize,
    },
    /// Flush `outbox` (ending with the 9-byte `DATA` header), then `splice_from_pipe`.
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    Splice {
        filled: http_kit_io::splice::FilledPipe,
    },
}

/// Executes one cancellation-safe socket write step, returning ownership of `writer` and `outbox`.
pub(crate) async fn step_write<W: Write + SendFile + SpliceWrite>(
    mut writer: W,
    mut outbox: Outbox,
    op: WriteOp,
) -> (W, Outbox, Result<(), Error>) {
    let result = async {
        outbox.flush(&mut writer).await?;
        match op {
            WriteOp::Flush => {}
            #[cfg(feature = "fs")]
            WriteOp::SendFile { file, offset, len } => {
                tracing::trace!(offset, len, "sending HTTP/2 DATA file region");
                let BufResult(res, _file) = writer.send_file_all(file, offset, len).await;
                res?;
            }
            #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
            WriteOp::Splice { filled } => {
                let len = filled.len();
                tracing::trace!(len, "splicing pipe into HTTP/2 DATA frame");
                let pipe = writer.splice_from_pipe(filled).await?;
                outbox.return_pipe(pipe);
            }
        }
        writer.flush().await?;
        Ok(())
    }
    .await;
    (writer, outbox, result)
}

/// Flushes final control frames (such as `GOAWAY`) and shuts down the write half cleanly.
pub(crate) async fn flush_and_shutdown<S: Side, W: Write>(
    proto: &mut ProtoConn<S>,
    writer: &mut W,
    outbox: &mut Outbox,
) -> Result<(), Error> {
    proto.drain_control(&mut outbox.bufs);
    outbox.flush(writer).await?;
    writer.flush().await?;
    match writer.shutdown().await {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::NotConnected
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset
            ) =>
        {
            tracing::debug!("peer closed socket before write shutdown");
            Ok(())
        }
        other => other.map_err(Error::from),
    }
}

/// Best-effort flush of queued `GOAWAY` + shutdown when closing on a connection error.
pub(crate) async fn best_effort_error_close<
    S: Side,
    R: ReadOwned + SpliceRead,
    W: Write,
    T: Timer,
>(
    proto: &mut ProtoConn<S>,
    recv: Option<&mut Recv<R>>,
    writer: &mut W,
    outbox: &mut Outbox,
    timer: &T,
) {
    proto.drain_control(&mut outbox.bufs);
    let _ = outbox.flush(writer).await;
    let _ = writer.flush().await;
    let _ = writer.shutdown().await;
    if let Some(recv) = recv {
        recv.drain_eof(timer).await;
    }
}

enum SavedBody {
    Untouched,
    Bytes(Bytes),
    #[cfg(feature = "fs")]
    File(http_kit::FileRegion),
    Unrecoverable,
}

enum PendingFrame {
    Data {
        bytes: Bytes,
        known_end: bool,
    },
    #[cfg(feature = "fs")]
    File {
        file: std::sync::Arc<std::fs::File>,
        offset: u64,
        remaining: u64,
        known_end: bool,
    },
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    Pipe {
        filled: http_kit_io::splice::FilledPipe,
    },
    Trailers(HeaderMap),
    End,
}

/// State of one stream's outgoing body inside [`OutgoingStreams`].
pub(crate) struct OutgoingEntry {
    body: Body,
    initial_len: Option<usize>,
    mime_carrier: Body,
    saved: SavedBody,
    pending: Option<PendingFrame>,
}

impl OutgoingEntry {
    /// Reconstructs the original [`Body`] if the stream was rejected unprocessed
    /// (`REFUSED_STREAM` or `GOAWAY`) and the body is untouched or single-chunk replayable.
    pub(crate) fn into_recoverable(self) -> Option<Body> {
        let mime = self.mime_carrier.mime().cloned();
        let body = match self.saved {
            SavedBody::Untouched => return Some(self.body),
            SavedBody::Bytes(bytes) => Body::from_bytes(bytes),
            #[cfg(feature = "fs")]
            SavedBody::File(region) => Body::from_file_region(region),
            SavedBody::Unrecoverable => return None,
        };
        Some(match mime {
            Some(mime) => body.with_mime(mime),
            None => body,
        })
    }
}

/// Fair round-robin scheduler for outgoing stream bodies on one connection.
#[derive(Default)]
pub(crate) struct OutgoingStreams {
    streams: HashMap<StreamId, OutgoingEntry>,
    order: VecDeque<StreamId>,
    /// Single-chunk client request bodies that already finished encoding onto
    /// the wire, retained until the response head arrives in case the server
    /// rejects the stream unprocessed (`REFUSED_STREAM` or `GOAWAY`).
    sent_recoverable: HashMap<StreamId, Body>,
    retain_recoverable: bool,
}

impl OutgoingStreams {
    pub(crate) fn new_client() -> Self {
        Self {
            retain_recoverable: true,
            ..Self::default()
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    pub(crate) fn contains(&self, stream_id: StreamId) -> bool {
        self.streams.contains_key(&stream_id)
    }

    pub(crate) fn clear_recoverable(&mut self, stream_id: StreamId) {
        self.sent_recoverable.remove(&stream_id);
    }

    pub(crate) fn take_recoverable(&mut self, stream_id: StreamId) -> Option<Body> {
        if let Some(entry) = self.streams.remove(&stream_id) {
            self.sent_recoverable.remove(&stream_id);
            return entry.into_recoverable();
        }
        self.sent_recoverable.remove(&stream_id)
    }

    pub(crate) fn insert(&mut self, stream_id: StreamId, body: Body) {
        let initial_len = body.len();
        let mut mime_carrier = Body::empty();
        if let Some(mime) = body.mime().cloned() {
            mime_carrier = mime_carrier.with_mime(mime);
        }
        self.streams.insert(
            stream_id,
            OutgoingEntry {
                body,
                initial_len,
                mime_carrier,
                saved: SavedBody::Untouched,
                pending: None,
            },
        );
        self.order.push_back(stream_id);
    }

    pub(crate) fn remove(&mut self, stream_id: StreamId) {
        self.streams.remove(&stream_id);
        self.sent_recoverable.remove(&stream_id);
    }

    fn finish_stream(&mut self, stream_id: StreamId) {
        if let Some(entry) = self.streams.remove(&stream_id)
            && self.retain_recoverable
            && let Some(body) = entry.into_recoverable()
        {
            self.sent_recoverable.insert(stream_id, body);
        }
    }

    /// Polls outgoing bodies and encodes ready frames into `outbox`, returning
    /// any special [`WriteOp`] (`SendFile` / `Splice`) or `WriteOp::Flush` when
    /// `outbox` has bytes to transmit.
    pub(crate) fn poll_ready<S: Side, W: SpliceWrite>(
        &mut self,
        cx: &mut Context<'_>,
        proto: &mut ProtoConn<S>,
        writer: &W,
        outbox: &mut Outbox,
        failed: &mut Vec<(StreamId, Error)>,
    ) -> Option<WriteOp> {
        proto.drain_control(&mut outbox.bufs);
        while !outbox.is_full() && !self.order.is_empty() {
            let pass_len = self.order.len();
            let mut progressed = false;
            for _ in 0..pass_len {
                if outbox.is_full() {
                    break;
                }
                let Some(stream_id) = self.order.pop_front() else {
                    break;
                };
                let Some(entry) = self.streams.get_mut(&stream_id) else {
                    continue;
                };

                // Pull the next non-empty frame if none is buffered on this stream.
                if entry.pending.is_none() {
                    match poll_next_non_empty(
                        cx,
                        entry,
                        proto.send_window(stream_id),
                        writer,
                        outbox,
                    ) {
                        Poll::Pending => {
                            self.order.push_back(stream_id);
                            continue;
                        }
                        Poll::Ready(Ok(pending_frame)) => {
                            entry.pending = Some(pending_frame);
                        }
                        Poll::Ready(Err(error)) => {
                            proto.send_reset(stream_id, Reason::INTERNAL_ERROR);
                            proto.drain_control(&mut outbox.bufs);
                            self.streams.remove(&stream_id);
                            failed.push((stream_id, error));
                            progressed = true;
                            continue;
                        }
                    }
                }

                let pending_frame = entry.pending.take().expect("populated above");
                match pending_frame {
                    PendingFrame::End => {
                        let mut empty = Bytes::new();
                        match proto.encode_data(stream_id, &mut empty, true, &mut outbox.bufs) {
                            Ok(_) => {
                                self.finish_stream(stream_id);
                                progressed = true;
                            }
                            Err(error) => {
                                proto.send_reset(stream_id, Reason::PROTOCOL_ERROR);
                                proto.drain_control(&mut outbox.bufs);
                                self.remove(stream_id);
                                failed.push((stream_id, error));
                                progressed = true;
                            }
                        }
                    }
                    PendingFrame::Trailers(trailers) => {
                        entry.saved = SavedBody::Unrecoverable;
                        match proto.send_trailers(stream_id, &trailers) {
                            Ok(()) => {
                                proto.drain_control(&mut outbox.bufs);
                                self.remove(stream_id);
                                progressed = true;
                            }
                            Err(error) => {
                                proto.send_reset(stream_id, Reason::PROTOCOL_ERROR);
                                proto.drain_control(&mut outbox.bufs);
                                self.remove(stream_id);
                                failed.push((stream_id, error));
                                progressed = true;
                            }
                        }
                    }
                    PendingFrame::Data {
                        mut bytes,
                        known_end,
                    } => {
                        let before = bytes.len();
                        match proto.encode_data(stream_id, &mut bytes, known_end, &mut outbox.bufs)
                        {
                            Ok(done) => {
                                if bytes.len() < before {
                                    progressed = true;
                                }
                                if done && known_end {
                                    self.finish_stream(stream_id);
                                } else if bytes.is_empty() {
                                    self.order.push_back(stream_id);
                                } else {
                                    entry.pending = Some(PendingFrame::Data { bytes, known_end });
                                    self.order.push_back(stream_id);
                                }
                            }
                            Err(error) => {
                                proto.send_reset(stream_id, Reason::PROTOCOL_ERROR);
                                proto.drain_control(&mut outbox.bufs);
                                self.remove(stream_id);
                                failed.push((stream_id, error));
                                progressed = true;
                            }
                        }
                    }
                    #[cfg(feature = "fs")]
                    PendingFrame::File {
                        file,
                        offset,
                        remaining,
                        known_end,
                    } => {
                        let chunk_req = usize::try_from(remaining).unwrap_or(usize::MAX);
                        let end_if_complete = known_end && (chunk_req as u64 == remaining);
                        match proto.prepare_raw_data(
                            stream_id,
                            chunk_req,
                            end_if_complete,
                            &mut outbox.bufs,
                        ) {
                            Ok(0) => {
                                entry.pending = Some(PendingFrame::File {
                                    file,
                                    offset,
                                    remaining,
                                    known_end,
                                });
                                self.order.push_back(stream_id);
                            }
                            Ok(n) => {
                                let left = remaining - n as u64;
                                if left == 0 && known_end {
                                    self.finish_stream(stream_id);
                                } else if left == 0 {
                                    self.order.push_back(stream_id);
                                } else {
                                    entry.pending = Some(PendingFrame::File {
                                        file: std::sync::Arc::clone(&file),
                                        offset: offset + n as u64,
                                        remaining: left,
                                        known_end,
                                    });
                                    self.order.push_back(stream_id);
                                }
                                return Some(WriteOp::SendFile {
                                    file,
                                    offset,
                                    len: n,
                                });
                            }
                            Err(error) => {
                                proto.send_reset(stream_id, Reason::PROTOCOL_ERROR);
                                proto.drain_control(&mut outbox.bufs);
                                self.remove(stream_id);
                                failed.push((stream_id, error));
                                progressed = true;
                            }
                        }
                    }
                    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                    PendingFrame::Pipe { filled } => {
                        if !SpliceWrite::can_splice(writer)
                            || filled.len() > proto.peer_max_frame_size()
                        {
                            match filled.read_out() {
                                Ok((bytes, pipe)) => {
                                    outbox.return_pipe(pipe);
                                    let known_end = entry.body.is_empty() == Some(true);
                                    entry.pending = Some(PendingFrame::Data { bytes, known_end });
                                    self.order.push_front(stream_id);
                                    progressed = true;
                                }
                                Err(io_err) => {
                                    let error = Error::from(io_err);
                                    proto.send_reset(stream_id, Reason::INTERNAL_ERROR);
                                    proto.drain_control(&mut outbox.bufs);
                                    self.streams.remove(&stream_id);
                                    failed.push((stream_id, error));
                                    progressed = true;
                                }
                            }
                            continue;
                        }
                        let len = filled.len();
                        if proto.send_window(stream_id) < len {
                            entry.pending = Some(PendingFrame::Pipe { filled });
                            self.order.push_back(stream_id);
                            continue;
                        }
                        let known_end = entry.body.is_empty() == Some(true);
                        match proto.prepare_raw_data(stream_id, len, known_end, &mut outbox.bufs) {
                            Ok(n) => {
                                debug_assert_eq!(n, len);
                                if known_end {
                                    self.streams.remove(&stream_id);
                                } else {
                                    self.order.push_back(stream_id);
                                }
                                return Some(WriteOp::Splice { filled });
                            }
                            Err(error) => {
                                proto.send_reset(stream_id, Reason::PROTOCOL_ERROR);
                                proto.drain_control(&mut outbox.bufs);
                                self.streams.remove(&stream_id);
                                failed.push((stream_id, error));
                                progressed = true;
                            }
                        }
                    }
                }
            }
            if !progressed {
                break;
            }
        }
        proto.drain_control(&mut outbox.bufs);
        (!outbox.is_empty()).then_some(WriteOp::Flush)
    }
}

fn poll_next_non_empty<W: SpliceWrite>(
    cx: &mut Context<'_>,
    entry: &mut OutgoingEntry,
    window: usize,
    writer: &W,
    outbox: &mut Outbox,
) -> Poll<Result<PendingFrame, Error>> {
    loop {
        let mut offer = outbox.take_offer(writer, window);
        let polled = Pin::new(&mut entry.body).poll_frame_offering(cx, offer.as_mut());
        outbox.restore_offer(offer);
        match polled {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => return Poll::Ready(Ok(PendingFrame::End)),
            Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(Error::from(err))),
            Poll::Ready(Some(Ok(frame))) => {
                let first_poll = matches!(entry.saved, SavedBody::Untouched);
                match frame {
                    BodyFrame::Data(bytes) => {
                        let known_end = entry.body.is_empty() == Some(true);
                        if first_poll && known_end && entry.initial_len == Some(bytes.len()) {
                            entry.saved = SavedBody::Bytes(bytes.clone());
                        } else {
                            entry.saved = SavedBody::Unrecoverable;
                        }
                        if bytes.is_empty() {
                            if known_end {
                                return Poll::Ready(Ok(PendingFrame::End));
                            }
                            continue;
                        }
                        return Poll::Ready(Ok(PendingFrame::Data { bytes, known_end }));
                    }
                    BodyFrame::Trailers(trailers) => {
                        entry.saved = SavedBody::Unrecoverable;
                        return Poll::Ready(Ok(PendingFrame::Trailers(trailers)));
                    }
                    #[cfg(feature = "fs")]
                    BodyFrame::File(region) => {
                        let known_end = entry.body.is_empty() == Some(true);
                        if first_poll
                            && known_end
                            && entry
                                .initial_len
                                .is_some_and(|len| len as u64 == region.len())
                        {
                            entry.saved = SavedBody::File(region.clone());
                        } else {
                            entry.saved = SavedBody::Unrecoverable;
                        }
                        let (file, offset, remaining) = region.into_parts();
                        if remaining == 0 {
                            if known_end {
                                return Poll::Ready(Ok(PendingFrame::End));
                            }
                            continue;
                        }
                        return Poll::Ready(Ok(PendingFrame::File {
                            file,
                            offset,
                            remaining,
                            known_end,
                        }));
                    }
                    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                    BodyFrame::Pipe(filled) => {
                        entry.saved = SavedBody::Unrecoverable;
                        return Poll::Ready(Ok(PendingFrame::Pipe { filled }));
                    }
                    _ => {
                        entry.saved = SavedBody::Unrecoverable;
                        return Poll::Ready(Err(Error::UnsupportedFrame));
                    }
                }
            }
        }
    }
}
