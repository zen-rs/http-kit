//! The I/O both drivers share: the receive buffer, sending a message, and
//! pumping a received body to its consumer.

use std::{
    future::{Future, pending, poll_fn},
    io, mem,
    pin::{Pin, pin},
    task::Poll,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use futures_lite::{
    Stream,
    future::{or, poll_once},
};
use http_kit::{Body, BodyError, BodyFrame, PipeOffer};
use http_kit_io::{
    BufResult, IntoInner as _, IoBuf as _, ReadOwned, Received, SendFile, SpliceRead, SpliceWrite,
    Timer, Write,
};

use crate::{
    Error, Limits, Timeout,
    body::{BodySender, Message},
    proto::{BodyDecoder, BodyEncoder, Decoded},
    splice::{Attempt, try_splice},
};

/// The most buffers one vectored write carries. Linux and Darwin accept
/// 1024 (`IOV_MAX`); staying well under it leaves room for whatever a
/// layered writer adds.
const MAX_WRITE_BUFFERS: usize = 64;

/// The read side of a connection: the socket and the receive buffer every
/// head and body is split off.
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
            read_size,
        }
    }

    /// Reads more bytes onto the end of the buffer, returning how many; `0`
    /// is the end of the stream.
    ///
    /// A stream that lends its own receive buffer has the bytes copied onto
    /// the end of this one and gets its buffer back at once, so the
    /// connection reserves room only for bytes that arrived. Otherwise the
    /// read lands in the buffer's spare capacity, and the bytes are later
    /// split off that same allocation, so nothing received is copied; if this
    /// future is dropped mid-read then, the buffer goes with it, and the
    /// connection is unusable and must close.
    pub(crate) async fn fill(&mut self) -> Result<usize, Error> {
        loop {
            match self.reader.read_owned().await {
                Ok(Received::Lent(bytes)) => {
                    self.buf.extend_from_slice(&bytes);
                    return Ok(bytes.len());
                }
                Ok(Received::End) => return Ok(0),
                Ok(Received::ReadInstead) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.buf.reserve(self.read_size.max(1));
        let mut buf = mem::take(&mut self.buf);
        loop {
            let len = buf.len();
            let BufResult(result, slice) = self.reader.read(buf.slice(len..)).await;
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
}

/// The instant `timeout` from now, or `None` when there is no timeout or it
/// is too long to represent (which is no deadline at all).
pub(crate) fn deadline_after(timeout: Option<Duration>) -> Option<Instant> {
    Instant::now().checked_add(timeout?)
}

/// Runs `future` until `deadline`; `None` if the deadline came first. A
/// future that is ready at the same time as its deadline wins.
pub(crate) async fn until<T: Timer, F: Future>(
    timer: &T,
    deadline: Option<Instant>,
    future: F,
) -> Option<F::Output> {
    let done = async { Some(future.await) };
    let expired = async {
        match deadline {
            Some(deadline) => timer.sleep_until(deadline).await,
            None => pending().await,
        }
        None
    };
    or(done, expired).await
}

/// Buffers queued for one vectored write, and the empty pipe the last pipe
/// frame sent left behind, which the next body sent is offered.
#[derive(Default)]
pub(crate) struct Outbox {
    bufs: Vec<Bytes>,
    #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
    pipe: Option<http_kit_io::splice::Pipe>,
}

impl Outbox {
    pub(crate) fn push(&mut self, buf: Bytes) {
        if !buf.is_empty() {
            self.bufs.push(buf);
        }
    }

    #[cfg(any(
        feature = "fs",
        all(feature = "pipe", any(target_os = "linux", target_os = "android"))
    ))]
    pub(crate) fn extend(&mut self, bufs: impl IntoIterator<Item = Bytes>) {
        for buf in bufs {
            self.push(buf);
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.bufs.len() >= MAX_WRITE_BUFFERS
    }

    /// Writes everything queued. The buffers go to the writer, which may
    /// keep them until the kernel has sent them (a zero-copy send); a writer
    /// that hands them back has their allocation reused for the next message.
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
}

/// Sends a message: the head already queued in `outbox`, then `body` framed
/// by `encoder`.
///
/// Data frames are gathered into vectored writes; whenever the body has no
/// frame ready, what is queued goes out first, so a slow body never holds
/// back its head. A file region goes to [`SendFile`] untouched, and a pipe
/// to [`SpliceWrite`], each framed on the writer side.
///
/// A writer that can splice polls the body with a [`PipeOffer`] carrying the
/// pipe the last pipe frame left, so a body forwarded from a socket comes as
/// pipe frames that all reuse the one pipe the connection keeps.
pub(crate) async fn send_message<W: Write + SendFile + SpliceWrite>(
    writer: &mut W,
    outbox: &mut Outbox,
    body: Option<Body>,
    encoder: &mut BodyEncoder,
) -> Result<(), Error> {
    if let Some(mut body) = body.filter(|_| encoder.sends_body()) {
        let mut offer = writer_offer(writer, outbox);
        loop {
            let frame = match poll_once(next_sent_frame(&mut body, offer.as_mut())).await {
                Some(frame) => frame,
                None => {
                    outbox.flush(writer).await?;
                    next_sent_frame(&mut body, offer.as_mut()).await
                }
            };
            match frame {
                None => break,
                Some(Err(error)) => return Err(error.into()),
                Some(Ok(BodyFrame::Data(data))) => encoder.data(data, &mut outbox.bufs)?,
                Some(Ok(BodyFrame::Trailers(trailers))) => {
                    outbox.push(encoder.trailers(&trailers)?);
                }
                #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                Some(Ok(BodyFrame::Pipe(filled))) => {
                    let pipe = send_pipe(writer, outbox, encoder, filled).await?;
                    // The emptied pipe is offered for the next frame, unless
                    // the offer still holds the one it had: the frame was a
                    // pipe its source made without taking the offered one.
                    if let Some(offer) = &mut offer {
                        offer.reattach(PipeOffer::with_pipe(offer.max(), pipe));
                    }
                }
                Some(Ok(other)) => send_other_frame(writer, outbox, encoder, other).await?,
            }
            if outbox.is_full() {
                outbox.flush(writer).await?;
            }
        }
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        {
            outbox.pipe = offer.and_then(|mut offer| offer.take_pipe());
        }
    }
    if let Some(end) = encoder.finish()? {
        outbox.push(end);
    }
    outbox.flush(writer).await?;
    writer.flush().await?;
    Ok(())
}

/// What a writer offers the body it sends: pipe frames when its socket can
/// splice, of any size, since [`send_pipe`] writes a whole pipe however full,
/// carrying the pipe the connection kept from its last pipe frame.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
fn writer_offer<W: SpliceWrite>(writer: &W, outbox: &mut Outbox) -> Option<PipeOffer> {
    SpliceWrite::can_splice(writer).then(|| match outbox.pipe.take() {
        Some(pipe) => PipeOffer::with_pipe(usize::MAX, pipe),
        None => PipeOffer::new(usize::MAX),
    })
}

/// Where pipes do not exist, or the feature is off, a writer offers nothing.
#[cfg(not(all(feature = "pipe", any(target_os = "linux", target_os = "android"))))]
const fn writer_offer<W>(_writer: &W, _outbox: &mut Outbox) -> Option<PipeOffer> {
    None
}

/// The next frame of a body being sent, polled with `offer` when the writer
/// made one.
async fn next_sent_frame(
    body: &mut Body,
    mut offer: Option<&mut PipeOffer>,
) -> Option<Result<BodyFrame, BodyError>> {
    poll_fn(|cx| match offer.as_deref_mut() {
        Some(offer) => Pin::new(&mut *body).poll_frame_offering(cx, offer),
        None => Pin::new(&mut *body).poll_next(cx),
    })
    .await
}

/// Sends a frame that is neither data, trailers nor a pipe: a file region,
/// with the feature it needs.
#[cfg_attr(not(feature = "fs"), allow(unused_variables))]
async fn send_other_frame<W: Write + SendFile + SpliceWrite>(
    writer: &mut W,
    outbox: &mut Outbox,
    encoder: &mut BodyEncoder,
    frame: BodyFrame,
) -> Result<(), Error> {
    match frame {
        #[cfg(feature = "fs")]
        BodyFrame::File(region) => send_region(writer, outbox, encoder, region).await,
        _ => Err(Error::UnsupportedFrame),
    }
}

/// Sends the bytes of a pipe: spliced into the socket when it can take them,
/// framed like a file region, and otherwise read out and sent as data.
/// Returns the emptied pipe.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
async fn send_pipe<W: Write + SendFile + SpliceWrite>(
    writer: &mut W,
    outbox: &mut Outbox,
    encoder: &mut BodyEncoder,
    filled: http_kit_io::splice::FilledPipe,
) -> Result<http_kit_io::splice::Pipe, Error> {
    if !SpliceWrite::can_splice(writer) {
        let (data, pipe) = filled.read_out()?;
        encoder.data(data, &mut outbox.bufs)?;
        return Ok(pipe);
    }
    let len = filled.len() as u64;
    outbox.extend(encoder.region_start(len)?);
    outbox.flush(writer).await?;
    tracing::trace!(len, "sending a pipe");
    let pipe = writer.splice_from_pipe(filled).await?;
    outbox.extend(encoder.region_end());
    Ok(pipe)
}

#[cfg(feature = "fs")]
async fn send_region<W: Write + SendFile>(
    writer: &mut W,
    outbox: &mut Outbox,
    encoder: &mut BodyEncoder,
    region: http_kit::FileRegion,
) -> Result<(), Error> {
    let (file, offset, len) = region.into_parts();
    if len == 0 {
        return Ok(());
    }
    let size = usize::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file region exceeds the address space",
        )
    })?;
    outbox.extend(encoder.region_start(len)?);
    outbox.flush(writer).await?;
    tracing::trace!(offset, len, "sending a file region");
    let BufResult(result, _file) = writer.send_file_all(file, offset, size).await;
    result?;
    outbox.extend(encoder.region_end());
    Ok(())
}

/// How pumping a received body ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pumped {
    /// The body was read to its end; the connection is positioned at the
    /// next message.
    Complete,
    /// The consumer dropped the body before its end.
    Abandoned,
}

/// Reads a received body and hands it to its consumer one frame per demand.
///
/// `before_first_read` runs once, when the consumer first asks for data and
/// before anything is read (a server sends `100 Continue` there). Each read
/// of the socket is bounded by `body_idle`, if any.
///
/// A demand that carries a [`PipeOffer`] is answered with a pipe frame when
/// the socket can splice, nothing is buffered and the decoder is in a raw
/// run; every other frame is data or trailers, whatever was offered.
pub(crate) async fn pump_body<R: ReadOwned + SpliceRead, T: Timer, F: Future<Output = ()>>(
    recv: &mut Recv<R>,
    mut decoder: BodyDecoder,
    limits: &Limits,
    sender: BodySender,
    timer: &T,
    body_idle: Option<Duration>,
    before_first_read: F,
) -> Result<Pumped, Error> {
    let mut before_first_read = Some(before_first_read);
    loop {
        let Some(mut offer) = sender.demanded().await else {
            return Ok(Pumped::Abandoned);
        };
        if let Some(first) = before_first_read.take() {
            first.await;
        }
        let frame = match next_frame(recv, &mut decoder, limits, timer, body_idle, &mut offer).await
        {
            Ok(frame) => frame,
            Err(error) => {
                sender.send(Message::Error(error.clone())).await;
                return Err(error);
            }
        };
        // A send to a dropped body fails; the next demand then reports it.
        if let Some(frame) = frame {
            sender.send(Message::Frame(frame, offer.take())).await;
        }
        // The end is queued behind the last frame without waiting for a
        // demand: the connection is past the body as soon as it is decoded,
        // however slowly the consumer reads. It carries the offer of a demand
        // the end itself answered.
        if decoder.is_done() {
            sender.send(Message::End(offer)).await;
            return Ok(Pumped::Complete);
        }
    }
}

/// The next frame of the body, `None` when the body ended without one.
///
/// Each time the decoder needs bytes it first offers the socket to the
/// consumer's pipe: a chunk's data, for one, starts right after the chunk-size
/// line that was just decoded, with nothing buffered.
async fn next_frame<R: ReadOwned + SpliceRead, T: Timer>(
    recv: &mut Recv<R>,
    decoder: &mut BodyDecoder,
    limits: &Limits,
    timer: &T,
    body_idle: Option<Duration>,
    offer: &mut Option<PipeOffer>,
) -> Result<Option<BodyFrame>, Error> {
    let decoded = loop {
        if let Some(decoded) = decoder.decode(&mut recv.buf, limits)? {
            break decoded;
        }
        // The decoder needs bytes, possibly after consuming framing from the
        // buffer just now; the socket goes to the pipe before any read.
        if let Some(offer) = offer {
            match try_splice(recv, decoder, limits, timer, body_idle, offer).await? {
                Attempt::Skip => {}
                #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                Attempt::Frame(frame) => return Ok(Some(frame)),
                #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                Attempt::End => return Ok(None),
            }
        }
        let read = until(timer, deadline_after(body_idle), recv.fill())
            .await
            .ok_or(Error::Timeout(Timeout::BodyRead))??;
        if read == 0 {
            break decoder.decode_eof(&mut recv.buf, limits)?;
        }
    };
    Ok(match decoded {
        Decoded::Data(data) => Some(BodyFrame::Data(data)),
        Decoded::Trailers(trailers) => Some(BodyFrame::Trailers(trailers)),
        Decoded::End => None,
    })
}

/// Drives `main` to completion while also driving `side` for as long as it
/// runs, and returns `main`'s output with `side`'s if it finished. A `side`
/// still running when `main` completes is dropped.
pub(crate) async fn while_driving<M: Future, S: Future>(
    main: M,
    side: S,
) -> (M::Output, Option<S::Output>) {
    let mut main = pin!(main);
    let mut side = pin!(side);
    let mut side_output = None;
    let output = poll_fn(|cx| {
        if side_output.is_none()
            && let Poll::Ready(output) = side.as_mut().poll(cx)
        {
            side_output = Some(output);
        }
        main.as_mut().poll(cx)
    })
    .await;
    (output, side_output)
}
