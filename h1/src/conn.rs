//! The I/O both drivers share: the receive buffer, sending a message, and
//! pumping a received body to its consumer.

use std::{
    future::{Future, pending, poll_fn},
    io, mem,
    pin::pin,
    task::Poll,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use futures_lite::{
    StreamExt as _,
    future::{or, poll_once},
};
use http_kit::{Body, BodyFrame, PipeOffer};
use http_kit_io::{
    BufResult, IntoInner as _, IoBuf as _, Read, SendFile, SpliceRead, SpliceWrite, Timer, Write,
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

impl<R: Read> Recv<R> {
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
    /// The read lands in the buffer's spare capacity, and the bytes are
    /// later split off that same allocation, so nothing received is copied.
    /// If this future is dropped mid-read, the buffer goes with it; the
    /// connection is unusable then and must close.
    pub(crate) async fn fill(&mut self) -> Result<usize, Error> {
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

/// Buffers queued for one vectored write.
#[derive(Default)]
pub(crate) struct Outbox {
    bufs: Vec<Bytes>,
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

    /// Writes everything queued.
    pub(crate) async fn flush<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        let mut bufs = mem::take(&mut self.bufs);
        while !bufs.is_empty() {
            let BufResult(result, returned) = writer.write_vectored(bufs).await;
            bufs = returned;
            let mut written = match result {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "stream accepted no bytes",
                    )
                    .into());
                }
                Ok(n) => n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            let done = bufs
                .iter()
                .take_while(|buf| {
                    if written >= buf.len() {
                        written -= buf.len();
                        true
                    } else {
                        false
                    }
                })
                .count();
            bufs.drain(..done);
            if written > 0 {
                let first = &mut bufs[0];
                *first = Bytes::slice(first, written..);
            }
        }
        // Hand the allocation back for the next message.
        self.bufs = bufs;
        Ok(())
    }
}

/// Sends a message: the head already queued in `outbox`, then `body` framed
/// by `encoder`.
///
/// Data frames are gathered into vectored writes; whenever the body has no
/// frame ready, what is queued goes out first, so a slow body never holds
/// back its head. A file region goes to [`SendFile`] untouched, and a pipe
/// to [`SpliceWrite`], each framed on the writer side.
pub(crate) async fn send_message<W: Write + SendFile + SpliceWrite>(
    writer: &mut W,
    outbox: &mut Outbox,
    body: Option<Body>,
    encoder: &mut BodyEncoder,
) -> Result<(), Error> {
    if let Some(mut body) = body.filter(|_| encoder.sends_body()) {
        loop {
            let frame = match poll_once(body.next()).await {
                Some(frame) => frame,
                None => {
                    outbox.flush(writer).await?;
                    body.next().await
                }
            };
            match frame {
                None => break,
                Some(Err(error)) => return Err(error.into()),
                Some(Ok(BodyFrame::Data(data))) => encoder.data(data, &mut outbox.bufs)?,
                Some(Ok(BodyFrame::Trailers(trailers))) => {
                    outbox.push(encoder.trailers(&trailers)?);
                }
                Some(Ok(other)) => send_other_frame(writer, outbox, encoder, other).await?,
            }
            if outbox.is_full() {
                outbox.flush(writer).await?;
            }
        }
    }
    if let Some(end) = encoder.finish()? {
        outbox.push(end);
    }
    outbox.flush(writer).await?;
    writer.flush().await?;
    Ok(())
}

/// Sends a frame that is neither data nor trailers: a file region, or a pipe,
/// each with the features it needs.
#[cfg_attr(
    not(any(
        feature = "fs",
        all(feature = "pipe", any(target_os = "linux", target_os = "android"))
    )),
    allow(unused_variables)
)]
async fn send_other_frame<W: Write + SendFile + SpliceWrite>(
    writer: &mut W,
    outbox: &mut Outbox,
    encoder: &mut BodyEncoder,
    frame: BodyFrame,
) -> Result<(), Error> {
    match frame {
        #[cfg(feature = "fs")]
        BodyFrame::File(region) => send_region(writer, outbox, encoder, region).await,
        #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
        BodyFrame::Pipe(filled) => send_pipe(writer, outbox, encoder, filled).await,
        _ => Err(Error::UnsupportedFrame),
    }
}

/// Sends the bytes of a pipe: spliced into the socket when it can take them,
/// framed like a file region, and otherwise read out and sent as data.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
async fn send_pipe<W: Write + SendFile + SpliceWrite>(
    writer: &mut W,
    outbox: &mut Outbox,
    encoder: &mut BodyEncoder,
    filled: http_kit_io::splice::FilledPipe,
) -> Result<(), Error> {
    if !SpliceWrite::can_splice(writer) {
        let (data, _pipe) = filled.read_out()?;
        encoder.data(data, &mut outbox.bufs)?;
        return Ok(());
    }
    let len = filled.len() as u64;
    outbox.extend(encoder.region_start(len)?);
    outbox.flush(writer).await?;
    tracing::trace!(len, "sending a pipe");
    writer.splice_from_pipe(filled).await?;
    outbox.extend(encoder.region_end());
    Ok(())
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
/// of the socket is bounded by `read_timeout`, if any.
///
/// A demand that carries a [`PipeOffer`] is answered with a pipe frame when
/// the socket can splice, nothing is buffered and the decoder is in a raw
/// run; every other frame is data or trailers, whatever was offered.
pub(crate) async fn pump_body<R: Read + SpliceRead, T: Timer, F: Future<Output = ()>>(
    recv: &mut Recv<R>,
    mut decoder: BodyDecoder,
    limits: &Limits,
    sender: BodySender,
    timer: &T,
    read_timeout: Option<Duration>,
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
        let frame =
            match next_frame(recv, &mut decoder, limits, timer, read_timeout, &mut offer).await {
                Ok(frame) => frame,
                Err(error) => {
                    sender.send(Message::Error(error.clone())).await;
                    return Err(error);
                }
            };
        // A send to a dropped body fails; the next demand then reports it.
        if let Some(frame) = frame {
            sender.send(Message::Frame(frame, offer)).await;
        }
        // The end is queued behind the last frame without waiting for a
        // demand: the connection is past the body as soon as it is decoded,
        // however slowly the consumer reads.
        if decoder.is_done() {
            sender.send(Message::End).await;
            return Ok(Pumped::Complete);
        }
    }
}

/// The next frame of the body, `None` when the body ended without one.
///
/// Each time the decoder needs bytes it first offers the socket to the
/// consumer's pipe: a chunk's data, for one, starts right after the chunk-size
/// line that was just decoded, with nothing buffered.
async fn next_frame<R: Read + SpliceRead, T: Timer>(
    recv: &mut Recv<R>,
    decoder: &mut BodyDecoder,
    limits: &Limits,
    timer: &T,
    read_timeout: Option<Duration>,
    offer: &mut Option<PipeOffer>,
) -> Result<Option<BodyFrame>, Error> {
    let decoded = loop {
        if let Some(decoded) = decoder.decode(&mut recv.buf, limits)? {
            break decoded;
        }
        // The decoder needs bytes, possibly after consuming framing from the
        // buffer just now; the socket goes to the pipe before any read.
        if let Some(offer) = offer {
            match try_splice(recv, decoder, limits, timer, read_timeout, offer).await? {
                Attempt::Skip => {}
                #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                Attempt::Frame(frame) => return Ok(Some(frame)),
                #[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
                Attempt::End => return Ok(None),
            }
        }
        let read = until(timer, deadline_after(read_timeout), recv.fill())
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
