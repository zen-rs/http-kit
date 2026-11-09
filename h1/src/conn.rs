//! The I/O both drivers share: the receive buffer, sending a message, and
//! pumping a received body to its consumer.

use std::{
    future::{Future, poll_fn},
    io, mem,
    pin::pin,
    task::Poll,
};

use bytes::{Bytes, BytesMut};
use futures_lite::{StreamExt as _, future::poll_once};
use http_kit::{Body, BodyFrame};
use http_kit_io::{BufResult, IntoInner as _, IoBuf as _, Read, SendFile, Write};

use crate::{
    Error, Limits,
    body::{BodySender, Message},
    proto::{BodyDecoder, BodyEncoder, Decoded},
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

    #[cfg(feature = "fs")]
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
/// back its head. A file region goes to [`SendFile`] untouched.
pub(crate) async fn send_message<W: Write + SendFile>(
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

#[cfg(feature = "fs")]
async fn send_other_frame<W: Write + SendFile>(
    writer: &mut W,
    outbox: &mut Outbox,
    encoder: &mut BodyEncoder,
    frame: BodyFrame,
) -> Result<(), Error> {
    let BodyFrame::File(region) = frame else {
        return Err(Error::UnsupportedFrame);
    };
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

#[cfg(not(feature = "fs"))]
async fn send_other_frame<W: Write + SendFile>(
    _writer: &mut W,
    _outbox: &mut Outbox,
    _encoder: &mut BodyEncoder,
    _frame: BodyFrame,
) -> Result<(), Error> {
    Err(Error::UnsupportedFrame)
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
/// before anything is read (a server sends `100 Continue` there).
pub(crate) async fn pump_body<R: Read, F: Future<Output = ()>>(
    recv: &mut Recv<R>,
    mut decoder: BodyDecoder,
    limits: &Limits,
    sender: BodySender,
    before_first_read: F,
) -> Result<Pumped, Error> {
    let mut before_first_read = Some(before_first_read);
    loop {
        if !sender.demanded().await {
            return Ok(Pumped::Abandoned);
        }
        if let Some(first) = before_first_read.take() {
            first.await;
        }
        let decoded = match next_decoded(recv, &mut decoder, limits).await {
            Ok(decoded) => decoded,
            Err(error) => {
                sender.send(Message::Error(error.clone())).await;
                return Err(error);
            }
        };
        // A send to a dropped body fails; the next demand then reports it.
        match decoded {
            Decoded::Data(data) => {
                sender.send(Message::Frame(BodyFrame::Data(data))).await;
            }
            Decoded::Trailers(trailers) => {
                sender
                    .send(Message::Frame(BodyFrame::Trailers(trailers)))
                    .await;
            }
            Decoded::End => {}
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

async fn next_decoded<R: Read>(
    recv: &mut Recv<R>,
    decoder: &mut BodyDecoder,
    limits: &Limits,
) -> Result<Decoded, Error> {
    loop {
        if let Some(decoded) = decoder.decode(&mut recv.buf, limits)? {
            return Ok(decoded);
        }
        if recv.fill().await? == 0 {
            return Ok(decoder.decode_eof(&mut recv.buf, limits)?);
        }
    }
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
