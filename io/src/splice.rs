//! Socket-to-socket forwarding through a pipe, without the bytes passing
//! through user space.
//!
//! A byte forwarder (a reverse proxy, a tunnel) reads from one socket into a
//! buffer and writes the buffer to another. On Linux the kernel can move the
//! bytes itself: `splice(2)` from the source socket into a pipe, then from the
//! pipe into the destination socket.
//!
//! - [`SpliceRead`] and [`SpliceWrite`] are the two steps, implemented by every
//!   stream and half this crate ships on every platform. Their methods, and
//!   the pipe types they move, exist on Linux and Android only; elsewhere the
//!   traits are markers, so which types implement them never depends on the
//!   platform or on features.
//! - `Pipe`, `FilledPipe` and `Spliced` carry the pipe between the two
//!   steps. Dropping any of them closes the pipe, so a step that is cancelled
//!   never leaves stale bytes for a later transfer to pick up.
//! - `SpliceDuplex` joins two erased connections in both directions.
//!
//! A splice never waits inside the kernel or on a kernel worker thread: the
//! stream waits for readiness with its driver, then makes a non-blocking
//! `splice(2)` call on the calling thread.

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::{
    future::Future,
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    pin::Pin,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
use bytes::Bytes;

use crate::stream::{Read, Write};

/// An empty pipe, ready to be filled by [`SpliceRead::splice_to_pipe`].
///
/// It has the kernel's default capacity.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
pub struct Pipe {
    read: OwnedFd,
    write: OwnedFd,
    capacity: usize,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Pipe {
    /// Creates an empty pipe.
    ///
    /// # Errors
    ///
    /// Fails if the process is out of descriptors or pipe memory.
    pub fn new() -> io::Result<Self> {
        let (read, write, capacity) = crate::sys::linux::pipe()?;
        Ok(Self {
            read,
            write,
            capacity,
        })
    }

    /// How many bytes the pipe holds before a writer would block, the most
    /// one splice into it moves.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn read_fd(&self) -> BorrowedFd<'_> {
        self.read.as_fd()
    }

    pub(crate) fn write_fd(&self) -> BorrowedFd<'_> {
        self.write.as_fd()
    }
}

/// A pipe holding bytes spliced from a socket.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
pub struct FilledPipe {
    pipe: Pipe,
    len: usize,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl FilledPipe {
    /// Wraps a pipe that holds `len` bytes.
    pub(crate) const fn new(pipe: Pipe, len: usize) -> Self {
        Self { pipe, len }
    }

    /// How many bytes the pipe holds.
    #[must_use]
    #[allow(clippy::len_without_is_empty)] // a filled pipe holds at least one byte
    pub const fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn pipe(&self) -> &Pipe {
        &self.pipe
    }

    pub(crate) fn into_pipe(self) -> Pipe {
        self.pipe
    }

    /// Reads the bytes out of the pipe into memory, and returns the emptied
    /// pipe. The bytes are already in the pipe, so this never waits.
    ///
    /// # Errors
    ///
    /// Fails if the kernel fails the read.
    pub fn read_out(self) -> io::Result<(Bytes, Pipe)> {
        let mut bytes = vec![0; self.len];
        let mut read = 0;
        while read < bytes.len() {
            match crate::sys::linux::read_pipe(self.pipe.read_fd(), &mut bytes[read..])? {
                0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "pipe held fewer bytes than it was filled with",
                    ));
                }
                n => read += n,
            }
        }
        Ok((Bytes::from(bytes), self.pipe))
    }
}

/// The outcome of [`SpliceRead::splice_to_pipe`].
#[cfg(any(target_os = "linux", target_os = "android"))]
#[derive(Debug)]
pub enum Spliced {
    /// Bytes arrived: the pipe holds them.
    Filled(FilledPipe),
    /// The stream ended; the pipe is still empty.
    End(Pipe),
}

/// A stream that can be spliced from into a pipe.
pub trait SpliceRead: Read {
    /// Whether this stream's bytes can go through a pipe without being read
    /// into memory. A stream that answers `false` is forwarded by reading and
    /// writing.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool;

    /// Waits until the stream has bytes, then moves up to `max` of them (and
    /// no more than the pipe's capacity) into the empty `pipe`. `max` must
    /// not be zero.
    ///
    /// # Errors
    ///
    /// The error comes with the pipe, still empty, so the caller keeps it.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        max: usize,
    ) -> impl Future<Output = Result<Spliced, (io::Error, Pipe)>>;
}

/// A stream that can be spliced to from a pipe.
pub trait SpliceWrite: Write {
    /// Whether bytes can go from a pipe to this stream without being read
    /// into memory. A stream that answers `false` is forwarded by reading and
    /// writing.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool;

    /// Writes every byte of `filled` to the stream and returns the emptied
    /// pipe.
    ///
    /// # Errors
    ///
    /// Fails if the stream does; the bytes not yet written are lost with the
    /// pipe.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_from_pipe(&mut self, filled: FilledPipe) -> impl Future<Output = io::Result<Pipe>>;
}

/// A boxed future that need not be `Send`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// [`SpliceRead`] without generics, so a stream can be used behind a
/// `Box<dyn DynSpliceRead>`. Every [`SpliceRead`] implements it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub trait DynSpliceRead {
    /// [`SpliceRead::can_splice`].
    fn can_splice(&self) -> bool;

    /// [`SpliceRead::splice_to_pipe`].
    fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        max: usize,
    ) -> LocalBoxFuture<'_, Result<Spliced, (io::Error, Pipe)>>;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl<T: SpliceRead> DynSpliceRead for T {
    fn can_splice(&self) -> bool {
        SpliceRead::can_splice(self)
    }

    fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        max: usize,
    ) -> LocalBoxFuture<'_, Result<Spliced, (io::Error, Pipe)>> {
        Box::pin(SpliceRead::splice_to_pipe(self, pipe, max))
    }
}

/// [`SpliceWrite`] without generics, so a stream can be used behind a
/// `Box<dyn DynSpliceWrite>`. Every [`SpliceWrite`] implements it.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub trait DynSpliceWrite {
    /// [`SpliceWrite::can_splice`].
    fn can_splice(&self) -> bool;

    /// [`SpliceWrite::splice_from_pipe`].
    fn splice_from_pipe(&mut self, filled: FilledPipe) -> LocalBoxFuture<'_, io::Result<Pipe>>;

    /// [`Write::write_all`] of `bytes`.
    fn write_bytes(&mut self, bytes: Bytes) -> LocalBoxFuture<'_, io::Result<()>>;

    /// [`Write::shutdown`].
    fn shutdown(&mut self) -> LocalBoxFuture<'_, io::Result<()>>;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl<T: SpliceWrite> DynSpliceWrite for T {
    fn can_splice(&self) -> bool {
        SpliceWrite::can_splice(self)
    }

    fn splice_from_pipe(&mut self, filled: FilledPipe) -> LocalBoxFuture<'_, io::Result<Pipe>> {
        Box::pin(SpliceWrite::splice_from_pipe(self, filled))
    }

    fn write_bytes(&mut self, bytes: Bytes) -> LocalBoxFuture<'_, io::Result<()>> {
        Box::pin(async move { Write::write_all(self, bytes).await.0 })
    }

    fn shutdown(&mut self) -> LocalBoxFuture<'_, io::Result<()>> {
        Box::pin(Write::shutdown(self))
    }
}

/// One end of a tunnel: a connection's two halves, erased, with the bytes
/// already read from it that still have to be forwarded.
///
/// Both ends of an upgraded connection reach a forwarder through erased
/// tokens, so erasure is the shape here; [`SpliceDuplex::join`] is its only
/// use.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct SpliceDuplex {
    replay: Bytes,
    read: Box<dyn DynSpliceRead>,
    write: Box<dyn DynSpliceWrite>,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl std::fmt::Debug for SpliceDuplex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpliceDuplex")
            .field("replay", &self.replay.len())
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl SpliceDuplex {
    /// An end made of a connection's halves. `replay` is what was already
    /// read from the connection, which [`join`](Self::join) writes to the
    /// other end before anything else.
    pub fn new(
        replay: Bytes,
        read: impl SpliceRead + 'static,
        write: impl SpliceWrite + 'static,
    ) -> Self {
        Self {
            replay,
            read: Box::new(read),
            write: Box::new(write),
        }
    }

    /// Whether both halves can splice, which [`join`](Self::join) requires.
    #[must_use]
    pub fn can_splice(&self) -> bool {
        self.read.can_splice() && self.write.can_splice()
    }

    /// Forwards between this end and `other` in both directions until both
    /// have ended, returning the bytes forwarded from `self` to `other` and
    /// from `other` to `self`, replayed bytes included.
    ///
    /// Each end's replay bytes are written to the opposite end first. When
    /// one end reaches end of stream, the opposite end's write side is shut
    /// down, so a half-close travels through. The two directions run
    /// concurrently on one pipe each, and the first error ends both.
    ///
    /// # Errors
    ///
    /// Fails with [`io::ErrorKind::Unsupported`] if an end cannot splice, and
    /// with the first I/O error of either direction.
    pub async fn join(self, other: Self) -> io::Result<(u64, u64)> {
        if !self.can_splice() || !other.can_splice() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a connection of the tunnel cannot splice",
            ));
        }
        let Self {
            replay: forward_replay,
            read: forward_read,
            write: backward_write,
        } = self;
        let Self {
            replay: backward_replay,
            read: backward_read,
            write: forward_write,
        } = other;
        futures_lite::future::try_zip(
            pump(forward_replay, forward_read, forward_write),
            pump(backward_replay, backward_read, backward_write),
        )
        .await
    }
}

/// One direction of a tunnel: the replay bytes, then everything `read`
/// yields, to `write`, which is shut down at the end of the stream.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn pump(
    replay: Bytes,
    mut read: Box<dyn DynSpliceRead>,
    mut write: Box<dyn DynSpliceWrite>,
) -> io::Result<u64> {
    let mut forwarded = replay.len() as u64;
    if !replay.is_empty() {
        write.write_bytes(replay).await?;
    }
    let mut pipe = Pipe::new()?;
    loop {
        match read.splice_to_pipe(pipe, usize::MAX).await {
            Ok(Spliced::Filled(filled)) => {
                forwarded += filled.len() as u64;
                pipe = write.splice_from_pipe(filled).await?;
            }
            Ok(Spliced::End(_)) => {
                write.shutdown().await?;
                return Ok(forwarded);
            }
            Err((err, _)) => return Err(err),
        }
    }
}
