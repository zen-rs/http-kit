//! The poll-style capability.
//!
//! Some consumers (hyper, a `futures_io`-based TLS stack) can only drive a
//! stream through `poll_read`/`poll_write` with borrowed buffers.
//! [`IntoPoll`] converts a stream into such a type. A readiness-based
//! implementation offers it directly. A completion-based one cannot let the
//! kernel write into a buffer that is only borrowed for one poll, so it offers
//! [`CopyingPoll`], whose name states the extra copy.

use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use compio_buf::BufResult;
use futures_io::{AsyncRead, AsyncWrite};

use crate::stream::{Read, Split, Write};

/// Converts a stream into one driven through `futures_io`'s poll-style
/// traits.
pub trait IntoPoll {
    /// The poll-style stream.
    type Poll: AsyncRead + AsyncWrite + Unpin;

    /// Converts the stream.
    fn into_poll(self) -> Self::Poll;
}

type LocalFuture<T> = Pin<Box<dyn Future<Output = T>>>;

/// A poll-style view of an owned-buffer stream that copies through buffers of
/// its own: received bytes are copied out of its read buffer into the caller's,
/// and written bytes into its write buffer before they are sent.
///
/// It works over any stream that [`Split`]s, so a layer such as TLS built on
/// the owned-buffer traits gets the poll-style view too.
pub struct CopyingPoll<S: Split> {
    read: ReadState<S::ReadHalf>,
    write: WriteState<S::WriteHalf>,
}

enum ReadState<R> {
    /// The half, its buffer, and how much of the buffer was handed out.
    Idle {
        half: R,
        buf: Vec<u8>,
        pos: usize,
    },
    Busy(LocalFuture<(R, BufResult<usize, Vec<u8>>)>),
    /// Transient while the state is being replaced; seen only after a panic.
    Poisoned,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WriteOp {
    Write,
    Flush,
    Shutdown,
}

enum WriteState<W> {
    Idle {
        half: W,
        buf: Vec<u8>,
    },
    Busy {
        op: WriteOp,
        fut: LocalFuture<(W, Vec<u8>, io::Result<()>)>,
    },
    Poisoned,
}

impl<S: Split> CopyingPoll<S> {
    /// The capacity of each of the two buffers [`new`](Self::new) allocates:
    /// the largest TLS record, so a TLS layer above reads whole records.
    pub const DEFAULT_CAPACITY: usize = 16 * 1024;

    /// Wraps `stream` with [`DEFAULT_CAPACITY`](Self::DEFAULT_CAPACITY)-byte
    /// buffers.
    pub fn new(stream: S) -> Self {
        Self::with_capacity(stream, Self::DEFAULT_CAPACITY)
    }

    /// Wraps `stream` with a read buffer and a write buffer of `capacity`
    /// bytes each.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    pub fn with_capacity(stream: S, capacity: usize) -> Self {
        assert!(capacity > 0, "a copying stream needs buffer space");
        let (read, write) = stream.split();
        Self {
            read: ReadState::Idle {
                half: read,
                buf: Vec::with_capacity(capacity),
                pos: 0,
            },
            write: WriteState::Idle {
                half: write,
                buf: Vec::with_capacity(capacity),
            },
        }
    }
}

// The halves are only ever moved by value (into and out of the boxed
// futures, which pin themselves), never pinned in place.
impl<S: Split> Unpin for CopyingPoll<S> {}

impl<S: Split> fmt::Debug for CopyingPoll<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reading = match &self.read {
            ReadState::Idle { buf, pos, .. } => format!("{} bytes buffered", buf.len() - pos),
            ReadState::Busy(_) => "reading".to_owned(),
            ReadState::Poisoned => "poisoned".to_owned(),
        };
        let writing = match &self.write {
            WriteState::Idle { .. } => "idle",
            WriteState::Busy { .. } => "writing",
            WriteState::Poisoned => "poisoned",
        };
        f.debug_struct("CopyingPoll")
            .field("read", &reading)
            .field("write", &writing)
            .finish()
    }
}

impl<S: Split> AsyncRead for CopyingPoll<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        loop {
            match &mut this.read {
                ReadState::Idle { buf, pos, .. } if *pos < buf.len() => {
                    let n = out.len().min(buf.len() - *pos);
                    out[..n].copy_from_slice(&buf[*pos..*pos + n]);
                    *pos += n;
                    return Poll::Ready(Ok(n));
                }
                ReadState::Idle { .. } if out.is_empty() => return Poll::Ready(Ok(0)),
                ReadState::Idle { .. } => {
                    let ReadState::Idle { mut half, buf, .. } =
                        std::mem::replace(&mut this.read, ReadState::Poisoned)
                    else {
                        unreachable!("matched as idle");
                    };
                    this.read = ReadState::Busy(Box::pin(async move {
                        let result = half.read(buf).await;
                        (half, result)
                    }));
                }
                ReadState::Busy(fut) => {
                    let (half, BufResult(res, buf)) = ready!(fut.as_mut().poll(cx));
                    let eof = res.as_ref().is_ok_and(|&n| n == 0);
                    this.read = ReadState::Idle { half, buf, pos: 0 };
                    if let Err(e) = res {
                        return Poll::Ready(Err(e));
                    }
                    if eof {
                        return Poll::Ready(Ok(0));
                    }
                }
                ReadState::Poisoned => panic!("CopyingPoll read after a panic"),
            }
        }
    }
}

impl<S: Split> CopyingPoll<S> {
    /// Drives an operation in flight to completion and returns its result, or
    /// `Ok(None)` if the writer was idle. Afterwards the writer is idle.
    fn poll_write_idle(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<WriteOp>>> {
        match &mut self.write {
            WriteState::Idle { .. } => Poll::Ready(Ok(None)),
            WriteState::Busy { op, fut } => {
                let op = *op;
                let (half, mut buf, res) = ready!(fut.as_mut().poll(cx));
                buf.clear();
                self.write = WriteState::Idle { half, buf };
                Poll::Ready(res.map(|()| Some(op)))
            }
            WriteState::Poisoned => panic!("CopyingPoll written after a panic"),
        }
    }

    /// Starts `op` on the idle writer and polls it once, so that the kernel
    /// sees the operation before the caller next polls.
    fn start(&mut self, cx: &mut Context<'_>, op: WriteOp) -> Poll<io::Result<()>> {
        let WriteState::Idle { mut half, buf } =
            std::mem::replace(&mut self.write, WriteState::Poisoned)
        else {
            unreachable!("started on an idle writer");
        };
        let fut: LocalFuture<_> = match op {
            WriteOp::Write => Box::pin(async move {
                let BufResult(res, buf) = half.write_all(buf).await;
                (half, buf, res)
            }),
            WriteOp::Flush => Box::pin(async move {
                let res = half.flush().await;
                (half, buf, res)
            }),
            WriteOp::Shutdown => Box::pin(async move {
                let res = half.shutdown().await;
                (half, buf, res)
            }),
        };
        self.write = WriteState::Busy { op, fut };
        self.poll_write_idle(cx).map_ok(drop)
    }

    /// Finishes any write in flight, then runs `op` to completion.
    fn poll_op(&mut self, cx: &mut Context<'_>, op: WriteOp) -> Poll<io::Result<()>> {
        if ready!(self.poll_write_idle(cx))? == Some(op) {
            return Poll::Ready(Ok(()));
        }
        self.start(cx, op)
    }
}

impl<S: Split> AsyncWrite for CopyingPoll<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_write_idle(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let WriteState::Idle { buf, .. } = &mut this.write else {
            unreachable!("poll_write_idle leaves the writer idle");
        };
        let n = data.len().min(buf.capacity());
        buf.extend_from_slice(&data[..n]);
        // The bytes are accepted once copied; a failure to send them surfaces
        // on the next write, flush or close.
        match this.start(cx, WriteOp::Write) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(n)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_op(cx, WriteOp::Flush)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_op(cx, WriteOp::Shutdown)
    }
}
