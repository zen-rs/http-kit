//! Stream sockets.

use std::{borrow::Borrow, fmt, fs::File, future::Future, io, net::SocketAddr, rc::Rc};

use compio_buf::{BufResult, IntoInner, IoBuf, IoBufMut, IoVectoredBuf};

/// Reads into owned buffers.
pub trait Read {
    /// Reads into `buf`, starting at its beginning: whatever it held is
    /// overwritten, up to its full capacity, and its length is set to the
    /// number of bytes read. To append, pass a [`compio_buf::Slice`] of the
    /// spare capacity (`buf.slice(buf.buf_len()..)`).
    ///
    /// `Ok(0)` into a buffer with spare capacity means end of stream.
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
}

/// Writes from owned buffers.
pub trait Write {
    /// Writes some of `buf`'s initialized bytes, returning how many.
    fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>>;

    /// Writes some of the bytes of several buffers in one call, returning how
    /// many. A protocol head and its body leave in one syscall without being
    /// copied together first.
    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>>;

    /// Flushes anything the writer itself buffers. A plain socket buffers
    /// nothing; a layer above one (TLS) may.
    fn flush(&mut self) -> impl Future<Output = io::Result<()>>;

    /// Shuts down the write direction (a TCP FIN) after flushing.
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>>;

    /// Writes all of `buf`'s initialized bytes.
    ///
    /// A zero-length write before the end is reported as
    /// [`io::ErrorKind::WriteZero`].
    fn write_all<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<(), B>> {
        async move {
            let len = buf.buf_len();
            let mut buf = buf;
            let mut written = 0;
            while written < len {
                let BufResult(res, slice) = self.write(buf.slice(written..)).await;
                buf = slice.into_inner();
                match res {
                    Ok(0) => {
                        return BufResult(
                            Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "stream accepted no bytes",
                            )),
                            buf,
                        );
                    }
                    Ok(n) => written += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return BufResult(Err(e), buf),
                }
            }
            BufResult(Ok(()), buf)
        }
    }
}

/// Splits a stream into halves that read and write concurrently, for
/// full-duplex protocols (an upgraded connection, a proxied tunnel).
pub trait Split {
    /// The reading half.
    type ReadHalf: Read + 'static;
    /// The writing half.
    type WriteHalf: Write + 'static;

    /// Splits the stream. The connection closes when both halves are dropped.
    fn split(self) -> (Self::ReadHalf, Self::WriteHalf);
}

/// Accepts stream connections.
pub trait Listener {
    /// The accepted stream.
    type Stream;

    /// Waits for the next connection and returns it with its peer address.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>>;

    /// The address this listener is bound to.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// Sends a file region to a stream socket without passing it through user
/// space, where the platform allows.
///
/// Which mechanism an implementation uses is stated on its type; where none
/// exists the region is read into a buffer and written.
pub trait SendFile {
    /// Sends up to `len` bytes of `file` starting at `offset`, returning how
    /// many were sent. `Ok(0)` for a non-zero `len` means `offset` is at or
    /// past the end of the file. The file's own position is not used or
    /// changed.
    ///
    /// The file is taken by value (a `File`, an `Rc<File>`, ...) and handed
    /// back, because a completion-based driver keeps the descriptor in use
    /// until the operation completes.
    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<usize, F>>;

    /// Sends exactly `len` bytes of `file` starting at `offset`.
    ///
    /// A file shorter than `offset + len` is reported as
    /// [`io::ErrorKind::UnexpectedEof`].
    fn send_file_all<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<(), F>> {
        async move {
            let mut file = file;
            let mut sent = 0;
            while sent < len {
                let BufResult(res, f) =
                    self.send_file(file, offset + sent as u64, len - sent).await;
                file = f;
                match res {
                    Ok(0) => {
                        return BufResult(
                            Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "file ended before the requested region",
                            )),
                            file,
                        );
                    }
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return BufResult(Err(e), file),
                }
            }
            BufResult(Ok(()), file)
        }
    }
}

pub(crate) mod sealed {
    use std::{borrow::Borrow, fs::File, future::Future, io};

    use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf};

    /// A stream whose operations need only a shared reference, so that two
    /// halves can drive one socket concurrently. Every socket this crate
    /// implements is one.
    pub trait SharedStream: 'static {
        fn read<B: IoBufMut>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
        fn write<B: IoBuf>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
        fn write_vectored<B: IoVectoredBuf>(
            &self,
            buf: B,
        ) -> impl Future<Output = BufResult<usize, B>>;
        fn shutdown(&self) -> impl Future<Output = io::Result<()>>;
        fn send_file<F: Borrow<File> + 'static>(
            &self,
            file: F,
            offset: u64,
            len: usize,
        ) -> impl Future<Output = BufResult<usize, F>>;
    }
}

use sealed::SharedStream;

/// Implements the public stream traits for a whole socket type over its
/// [`SharedStream`] operations, and [`Split`] into [`ReadHalf`]/[`WriteHalf`].
#[cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]
macro_rules! impl_stream {
    ([$($generics:tt)*] $ty:ty) => {
        impl<$($generics)*> $crate::stream::Read for $ty {
            fn read<B: ::compio_buf::IoBufMut>(
                &mut self,
                buf: B,
            ) -> impl ::std::future::Future<Output = ::compio_buf::BufResult<usize, B>> {
                $crate::stream::sealed::SharedStream::read(&*self, buf)
            }
        }

        impl<$($generics)*> $crate::stream::Write for $ty {
            fn write<B: ::compio_buf::IoBuf>(
                &mut self,
                buf: B,
            ) -> impl ::std::future::Future<Output = ::compio_buf::BufResult<usize, B>> {
                $crate::stream::sealed::SharedStream::write(&*self, buf)
            }

            fn write_vectored<B: ::compio_buf::IoVectoredBuf>(
                &mut self,
                buf: B,
            ) -> impl ::std::future::Future<Output = ::compio_buf::BufResult<usize, B>> {
                $crate::stream::sealed::SharedStream::write_vectored(&*self, buf)
            }

            async fn flush(&mut self) -> ::std::io::Result<()> {
                Ok(())
            }

            fn shutdown(&mut self) -> impl ::std::future::Future<Output = ::std::io::Result<()>> {
                $crate::stream::sealed::SharedStream::shutdown(&*self)
            }
        }

        impl<$($generics)*> $crate::stream::SendFile for $ty {
            fn send_file<F: ::std::borrow::Borrow<::std::fs::File> + 'static>(
                &mut self,
                file: F,
                offset: u64,
                len: usize,
            ) -> impl ::std::future::Future<Output = ::compio_buf::BufResult<usize, F>> {
                $crate::stream::sealed::SharedStream::send_file(&*self, file, offset, len)
            }
        }

        impl<$($generics)*> $crate::stream::Split for $ty {
            type ReadHalf = $crate::stream::ReadHalf<$ty>;
            type WriteHalf = $crate::stream::WriteHalf<$ty>;

            fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
                $crate::stream::split_shared(self)
            }
        }
    };
}

#[cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]
pub(crate) use impl_stream;

#[cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]
pub(crate) fn split_shared<S: SharedStream>(stream: S) -> (ReadHalf<S>, WriteHalf<S>) {
    let shared = Rc::new(stream);
    (ReadHalf(shared.clone()), WriteHalf(shared))
}

/// The reading half of a split stream.
pub struct ReadHalf<S>(Rc<S>);

/// The writing half of a split stream.
pub struct WriteHalf<S>(Rc<S>);

impl<S> ReadHalf<S> {
    /// The stream both halves share.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.0
    }
}

impl<S> WriteHalf<S> {
    /// The stream both halves share.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.0
    }
}

impl<S: fmt::Debug> fmt::Debug for ReadHalf<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ReadHalf").field(&self.0).finish()
    }
}

impl<S: fmt::Debug> fmt::Debug for WriteHalf<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WriteHalf").field(&self.0).finish()
    }
}

impl<S: SharedStream> Read for ReadHalf<S> {
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.0.read(buf)
    }
}

impl<S: SharedStream> Write for WriteHalf<S> {
    fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.0.write(buf)
    }

    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>> {
        self.0.write_vectored(buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.0.shutdown()
    }
}

impl<S: SharedStream> SendFile for WriteHalf<S> {
    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<usize, F>> {
        self.0.send_file(file, offset, len)
    }
}

/// The file-to-socket path for a platform without `sendfile`/`splice`.
#[cfg(all(
    any(feature = "compio", feature = "tokio", feature = "async-io"),
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) mod copy {
    use std::{borrow::Borrow, fs::File, future::Future, io};

    use compio_buf::{BufResult, IoBuf, IoVectoredBuf};

    use super::{SharedStream, Write};

    /// One positional read into a buffer, then a write of all of it. The read is a
    /// synchronous call, which is what `sendfile` costs on a page-cache miss too.
    pub(crate) async fn copy_file_region<S: SharedStream, F: Borrow<File>>(
        stream: &S,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        /// The most one call reads, the default capacity of a Linux pipe, which
        /// bounds a `splice` round the same way.
        const CHUNK: usize = 64 * 1024;

        let mut chunk = vec![0; len.min(CHUNK)];
        let read = {
            let file: &File = file.borrow();
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::read_at(file, &mut chunk, offset)
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::FileExt::seek_read(file, &mut chunk, offset)
            }
        };
        let n = match read {
            Ok(n) => n,
            Err(e) => return BufResult(Err(e), file),
        };
        chunk.truncate(n);
        let BufResult(res, _) = ByRef(stream).write_all(chunk).await;
        BufResult(res.map(|()| n), file)
    }

    /// [`Write`] over a shared reference, so the fallback reuses
    /// [`Write::write_all`].
    struct ByRef<'a, S>(&'a S);

    impl<S: SharedStream> Write for ByRef<'_, S> {
        fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
            self.0.write(buf)
        }

        fn write_vectored<B: IoVectoredBuf>(
            &mut self,
            buf: B,
        ) -> impl Future<Output = BufResult<usize, B>> {
            self.0.write_vectored(buf)
        }

        async fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }

        fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
            self.0.shutdown()
        }
    }
}
