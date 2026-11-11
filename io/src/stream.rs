//! Stream sockets.

use std::{borrow::Borrow, fmt, fs::File, future::Future, io, ops::Deref, rc::Rc};

use compio_buf::{BufResult, IntoInner, IoBuf, IoBufMut, IoVectoredBuf};

/// Reads into owned buffers.
pub trait Read {
    /// Reads into `buf`, starting at its beginning: whatever it held is
    /// overwritten, up to its full capacity, and its length is set to the
    /// number of bytes read. To append, pass a [`compio_buf::Slice`] of the
    /// spare capacity (`buf.slice(buf.buf_len()..)`).
    ///
    /// `Ok(0)` into a buffer with spare capacity means end of stream.
    ///
    /// A stream that receives ahead of its reader ([`ReadOwned`]) copies what
    /// it already received first, and keeps what does not fit for the next
    /// read.
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
}

/// What [`ReadOwned::read_owned`] came back with.
#[derive(Debug)]
pub enum Received<B> {
    /// Received bytes in a buffer the stream owns. Dropping it hands the
    /// buffer back to the stream.
    Lent(B),
    /// The end of the stream.
    End,
    /// The stream has no buffer of its own to lend now: read into one of the
    /// caller's with [`Read::read`].
    ReadInstead,
}

/// Reads that lend the stream's own receive buffer, so a reader waiting for
/// bytes holds no buffer of its own.
///
/// The compio implementation on Linux receives with a multishot receive into
/// the provided buffer ring of the thread's runtime: one submission serves
/// many receives, and a connection pins a buffer only from the moment bytes
/// arrive until its reader is done with them. Every other implementation
/// answers [`Received::ReadInstead`], and so does the compio one whenever no
/// ring buffer is free.
pub trait ReadOwned: Read {
    /// The received bytes as lent out.
    type Buf: Deref<Target = [u8]>;

    /// Waits for received bytes and lends them out.
    fn read_owned(&mut self) -> impl Future<Output = io::Result<Received<Self::Buf>>>;
}

/// The [`ReadOwned::Buf`] of a stream that never lends a buffer: there is
/// none.
#[derive(Debug, Clone, Copy)]
pub enum NoBuf {}

impl Deref for NoBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match *self {}
    }
}

/// A stream that may receive ahead of its reader, and can stop.
///
/// Whoever hands the socket's receive side to the kernel (kernel TLS) needs
/// every byte not yet received to still be in the socket.
pub trait ReadAhead {
    /// Stops receiving ahead of the reader, for good: from now on the socket
    /// is read only when the reader asks. Returns the bytes received ahead
    /// and not yet read, in order; the end of the stream or an error the
    /// receive ended with is reported by the next read.
    fn stop_read_ahead(&mut self) -> impl Future<Output = Vec<u8>>;
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

    /// Writes all the bytes of `buf`, several buffers gathered as
    /// [`write_vectored`](Self::write_vectored) takes them, and hands `buf`
    /// back unless the writer still needs it.
    ///
    /// A writer that sends without copying (the compio implementation's
    /// zero-copy send on Linux) returns once the kernel has taken every byte,
    /// but the kernel goes on reading them from `buf` until the peer
    /// acknowledges them: such a writer keeps `buf`, drops it when the kernel
    /// is done with it, and answers `None`. A write that copies answers
    /// `Some(buf)`, so the caller can reuse the allocation.
    ///
    /// A zero-length write before the end is reported as
    /// [`io::ErrorKind::WriteZero`].
    fn write_all_owned<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<(), Option<B>>> {
        async move {
            let BufResult(res, buf) = write_all_vectored(self, buf).await;
            BufResult(res, Some(buf))
        }
    }

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

/// Writes all of `buf` through [`Write::write_vectored`], copying.
pub(crate) async fn write_all_vectored<W: Write + ?Sized, B: IoVectoredBuf>(
    writer: &mut W,
    buf: B,
) -> BufResult<(), B> {
    let len = buf.total_len();
    let mut buf = buf;
    let mut written = 0;
    while written < len {
        let BufResult(res, slice) = writer.write_vectored(buf.slice(written)).await;
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
    /// The address family's address type: [`std::net::SocketAddr`] for TCP,
    /// `std::os::unix::net::SocketAddr` for a Unix-domain socket.
    type Addr;

    /// Waits for the next connection and returns it with its peer address.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, Self::Addr)>>;

    /// The address this listener is bound to.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    fn local_addr(&self) -> io::Result<Self::Addr>;
}

/// Writes bytes together with ancillary data, in one `sendmsg(2)`.
///
/// A protocol the kernel frames takes per-message metadata this way: kernel
/// TLS, for one, sends a record of a type other than application data when
/// the record type comes as a `TLS_SET_RECORD_TYPE` control message.
#[cfg(unix)]
pub trait WriteControl {
    /// Writes some of `buf`'s initialized bytes with `control`, an encoded
    /// control-message buffer (`cmsghdr`s, as `CMSG_SPACE` lays them out),
    /// returning how many bytes of `buf` were written.
    fn write_control<B: IoBuf, C: IoBuf>(
        &mut self,
        buf: B,
        control: C,
    ) -> impl Future<Output = BufResult<usize, (B, C)>>;
}

/// Socket options of a connected TCP stream.
pub trait TcpOptions {
    /// Sets `TCP_NODELAY`: with it, a small write goes out at once instead of
    /// waiting to be coalesced with the next (Nagle's algorithm), which is
    /// what request/response traffic wants.
    ///
    /// # Errors
    ///
    /// Fails if the operating system rejects the option.
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()>;

    /// Whether `TCP_NODELAY` is set.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    fn nodelay(&self) -> io::Result<bool>;
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
        type Buf: std::ops::Deref<Target = [u8]>;

        fn read<B: IoBufMut>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
        fn read_owned(&self) -> impl Future<Output = io::Result<crate::Received<Self::Buf>>>;
        fn stop_read_ahead(&self) -> impl Future<Output = Vec<u8>>;
        fn write<B: IoBuf>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
        fn write_vectored<B: IoVectoredBuf>(
            &self,
            buf: B,
        ) -> impl Future<Output = BufResult<usize, B>>;
        /// [`Write::write_all_owned`](crate::Write::write_all_owned); a
        /// socket that sends without copying overrides it.
        fn write_all_owned<B: IoVectoredBuf>(
            &self,
            buf: B,
        ) -> impl Future<Output = BufResult<(), Option<B>>>
        where
            Self: Sized,
        {
            async move {
                let BufResult(res, buf) =
                    super::write_all_vectored(&mut super::ByRef(self), buf).await;
                BufResult(res, Some(buf))
            }
        }
        fn shutdown(&self) -> impl Future<Output = io::Result<()>>;
        fn send_file<F: Borrow<File> + 'static>(
            &self,
            file: F,
            offset: u64,
            len: usize,
        ) -> impl Future<Output = BufResult<usize, F>>;
        #[cfg(unix)]
        fn write_control<B: IoBuf, C: IoBuf>(
            &self,
            buf: B,
            control: C,
        ) -> impl Future<Output = BufResult<usize, (B, C)>>;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn splice_to_pipe(
            &self,
            pipe: crate::splice::Pipe,
            max: usize,
        ) -> impl Future<Output = Result<crate::splice::Spliced, (io::Error, crate::splice::Pipe)>>;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        fn splice_from_pipe(
            &self,
            filled: crate::splice::FilledPipe,
        ) -> impl Future<Output = io::Result<crate::splice::Pipe>>;
    }
}

use sealed::SharedStream;

/// [`Write`] over a shared reference to a socket, for the copying paths
/// that reuse the trait's provided methods.
pub(crate) struct ByRef<'a, S>(pub(crate) &'a S);

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

        impl<$($generics)*> $crate::stream::ReadOwned for $ty {
            type Buf = <$ty as $crate::stream::sealed::SharedStream>::Buf;

            fn read_owned(
                &mut self,
            ) -> impl ::std::future::Future<
                Output = ::std::io::Result<$crate::stream::Received<Self::Buf>>,
            > {
                $crate::stream::sealed::SharedStream::read_owned(&*self)
            }
        }

        impl<$($generics)*> $crate::stream::ReadAhead for $ty {
            fn stop_read_ahead(
                &mut self,
            ) -> impl ::std::future::Future<Output = ::std::vec::Vec<u8>> {
                $crate::stream::sealed::SharedStream::stop_read_ahead(&*self)
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

            fn write_all_owned<B: ::compio_buf::IoVectoredBuf>(
                &mut self,
                buf: B,
            ) -> impl ::std::future::Future<Output = ::compio_buf::BufResult<(), Option<B>>> {
                $crate::stream::sealed::SharedStream::write_all_owned(&*self, buf)
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

        impl<$($generics)*> $crate::splice::SpliceRead for $ty {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fn can_splice(&self) -> bool {
                true
            }

            #[cfg(any(target_os = "linux", target_os = "android"))]
            fn splice_to_pipe(
                &mut self,
                pipe: $crate::splice::Pipe,
                max: usize,
            ) -> impl ::std::future::Future<
                Output = ::std::result::Result<
                    $crate::splice::Spliced,
                    (::std::io::Error, $crate::splice::Pipe),
                >,
            > {
                $crate::stream::sealed::SharedStream::splice_to_pipe(&*self, pipe, max)
            }
        }

        impl<$($generics)*> $crate::splice::SpliceWrite for $ty {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            fn can_splice(&self) -> bool {
                true
            }

            #[cfg(any(target_os = "linux", target_os = "android"))]
            fn splice_from_pipe(
                &mut self,
                filled: $crate::splice::FilledPipe,
            ) -> impl ::std::future::Future<Output = ::std::io::Result<$crate::splice::Pipe>> {
                $crate::stream::sealed::SharedStream::splice_from_pipe(&*self, filled)
            }
        }

        #[cfg(unix)]
        impl<$($generics)*> $crate::stream::WriteControl for $ty {
            fn write_control<B: ::compio_buf::IoBuf, C: ::compio_buf::IoBuf>(
                &mut self,
                buf: B,
                control: C,
            ) -> impl ::std::future::Future<Output = ::compio_buf::BufResult<usize, (B, C)>> {
                $crate::stream::sealed::SharedStream::write_control(&*self, buf, control)
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

#[cfg(unix)]
impl<S: std::os::fd::AsFd> std::os::fd::AsFd for ReadHalf<S> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(unix)]
impl<S: std::os::fd::AsFd> std::os::fd::AsFd for WriteHalf<S> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
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

impl<S: SharedStream> ReadOwned for ReadHalf<S> {
    type Buf = S::Buf;

    fn read_owned(&mut self) -> impl Future<Output = io::Result<Received<S::Buf>>> {
        self.0.read_owned()
    }
}

impl<S: SharedStream> ReadAhead for ReadHalf<S> {
    fn stop_read_ahead(&mut self) -> impl Future<Output = Vec<u8>> {
        self.0.stop_read_ahead()
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

    fn write_all_owned<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<(), Option<B>>> {
        self.0.write_all_owned(buf)
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

impl<S: SharedStream> crate::splice::SpliceRead for ReadHalf<S> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        true
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_to_pipe(
        &mut self,
        pipe: crate::splice::Pipe,
        max: usize,
    ) -> impl Future<Output = Result<crate::splice::Spliced, (io::Error, crate::splice::Pipe)>>
    {
        self.0.splice_to_pipe(pipe, max)
    }
}

impl<S: SharedStream> crate::splice::SpliceWrite for WriteHalf<S> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        true
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_from_pipe(
        &mut self,
        filled: crate::splice::FilledPipe,
    ) -> impl Future<Output = io::Result<crate::splice::Pipe>> {
        self.0.splice_from_pipe(filled)
    }
}

#[cfg(unix)]
impl<S: SharedStream> WriteControl for WriteHalf<S> {
    fn write_control<B: IoBuf, C: IoBuf>(
        &mut self,
        buf: B,
        control: C,
    ) -> impl Future<Output = BufResult<usize, (B, C)>> {
        self.0.write_control(buf, control)
    }
}

/// The file-to-socket path for a platform without `sendfile`/`splice`.
#[cfg(all(
    any(feature = "compio", feature = "tokio", feature = "async-io"),
    not(any(target_os = "linux", target_os = "android", target_vendor = "apple"))
))]
pub(crate) mod copy {
    use std::{borrow::Borrow, fs::File};

    use compio_buf::BufResult;

    use super::{ByRef, SharedStream, Write};

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
}
