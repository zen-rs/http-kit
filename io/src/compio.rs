//! The compio implementation: io_uring on Linux (falling back to polling
//! where the kernel refuses io_uring), IOCP on Windows, polling elsewhere.
//!
//! Every method must be called, and every future polled, inside a compio
//! runtime on the current thread.
//!
//! [`SendFile`](crate::SendFile) moves file data in the kernel: on Linux
//! through two `splice(2)` operations per round, file into a pipe submitted
//! to io_uring so that a page-cache miss blocks neither the thread nor the
//! ring, then pipe into the socket on the thread, non-blocking, waiting for
//! writability through the driver so that a slow reader holds no kernel
//! worker; on Apple platforms through `sendfile(2)` once the socket is
//! writable. Elsewhere the region is read into a buffer and written.
//!
//! On Linux over io_uring a stream receives with a multishot receive into
//! the provided buffer ring of the thread's runtime: one submission stays
//! armed and completes once per arrival, each into a ring buffer, until the
//! kernel ends it. A reader takes a ring buffer through
//! [`ReadOwned`](crate::ReadOwned), or has it copied into its own through
//! [`Read`](crate::Read); either way the buffer goes back to the ring as soon
//! as its bytes are consumed, so an idle connection holds none. When the
//! ring has no free buffer a read receives into the caller's buffer with a
//! submission of its own, and the next one arms again. A splice from the
//! socket first moves what the ring already received, so it never passes
//! those bytes.
//!
//! The ring is compio's buffer pool, one per runtime: size it on the
//! runtime's `ProactorBuilder` (`buffer_pool_size`, `buffer_pool_buffer_len`)
//! for the connections one thread serves. Buffers are consumed whole, one per
//! completion: compio reports no `IORING_CQE_F_BUF_MORE`, which incremental
//! consumption (`IOU_PBUF_RING_INC`) needs.
//!
//! The poll-style capability is a [`CopyingPoll`]: a completion-based driver
//! cannot read into a buffer borrowed for one poll.

use std::{
    borrow::Borrow,
    fmt,
    fs::File,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    num::NonZeroU16,
    time::Instant,
};

use ::compio::{
    io::{AsyncRead, AsyncWrite},
    net,
};
use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf};

use crate::{
    Datagram, Dial, FromStd, Listen,
    datagram::{DatagramSocket, RecvMeta, send_batched},
    poll::{CopyingPoll, IntoPoll},
    stream::{Listener, TcpOptions, impl_stream, sealed::SharedStream},
    time::Timer,
};
#[cfg(unix)]
use crate::{DialUnix, FromStdUnix, ListenUnix};

/// The compio implementation. It holds nothing: compio keeps its runtime per
/// thread, and every operation goes to the current thread's.
#[derive(Debug, Clone, Copy, Default)]
pub struct Compio;

impl Timer for Compio {
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        ::compio::time::sleep_until(deadline)
    }
}

impl Dial for Compio {
    type Connection = TcpStream;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        net::TcpStream::connect(addr).await.map(TcpStream::new)
    }
}

#[cfg(unix)]
impl DialUnix for Compio {
    type UnixConnection = UnixStream;

    async fn connect_unix(&self, path: &std::path::Path) -> io::Result<UnixStream> {
        net::UnixStream::connect(path).await.map(UnixStream::new)
    }
}

impl Listen for Compio {
    type Listener = TcpListener;

    fn bind_tcp(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        self.tcp_listener(std::net::TcpListener::bind(addr)?)
    }
}

#[cfg(unix)]
impl ListenUnix for Compio {
    type UnixListener = UnixListener;

    fn bind_unix(&self, path: &std::path::Path) -> io::Result<UnixListener> {
        self.unix_listener(std::os::unix::net::UnixListener::bind(path)?)
    }
}

impl Datagram for Compio {
    type UdpSocket = UdpSocket;

    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        self.udp_socket(std::net::UdpSocket::bind(addr)?)
    }
}

#[cfg(unix)]
impl FromStdUnix for Compio {
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<UnixListener> {
        net::UnixListener::from_std(listener).map(UnixListener::new)
    }
}

impl FromStd for Compio {
    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<TcpListener> {
        net::TcpListener::from_std(listener).map(TcpListener::new)
    }

    fn udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        // Set on the std socket, which borrows as a plain Winsock socket,
        // before compio takes it over.
        #[cfg(windows)]
        {
            use std::os::windows::io::AsSocket;

            crate::sys::control::enable_pktinfo(socket.as_socket(), socket.local_addr()?)?;
        }
        UdpSocket::new(net::UdpSocket::from_std(socket)?)
    }
}

/// A connected TCP stream.
pub type TcpStream = Stream<net::TcpStream>;
/// A connected Unix-domain stream socket.
#[cfg(unix)]
pub type UnixStream = Stream<net::UnixStream>;

/// A socket's file descriptor, which the Unix paths (`splice`, `sendfile`)
/// hand to the kernel; Windows sockets need none.
#[cfg(unix)]
trait Fd: std::os::fd::AsFd {}
#[cfg(unix)]
impl<T: std::os::fd::AsFd> Fd for T {}
#[cfg(not(unix))]
trait Fd {}
#[cfg(not(unix))]
impl<T> Fd for T {}

/// A stream socket of compio's, which the operations below drive through a
/// shared reference.
trait Socket: Clone + Fd + 'static {
    /// The descriptor, shared with an operation that outlives a call.
    #[cfg(target_os = "linux")]
    fn shared_fd(&self) -> ::compio::driver::SharedFd<socket2::Socket>;
    fn read<B: IoBufMut>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
    fn write<B: IoBuf>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
    fn write_vectored<B: IoVectoredBuf>(&self, buf: B)
    -> impl Future<Output = BufResult<usize, B>>;
    fn shutdown(&self) -> impl Future<Output = io::Result<()>>;
    /// `sendmsg(2)` of `buf` with the control messages in `control`.
    #[cfg(unix)]
    fn write_control<B: IoBuf, C: IoBuf>(
        &self,
        buf: B,
        control: C,
    ) -> impl Future<Output = BufResult<usize, (B, C)>>;
    /// `sendfile(2)` of a region once the socket is writable.
    #[cfg(target_vendor = "apple")]
    fn sendfile(
        &self,
        file: &File,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = io::Result<usize>>;
}

macro_rules! impl_socket {
    ($ty:ty) => {
        impl Socket for $ty {
            #[cfg(target_os = "linux")]
            fn shared_fd(&self) -> ::compio::driver::SharedFd<socket2::Socket> {
                ::compio::driver::ToSharedFd::to_shared_fd(self)
            }

            async fn read<B: IoBufMut>(&self, buf: B) -> BufResult<usize, B> {
                let mut stream = self;
                AsyncRead::read(&mut stream, buf).await
            }

            async fn write<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
                let mut stream = self;
                AsyncWrite::write(&mut stream, buf).await
            }

            async fn write_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
                let mut stream = self;
                AsyncWrite::write_vectored(&mut stream, buf).await
            }

            async fn shutdown(&self) -> io::Result<()> {
                let mut stream = self;
                AsyncWrite::shutdown(&mut stream).await
            }

            #[cfg(unix)]
            async fn write_control<B: IoBuf, C: IoBuf>(
                &self,
                buf: B,
                control: C,
            ) -> BufResult<usize, (B, C)> {
                use ::compio::driver::op::{SendFlags, SendMsg};
                use compio_buf::IntoInner as _;

                let op = SendMsg::new(self.clone(), [buf], control, None, SendFlags::empty());
                let BufResult(res, op) = ::compio::runtime::submit(op).await;
                let ([buf], control) = op.into_inner();
                BufResult(res, (buf, control))
            }

            #[cfg(target_vendor = "apple")]
            async fn sendfile(&self, file: &File, offset: u64, len: usize) -> io::Result<usize> {
                use std::os::fd::AsRawFd;

                let poll_fd = <$ty>::to_poll_fd(self)?;
                loop {
                    std::future::poll_fn(|cx| poll_fd.poll_write_ready(cx)).await?;
                    match crate::sys::apple::sendfile(
                        poll_fd.as_raw_fd(),
                        file.as_raw_fd(),
                        offset,
                        len,
                    ) {
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        res => return res,
                    }
                }
            }
        }
    };
}

impl_socket!(net::TcpStream);
#[cfg(unix)]
impl_socket!(net::UnixStream);

/// A connected stream socket.
pub struct Stream<S> {
    inner: S,
    /// The pipe file transfers splice through, kept between transfers. A
    /// transfer takes it out while data may sit in it, so one that fails or
    /// is cancelled midway drops it instead of leaving stale bytes behind.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pipe: std::cell::Cell<Option<splice::Pipe>>,
    /// Whether the socket is `O_NONBLOCK`, which every splice through a pipe
    /// requires and which compio's own operations on io_uring still wait on
    /// inside the kernel.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    nonblocking: std::cell::Cell<bool>,
    /// The multishot receive and what it received ahead of the reader.
    #[cfg(target_os = "linux")]
    recv: recv::Recv,
}

impl<S> Stream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pipe: std::cell::Cell::new(None),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            nonblocking: std::cell::Cell::new(false),
            #[cfg(target_os = "linux")]
            recv: recv::Recv::default(),
        }
    }

    /// compio's stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

/// Adopts a connected compio stream: one a runtime of this thread registered,
/// such as a socket accepted elsewhere and handed over as a std stream (on
/// Windows a socket joins one completion port only, so a thread-per-core
/// server accepts where no port is involved and each thread adopts its share).
impl From<net::TcpStream> for TcpStream {
    fn from(stream: net::TcpStream) -> Self {
        Self::new(stream)
    }
}

#[cfg(unix)]
impl Stream<net::UnixStream> {
    /// The local address.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    pub fn local_addr(&self) -> io::Result<std::os::unix::net::SocketAddr> {
        crate::sys::unix::local_addr(&self.inner)
    }

    /// The peer's address.
    ///
    /// # Errors
    ///
    /// Fails if the socket is not connected.
    pub fn peer_addr(&self) -> io::Result<std::os::unix::net::SocketAddr> {
        crate::sys::unix::peer_addr(&self.inner)
    }
}

impl Stream<net::TcpStream> {
    /// The local address.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// The peer's address.
    ///
    /// # Errors
    ///
    /// Fails if the socket is not connected.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}

impl TcpOptions for Stream<net::TcpStream> {
    fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }
}

impl<S: fmt::Debug> fmt::Debug for Stream<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl<S: std::os::fd::AsFd> std::os::fd::AsFd for Stream<S> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl<S: Socket> SharedStream for Stream<S> {
    #[cfg(target_os = "linux")]
    type Buf = RecvBuf;
    #[cfg(not(target_os = "linux"))]
    type Buf = crate::NoBuf;

    async fn read<B: IoBufMut>(&self, buf: B) -> BufResult<usize, B> {
        #[cfg(target_os = "linux")]
        let buf = match self.recv.read_ahead(&self.inner, buf).await {
            recv::Copied::Done(result) => return result,
            recv::Copied::ReadInstead(buf) => buf,
        };
        read_single(&self.inner, buf).await
    }

    async fn read_owned(&self) -> io::Result<crate::Received<Self::Buf>> {
        #[cfg(target_os = "linux")]
        {
            self.recv.read_owned(&self.inner).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(crate::Received::ReadInstead)
        }
    }

    async fn stop_read_ahead(&self) -> Vec<u8> {
        #[cfg(target_os = "linux")]
        {
            self.recv.stop().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    async fn write<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
        self.inner.write(buf).await
    }

    async fn write_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
        self.inner.write_vectored(buf).await
    }

    async fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown().await
    }

    #[cfg(unix)]
    async fn write_control<B: IoBuf, C: IoBuf>(
        &self,
        buf: B,
        control: C,
    ) -> BufResult<usize, (B, C)> {
        self.inner.write_control(buf, control).await
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn splice_to_pipe(
        &self,
        pipe: crate::splice::Pipe,
        max: usize,
    ) -> Result<crate::splice::Spliced, (io::Error, crate::splice::Pipe)> {
        splice::to_pipe(self, pipe, max).await
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn splice_from_pipe(
        &self,
        filled: crate::splice::FilledPipe,
    ) -> io::Result<crate::splice::Pipe> {
        splice::from_pipe(self, filled).await
    }

    async fn send_file<F: Borrow<File> + 'static>(
        &self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        if len == 0 {
            return BufResult(Ok(0), file);
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            splice::send_file(self, file, offset, len).await
        }
        #[cfg(target_vendor = "apple")]
        {
            let res = self.inner.sendfile(file.borrow(), offset, len).await;
            BufResult(res, file)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            crate::stream::copy::copy_file_region(self, file, offset, len).await
        }
    }
}

/// One receive into the caller's buffer, with a submission of its own.
async fn read_single<S: Socket, B: IoBufMut>(socket: &S, mut buf: B) -> BufResult<usize, B> {
    // compio writes from the start but only ever grows the length; the
    // contract is a length of exactly what was read.
    buf.clear();
    socket.read(buf).await
}

impl_stream!([S: Socket] Stream<S>);

impl<S: Socket> IntoPoll for Stream<S> {
    type Poll = CopyingPoll<Self>;

    fn into_poll(self) -> CopyingPoll<Self> {
        CopyingPoll::new(self)
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod splice {
    use std::{
        borrow::Borrow,
        fs::File,
        io,
        os::fd::{AsFd, BorrowedFd, OwnedFd},
        rc::Rc,
    };

    use ::compio::driver::op::{Interest, PollOnce, Splice, SpliceFlags};
    use compio_buf::{BufResult, IntoInner};

    use super::{Socket, Stream};
    use crate::splice::{FilledPipe, Spliced};

    /// A pipe and how many bytes it holds before a writer would block.
    pub(super) struct Pipe {
        read: PipeEnd,
        write: PipeEnd,
        capacity: usize,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            let (read, write, capacity) = crate::sys::pipe::pipe()?;
            Ok(Self {
                read: PipeEnd(Rc::new(read)),
                write: PipeEnd(Rc::new(write)),
                capacity,
            })
        }
    }

    /// One end of the pipe, shared with the operation using it.
    #[derive(Clone)]
    struct PipeEnd(Rc<OwnedFd>);

    impl AsFd for PipeEnd {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.as_fd()
        }
    }

    /// The caller's file, owned by the operation until it completes.
    struct FileFd<F>(F);

    impl<F: Borrow<File>> AsFd for FileFd<F> {
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.0.borrow().as_fd()
        }
    }

    /// One round: up to a pipe's capacity from the file into the pipe, then
    /// all of it from the pipe into the socket.
    ///
    /// The second step is not an io_uring splice: io_uring runs every splice
    /// on an io-wq worker, and with no poll support for the operation a
    /// splice into a full socket either holds that worker until the peer
    /// reads (blocking socket) or fails with `EAGAIN` after the handoff
    /// (non-blocking one). A `splice(2)` on the thread into the non-blocking
    /// socket moves what the socket takes at once, and a full socket is
    /// waited on with a poll the driver arms, which holds no thread.
    pub(super) async fn send_file<S: Socket + AsFd, F: Borrow<File> + 'static>(
        stream: &Stream<S>,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        let Ok(offset) = i64::try_from(offset) else {
            return BufResult(
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "file offset exceeds i64",
                )),
                file,
            );
        };
        let pipe = match stream.pipe.take() {
            Some(pipe) => pipe,
            None => match nonblocking(stream).and_then(|()| Pipe::new()) {
                Ok(pipe) => pipe,
                Err(e) => return BufResult(Err(e), file),
            },
        };

        let fill = Splice::new(
            FileFd(file),
            offset,
            pipe.write.clone(),
            -1,
            len.min(pipe.capacity),
            SpliceFlags::empty(),
        );
        let BufResult(res, fill) = ::compio::runtime::submit(fill).await;
        let (FileFd(file), _) = fill.into_inner();
        let filled = match res {
            Ok(n) => n,
            Err(e) => {
                // A failed splice moved nothing; the pipe is still empty.
                stream.pipe.set(Some(pipe));
                return BufResult(Err(e), file);
            }
        };

        let mut drained = 0;
        while drained < filled {
            match crate::sys::pipe::splice(
                pipe.read.as_fd(),
                stream.inner.as_fd(),
                filled - drained,
            ) {
                Ok(0) => {
                    return BufResult(
                        Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "stream accepted no bytes",
                        )),
                        file,
                    );
                }
                Ok(n) => drained += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let writable = PollOnce::new(stream.inner.clone(), Interest::Writable);
                    if let Err(e) = ::compio::runtime::submit(writable).await.0 {
                        return BufResult(Err(e), file);
                    }
                }
                Err(e) => return BufResult(Err(e), file),
            }
        }
        stream.pipe.set(Some(pipe));
        BufResult(Ok(filled), file)
    }

    /// Makes the socket `O_NONBLOCK`, once.
    fn nonblocking<S: Socket + AsFd>(stream: &Stream<S>) -> io::Result<()> {
        if !stream.nonblocking.get() {
            crate::sys::pipe::set_nonblocking(stream.inner.as_fd())?;
            stream.nonblocking.set(true);
        }
        Ok(())
    }

    /// Waits for the socket to be ready for `interest` with a poll the
    /// driver arms, which holds no thread.
    async fn ready<S: Socket + AsFd>(stream: &Stream<S>, interest: Interest) -> io::Result<()> {
        ::compio::runtime::submit(PollOnce::new(stream.inner.clone(), interest))
            .await
            .0
            .map(drop)
    }

    /// Socket to pipe: waits for readability, then one non-blocking
    /// `splice(2)`. io_uring would run the splice on an io-wq worker, which
    /// an idle peer would hold.
    ///
    /// What the multishot receive took from the socket ahead of the reader
    /// goes into the pipe first, from memory; only once nothing is held, and
    /// the receive is no longer armed to take more, does the socket splice.
    pub(super) async fn to_pipe<S: Socket + AsFd>(
        stream: &Stream<S>,
        pipe: crate::splice::Pipe,
        max: usize,
    ) -> Result<Spliced, (io::Error, crate::splice::Pipe)> {
        if max == 0 {
            return Err((
                io::Error::new(io::ErrorKind::InvalidInput, "splice of zero bytes"),
                pipe,
            ));
        }
        #[cfg(target_os = "linux")]
        let pipe = match stream.recv.splice_held(pipe, max).await {
            super::recv::Held::Spliced(spliced) => return spliced,
            super::recv::Held::None(pipe) => pipe,
        };
        if let Err(e) = nonblocking(stream) {
            return Err((e, pipe));
        }
        let len = max.min(pipe.capacity());
        loop {
            match crate::sys::pipe::splice(stream.inner.as_fd(), pipe.write_fd(), len) {
                Ok(0) => return Ok(Spliced::End(pipe)),
                Ok(n) => return Ok(Spliced::Filled(FilledPipe::new(pipe, n))),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = ready(stream, Interest::Readable).await {
                        return Err((e, pipe));
                    }
                }
                Err(e) => return Err((e, pipe)),
            }
        }
    }

    /// Pipe to socket, as [`send_file`] does it.
    pub(super) async fn from_pipe<S: Socket + AsFd>(
        stream: &Stream<S>,
        filled: FilledPipe,
    ) -> io::Result<crate::splice::Pipe> {
        nonblocking(stream)?;
        let mut left = filled.len();
        while left > 0 {
            match crate::sys::pipe::splice(filled.pipe().read_fd(), stream.inner.as_fd(), left) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "stream accepted no bytes",
                    ));
                }
                Ok(n) => left -= n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready(stream, Interest::Writable).await?;
                }
                Err(e) => return Err(e),
            }
        }
        Ok(filled.into_pipe())
    }
}

/// Bytes a multishot receive put in a buffer of the runtime's ring, lent to
/// the reader by [`ReadOwned`](crate::ReadOwned). Dropping it hands the
/// buffer back to the ring, so a reader holds it only as long as it needs the
/// bytes.
#[cfg(target_os = "linux")]
pub struct RecvBuf {
    buf: ::compio::driver::BufferRef,
    /// How much of the buffer was already read.
    start: usize,
}

#[cfg(target_os = "linux")]
impl RecvBuf {
    const fn new(buf: ::compio::driver::BufferRef) -> Self {
        Self { buf, start: 0 }
    }

    const fn advance(&mut self, n: usize) {
        self.start += n;
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for RecvBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[self.start..]
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for RecvBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvBuf")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Multishot receive on io_uring into the runtime's provided buffer ring.
///
/// The operation belongs to the stream, not to a read, so a read a caller
/// abandons (one raced against a timeout) leaves it armed with whatever it
/// already received. It is ended (cancelled, then drained, so nothing it
/// received is lost) only before the socket goes to someone else: a splice,
/// or for good when the reader stops reading ahead.
#[cfg(target_os = "linux")]
mod recv {
    use std::{cell::RefCell, collections::VecDeque, io};

    use ::compio::{
        driver::{
            SharedFd,
            op::{RecvFlags, RecvMulti},
        },
        runtime::{
            BufferPool, CancelToken, Runtime, StreamExt as _, SubmitMultiManaged, WithCancel,
        },
    };
    use compio_buf::{BufResult, IoBufMut};
    use futures_lite::StreamExt as _;

    use super::{RecvBuf, Socket};
    use crate::{
        Received,
        splice::{Pipe, Spliced},
    };

    type Op = WithCancel<SubmitMultiManaged<RecvMulti<SharedFd<socket2::Socket>>>>;

    /// The receive side of one stream.
    #[derive(Default)]
    pub(super) struct Recv(RefCell<State>);

    #[derive(Default)]
    struct State {
        /// The thread's ring, looked up on the first read: `Some(None)` where
        /// there is none (the runtime is not on io_uring, or the kernel
        /// refused the ring).
        ring: Option<Option<BufferPool>>,
        armed: Option<Armed>,
        /// Bytes received ahead of the reader, in order; the first may be
        /// partly read.
        held: VecDeque<RecvBuf>,
        /// How the receive ended, reported once `held` is read.
        end: Option<End>,
        /// The last receive ended for want of a free ring buffer: the next
        /// read takes the caller's buffer instead of arming again at once.
        exhausted: bool,
        /// The reader stopped reading ahead.
        stopped: bool,
    }

    /// The armed receive and the token that cancels it.
    struct Armed {
        op: Op,
        cancel: CancelToken,
    }

    enum End {
        /// Sticky, like the end of a socket.
        Eof,
        /// Reported once; the next read arms again.
        Error(io::Error),
    }

    enum Next {
        Buf(RecvBuf),
        Eof,
        ReadInstead,
    }

    /// What a copying read came to.
    pub(super) enum Copied<B> {
        Done(BufResult<usize, B>),
        /// Read into the caller's buffer with a receive of its own.
        ReadInstead(B),
    }

    /// What a splice found held.
    pub(super) enum Held {
        Spliced(Result<Spliced, (io::Error, Pipe)>),
        /// Nothing: the socket holds everything not yet read.
        None(Pipe),
    }

    impl Armed {
        fn new<S: Socket>(socket: &S, ring: &BufferPool) -> io::Result<Self> {
            // A length of 0 receives up to a whole ring buffer at a time.
            let op = RecvMulti::new(socket.shared_fd(), ring, 0, RecvFlags::empty())?;
            let cancel = CancelToken::new();
            let op = ::compio::runtime::submit_multi(op)
                .into_managed(ring.clone())
                .with_cancel(cancel.clone());
            Ok(Self { op, cancel })
        }
    }

    /// Whether a receive ended because the ring had no free buffer: compio's
    /// io_uring driver reports `ENOBUFS` as a [`io::ErrorKind::ResourceBusy`]
    /// error of its own, without the OS code (compio-driver 0.12,
    /// `create_result`), which a real `EBUSY` would carry.
    fn ring_dry(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::ResourceBusy && error.raw_os_error().is_none()
    }

    /// The thread's ring, looked up once per stream.
    fn ring(ring: &mut Option<Option<BufferPool>>) -> Option<BufferPool> {
        ring.get_or_insert_with(|| {
            Runtime::with_current(|runtime| {
                if runtime.driver_type().is_iouring() {
                    runtime.buffer_pool().ok()
                } else {
                    None
                }
            })
        })
        .clone()
    }

    impl State {
        /// The next received bytes, waiting for them if none are held.
        async fn next<S: Socket>(&mut self, socket: &S) -> io::Result<Next> {
            loop {
                if let Some(buf) = self.held.pop_front() {
                    return Ok(Next::Buf(buf));
                }
                match self.end.take() {
                    Some(End::Eof) => {
                        self.end = Some(End::Eof);
                        return Ok(Next::Eof);
                    }
                    Some(End::Error(error)) => return Err(error),
                    None => {}
                }
                if self.stopped || self.exhausted {
                    if self.armed.is_some() {
                        self.disarm().await;
                        continue;
                    }
                    self.exhausted = false;
                    return Ok(Next::ReadInstead);
                }
                let armed = match &mut self.armed {
                    Some(armed) => armed,
                    slot @ None => {
                        let Some(ring) = ring(&mut self.ring) else {
                            return Ok(Next::ReadInstead);
                        };
                        slot.insert(Armed::new(socket, &ring)?)
                    }
                };
                match armed.op.next().await {
                    // The kernel ended the receive with its last completion:
                    // arm another.
                    None => self.armed = None,
                    Some(Ok(Some(buf))) if !buf.is_empty() => {
                        return Ok(Next::Buf(RecvBuf::new(buf)));
                    }
                    Some(Ok(_)) => {
                        self.armed = None;
                        self.end = Some(End::Eof);
                    }
                    Some(Err(error)) if ring_dry(&error) => {
                        self.armed = None;
                        self.exhausted = true;
                    }
                    Some(Err(error)) => {
                        self.armed = None;
                        return Err(error);
                    }
                }
            }
        }

        /// Ends the armed receive, keeping everything it received.
        async fn disarm(&mut self) {
            while let Some(armed) = &mut self.armed {
                if !armed.cancel.is_cancelled() {
                    armed.cancel.clone().cancel();
                }
                match armed.op.next().await {
                    None => self.armed = None,
                    Some(Ok(Some(buf))) if !buf.is_empty() => {
                        self.held.push_back(RecvBuf::new(buf));
                    }
                    Some(Ok(_)) => self.end = Some(End::Eof),
                    Some(Err(error))
                        if ring_dry(&error) || error.raw_os_error() == Some(libc::ECANCELED) => {}
                    Some(Err(error)) => self.end = Some(End::Error(error)),
                }
            }
        }
    }

    impl Recv {
        /// [`Read::read`](crate::Read::read): copies what was received into
        /// `buf`, keeping what does not fit.
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side for the read, released when the read ends or is dropped"
        )]
        pub(super) async fn read_ahead<S: Socket, B: IoBufMut>(
            &self,
            socket: &S,
            mut buf: B,
        ) -> Copied<B> {
            if buf.as_uninit().is_empty() {
                buf.clear();
                return Copied::Done(BufResult(Ok(0), buf));
            }
            let mut state = self.0.borrow_mut();
            match state.next(socket).await {
                Ok(Next::Buf(mut held)) => {
                    let n = copy_into(&mut buf, &held);
                    held.advance(n);
                    if !held.is_empty() {
                        state.held.push_front(held);
                    }
                    Copied::Done(BufResult(Ok(n), buf))
                }
                Ok(Next::Eof) => {
                    buf.clear();
                    Copied::Done(BufResult(Ok(0), buf))
                }
                Ok(Next::ReadInstead) => Copied::ReadInstead(buf),
                Err(error) => Copied::Done(BufResult(Err(error), buf)),
            }
        }

        /// [`ReadOwned::read_owned`](crate::ReadOwned::read_owned).
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side for the read, released when the read ends or is dropped"
        )]
        pub(super) async fn read_owned<S: Socket>(
            &self,
            socket: &S,
        ) -> io::Result<Received<RecvBuf>> {
            Ok(match self.0.borrow_mut().next(socket).await? {
                Next::Buf(buf) => Received::Lent(buf),
                Next::Eof => Received::End,
                Next::ReadInstead => Received::ReadInstead,
            })
        }

        /// [`ReadAhead::stop_read_ahead`](crate::ReadAhead::stop_read_ahead).
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side while the receive drains"
        )]
        pub(super) async fn stop(&self) -> Vec<u8> {
            let mut state = self.0.borrow_mut();
            state.stopped = true;
            state.disarm().await;
            let mut bytes = Vec::with_capacity(state.held.iter().map(|buf| buf.len()).sum());
            for buf in state.held.drain(..) {
                bytes.extend_from_slice(&buf);
            }
            bytes
        }

        /// Puts held bytes, at most `max`, into `pipe` ahead of anything the
        /// socket splices. With none held, ends the armed receive first, so
        /// that the socket holds everything not yet read.
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side while the receive drains"
        )]
        pub(super) async fn splice_held(&self, pipe: Pipe, max: usize) -> Held {
            let mut state = self.0.borrow_mut();
            if state.held.is_empty() {
                state.disarm().await;
            }
            if let Some(mut buf) = state.held.pop_front() {
                let n = buf.len().min(max);
                let filled = pipe.fill(&buf[..n]).map(|filled| {
                    buf.advance(filled.len());
                    Spliced::Filled(filled)
                });
                if !buf.is_empty() {
                    state.held.push_front(buf);
                }
                return Held::Spliced(filled);
            }
            match state.end.take() {
                Some(End::Eof) => {
                    state.end = Some(End::Eof);
                    Held::Spliced(Ok(Spliced::End(pipe)))
                }
                Some(End::Error(error)) => Held::Spliced(Err((error, pipe))),
                None => Held::None(pipe),
            }
        }
    }

    /// Copies as much of `bytes` as fits into `buf`, from its start, and sets
    /// its length to that.
    fn copy_into<B: IoBufMut>(buf: &mut B, bytes: &[u8]) -> usize {
        let room = buf.as_uninit();
        let n = room.len().min(bytes.len());
        // SAFETY: `room` has at least `n` bytes, and a ring buffer never
        // overlaps the caller's.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), room.as_mut_ptr().cast(), n) };
        // SAFETY: the first `n` bytes were initialized just now.
        unsafe { buf.set_len(n) };
        n
    }
}

/// Multishot accept on io_uring: one submission stays armed on the
/// listener and completes once per connection, until the kernel ends it.
///
/// The operation belongs to the listener, not to an `accept` call, so an
/// accept a caller abandons (a server racing it against shutdown drops one
/// every time) leaves it armed with whatever it has already accepted. compio
/// accepts once per submission where the kernel predates multishot accept
/// (5.19) or io_uring is unavailable; the next accept then submits again.
#[cfg(target_os = "linux")]
mod multishot {
    use std::{
        cell::RefCell,
        io,
        os::fd::{FromRawFd as _, OwnedFd},
    };

    use ::compio::{
        driver::{SharedFd, ToSharedFd, op::AcceptMulti},
        runtime::SubmitMulti,
    };
    use compio_buf::{BufResult, IntoInner as _};
    use futures_core::stream::FusedStream as _;
    use futures_lite::StreamExt as _;

    type Op = SubmitMulti<AcceptMulti<SharedFd<socket2::Socket>>>;

    fn arm(listener: &impl ToSharedFd<socket2::Socket>) -> Op {
        ::compio::runtime::submit_multi(AcceptMulti::new(listener.to_shared_fd()))
    }

    /// The listener's armed accept, borrowed by the `accept` polling it.
    pub(super) struct Accepts(RefCell<Op>);

    impl Accepts {
        /// An accept not yet submitted: the first `next` submits it.
        pub(super) fn new(listener: &impl ToSharedFd<socket2::Socket>) -> Self {
            Self(RefCell::new(arm(listener)))
        }

        /// The next connection the armed accept completes with, or `None`
        /// while another `accept` on this listener is polling it; that caller
        /// then accepts with a submission of its own, since the operation
        /// wakes one waiter only.
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the borrow is the accept's exclusive hold on the operation, released when the accept ends or is dropped"
        )]
        pub(super) async fn next(
            &self,
            listener: &impl ToSharedFd<socket2::Socket>,
        ) -> Option<io::Result<OwnedFd>> {
            let mut op = self.0.try_borrow_mut().ok()?;
            let BufResult(res, _) = op
                .next()
                .await
                .expect("a terminated accept is replaced in the poll that ends it");
            if !op.is_terminated() {
                // SAFETY: a multishot completion hands over the accepted
                // descriptor, which nothing else owns.
                return Some(res.map(|fd| unsafe { OwnedFd::from_raw_fd(fd as _) }));
            }
            // The kernel ended the multishot (or there was none): a successful
            // last completion leaves the socket in the operation.
            let finished = std::mem::replace(&mut *op, arm(listener));
            Some(res.map(|_| {
                let op = finished
                    .try_take()
                    .map_err(drop)
                    .expect("a terminated accept has completed");
                OwnedFd::from(op.into_inner())
            }))
        }
    }

    impl std::fmt::Debug for Accepts {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Accepts").finish_non_exhaustive()
        }
    }
}

/// A listening TCP socket.
#[derive(Debug)]
pub struct TcpListener {
    inner: net::TcpListener,
    #[cfg(target_os = "linux")]
    accepts: multishot::Accepts,
}

impl TcpListener {
    fn new(inner: net::TcpListener) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            accepts: multishot::Accepts::new(&inner),
            inner,
        }
    }

    /// compio's listener.
    #[must_use]
    pub fn get_ref(&self) -> &net::TcpListener {
        &self.inner
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl Listener for TcpListener {
    type Stream = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        #[cfg(target_os = "linux")]
        if let Some(accepted) = self.accepts.next(&self.inner).await {
            // A multishot accept shares one address buffer between its
            // completions, so it reports no peer.
            let stream = net::TcpStream::from_std(accepted?.into())?;
            let peer = stream.peer_addr()?;
            return Ok((TcpStream::new(stream), peer));
        }
        let (stream, peer) = self.inner.accept().await?;
        Ok((TcpStream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// A listening Unix-domain socket.
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixListener {
    inner: net::UnixListener,
    #[cfg(target_os = "linux")]
    accepts: multishot::Accepts,
}

#[cfg(unix)]
impl UnixListener {
    fn new(inner: net::UnixListener) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            accepts: multishot::Accepts::new(&inner),
            inner,
        }
    }

    /// compio's listener.
    #[must_use]
    pub fn get_ref(&self) -> &net::UnixListener {
        &self.inner
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for UnixListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(unix)]
impl Listener for UnixListener {
    type Stream = UnixStream;
    type Addr = std::os::unix::net::SocketAddr;

    async fn accept(&self) -> io::Result<(UnixStream, Self::Addr)> {
        #[cfg(target_os = "linux")]
        let stream = match self.accepts.next(&self.inner).await {
            Some(accepted) => net::UnixStream::from_std(accepted?.into())?,
            None => self.inner.accept().await?.0,
        };
        #[cfg(not(target_os = "linux"))]
        let (stream, _) = self.inner.accept().await?;
        let stream = UnixStream::new(stream);
        let peer = stream.peer_addr()?;
        Ok((stream, peer))
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        crate::sys::unix::listener_addr(&self.inner)
    }
}

/// A datagram operation's result with its error in the code every other
/// implementation reports: on Windows, compio completes through a completion
/// port, which reports an ICMP error as its Win32 code.
fn completed<T>(res: io::Result<T>) -> io::Result<T> {
    #[cfg(windows)]
    return res.map_err(crate::sys::iocp::socket_error);
    #[cfg(not(windows))]
    res
}

/// A UDP socket, with segmentation offload and receive coalescing on Linux.
#[derive(Debug)]
pub struct UdpSocket {
    inner: net::UdpSocket,
    max_segments: usize,
}

impl UdpSocket {
    fn new(inner: net::UdpSocket) -> io::Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            use std::os::fd::AsFd;

            crate::sys::control::enable_pktinfo(inner.as_fd(), inner.local_addr()?)?;
        }
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let max_segments = {
            use std::os::fd::AsFd;

            crate::sys::linux::enable_gro(inner.as_fd())?;
            crate::sys::linux::max_gso_segments(inner.as_fd())?
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let max_segments = 1;
        Ok(Self {
            inner,
            max_segments,
        })
    }

    /// compio's socket.
    #[must_use]
    pub fn get_ref(&self) -> &net::UdpSocket {
        &self.inner
    }

    async fn send_one<B: IoBuf>(
        &self,
        buf: B,
        segment: Option<NonZeroU16>,
        target: SocketAddr,
        source: Option<IpAddr>,
    ) -> BufResult<usize, B> {
        let BufResult(res, buf) = match (segment, source) {
            (None, None) => self.inner.send_to(buf, target).await,
            #[cfg(any(
                target_os = "linux",
                target_os = "android",
                target_vendor = "apple",
                windows
            ))]
            (segment, source) => {
                let control = crate::sys::control::ControlBuf::send(segment, source);
                let BufResult(res, (buf, _)) = self.inner.send_msg(buf, control, target).await;
                BufResult(res, buf)
            }
            #[cfg(not(any(
                target_os = "linux",
                target_os = "android",
                target_vendor = "apple",
                windows
            )))]
            (None, Some(_)) => BufResult(
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "choosing a datagram's source address is not supported on this platform",
                )),
                buf,
            ),
            #[cfg(not(any(
                target_os = "linux",
                target_os = "android",
                target_vendor = "apple",
                windows
            )))]
            (Some(_), _) => unreachable!("segmented sends need segmentation offload"),
        };
        BufResult(completed(res), buf)
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl DatagramSocket for UdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_send_segments(&self) -> usize {
        self.max_segments
    }

    fn send_from<B: IoBuf>(
        &self,
        buf: B,
        target: SocketAddr,
        source: Option<IpAddr>,
    ) -> impl Future<Output = BufResult<usize, B>> {
        self.send_one(buf, None, target, source)
    }

    fn send_segments_from<B: IoBuf>(
        &self,
        buf: B,
        segment_size: NonZeroU16,
        target: SocketAddr,
        source: Option<IpAddr>,
    ) -> impl Future<Output = BufResult<usize, B>> {
        send_batched(buf, segment_size, self.max_segments, move |slice, gso| {
            self.send_one(slice, gso, target, source)
        })
    }

    async fn recv_from<B: IoBufMut>(&self, mut buf: B) -> BufResult<RecvMeta, B> {
        // As for stream reads: compio only grows the length.
        buf.clear();
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        ))]
        {
            use ::compio::driver::op::ReturnFlags;

            /// On Linux a truncation could have cut whole coalesced
            /// datagrams; elsewhere UDP's truncation is the contract.
            fn check_truncation(flags: ReturnFlags) -> io::Result<()> {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                if flags.contains(ReturnFlags::TRUNC) {
                    return Err(crate::datagram::truncated_coalesced());
                }
                #[cfg(not(any(target_os = "linux", target_os = "android")))]
                let _ = flags;
                Ok(())
            }

            let control = crate::sys::control::ControlBuf::new();
            let BufResult(res, (buf, control)) = self.inner.recv_msg(buf, control).await;
            let res = res.and_then(|(n, control_len, from, flags)| {
                check_truncation(flags)?;
                let received = control.parse(control_len);
                let segment = received.segment.unwrap_or(n);
                Ok(RecvMeta::new(n, segment, from).with_destination(received.destination))
            });
            BufResult(completed(res), buf)
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        )))]
        {
            let BufResult(res, buf) = self.inner.recv_from(buf).await;
            BufResult(res.map(|(n, from)| RecvMeta::single(n, from)), buf)
        }
    }
}
