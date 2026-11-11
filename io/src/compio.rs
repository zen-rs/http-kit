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
    Io,
    datagram::{DatagramSocket, RecvMeta, send_batched},
    poll::{CopyingPoll, IntoPoll},
    stream::{Listener, TcpOptions, impl_stream, sealed::SharedStream},
    time::Timer,
};

/// The compio implementation. It holds nothing: compio keeps its runtime per
/// thread, and every operation goes to the current thread's.
#[derive(Debug, Clone, Copy, Default)]
pub struct Compio;

impl Timer for Compio {
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        ::compio::time::sleep_until(deadline)
    }
}

impl Io for Compio {
    type TcpStream = TcpStream;
    type TcpListener = TcpListener;
    #[cfg(unix)]
    type UnixStream = UnixStream;
    #[cfg(unix)]
    type UnixListener = UnixListener;
    type UdpSocket = UdpSocket;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        net::TcpStream::connect(addr).await.map(TcpStream::new)
    }

    #[cfg(unix)]
    async fn connect_unix(&self, path: &std::path::Path) -> io::Result<UnixStream> {
        net::UnixStream::connect(path).await.map(UnixStream::new)
    }

    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<TcpListener> {
        net::TcpListener::from_std(listener).map(TcpListener)
    }

    #[cfg(unix)]
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<UnixListener> {
        net::UnixListener::from_std(listener).map(UnixListener)
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
}

impl<S> Stream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pipe: std::cell::Cell::new(None),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            nonblocking: std::cell::Cell::new(false),
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
    async fn read<B: IoBufMut>(&self, mut buf: B) -> BufResult<usize, B> {
        // compio writes from the start but only ever grows the length; the
        // contract is a length of exactly what was read.
        buf.clear();
        self.inner.read(buf).await
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

/// A listening TCP socket.
#[derive(Debug)]
pub struct TcpListener(net::TcpListener);

impl TcpListener {
    /// compio's listener.
    #[must_use]
    pub fn get_ref(&self) -> &net::TcpListener {
        &self.0
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Listener for TcpListener {
    type Stream = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.0.accept().await?;
        Ok((TcpStream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }
}

/// A listening Unix-domain socket.
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixListener(net::UnixListener);

#[cfg(unix)]
impl UnixListener {
    /// compio's listener.
    #[must_use]
    pub fn get_ref(&self) -> &net::UnixListener {
        &self.0
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for UnixListener {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

#[cfg(unix)]
impl Listener for UnixListener {
    type Stream = UnixStream;
    type Addr = std::os::unix::net::SocketAddr;

    async fn accept(&self) -> io::Result<(UnixStream, Self::Addr)> {
        let (stream, _) = self.0.accept().await?;
        let stream = UnixStream::new(stream);
        let peer = stream.peer_addr()?;
        Ok((stream, peer))
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        crate::sys::unix::listener_addr(&self.0)
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
