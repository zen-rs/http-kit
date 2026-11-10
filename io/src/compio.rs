//! The compio implementation: io_uring on Linux (falling back to polling
//! where the kernel refuses io_uring), IOCP on Windows, polling elsewhere.
//!
//! Every method must be called, and every future polled, inside a compio
//! runtime on the current thread.
//!
//! [`SendFile`](crate::SendFile) moves file data in the kernel: on Linux
//! through two `splice(2)` operations per round (file into a pipe, pipe into
//! the socket), submitted to io_uring so that a page-cache miss blocks
//! neither the thread nor the ring; on Apple platforms through `sendfile(2)`
//! once the socket is writable. Elsewhere the region is read into a buffer
//! and written.
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
    io::{AsyncRead as _, AsyncWrite as _},
    net,
};
use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf};

use crate::{
    Io,
    datagram::{DatagramSocket, RecvMeta, send_batched},
    poll::{CopyingPoll, IntoPoll},
    stream::{Listener, impl_stream, sealed::SharedStream},
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
    type UdpSocket = UdpSocket;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        net::TcpStream::connect(addr).await.map(TcpStream::new)
    }

    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<TcpListener> {
        net::TcpListener::from_std(listener).map(TcpListener)
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
pub struct TcpStream {
    inner: net::TcpStream,
    /// The pipe file transfers splice through, kept between transfers. A
    /// transfer takes it out while data may sit in it, so one that fails or
    /// is cancelled midway drops it instead of leaving stale bytes behind.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pipe: std::cell::Cell<Option<splice::Pipe>>,
}

impl TcpStream {
    fn new(inner: net::TcpStream) -> Self {
        Self {
            inner,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pipe: std::cell::Cell::new(None),
        }
    }

    /// compio's stream.
    #[must_use]
    pub fn get_ref(&self) -> &net::TcpStream {
        &self.inner
    }

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

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpStream")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for TcpStream {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl SharedStream for TcpStream {
    async fn read<B: IoBufMut>(&self, mut buf: B) -> BufResult<usize, B> {
        // compio writes from the start but only ever grows the length; the
        // contract is a length of exactly what was read.
        buf.clear();
        let mut stream = &self.inner;
        stream.read(buf).await
    }

    async fn write<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
        let mut stream = &self.inner;
        stream.write(buf).await
    }

    async fn write_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
        let mut stream = &self.inner;
        stream.write_vectored(buf).await
    }

    async fn shutdown(&self) -> io::Result<()> {
        let mut stream = &self.inner;
        stream.shutdown().await
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
            use std::os::fd::AsRawFd;

            let poll_fd = match self.inner.to_poll_fd() {
                Ok(poll_fd) => poll_fd,
                Err(e) => return BufResult(Err(e), file),
            };
            loop {
                if let Err(e) = std::future::poll_fn(|cx| poll_fd.poll_write_ready(cx)).await {
                    return BufResult(Err(e), file);
                }
                let f: &File = file.borrow();
                match crate::sys::apple::sendfile(poll_fd.as_raw_fd(), f.as_raw_fd(), offset, len) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    res => return BufResult(res, file),
                }
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            crate::stream::copy::copy_file_region(self, file, offset, len).await
        }
    }
}

impl_stream!([] TcpStream);

impl IntoPoll for TcpStream {
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

    use ::compio::driver::op::{Splice, SpliceFlags};
    use compio_buf::{BufResult, IntoInner};

    use super::TcpStream;

    /// A pipe and how many bytes it holds before a writer would block.
    pub(super) struct Pipe {
        read: PipeEnd,
        write: PipeEnd,
        capacity: usize,
    }

    impl Pipe {
        fn new() -> io::Result<Self> {
            let (read, write, capacity) = crate::sys::linux::pipe()?;
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
    pub(super) async fn send_file<F: Borrow<File> + 'static>(
        stream: &TcpStream,
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
            None => match Pipe::new() {
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
            let drain = Splice::new(
                pipe.read.clone(),
                -1,
                stream.inner.clone(),
                -1,
                filled - drained,
                SpliceFlags::empty(),
            );
            match ::compio::runtime::submit(drain).await.0 {
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
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return BufResult(Err(e), file),
            }
        }
        stream.pipe.set(Some(pipe));
        BufResult(Ok(filled), file)
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

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.0.accept().await?;
        Ok((TcpStream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
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
