//! Owned-buffer sockets over a readiness reactor, shared by the `tokio` and
//! `async-io` implementations.
//!
//! The reactor only says when a socket is ready; the operation itself is a
//! non-blocking syscall straight into or out of the caller's buffer, so no
//! data is copied on the way. Receives write into the buffer's uninitialized
//! capacity without zeroing it first.

use std::{
    borrow::Borrow,
    fmt,
    fs::File,
    future::Future,
    io::{self, IoSlice},
    net::{IpAddr, Shutdown, SocketAddr},
    num::NonZeroU16,
};

use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf};
use socket2::{SockAddr, SockRef};

use crate::{
    datagram::{DatagramSocket, RecvMeta, send_batched},
    stream::sealed::SharedStream,
};

pub(crate) mod sealed {
    use std::{future::Future, io};

    use socket2::SockRef;

    /// A socket registered with a readiness reactor.
    pub trait Ready: 'static {
        /// The socket, for syscalls.
        fn sock(&self) -> SockRef<'_>;

        /// Runs `op` once the socket is readable, again after each
        /// [`io::ErrorKind::WouldBlock`].
        fn read_io<R>(
            &self,
            op: impl FnMut(SockRef<'_>) -> io::Result<R>,
        ) -> impl Future<Output = io::Result<R>>;

        /// Runs `op` once the socket is writable, again after each
        /// [`io::ErrorKind::WouldBlock`].
        fn write_io<R>(
            &self,
            op: impl FnMut(SockRef<'_>) -> io::Result<R>,
        ) -> impl Future<Output = io::Result<R>>;
    }

    /// A stream socket of one address family, which reports that family's
    /// address type.
    pub trait Family: Ready {
        /// The family's address.
        type Addr;

        /// The local address.
        fn local_addr(&self) -> io::Result<Self::Addr>;

        /// The peer's address.
        fn peer_addr(&self) -> io::Result<Self::Addr>;
    }
}

use sealed::{Family, Ready};

/// A connected stream socket on a readiness reactor.
pub struct Stream<T>(T);

impl<T> Stream<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self(inner)
    }

    /// The reactor's socket.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.0
    }

    /// Unwraps the reactor's socket.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T: Family> Stream<T> {
    /// The local address.
    ///
    /// # Errors
    ///
    /// Fails if the operating system cannot report it.
    pub fn local_addr(&self) -> io::Result<T::Addr> {
        self.0.local_addr()
    }

    /// The peer's address.
    ///
    /// # Errors
    ///
    /// Fails if the socket is not connected.
    pub fn peer_addr(&self) -> io::Result<T::Addr> {
        self.0.peer_addr()
    }
}

/// Implements [`Family`] for an IP stream socket.
macro_rules! impl_tcp_family {
    ($ty:ty) => {
        impl $crate::readiness::sealed::Family for $ty {
            type Addr = ::std::net::SocketAddr;

            fn local_addr(&self) -> ::std::io::Result<Self::Addr> {
                $crate::readiness::socket_addr(
                    $crate::readiness::sealed::Ready::sock(self).local_addr()?,
                )
            }

            fn peer_addr(&self) -> ::std::io::Result<Self::Addr> {
                $crate::readiness::socket_addr(
                    $crate::readiness::sealed::Ready::sock(self).peer_addr()?,
                )
            }
        }
    };
}

/// Implements [`Family`] for a Unix-domain stream socket.
#[cfg(unix)]
macro_rules! impl_unix_family {
    ($ty:ty) => {
        impl $crate::readiness::sealed::Family for $ty {
            type Addr = ::std::os::unix::net::SocketAddr;

            fn local_addr(&self) -> ::std::io::Result<Self::Addr> {
                $crate::sys::unix::local_addr(self)
            }

            fn peer_addr(&self) -> ::std::io::Result<Self::Addr> {
                $crate::sys::unix::peer_addr(self)
            }
        }
    };
}

pub(crate) use impl_tcp_family;
#[cfg(unix)]
pub(crate) use impl_unix_family;

impl<T: fmt::Debug> fmt::Debug for Stream<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Stream").field(&self.0).finish()
    }
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> std::os::fd::AsFd for Stream<T> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

pub(crate) fn socket_addr(addr: SockAddr) -> io::Result<SocketAddr> {
    addr.as_socket().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "socket address is not an IP address",
        )
    })
}

impl<T: Ready> SharedStream for Stream<T> {
    async fn read<B: IoBufMut>(&self, mut buf: B) -> BufResult<usize, B> {
        let res = self.0.read_io(|sock| sock.recv(buf.as_uninit())).await;
        if let Ok(n) = res {
            // SAFETY: `recv` initialized the first `n` bytes of the buffer.
            unsafe { buf.set_len(n) };
        }
        BufResult(res, buf)
    }

    async fn write<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
        let res = self.0.write_io(|sock| send(sock, buf.as_init())).await;
        BufResult(res, buf)
    }

    async fn write_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
        let res = {
            let slices: Vec<IoSlice<'_>> = buf.iter_slice().map(IoSlice::new).collect();
            self.0.write_io(|sock| sock.send_vectored(&slices)).await
        };
        BufResult(res, buf)
    }

    async fn shutdown(&self) -> io::Result<()> {
        self.0.sock().shutdown(Shutdown::Write)
    }

    async fn send_file<F: Borrow<File> + 'static>(
        &self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            if len == 0 {
                return BufResult(Ok(0), file);
            }
            let res = self
                .0
                .write_io(|sock| {
                    let f: &File = file.borrow();
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    {
                        use std::os::fd::AsFd;
                        crate::sys::linux::sendfile(sock.as_fd(), f.as_fd(), offset, len)
                    }
                    #[cfg(target_vendor = "apple")]
                    {
                        use std::os::fd::AsRawFd;
                        crate::sys::apple::sendfile(sock.as_raw_fd(), f.as_raw_fd(), offset, len)
                    }
                })
                .await;
            BufResult(res, file)
        }
        #[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
        {
            crate::stream::copy::copy_file_region(self, file, offset, len).await
        }
    }
}

crate::stream::impl_stream!([T: Ready] Stream<T>);

/// `send(2)`, without raising `SIGPIPE` where the platform takes a flag for
/// that.
fn send(sock: SockRef<'_>, buf: &[u8]) -> io::Result<usize> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        sock.send_with_flags(buf, libc::MSG_NOSIGNAL)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        sock.send(buf)
    }
}

/// A listening stream socket on a readiness reactor.
pub struct Listener<T>(T);

impl<T> Listener<T> {
    pub(crate) fn new(inner: T) -> Self {
        Self(inner)
    }

    /// The reactor's socket.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for Listener<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Listener").field(&self.0).finish()
    }
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> std::os::fd::AsFd for Listener<T> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// A datagram socket on a readiness reactor.
pub struct Datagram<T> {
    inner: T,
    max_segments: usize,
    /// Winsock has no `recvmsg` to call; this is its `WSARecvMsg`.
    #[cfg(windows)]
    recv_msg: crate::sys::winsock::RecvMsg,
}

impl<T: Ready> Datagram<T> {
    /// Wraps a registered socket, enabling segmentation offload and receive
    /// coalescing where the kernel has them.
    pub(crate) fn new(inner: T) -> io::Result<Self> {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        {
            use std::os::fd::AsFd;

            let sock = inner.sock();
            let local = socket_addr(sock.local_addr()?)?;
            crate::sys::control::enable_pktinfo(sock.as_fd(), local)?;
        }
        #[cfg(windows)]
        let recv_msg = {
            use std::os::windows::io::AsSocket;

            let sock = inner.sock();
            let local = socket_addr(sock.local_addr()?)?;
            crate::sys::control::enable_pktinfo(sock.as_socket(), local)?;
            crate::sys::winsock::RecvMsg::load(sock.as_socket())?
        };
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let max_segments = {
            use std::os::fd::AsFd;

            let sock = inner.sock();
            crate::sys::linux::enable_gro(sock.as_fd())?;
            crate::sys::linux::max_gso_segments(sock.as_fd())?
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let max_segments = 1;
        Ok(Self {
            inner,
            max_segments,
            #[cfg(windows)]
            recv_msg,
        })
    }
}

impl<T> Datagram<T> {
    /// The reactor's socket.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.inner
    }
}

impl<T: fmt::Debug> fmt::Debug for Datagram<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Datagram")
            .field("inner", &self.inner)
            .field("max_segments", &self.max_segments)
            .finish()
    }
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd> std::os::fd::AsFd for Datagram<T> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl<T: Ready> Datagram<T> {
    async fn send_one<B: IoBuf>(
        &self,
        buf: B,
        segment: Option<NonZeroU16>,
        target: SockAddr,
        source: Option<IpAddr>,
    ) -> BufResult<usize, B> {
        let res = self
            .inner
            .write_io(|sock| match (segment, source) {
                (None, None) => sock.send_to(buf.as_init(), &target),
                #[cfg(any(
                    target_os = "linux",
                    target_os = "android",
                    target_vendor = "apple",
                    windows
                ))]
                (segment, source) => {
                    let control = crate::sys::control::ControlBuf::send(segment, source);
                    let bufs = [IoSlice::new(buf.as_init())];
                    let msg = socket2::MsgHdr::new()
                        .with_addr(&target)
                        .with_buffers(&bufs)
                        .with_control(control.as_init());
                    sock.sendmsg(&msg, 0)
                }
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "android",
                    target_vendor = "apple",
                    windows
                )))]
                (None, Some(_)) => Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "choosing a datagram's source address is not supported on this platform",
                )),
                #[cfg(not(any(
                    target_os = "linux",
                    target_os = "android",
                    target_vendor = "apple",
                    windows
                )))]
                (Some(_), _) => unreachable!("segmented sends need segmentation offload"),
            })
            .await;
        BufResult(res, buf)
    }
}

impl<T: Ready> DatagramSocket for Datagram<T> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        socket_addr(self.inner.sock().local_addr()?)
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
        self.send_one(buf, None, SockAddr::from(target), source)
    }

    fn send_segments_from<B: IoBuf>(
        &self,
        buf: B,
        segment_size: NonZeroU16,
        target: SocketAddr,
        source: Option<IpAddr>,
    ) -> impl Future<Output = BufResult<usize, B>> {
        let target = SockAddr::from(target);
        send_batched(buf, segment_size, self.max_segments, move |slice, gso| {
            self.send_one(slice, gso, target.clone(), source)
        })
    }

    async fn recv_from<B: IoBufMut>(&self, mut buf: B) -> BufResult<RecvMeta, B> {
        #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
        let res = {
            use socket2::{MaybeUninitSlice, SockAddrStorage};

            let mut control = crate::sys::control::ControlBuf::new();
            self.inner
                .read_io(|sock| {
                    // SAFETY: a zeroed storage of its full size is a valid
                    // (unspecified) address for the kernel to overwrite.
                    let mut from = unsafe {
                        SockAddr::new(
                            SockAddrStorage::zeroed(),
                            size_of::<SockAddrStorage>() as libc::socklen_t,
                        )
                    };
                    let mut bufs = [MaybeUninitSlice::new(buf.as_uninit())];
                    let mut msg = socket2::MsgHdrMut::new()
                        .with_addr(&mut from)
                        .with_buffers(&mut bufs)
                        .with_control(control.as_uninit());
                    let n = sock.recvmsg(&mut msg, 0)?;
                    let (truncated, control_len) = (msg.flags().is_truncated(), msg.control_len());
                    #[cfg(any(target_os = "linux", target_os = "android"))]
                    if truncated {
                        return Err(crate::datagram::truncated_coalesced());
                    }
                    #[cfg(not(any(target_os = "linux", target_os = "android")))]
                    let _ = truncated;
                    let received = control.parse(control_len);
                    let segment = received.segment.unwrap_or(n);
                    Ok(RecvMeta::new(n, segment, socket_addr(from)?)
                        .with_destination(received.destination))
                })
                .await
        };
        #[cfg(windows)]
        let res = {
            use std::os::windows::io::AsSocket;

            let mut control = crate::sys::control::ControlBuf::new();
            self.inner
                .read_io(|sock| {
                    let (n, control_len, from) = self.recv_msg.recv(
                        sock.as_socket(),
                        buf.as_uninit(),
                        control.as_uninit(),
                    )?;
                    let received = control.parse(control_len);
                    let segment = received.segment.unwrap_or(n);
                    Ok(RecvMeta::new(n, segment, socket_addr(from)?)
                        .with_destination(received.destination))
                })
                .await
        };
        #[cfg(not(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        )))]
        let res = self
            .inner
            .read_io(|sock| {
                let (n, from) = sock.recv_from(buf.as_uninit())?;
                Ok(RecvMeta::single(n, socket_addr(from)?))
            })
            .await;
        if let Ok(meta) = &res {
            // SAFETY: the receive initialized the first `len` bytes.
            unsafe { buf.set_len(meta.len()) };
        }
        BufResult(res, buf)
    }
}
