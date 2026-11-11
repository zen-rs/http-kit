//! The async-io implementation, adapted to owned buffers.
//!
//! async-io runs one reactor per process; any executor can poll these
//! futures, and nothing here requires `Send`.
//!
//! [`SendFile`](crate::SendFile) is `sendfile(2)` on Linux and Apple
//! platforms; elsewhere the region is read into a buffer and written. The
//! poll-style capability, [`PollStream`], reads and writes through async-io's
//! own [`Async`] stream, so it costs no copy.

use std::{
    future::Future,
    io,
    net::{Shutdown, SocketAddr},
    pin::Pin,
    task::{Context, Poll, ready},
    time::Instant,
};

use ::async_io::Async;
use socket2::SockRef;

use crate::{
    Datagram, Dial, FromStd, Listen,
    poll::IntoPoll,
    readiness::{self, sealed::Ready},
    stream::Listener,
    time::Timer,
};
#[cfg(unix)]
use crate::{DialUnix, FromStdUnix, ListenUnix};

/// The async-io implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct AsyncIo;

/// A connected TCP stream.
pub type TcpStream = readiness::Stream<Async<std::net::TcpStream>>;
/// A listening TCP socket.
pub type TcpListener = readiness::Listener<Async<std::net::TcpListener>>;
/// A connected Unix-domain stream socket.
#[cfg(unix)]
pub type UnixStream = readiness::Stream<Async<std::os::unix::net::UnixStream>>;
/// A listening Unix-domain socket.
#[cfg(unix)]
pub type UnixListener = readiness::Listener<Async<std::os::unix::net::UnixListener>>;
/// A UDP socket, with segmentation offload and receive coalescing on Linux.
pub type UdpSocket = readiness::Datagram<Async<std::net::UdpSocket>>;

impl Timer for AsyncIo {
    async fn sleep_until(&self, deadline: Instant) {
        ::async_io::Timer::at(deadline).await;
    }
}

impl Dial for AsyncIo {
    type Connection = TcpStream;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        Async::<std::net::TcpStream>::connect(addr)
            .await
            .map(readiness::Stream::new)
    }
}

#[cfg(unix)]
impl DialUnix for AsyncIo {
    type UnixConnection = UnixStream;

    async fn connect_unix(&self, path: &std::path::Path) -> io::Result<UnixStream> {
        Async::<std::os::unix::net::UnixStream>::connect(path)
            .await
            .map(readiness::Stream::new)
    }
}

impl Listen for AsyncIo {
    type Listener = TcpListener;

    fn bind_tcp(&self, addr: SocketAddr) -> io::Result<TcpListener> {
        self.tcp_listener(std::net::TcpListener::bind(addr)?)
    }
}

#[cfg(unix)]
impl ListenUnix for AsyncIo {
    type UnixListener = UnixListener;

    fn bind_unix(&self, path: &std::path::Path) -> io::Result<UnixListener> {
        self.unix_listener(std::os::unix::net::UnixListener::bind(path)?)
    }
}

impl Datagram for AsyncIo {
    type UdpSocket = UdpSocket;

    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        self.udp_socket(std::net::UdpSocket::bind(addr)?)
    }
}

#[cfg(unix)]
impl FromStdUnix for AsyncIo {
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<UnixListener> {
        Async::new(listener).map(readiness::Listener::new)
    }
}

impl FromStd for AsyncIo {
    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<TcpListener> {
        Async::new(listener).map(readiness::Listener::new)
    }

    fn udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        readiness::Datagram::new(Async::new(socket)?)
    }
}

impl<T: 'static> Ready for Async<T>
where
    for<'a> SockRef<'a>: From<&'a T>,
{
    fn sock(&self) -> SockRef<'_> {
        SockRef::from(self.get_ref())
    }

    fn read_io<R>(
        &self,
        mut op: impl FnMut(SockRef<'_>) -> io::Result<R>,
    ) -> impl Future<Output = io::Result<R>> {
        self.read_with(move |inner| op(SockRef::from(inner)))
    }

    fn write_io<R>(
        &self,
        mut op: impl FnMut(SockRef<'_>) -> io::Result<R>,
    ) -> impl Future<Output = io::Result<R>> {
        self.write_with(move |inner| op(SockRef::from(inner)))
    }
}

readiness::impl_tcp_family!(Async<std::net::TcpStream>);
#[cfg(unix)]
readiness::impl_unix_family!(Async<std::os::unix::net::UnixStream>);

impl Listener for TcpListener {
    type Stream = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.get_ref().accept().await?;
        Ok((readiness::Stream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().get_ref().local_addr()
    }
}

#[cfg(unix)]
impl Listener for UnixListener {
    type Stream = UnixStream;
    type Addr = std::os::unix::net::SocketAddr;

    async fn accept(&self) -> io::Result<(UnixStream, Self::Addr)> {
        let (stream, peer) = self.get_ref().accept().await?;
        Ok((readiness::Stream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.get_ref().get_ref().local_addr()
    }
}

impl IntoPoll for TcpStream {
    type Poll = PollStream;

    fn into_poll(self) -> PollStream {
        PollStream(self.into_inner())
    }
}

#[cfg(unix)]
impl IntoPoll for UnixStream {
    type Poll = PollStream<std::os::unix::net::UnixStream>;

    fn into_poll(self) -> Self::Poll {
        PollStream(self.into_inner())
    }
}

/// async-io's stream behind `futures_io`'s traits, reading into the caller's
/// buffer directly. Unlike [`Async`]'s own `poll_close`, which only flushes,
/// closing shuts down the write direction, as every other implementation's
/// poll-style stream does.
#[derive(Debug)]
pub struct PollStream<T: 'static = std::net::TcpStream>(Async<T>);

impl<T: 'static> PollStream<T> {
    /// async-io's stream.
    #[must_use]
    pub fn into_inner(self) -> Async<T> {
        self.0
    }
}

impl<T> futures_io::AsyncRead for PollStream<T>
where
    T: 'static,
    Async<T>: futures_io::AsyncRead,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }

    fn poll_read_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read_vectored(cx, bufs)
    }
}

impl<T> futures_io::AsyncWrite for PollStream<T>
where
    T: 'static,
    Async<T>: futures_io::AsyncWrite + Ready,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.0).poll_flush(cx))?;
        Poll::Ready(self.0.sock().shutdown(Shutdown::Write))
    }
}
