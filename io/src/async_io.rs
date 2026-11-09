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
    Io,
    poll::IntoPoll,
    readiness::{self, sealed::Ready},
    stream::Listener,
    time::Timer,
};

/// The async-io implementation.
#[derive(Debug, Clone, Copy, Default)]
pub struct AsyncIo;

/// A connected TCP stream.
pub type TcpStream = readiness::Stream<Async<std::net::TcpStream>>;
/// A listening TCP socket.
pub type TcpListener = readiness::Listener<Async<std::net::TcpListener>>;
/// A UDP socket, with segmentation offload and receive coalescing on Linux.
pub type UdpSocket = readiness::Datagram<Async<std::net::UdpSocket>>;

impl Timer for AsyncIo {
    async fn sleep_until(&self, deadline: Instant) {
        ::async_io::Timer::at(deadline).await;
    }
}

impl Io for AsyncIo {
    type TcpStream = TcpStream;
    type TcpListener = TcpListener;
    type UdpSocket = UdpSocket;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        Async::<std::net::TcpStream>::connect(addr)
            .await
            .map(readiness::Stream::new)
    }

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

impl Listener for TcpListener {
    type Stream = TcpStream;

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.get_ref().accept().await?;
        Ok((readiness::Stream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().get_ref().local_addr()
    }
}

impl IntoPoll for TcpStream {
    type Poll = PollStream;

    fn into_poll(self) -> PollStream {
        PollStream(self.into_inner())
    }
}

/// async-io's stream behind `futures_io`'s traits, reading into the caller's
/// buffer directly. Unlike [`Async`]'s own `poll_close`, which only flushes,
/// closing shuts down the write direction, as every other implementation's
/// poll-style stream does.
#[derive(Debug)]
pub struct PollStream(Async<std::net::TcpStream>);

impl PollStream {
    /// async-io's stream.
    #[must_use]
    pub fn into_inner(self) -> Async<std::net::TcpStream> {
        self.0
    }
}

impl futures_io::AsyncRead for PollStream {
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

impl futures_io::AsyncWrite for PollStream {
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
        Poll::Ready(self.0.get_ref().shutdown(Shutdown::Write))
    }
}
