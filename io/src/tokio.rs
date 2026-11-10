//! The tokio implementation, adapted to owned buffers.
//!
//! Every method must be called, and every future polled, inside a tokio
//! runtime with its I/O and time drivers enabled. A current-thread runtime
//! per core is the thread-per-core arrangement; nothing here requires `Send`.
//!
//! [`SendFile`](crate::SendFile) is `sendfile(2)` on Linux and Apple
//! platforms; elsewhere the region is read into a buffer and written. The
//! poll-style capability is tokio's own stream, so it costs no copy.

use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll, ready},
    time::Instant,
};

use ::tokio::io::{Interest, ReadBuf};
use socket2::SockRef;

use crate::{
    Io,
    poll::IntoPoll,
    readiness::{self, sealed::Ready},
    stream::Listener,
    time::Timer,
};

/// The tokio implementation. It holds nothing: tokio keeps its runtime
/// context per thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct Tokio;

/// A connected TCP stream.
pub type TcpStream = readiness::Stream<::tokio::net::TcpStream>;
/// A listening TCP socket.
pub type TcpListener = readiness::Listener<::tokio::net::TcpListener>;
/// A connected Unix-domain stream socket.
#[cfg(unix)]
pub type UnixStream = readiness::Stream<::tokio::net::UnixStream>;
/// A listening Unix-domain socket.
#[cfg(unix)]
pub type UnixListener = readiness::Listener<::tokio::net::UnixListener>;
/// A UDP socket, with segmentation offload and receive coalescing on Linux.
pub type UdpSocket = readiness::Datagram<::tokio::net::UdpSocket>;

impl Timer for Tokio {
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        ::tokio::time::sleep_until(deadline.into())
    }
}

impl Io for Tokio {
    type TcpStream = TcpStream;
    type TcpListener = TcpListener;
    #[cfg(unix)]
    type UnixStream = UnixStream;
    #[cfg(unix)]
    type UnixListener = UnixListener;
    type UdpSocket = UdpSocket;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        ::tokio::net::TcpStream::connect(addr)
            .await
            .map(readiness::Stream::new)
    }

    #[cfg(unix)]
    async fn connect_unix(&self, path: &std::path::Path) -> io::Result<UnixStream> {
        ::tokio::net::UnixStream::connect(path)
            .await
            .map(readiness::Stream::new)
    }

    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<TcpListener> {
        listener.set_nonblocking(true)?;
        ::tokio::net::TcpListener::from_std(listener).map(readiness::Listener::new)
    }

    #[cfg(unix)]
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<UnixListener> {
        listener.set_nonblocking(true)?;
        ::tokio::net::UnixListener::from_std(listener).map(readiness::Listener::new)
    }

    fn udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<UdpSocket> {
        socket.set_nonblocking(true)?;
        readiness::Datagram::new(::tokio::net::UdpSocket::from_std(socket)?)
    }
}

macro_rules! impl_ready {
    ($ty:ty) => {
        impl Ready for $ty {
            fn sock(&self) -> SockRef<'_> {
                SockRef::from(self)
            }

            fn read_io<R>(
                &self,
                mut op: impl FnMut(SockRef<'_>) -> io::Result<R>,
            ) -> impl Future<Output = io::Result<R>> {
                self.async_io(Interest::READABLE, move || op(SockRef::from(self)))
            }

            fn write_io<R>(
                &self,
                mut op: impl FnMut(SockRef<'_>) -> io::Result<R>,
            ) -> impl Future<Output = io::Result<R>> {
                self.async_io(Interest::WRITABLE, move || op(SockRef::from(self)))
            }
        }
    };
}

impl_ready!(::tokio::net::TcpStream);
impl_ready!(::tokio::net::UdpSocket);
#[cfg(unix)]
impl_ready!(::tokio::net::UnixStream);

readiness::impl_tcp_family!(::tokio::net::TcpStream);
#[cfg(unix)]
readiness::impl_unix_family!(::tokio::net::UnixStream);

impl Listener for TcpListener {
    type Stream = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, peer) = self.get_ref().accept().await?;
        Ok((readiness::Stream::new(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.get_ref().local_addr()
    }
}

#[cfg(unix)]
impl Listener for UnixListener {
    type Stream = UnixStream;
    type Addr = std::os::unix::net::SocketAddr;

    async fn accept(&self) -> io::Result<(UnixStream, Self::Addr)> {
        let (stream, peer) = self.get_ref().accept().await?;
        Ok((readiness::Stream::new(stream), peer.into()))
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.get_ref().local_addr().map(Into::into)
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
    type Poll = PollStream<::tokio::net::UnixStream>;

    fn into_poll(self) -> Self::Poll {
        PollStream(self.into_inner())
    }
}

/// tokio's stream behind `futures_io`'s traits: tokio reads into the
/// caller's buffer directly, so nothing is copied.
#[derive(Debug)]
pub struct PollStream<S = ::tokio::net::TcpStream>(S);

impl<S> PollStream<S> {
    /// tokio's stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S: ::tokio::io::AsyncRead + Unpin> futures_io::AsyncRead for PollStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut buf = ReadBuf::new(buf);
        ready!(Pin::new(&mut self.0).poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }
}

impl<S: ::tokio::io::AsyncWrite + Unpin> futures_io::AsyncWrite for PollStream<S> {
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
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
