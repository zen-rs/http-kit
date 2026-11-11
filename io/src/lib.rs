//! Runtime-neutral, owned-buffer I/O.
//!
//! A completion-based driver (io_uring, IOCP) owns a buffer from the moment an
//! operation is submitted until it completes, so borrowed-buffer interfaces
//! such as `futures_io::AsyncRead` can be served there only through a copy.
//! Every operation in this crate therefore takes its buffer by value and hands
//! it back in a [`BufResult`], whatever the driver underneath. The buffer
//! traits are [`compio_buf`]'s: [`IoBuf`] for data to send, [`IoBufMut`] for
//! space to receive into, [`IoVectoredBuf`] for gathered writes.
//!
//! # Traits
//!
//! - [`Read`], [`Write`], [`Split`] and [`Listener`]: stream sockets.
//! - [`TcpOptions`]: socket options of a connected TCP stream.
//! - [`SendFile`]: file-to-socket transfer, through `sendfile`/`splice` where
//!   the platform has them.
//! - [`SpliceRead`] and [`SpliceWrite`]: socket-to-socket forwarding through
//!   a pipe, see [`splice`].
//! - `WriteControl` (Unix): a write carrying control messages, for
//!   protocols the kernel frames (kernel TLS record types).
//! - [`DatagramSocket`]: datagram sockets with segmentation offload (GSO) on
//!   send and receive coalescing (GRO).
//! - [`Timer`] for deadlines.
//! - [`Io`]: one implementation's family of sockets and timer, for code that
//!   creates its own.
//! - [`IntoPoll`]: the poll-style `futures_io` capability for consumers that
//!   need one. An implementation that can offer it only through a copy says
//!   so in its type, [`CopyingPoll`].
//!
//! No future or buffer is required to be `Send`: the intended deployment runs
//! one driver per thread and keeps each connection on the thread that
//! accepted it.
//!
//! # Implementations
//!
//! Each sits behind a feature of the same name:
//!
//! - `compio` ([`compio::Compio`]): io_uring on Linux, IOCP on Windows,
//!   polling elsewhere.
//! - `tokio` ([`tokio::Tokio`]) and `async-io` ([`async_io::AsyncIo`]):
//!   readiness reactors adapted to owned buffers. The kernel still reads into
//!   and writes from the caller's buffer directly; only the wait differs.

pub mod datagram;
pub mod poll;
pub mod splice;
pub mod stream;
pub mod time;

mod sys;

#[cfg(any(feature = "tokio", feature = "async-io"))]
pub mod readiness;

#[cfg(feature = "async-io")]
pub mod async_io;
#[cfg(feature = "compio")]
pub mod compio;
#[cfg(feature = "tokio")]
pub mod tokio;

use std::{future::Future, io, net::SocketAddr};

pub use compio_buf::{self, BufResult, IntoInner, IoBuf, IoBufMut, IoVectoredBuf, SetLen};

pub use crate::{
    datagram::{DatagramSocket, RecvMeta},
    poll::{CopyingPoll, IntoPoll},
    splice::{SpliceRead, SpliceWrite},
    stream::{Listener, Read, ReadHalf, SendFile, Split, TcpOptions, Write, WriteHalf},
    time::Timer,
};

#[cfg(unix)]
pub use crate::stream::WriteControl;

/// One I/O implementation: its stream and datagram sockets and its timer.
///
/// Code that only consumes sockets handed to it is generic over the socket
/// traits; code that opens its own (a client dialling out, a server binding
/// one listener per thread) is generic over `Io`. Every method must be called
/// on a thread where the implementation's runtime is running.
pub trait Io: Timer + Clone + 'static {
    /// A connected stream socket.
    type TcpStream: Read
        + Write
        + SendFile
        + SpliceRead
        + SpliceWrite
        + Split
        + IntoPoll
        + TcpOptions
        + 'static;
    /// A listening stream socket.
    type TcpListener: Listener<Stream = Self::TcpStream, Addr = SocketAddr> + 'static;
    /// A connected Unix-domain stream socket.
    #[cfg(unix)]
    type UnixStream: Read + Write + SendFile + SpliceRead + SpliceWrite + Split + IntoPoll + 'static;
    /// A listening Unix-domain stream socket.
    #[cfg(unix)]
    type UnixListener: Listener<Stream = Self::UnixStream, Addr = std::os::unix::net::SocketAddr>
        + 'static;
    /// A datagram socket.
    type UdpSocket: DatagramSocket + 'static;

    /// Opens a stream connection to `addr`.
    fn connect(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::TcpStream>>;

    /// Opens a stream connection to the Unix-domain socket at `path`.
    #[cfg(unix)]
    fn connect_unix(
        &self,
        path: &std::path::Path,
    ) -> impl Future<Output = io::Result<Self::UnixStream>>;

    /// Adopts a bound, listening std socket, configured however the caller
    /// needs (`SO_REUSEPORT` for one listener per thread, a backlog, ...).
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be registered with the driver.
    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<Self::TcpListener>;

    /// Adopts a bound, listening std Unix-domain socket, as
    /// [`tcp_listener`](Self::tcp_listener) adopts a TCP one.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be registered with the driver.
    #[cfg(unix)]
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<Self::UnixListener>;

    /// Adopts a bound std datagram socket.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be registered with the driver.
    fn udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Self::UdpSocket>;

    /// Binds a listener to `addr` with the platform's default options.
    ///
    /// # Errors
    ///
    /// Fails if the address cannot be bound.
    fn bind_tcp(&self, addr: SocketAddr) -> io::Result<Self::TcpListener> {
        self.tcp_listener(std::net::TcpListener::bind(addr)?)
    }

    /// Binds a datagram socket to `addr` with the platform's default options.
    ///
    /// # Errors
    ///
    /// Fails if the address cannot be bound.
    fn bind_udp(&self, addr: SocketAddr) -> io::Result<Self::UdpSocket> {
        self.udp_socket(std::net::UdpSocket::bind(addr)?)
    }
}
