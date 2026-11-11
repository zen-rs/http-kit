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
//! - [`ReadOwned`]: reads that lend the stream's own receive buffer (a ring
//!   buffer the kernel received into, on io_uring), and [`ReadAhead`] to stop
//!   a stream receiving ahead of its reader before the kernel takes the
//!   socket.
//! - [`StreamSocket`]: the bounds a connected stream carries for the protocol
//!   crates.
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
//! - [`IntoPoll`]: the poll-style `futures_io` capability for consumers that
//!   need one. An implementation that can offer it only through a copy says
//!   so in its type, [`CopyingPoll`].
//!
//! # Capabilities
//!
//! One implementation's ability to create sockets is split into one trait per
//! capability, so that code names only what it uses and a platform offers only
//! what it has:
//!
//! - [`Dial`] and [`DialUnix`] open stream connections.
//! - [`Listen`] and [`ListenUnix`] bind listeners.
//! - [`Datagram`] binds datagram sockets.
//! - [`FromStd`] and [`FromStdUnix`] adopt sockets the operating system
//!   created and the caller configured.
//! - [`Resolve`] turns a host name into addresses.
//!
//! Every method must be called on a thread where the implementation's runtime
//! is running.
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
pub mod resolve;
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
    resolve::{Answer, Family, Resolve},
    splice::{SpliceRead, SpliceWrite},
    stream::{
        Listener, NoBuf, Read, ReadAhead, ReadHalf, ReadOwned, Received, SendFile, Split,
        TcpOptions, Write, WriteHalf,
    },
    time::Timer,
};

#[cfg(unix)]
pub use crate::stream::WriteControl;

/// A connected stream socket: whole for a handshake, split for full-duplex
/// protocols.
///
/// It is the bound the protocol crates put on the halves of a stream, named
/// once. It is implemented for every type that meets it.
pub trait StreamSocket:
    ReadOwned
    + ReadAhead
    + Write
    + Split<ReadHalf: ReadOwned + ReadAhead + SpliceRead, WriteHalf: SendFile + SpliceWrite>
    + 'static
{
}

impl<S> StreamSocket for S where
    S: ReadOwned
        + ReadAhead
        + Write
        + Split<ReadHalf: ReadOwned + ReadAhead + SpliceRead, WriteHalf: SendFile + SpliceWrite>
        + 'static
{
}

/// Opens TCP connections.
pub trait Dial {
    /// A connected TCP stream.
    type Connection: StreamSocket + TcpOptions;

    /// Opens a connection to `addr`.
    fn connect(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Connection>>;
}

/// Opens Unix-domain stream connections.
#[cfg(unix)]
pub trait DialUnix {
    /// A connected Unix-domain stream socket.
    type UnixConnection: StreamSocket;

    /// Opens a connection to the Unix-domain socket at `path`.
    fn connect_unix(
        &self,
        path: &std::path::Path,
    ) -> impl Future<Output = io::Result<Self::UnixConnection>>;
}

/// Accepts TCP connections.
pub trait Listen {
    /// A listening TCP socket.
    type Listener: Listener<Addr = SocketAddr, Stream: StreamSocket + TcpOptions> + 'static;

    /// Binds and listens on `addr` with the platform's default options.
    ///
    /// # Errors
    ///
    /// Fails if the address cannot be bound.
    fn bind_tcp(&self, addr: SocketAddr) -> io::Result<Self::Listener>;
}

/// Accepts Unix-domain stream connections.
#[cfg(unix)]
pub trait ListenUnix {
    /// A listening Unix-domain socket.
    type UnixListener: Listener<Addr = std::os::unix::net::SocketAddr, Stream: StreamSocket>
        + 'static;

    /// Binds and listens on the Unix-domain socket at `path` with the
    /// platform's default options.
    ///
    /// # Errors
    ///
    /// Fails if the path cannot be bound.
    fn bind_unix(&self, path: &std::path::Path) -> io::Result<Self::UnixListener>;
}

/// Binds datagram sockets.
pub trait Datagram {
    /// A datagram socket.
    type UdpSocket: DatagramSocket + 'static;

    /// Binds a datagram socket to `addr` with the platform's default options.
    ///
    /// It is a future because a host may bind over a round trip.
    ///
    /// # Errors
    ///
    /// Fails if the address cannot be bound.
    fn bind_udp(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::UdpSocket>>;
}

/// Adopts sockets the operating system created and the caller configured
/// (`SO_REUSEPORT` for one listener per thread, a backlog, ...).
pub trait FromStd: Listen + Datagram {
    /// Adopts a bound, listening std socket.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be registered with the driver.
    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<Self::Listener>;

    /// Adopts a bound std datagram socket.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be registered with the driver.
    fn udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Self::UdpSocket>;
}

/// Adopts Unix-domain sockets the operating system created and the caller
/// configured.
#[cfg(unix)]
pub trait FromStdUnix: ListenUnix {
    /// Adopts a bound, listening std Unix-domain socket, as
    /// [`FromStd::tcp_listener`] adopts a TCP one.
    ///
    /// # Errors
    ///
    /// Fails if the socket cannot be registered with the driver.
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<Self::UnixListener>;
}
