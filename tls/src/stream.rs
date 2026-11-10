//! The established connection and its halves.

use std::{borrow::Borrow, fmt, fs::File, io};

use http_kit_io::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, Read, SendFile, Split, Write};
use rustls::{ProtocolVersion, SupportedCipherSuite};

use crate::{side::Side, user};

/// Where a connection's records are encrypted and decrypted, settled once
/// when its handshake completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// rustls does it in user space; the socket carries ciphertext.
    User,
    /// The kernel does it (Linux kernel TLS): the socket reads and writes
    /// plaintext, and file regions go out through `sendfile`/`splice`
    /// without entering user space.
    Kernel,
}

/// What the handshake settled.
#[derive(Debug, Clone)]
pub struct Negotiated {
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) version: ProtocolVersion,
    pub(crate) suite: SupportedCipherSuite,
    pub(crate) mode: Mode,
}

impl Negotiated {
    pub(crate) fn of<D: Side>(conn: &D::Connection) -> Self {
        Self {
            alpn: conn.alpn_protocol().map(<[u8]>::to_vec),
            version: conn
                .protocol_version()
                .expect("a completed handshake has a version"),
            suite: conn
                .negotiated_cipher_suite()
                .expect("a completed handshake has a cipher suite"),
            mode: Mode::User,
        }
    }

    /// The application protocol ALPN chose, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// The protocol version.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.version
    }

    /// The cipher suite.
    #[must_use]
    pub const fn cipher_suite(&self) -> SupportedCipherSuite {
        self.suite
    }

    /// Where records are encrypted and decrypted.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.mode
    }
}

/// The reading half of the stream TLS runs over. On Unix it lends its
/// descriptor, where kernel TLS hands over records other than data.
#[cfg(unix)]
pub trait TransportRead: Read + std::os::fd::AsFd + 'static {}
#[cfg(unix)]
impl<R: Read + std::os::fd::AsFd + 'static> TransportRead for R {}
/// The reading half of the stream TLS runs over.
#[cfg(not(unix))]
pub trait TransportRead: Read + 'static {}
#[cfg(not(unix))]
impl<R: Read + 'static> TransportRead for R {}

/// The writing half of the stream TLS runs over. On Unix it also writes
/// control messages, which is how kernel TLS sends an alert or a key update,
/// and lends its descriptor for the kernel TLS socket options.
#[cfg(unix)]
pub trait TransportWrite:
    Write + SendFile + http_kit_io::WriteControl + std::os::fd::AsFd + 'static
{
}
#[cfg(unix)]
impl<W: Write + SendFile + http_kit_io::WriteControl + std::os::fd::AsFd + 'static> TransportWrite
    for W
{
}
/// The writing half of the stream TLS runs over.
#[cfg(not(unix))]
pub trait TransportWrite: Write + SendFile + 'static {}
#[cfg(not(unix))]
impl<W: Write + SendFile + 'static> TransportWrite for W {}

/// A stream TLS runs over: every stream socket of `http-kit-io` is one.
pub trait Transport: Split<ReadHalf: TransportRead, WriteHalf: TransportWrite> + 'static {}
impl<S: Split<ReadHalf: TransportRead, WriteHalf: TransportWrite> + 'static> Transport for S {}

pub(crate) enum ReadInner<R, D: Side> {
    User(user::Reader<R, D>),
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    Kernel(crate::kernel::linux::Reader<R, D>),
}

pub(crate) enum WriteInner<W, D: Side> {
    User(user::Writer<W, D>),
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    Kernel(crate::kernel::linux::Writer<W, D>),
}

/// The reading half of a [`TlsStream`].
pub struct TlsReadHalf<R, D: Side>(pub(crate) ReadInner<R, D>);

/// The writing half of a [`TlsStream`].
pub struct TlsWriteHalf<W, D: Side>(pub(crate) WriteInner<W, D>);

/// An established TLS connection over the stream `S`, on side `D`
/// ([`Server`](crate::Server) or [`Client`](crate::Client)).
///
/// It is a stream like the one under it ([`Read`], [`Write`], [`SendFile`],
/// [`Split`]), so an HTTP/1.1 connection runs over it unchanged.
pub struct TlsStream<S: Split, D: Side> {
    pub(crate) read: TlsReadHalf<S::ReadHalf, D>,
    pub(crate) write: TlsWriteHalf<S::WriteHalf, D>,
    pub(crate) negotiated: Negotiated,
}

impl<S: Split, D: Side> TlsStream<S, D> {
    /// What the handshake settled: ALPN, version, cipher suite and
    /// [`Mode`].
    #[must_use]
    pub const fn negotiated(&self) -> &Negotiated {
        &self.negotiated
    }

    /// The application protocol ALPN chose, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.negotiated.alpn_protocol()
    }

    /// Where records are encrypted and decrypted.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.negotiated.mode
    }
}

impl<R, D: Side> TlsReadHalf<R, D> {
    /// Where records are decrypted.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        match self.0 {
            ReadInner::User(_) => Mode::User,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            ReadInner::Kernel(_) => Mode::Kernel,
        }
    }

    /// The socket's reading half underneath.
    #[must_use]
    pub const fn get_ref(&self) -> &R {
        match &self.0 {
            ReadInner::User(reader) => reader.get_ref(),
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            ReadInner::Kernel(reader) => reader.get_ref(),
        }
    }
}

impl<W, D: Side> TlsWriteHalf<W, D> {
    /// Where records are encrypted.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        match self.0 {
            WriteInner::User(_) => Mode::User,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(_) => Mode::Kernel,
        }
    }

    /// The socket's writing half underneath.
    #[must_use]
    pub const fn get_ref(&self) -> &W {
        match &self.0 {
            WriteInner::User(writer) => writer.get_ref(),
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(writer) => writer.get_ref(),
        }
    }
}

impl<R, D: Side> fmt::Debug for TlsReadHalf<R, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsReadHalf")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<W, D: Side> fmt::Debug for TlsWriteHalf<W, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsWriteHalf")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<S: Split, D: Side> fmt::Debug for TlsStream<S, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("negotiated", &self.negotiated)
            .finish_non_exhaustive()
    }
}

impl<R: TransportRead, D: Side> Read for TlsReadHalf<R, D> {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            ReadInner::User(reader) => reader.read(buf).await,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            ReadInner::Kernel(reader) => reader.read(buf).await,
        }
    }
}

impl<W: TransportWrite, D: Side> Write for TlsWriteHalf<W, D> {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.write(buf).await,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(writer) => writer.write(buf).await,
        }
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.write_vectored(buf).await,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(writer) => writer.write_vectored(buf).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.flush().await,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(writer) => writer.flush().await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.shutdown().await,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(writer) => writer.shutdown().await,
        }
    }
}

impl<W: TransportWrite, D: Side> SendFile for TlsWriteHalf<W, D> {
    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.send_file(file, offset, len).await,
            #[cfg(all(target_os = "linux", feature = "kernel"))]
            WriteInner::Kernel(writer) => writer.send_file(file, offset, len).await,
        }
    }
}

impl<S: Transport, D: Side> Read for TlsStream<S, D> {
    fn read<B: IoBufMut>(
        &mut self,
        buf: B,
    ) -> impl std::future::Future<Output = BufResult<usize, B>> {
        self.read.read(buf)
    }
}

impl<S: Transport, D: Side> Write for TlsStream<S, D> {
    fn write<B: IoBuf>(
        &mut self,
        buf: B,
    ) -> impl std::future::Future<Output = BufResult<usize, B>> {
        self.write.write(buf)
    }

    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl std::future::Future<Output = BufResult<usize, B>> {
        self.write.write_vectored(buf)
    }

    fn flush(&mut self) -> impl std::future::Future<Output = io::Result<()>> {
        self.write.flush()
    }

    fn shutdown(&mut self) -> impl std::future::Future<Output = io::Result<()>> {
        self.write.shutdown()
    }
}

impl<S: Transport, D: Side> SendFile for TlsStream<S, D> {
    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl std::future::Future<Output = BufResult<usize, F>> {
        self.write.send_file(file, offset, len)
    }
}

impl<S: Transport, D: Side> Split for TlsStream<S, D> {
    type ReadHalf = TlsReadHalf<S::ReadHalf, D>;
    type WriteHalf = TlsWriteHalf<S::WriteHalf, D>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        (self.read, self.write)
    }
}
