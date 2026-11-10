//! The established connection and its halves.

use std::{borrow::Borrow, fmt, fs::File, future::Future, io};

use http_kit_io::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, Read, SendFile, Split, Write};
use rustls::{ProtocolVersion, SupportedCipherSuite};

use crate::{engine::Engine, side::Side, user};

/// Where a connection's records are encrypted and decrypted, settled once
/// when its handshake completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// rustls does it in user space; the transport carries ciphertext.
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

/// The reading half of a kernel TLS connection over `R`.
///
/// Only the halves of a socket have one; every other transport's is
/// [`Never`], so a connection over it cannot be in kernel mode.
#[doc(hidden)]
pub trait KernelRead<R, D: Side>: Sized {
    /// Whether this is the kernel half of a socket, so the kernel may take
    /// the connection it belongs to.
    const SOCKET: bool;

    /// Wraps a socket's reading half; reached only where [`SOCKET`](Self::SOCKET).
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn adopt(reader: crate::kernel::linux::Reader<R, D>) -> Self;

    fn get_ref(&self) -> &R;

    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
}

/// The writing half of a kernel TLS connection over `W`, as [`KernelRead`].
#[doc(hidden)]
pub trait KernelWrite<W, D: Side>: Sized {
    fn get_ref(&self) -> &W;

    fn write<B: IoBuf>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>>;

    fn write_vectored<B: IoVectoredBuf>(
        &mut self,
        buf: B,
    ) -> impl Future<Output = BufResult<usize, B>>;

    fn flush(&mut self) -> impl Future<Output = io::Result<()>>;

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>>;

    fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<usize, F>>;
}

/// The kernel half of a transport the kernel cannot encrypt for: no value
/// exists.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub enum Never {}

impl<R, D: Side> KernelRead<R, D> for Never {
    const SOCKET: bool = false;

    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn adopt(_reader: crate::kernel::linux::Reader<R, D>) -> Self {
        unreachable!("only a socket's reading half is adopted by the kernel")
    }

    fn get_ref(&self) -> &R {
        match *self {}
    }

    async fn read<B: IoBufMut>(&mut self, _buf: B) -> BufResult<usize, B> {
        match *self {}
    }
}

impl<W, D: Side> KernelWrite<W, D> for Never {
    fn get_ref(&self) -> &W {
        match *self {}
    }

    async fn write<B: IoBuf>(&mut self, _buf: B) -> BufResult<usize, B> {
        match *self {}
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, _buf: B) -> BufResult<usize, B> {
        match *self {}
    }

    async fn flush(&mut self) -> io::Result<()> {
        match *self {}
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match *self {}
    }

    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        _file: F,
        _offset: u64,
        _len: usize,
    ) -> BufResult<usize, F> {
        match *self {}
    }
}

/// The reading half of the stream TLS runs over.
///
/// Any [`Read`] is one. On Linux with the `kernel` feature, one that also
/// lends its descriptor ([`AsFd`](std::os::fd::AsFd): a socket) can hand its
/// records to the kernel; a half that does not, such as a
/// [`TlsReadHalf`], keeps them in user space. That is decided by the type,
/// through [`Kernel`](Self::Kernel), never by a check at run time.
pub trait TransportRead: Read + Sized + 'static {
    /// What a kernel TLS connection reads through: [`Never`] unless the
    /// kernel can encrypt for this half.
    #[doc(hidden)]
    type Kernel<D: Side>: KernelRead<Self, D>;
}

/// The writing half of the stream TLS runs over: [`TransportRead`]'s
/// counterpart. On Linux with the `kernel` feature a half that is a socket
/// (it writes control messages, which is how kernel TLS sends an alert or a
/// key update, and lends its descriptor for the socket options) can be
/// handed to the kernel; any other keeps TLS in user space.
pub trait TransportWrite: Write + SendFile + Sized + 'static {
    /// What a kernel TLS connection writes through: [`Never`] unless the
    /// kernel can encrypt for this half.
    #[doc(hidden)]
    type Kernel<D: Side>: KernelWrite<Self, D>;

    /// Settles where the records of a connection whose handshake completed
    /// are encrypted. User space, unless this is a socket's half whose
    /// reading half is a socket's too and the kernel takes the connection.
    #[doc(hidden)]
    fn secure<R: TransportRead, D: Side>(
        engine: Engine<D>,
        reader: R,
        writer: Self,
        #[cfg(feature = "kernel")] kernel: Option<&crate::KernelTls>,
    ) -> impl Future<Output = io::Result<(ReadInner<R, D>, WriteInner<Self, D>)>> {
        #[cfg(feature = "kernel")]
        let _ = kernel;
        secure_in_user_space(engine, reader, writer)
    }
}

#[cfg(not(all(target_os = "linux", feature = "kernel")))]
impl<R: Read + 'static> TransportRead for R {
    type Kernel<D: Side> = Never;
}

#[cfg(not(all(target_os = "linux", feature = "kernel")))]
impl<W: Write + SendFile + 'static> TransportWrite for W {
    type Kernel<D: Side> = Never;
}

#[cfg(all(target_os = "linux", feature = "kernel"))]
impl<R: Read + std::os::fd::AsFd + 'static> TransportRead for R {
    type Kernel<D: Side> = crate::kernel::linux::Reader<R, D>;
}

#[cfg(all(target_os = "linux", feature = "kernel"))]
impl<W: Write + SendFile + http_kit_io::WriteControl + std::os::fd::AsFd + 'static> TransportWrite
    for W
{
    type Kernel<D: Side> = crate::kernel::linux::Writer<W, D>;

    async fn secure<R: TransportRead, D: Side>(
        mut engine: Engine<D>,
        mut reader: R,
        mut writer: Self,
        kernel: Option<&crate::KernelTls>,
    ) -> io::Result<(ReadInner<R, D>, WriteInner<Self, D>)> {
        use crate::kernel::linux::{self, Switched};

        if let Some(kernel) = kernel.filter(|_| <R::Kernel<D> as KernelRead<R, D>>::SOCKET) {
            match linux::switch(engine, &mut reader, &mut writer, kernel).await? {
                Switched::Kernel(shared, carried) => {
                    let (read, write) = linux::split(shared, carried, (reader, writer));
                    return Ok((
                        ReadInner::Kernel(<R::Kernel<D> as KernelRead<R, D>>::adopt(read)),
                        WriteInner::Kernel(write),
                    ));
                }
                Switched::User(returned) => engine = returned,
            }
        }
        secure_in_user_space(engine, reader, writer).await
    }
}

/// A TLS connection's halves are user-space transports: nothing below them
/// is a socket the kernel could encrypt for, so a TLS session over another
/// stays in user space.
#[cfg(all(target_os = "linux", feature = "kernel"))]
impl<R: TransportRead, D: Side> TransportRead for TlsReadHalf<R, D> {
    type Kernel<E: Side> = Never;
}

#[cfg(all(target_os = "linux", feature = "kernel"))]
impl<W: TransportWrite, D: Side> TransportWrite for TlsWriteHalf<W, D> {
    type Kernel<E: Side> = Never;
}

/// A stream TLS runs over: every stream socket of `http-kit-io` is one, and
/// so is a [`TlsStream`], for a TLS session inside another (a tunnel
/// through an HTTPS proxy).
///
/// Whether the kernel can take the records is a property of the type: a
/// socket's can, where kernel TLS is built in, and a [`TlsStream`]'s never.
pub trait Transport: Split<ReadHalf: TransportRead, WriteHalf: TransportWrite> + 'static {
    /// Settles where the records of a connection whose handshake completed
    /// are encrypted: the kernel's, when this transport is a socket, a
    /// `kernel` probe is given and the kernel takes the connection;
    /// otherwise rustls's.
    #[doc(hidden)]
    fn secure<D: Side>(
        engine: Engine<D>,
        reader: Self::ReadHalf,
        writer: Self::WriteHalf,
        #[cfg(feature = "kernel")] kernel: Option<&crate::KernelTls>,
    ) -> impl Future<Output = io::Result<Secured<Self, D>>>;
}

/// The two halves of a connection, once it is settled where its records are
/// encrypted.
#[doc(hidden)]
pub type Secured<S, D> = (
    ReadInner<<S as Split>::ReadHalf, D>,
    WriteInner<<S as Split>::WriteHalf, D>,
);

/// Records encrypted in user space, over any transport.
async fn secure_in_user_space<R: TransportRead, W: TransportWrite, D: Side>(
    engine: Engine<D>,
    reader: R,
    writer: W,
) -> io::Result<(ReadInner<R, D>, WriteInner<W, D>)> {
    let (read, write) = user::split(engine, (reader, writer));
    Ok((ReadInner::User(read), WriteInner::User(write)))
}

impl<S: Split<ReadHalf: TransportRead, WriteHalf: TransportWrite> + 'static> Transport for S {
    async fn secure<D: Side>(
        engine: Engine<D>,
        reader: Self::ReadHalf,
        writer: Self::WriteHalf,
        #[cfg(feature = "kernel")] kernel: Option<&crate::KernelTls>,
    ) -> io::Result<Secured<Self, D>> {
        <Self::WriteHalf as TransportWrite>::secure(
            engine,
            reader,
            writer,
            #[cfg(feature = "kernel")]
            kernel,
        )
        .await
    }
}

/// The reading half's two possible forms.
#[doc(hidden)]
pub enum ReadInner<R: TransportRead, D: Side> {
    User(user::Reader<R, D>),
    Kernel(R::Kernel<D>),
}

/// The writing half's two possible forms.
#[doc(hidden)]
pub enum WriteInner<W: TransportWrite, D: Side> {
    User(user::Writer<W, D>),
    Kernel(W::Kernel<D>),
}

impl<R: TransportRead, D: Side> ReadInner<R, D> {
    pub(crate) const fn mode(&self) -> Mode {
        match self {
            Self::User(_) => Mode::User,
            Self::Kernel(_) => Mode::Kernel,
        }
    }
}

/// The reading half of a [`TlsStream`].
pub struct TlsReadHalf<R: TransportRead, D: Side>(pub(crate) ReadInner<R, D>);

/// The writing half of a [`TlsStream`].
pub struct TlsWriteHalf<W: TransportWrite, D: Side>(pub(crate) WriteInner<W, D>);

/// An established TLS connection over the stream `S`, on side `D`
/// ([`Server`](crate::Server) or [`Client`](crate::Client)).
///
/// It is a stream like the one under it ([`Read`], [`Write`], [`SendFile`],
/// [`Split`]), so an HTTP/1.1 connection runs over it unchanged, and so is
/// another TLS session: a `TlsStream` is itself a [`Transport`], in user
/// space.
pub struct TlsStream<S: Transport, D: Side> {
    pub(crate) read: TlsReadHalf<S::ReadHalf, D>,
    pub(crate) write: TlsWriteHalf<S::WriteHalf, D>,
    pub(crate) negotiated: Negotiated,
}

impl<S: Transport, D: Side> TlsStream<S, D> {
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

impl<R: TransportRead, D: Side> TlsReadHalf<R, D> {
    /// Where records are decrypted.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        self.0.mode()
    }

    /// The socket's reading half underneath.
    #[must_use]
    pub fn get_ref(&self) -> &R {
        match &self.0 {
            ReadInner::User(reader) => reader.get_ref(),
            ReadInner::Kernel(reader) => reader.get_ref(),
        }
    }
}

impl<W: TransportWrite, D: Side> TlsWriteHalf<W, D> {
    /// Where records are encrypted.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        match self.0 {
            WriteInner::User(_) => Mode::User,
            WriteInner::Kernel(_) => Mode::Kernel,
        }
    }

    /// The socket's writing half underneath.
    #[must_use]
    pub fn get_ref(&self) -> &W {
        match &self.0 {
            WriteInner::User(writer) => writer.get_ref(),
            WriteInner::Kernel(writer) => writer.get_ref(),
        }
    }
}

impl<R: TransportRead, D: Side> fmt::Debug for TlsReadHalf<R, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsReadHalf")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<W: TransportWrite, D: Side> fmt::Debug for TlsWriteHalf<W, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsWriteHalf")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<S: Transport, D: Side> fmt::Debug for TlsStream<S, D> {
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
            ReadInner::Kernel(reader) => reader.read(buf).await,
        }
    }
}

impl<W: TransportWrite, D: Side> Write for TlsWriteHalf<W, D> {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.write(buf).await,
            WriteInner::Kernel(writer) => writer.write(buf).await,
        }
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.write_vectored(buf).await,
            WriteInner::Kernel(writer) => writer.write_vectored(buf).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.flush().await,
            WriteInner::Kernel(writer) => writer.flush().await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match &mut self.0 {
            WriteInner::User(writer) => writer.shutdown().await,
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

impl<R: TransportRead, D: Side> fmt::Debug for ReadInner<R, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadInner")
            .field("mode", &self.mode())
            .finish_non_exhaustive()
    }
}

impl<W: TransportWrite, D: Side> fmt::Debug for WriteInner<W, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteInner").finish_non_exhaustive()
    }
}
