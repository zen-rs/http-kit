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
//! On Linux over io_uring a stream receives with a multishot receive into
//! the provided buffer ring of the thread's runtime: one submission stays
//! armed and completes once per arrival, each into a ring buffer, until the
//! kernel ends it. A reader takes the received bytes in the ring through
//! [`ReadOwned`](crate::ReadOwned), or has them copied into its own buffer
//! through [`Read`](crate::Read); either way they are released as soon as
//! they are consumed, so an idle connection holds none of the ring. When the ring has
//! no free buffer a read receives into the caller's buffer with a submission
//! of its own, and the next one arms again. A splice from the socket first
//! moves what the ring already received, so it never passes those bytes.
//!
//! The ring is compio's buffer pool, one per runtime: size it on the
//! runtime's `ProactorBuilder` (`buffer_pool_size`, `buffer_pool_buffer_len`)
//! for the connections one thread serves, and have the kernel consume its
//! buffers incrementally with `buffer_pool_flag(IOU_PBUF_RING_INC)`. On Linux
//! 6.12 and later a completion then fills only as much of a buffer as it
//! received and marks the buffer `IORING_CQE_F_BUF_MORE` while it keeps it;
//! the next completion, of this connection or another on the thread,
//! continues in it, so small reads share a buffer instead of taking one each.
//! A buffer goes back to the ring once the kernel has finished with it and
//! every read lent out of it is released. An earlier kernel rejects the flag
//! when the ring registers, and compio then registers the ring without it:
//! buffers are consumed whole, one per completion.
//!
//! On Linux over io_uring a TCP stream's
//! [`write_all_owned`](crate::Write::write_all_owned) of at least
//! [`ZeroCopySend::threshold`] bytes sends without copying
//! (`IORING_OP_SENDMSG_ZC`): the kernel reads the bytes from the caller's
//! buffers until the peer acknowledges them. The write returns as soon as
//! the kernel has taken every byte; the stream keeps the buffers until the
//! kernel's notification says it no longer reads them, and drops them then.
//! What the kernel holds this way is bounded like any other unacknowledged
//! data, by the socket's send buffer, which counts zero-copy pages too.
//! Smaller writes, the other write methods, Unix-domain streams (which the
//! kernel does not send zero-copy) and every other platform copy.
//!
//! On Linux over io_uring each stream's socket takes a slot in its ring's
//! file table, and every operation on the stream (receives, multishot ones
//! included, sends, zero-copy ones included, polls, shutdown) names the
//! socket by that slot (`IOSQE_FIXED_FILE`): the kernel then neither looks
//! the descriptor up nor takes a reference to its file per operation. The
//! stream keeps its descriptor for what is not an io_uring operation (kernel
//! TLS options, addresses, `splice(2)`). The slot is taken on the side as the
//! stream is created, so the first operations may still use the descriptor,
//! and is given back once the stream is dropped. A ring registers its table,
//! [`FileTable::slots`] slots large, when its first stream asks for a slot;
//! a socket the table has no room for, or a kernel that cannot allocate
//! slots (before 5.19), leaves the stream on its descriptor. The ring's
//! table belongs to these streams: nothing else on the runtime may use it.
//!
//! On Linux over io_uring a ring may register a region of memory as its
//! one registered buffer ([`Compio::register_fixed_region`], sized by
//! [`FixedBuffers`]), which the kernel pins once. A zero-copy write whose
//! slices lie in the region goes out from it (`IORING_RECVSEND_FIXED_BUF`),
//! with none of its pages pinned or charged to `RLIMIT_MEMLOCK` per send;
//! slices outside it, fewer than [`ZeroCopySend::threshold`] bytes in all (a
//! head, chunk framing), are copied into the region beside them. A write of
//! several slices needs Linux 6.15, which the ring probes for when it
//! registers; a write the region cannot take (no slice in it, too much
//! outside it, no room, an older kernel) is sent zero-copy as before. Bytes
//! reach the region by being read into it (`FixedRegion::read_at`) or
//! written into a span of it (`FixedRegion::alloc`).
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

#[cfg(not(target_os = "linux"))]
use ::compio::io::{AsyncRead, AsyncWrite};
use ::compio::net;
use compio_buf::{BufResult, IoBuf, IoBufMut, IoVectoredBuf};

use crate::{
    Datagram, Dial, FromStd, Listen,
    datagram::{DatagramSocket, RecvMeta, send_batched},
    poll::{CopyingPoll, IntoPoll},
    stream::{Listener, TcpOptions, impl_stream, sealed::SharedStream},
    time::Timer,
};
#[cfg(unix)]
use crate::{DialUnix, FromStdUnix, ListenUnix};

#[cfg(target_os = "linux")]
mod fixed;
#[cfg(target_os = "linux")]
pub use fixed::{FixedBufMut, FixedRegion};

/// The compio implementation. compio keeps its runtime per thread, and every
/// operation goes to the current thread's; this holds the operator's
/// settings, [`ZeroCopySend`], [`FileTable`] and [`FixedBuffers`], which every
/// stream it creates or adopts shares, and its [`Scope`]: [`Shared`], the
/// settings alone, which any thread may hold, or [`Ring`], what one ring
/// registered for its streams, which stays on the ring's thread.
#[derive(Debug, Clone)]
pub struct Compio<R = Shared> {
    zero_copy: ZeroCopySend,
    file_table: FileTable,
    fixed_buffers: FixedBuffers,
    #[cfg_attr(
        not(target_os = "linux"),
        expect(
            dead_code,
            reason = "only Linux registers anything for a ring; elsewhere the scope is the type alone"
        )
    )]
    scope: R,
}

/// What a [`Compio`] carries beside the settings: [`Shared`] or [`Ring`].
pub trait Scope: sealed::Scope + Clone + fmt::Debug + 'static {}

mod sealed {
    pub trait Scope {
        /// The region of registered buffers of the current ring, which a
        /// stream sends from.
        #[cfg(target_os = "linux")]
        fn fixed_region(&self) -> Option<&super::FixedRegion>;
    }
}

/// The settings alone: a [`Compio`] any thread may hold.
#[derive(Debug, Clone, Copy, Default)]
pub struct Shared;

impl Scope for Shared {}

impl sealed::Scope for Shared {
    #[cfg(target_os = "linux")]
    fn fixed_region(&self) -> Option<&FixedRegion> {
        None
    }
}

/// What one ring registered for its streams, beside the settings:
/// [`Compio::register_fixed_region`] makes it on the ring's thread, and it
/// stays there (it is neither `Send` nor `Sync`), so a stream it creates can
/// only be on that thread.
///
/// It must be used while its ring's runtime lives, and inside it: a stream
/// made from it on another ring is a contract violation.
#[derive(Debug, Clone)]
pub struct Ring {
    #[cfg(target_os = "linux")]
    region: Option<FixedRegion>,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Scope for Ring {}

impl sealed::Scope for Ring {
    #[cfg(target_os = "linux")]
    fn fixed_region(&self) -> Option<&FixedRegion> {
        self.region.as_ref()
    }
}

impl Default for Compio {
    fn default() -> Self {
        Self {
            zero_copy: ZeroCopySend::default(),
            file_table: FileTable::default(),
            fixed_buffers: FixedBuffers::default(),
            scope: Shared,
        }
    }
}

impl Compio {
    /// Registers the current thread's ring's region, [`FixedBuffers::bytes`]
    /// large, and returns this implementation for the ring, carrying it: its
    /// streams then send zero-copy writes from the region when their bytes
    /// lie in it, and [`fixed_region`](Compio::fixed_region) hands the region
    /// out to fill.
    ///
    /// Call it once per ring, inside the ring's runtime. Without a region to
    /// register (a size of `0`, a runtime on polling, a platform other than
    /// Linux) the ring carries none.
    ///
    /// # Errors
    ///
    /// Fails if the region cannot be mapped or the kernel refuses to register
    /// it: over `RLIMIT_MEMLOCK`, or on a ring that already has registered
    /// buffers.
    pub async fn register_fixed_region(&self) -> io::Result<Compio<Ring>> {
        let scope = Ring {
            #[cfg(target_os = "linux")]
            region: FixedRegion::register(self.fixed_buffers.bytes()).await?,
            _thread: std::marker::PhantomData,
        };
        Ok(Compio {
            zero_copy: self.zero_copy.clone(),
            file_table: self.file_table.clone(),
            fixed_buffers: self.fixed_buffers.clone(),
            scope,
        })
    }
}

impl Compio<Ring> {
    /// The region of registered buffers the ring registered, if it registered
    /// one.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub const fn fixed_region(&self) -> Option<&FixedRegion> {
        self.scope.region.as_ref()
    }

    /// The settings alone, for another thread.
    #[must_use]
    pub fn shared(&self) -> Compio {
        Compio {
            zero_copy: self.zero_copy.clone(),
            file_table: self.file_table.clone(),
            fixed_buffers: self.fixed_buffers.clone(),
            scope: Shared,
        }
    }
}

impl<R: Scope> Compio<R> {
    /// This implementation with its rings' regions of registered buffers
    /// sized as `fixed_buffers` says.
    #[must_use]
    pub fn with_fixed_buffers(self, fixed_buffers: FixedBuffers) -> Self {
        Self {
            fixed_buffers,
            ..self
        }
    }

    /// The registered-buffer setting its rings share.
    #[must_use]
    pub const fn fixed_buffers(&self) -> &FixedBuffers {
        &self.fixed_buffers
    }

    /// This implementation with its streams sending zero-copy as `zero_copy`
    /// says.
    #[must_use]
    pub fn with_zero_copy(self, zero_copy: ZeroCopySend) -> Self {
        Self { zero_copy, ..self }
    }

    /// This implementation with its rings' file tables sized as `file_table`
    /// says.
    #[must_use]
    pub fn with_file_table(self, file_table: FileTable) -> Self {
        Self { file_table, ..self }
    }

    /// The zero-copy setting its streams share.
    #[must_use]
    pub const fn zero_copy(&self) -> &ZeroCopySend {
        &self.zero_copy
    }

    /// The file-table setting its streams share.
    #[must_use]
    pub const fn file_table(&self) -> &FileTable {
        &self.file_table
    }

    /// Adopts a connected compio stream: one a runtime of this thread
    /// registered, such as a socket accepted elsewhere and handed over as a
    /// std stream (on Windows a socket joins one completion port only, so a
    /// thread-per-core server accepts where no port is involved and each
    /// thread adopts its share).
    #[must_use]
    pub fn tcp_stream(&self, stream: net::TcpStream) -> TcpStream {
        TcpStream::new(stream, self)
    }
}

/// How many sockets a ring's file table holds, on Linux over io_uring: each
/// stream takes a slot while it lives, and a stream the table has no room
/// for uses its descriptor.
///
/// It is the operator's runtime-adjustable handle: every clone shares one
/// value, across threads. A ring sizes its table once, when its first stream
/// asks for a slot (the kernel cannot resize a table holding sockets), so a
/// change sizes the tables of rings that register theirs afterwards. `0`
/// stops streams created afterwards from taking slots at all, on every ring.
///
/// The kernel refuses a table larger than the process's `RLIMIT_NOFILE`
/// (`io_sqe_files_register`); the streams of a ring whose table was refused
/// report that error.
#[derive(Debug, Clone)]
pub struct FileTable {
    slots: std::sync::Arc<std::sync::atomic::AtomicU32>,
}

impl FileTable {
    /// The default size: the kernel's default soft `RLIMIT_NOFILE`
    /// (`INR_OPEN_CUR`, `include/uapi/linux/fs.h`), the largest table a
    /// process that has not raised its limit may register.
    pub const DEFAULT_SLOTS: u32 = 1024;

    /// A setting of `slots` slots.
    #[must_use]
    pub fn new(slots: u32) -> Self {
        Self {
            slots: std::sync::Arc::new(std::sync::atomic::AtomicU32::new(slots)),
        }
    }

    /// The slots a ring registers its table with.
    #[must_use]
    pub fn slots(&self) -> u32 {
        self.slots.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sets the size for every clone of this setting.
    pub fn set_slots(&self, slots: u32) {
        self.slots
            .store(slots, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for FileTable {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SLOTS)
    }
}

/// When a write goes out through io_uring's zero-copy send: from
/// [`threshold`](Self::threshold) bytes up, on Linux.
///
/// It is the operator's runtime-adjustable handle: every clone shares one
/// value, across threads, and a change applies to the next write of every
/// stream holding a clone. A threshold of `0` sends every such write
/// zero-copy; `usize::MAX` none.
///
/// A zero-copy send pins the pages it sends until the peer acknowledges
/// them, and io_uring charges them to the user's `RLIMIT_MEMLOCK` unless the
/// process has `CAP_IPC_LOCK` (`io_notif_account_mem`). When that limit is
/// reached the kernel refuses the send before sending anything, and the write
/// copies instead.
#[derive(Debug, Clone)]
pub struct ZeroCopySend {
    threshold: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ZeroCopySend {
    /// The default threshold. The kernel's `MSG_ZEROCOPY` documentation
    /// (`Documentation/networking/msg_zerocopy.rst`) finds pinning pages and
    /// waiting for the notification "generally only effective at writes over
    /// around 10 KB".
    pub const DEFAULT_THRESHOLD: usize = 10 * 1024;

    /// A setting with `threshold`.
    #[must_use]
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(threshold)),
        }
    }

    /// The fewest bytes a write sends zero-copy.
    #[must_use]
    pub fn threshold(&self) -> usize {
        self.threshold.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sets the threshold for every clone of this setting.
    pub fn set_threshold(&self, threshold: usize) {
        self.threshold
            .store(threshold, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for ZeroCopySend {
    fn default() -> Self {
        Self::new(Self::DEFAULT_THRESHOLD)
    }
}

/// How large a ring's region of registered buffers is, on Linux over
/// io_uring: the memory [`Compio::register_fixed_region`] maps and registers
/// for a thread's ring, which its `FixedRegion` hands out.
///
/// It is the operator's runtime-adjustable handle: every clone shares one
/// value, across threads. A ring registers its region once, so a change sizes
/// the regions registered afterwards. `0`, the default, registers none.
///
/// The kernel pins the whole region when it registers it and charges it to
/// the user's `RLIMIT_MEMLOCK` unless the process has `CAP_IPC_LOCK`
/// (`io_buffer_account_pin`), so a region larger than the limit allows is
/// refused, and the error names its size. In exchange a zero-copy send from
/// it is charged nothing and pins nothing per send.
#[derive(Debug, Clone, Default)]
pub struct FixedBuffers {
    bytes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl FixedBuffers {
    /// A setting of regions of `bytes` bytes.
    #[must_use]
    pub fn new(bytes: usize) -> Self {
        Self {
            bytes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(bytes)),
        }
    }

    /// The bytes a ring's region is registered with.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Sets the size for every clone of this setting.
    pub fn set_bytes(&self, bytes: usize) {
        self.bytes
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
    }
}

impl<R: Scope> Timer for Compio<R> {
    fn sleep_until(&self, deadline: Instant) -> impl Future<Output = ()> {
        ::compio::time::sleep_until(deadline)
    }
}

impl<R: Scope> Dial for Compio<R> {
    type Connection = TcpStream;

    async fn connect(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        let stream = net::TcpStream::connect(addr).await?;
        Ok(self.tcp_stream(stream))
    }
}

#[cfg(unix)]
impl<R: Scope> DialUnix for Compio<R> {
    type UnixConnection = UnixStream;

    async fn connect_unix(&self, path: &std::path::Path) -> io::Result<UnixStream> {
        let stream = net::UnixStream::connect(path).await?;
        Ok(UnixStream::new(stream, self))
    }
}

impl<R: Scope> Listen for Compio<R> {
    type Listener = TcpListener<R>;

    fn bind_tcp(&self, addr: SocketAddr) -> io::Result<TcpListener<R>> {
        self.tcp_listener(std::net::TcpListener::bind(addr)?)
    }
}

#[cfg(unix)]
impl<R: Scope> ListenUnix for Compio<R> {
    type UnixListener = UnixListener<R>;

    fn bind_unix(&self, path: &std::path::Path) -> io::Result<UnixListener<R>> {
        self.unix_listener(std::os::unix::net::UnixListener::bind(path)?)
    }
}

impl<R: Scope> Datagram for Compio<R> {
    type UdpSocket = UdpSocket;

    async fn bind_udp(&self, addr: SocketAddr) -> io::Result<UdpSocket> {
        self.udp_socket(std::net::UdpSocket::bind(addr)?)
    }
}

#[cfg(unix)]
impl<R: Scope> FromStdUnix for Compio<R> {
    fn unix_listener(
        &self,
        listener: std::os::unix::net::UnixListener,
    ) -> io::Result<UnixListener<R>> {
        let listener = net::UnixListener::from_std(listener)?;
        Ok(UnixListener::new(listener, self.clone()))
    }
}

impl<R: Scope> FromStd for Compio<R> {
    fn tcp_listener(&self, listener: std::net::TcpListener) -> io::Result<TcpListener<R>> {
        let listener = net::TcpListener::from_std(listener)?;
        Ok(TcpListener::new(listener, self.clone()))
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

/// A stream socket of compio's. On Linux the stream submits compio's
/// operations on it itself, so that they name the socket by its slot in the
/// ring's file table; elsewhere compio's stream drives them, through a
/// shared reference.
trait Socket: Clone + Fd + 'static {
    /// Whether the kernel sends from this socket zero-copy: it sets
    /// `SOCK_SUPPORT_ZC`, which io_uring's zero-copy send requires, on TCP
    /// sockets only (`tcp_init_sock`).
    #[cfg(target_os = "linux")]
    const ZERO_COPY: bool;
    /// The descriptor, shared with an operation that outlives a call.
    #[cfg(target_os = "linux")]
    fn shared_fd(&self) -> ::compio::driver::SharedFd<socket2::Socket>;
    #[cfg(not(target_os = "linux"))]
    fn read<B: IoBufMut>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
    #[cfg(not(target_os = "linux"))]
    fn write<B: IoBuf>(&self, buf: B) -> impl Future<Output = BufResult<usize, B>>;
    #[cfg(not(target_os = "linux"))]
    fn write_vectored<B: IoVectoredBuf>(&self, buf: B)
    -> impl Future<Output = BufResult<usize, B>>;
    #[cfg(not(target_os = "linux"))]
    fn shutdown(&self) -> impl Future<Output = io::Result<()>>;
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
    ($ty:ty, zero_copy: $zero_copy:literal) => {
        impl Socket for $ty {
            #[cfg(target_os = "linux")]
            const ZERO_COPY: bool = $zero_copy;

            #[cfg(target_os = "linux")]
            fn shared_fd(&self) -> ::compio::driver::SharedFd<socket2::Socket> {
                ::compio::driver::ToSharedFd::to_shared_fd(self)
            }

            #[cfg(not(target_os = "linux"))]
            async fn read<B: IoBufMut>(&self, buf: B) -> BufResult<usize, B> {
                let mut stream = self;
                AsyncRead::read(&mut stream, buf).await
            }

            #[cfg(not(target_os = "linux"))]
            async fn write<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
                let mut stream = self;
                AsyncWrite::write(&mut stream, buf).await
            }

            #[cfg(not(target_os = "linux"))]
            async fn write_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
                let mut stream = self;
                AsyncWrite::write_vectored(&mut stream, buf).await
            }

            #[cfg(not(target_os = "linux"))]
            async fn shutdown(&self) -> io::Result<()> {
                let mut stream = self;
                AsyncWrite::shutdown(&mut stream).await
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

impl_socket!(net::TcpStream, zero_copy: true);
#[cfg(unix)]
impl_socket!(net::UnixStream, zero_copy: false);

/// A connected stream socket.
pub struct Stream<S> {
    inner: S,
    /// The socket `inner`'s descriptor names, which every use of the
    /// descriptor's number checks it still does (debug builds).
    #[cfg(all(unix, debug_assertions))]
    identity: crate::sys::unix::Identity,
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
    /// The multishot receive and what it received ahead of the reader.
    #[cfg(target_os = "linux")]
    recv: recv::Recv,
    /// From what size a write sends zero-copy.
    #[cfg(target_os = "linux")]
    zero_copy: ZeroCopySend,
    /// The socket's slot in the ring's file table, which every operation
    /// names it by once it has one.
    #[cfg(target_os = "linux")]
    file: files::File,
    /// The last receive of its own found the socket empty: the next one waits
    /// for data before trying (`IORING_RECVSEND_POLL_FIRST`), as compio's
    /// stream does.
    #[cfg(target_os = "linux")]
    recv_empty: std::cell::Cell<bool>,
    /// The region of registered buffers of the stream's ring, which a
    /// zero-copy write whose bytes lie in it is sent from.
    #[cfg(target_os = "linux")]
    fixed: Option<FixedRegion>,
}

#[expect(
    private_bounds,
    reason = "every method is private: only this module creates and drives a stream"
)]
impl<S: Socket> Stream<S> {
    fn new<R: Scope>(inner: S, io: &Compio<R>) -> Self {
        // Only Linux sends zero-copy and registers files.
        #[cfg(not(target_os = "linux"))]
        let _ = io;
        Self {
            #[cfg(all(unix, debug_assertions))]
            identity: crate::sys::unix::Identity::of(std::os::fd::AsRawFd::as_raw_fd(
                &inner.as_fd(),
            ))
            .expect("a stream's socket is open when the stream is made"),
            #[cfg(target_os = "linux")]
            file: files::File::new(inner.shared_fd(), io.file_table()),
            inner,
            #[cfg(any(target_os = "linux", target_os = "android"))]
            pipe: std::cell::Cell::new(None),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            nonblocking: std::cell::Cell::new(false),
            #[cfg(target_os = "linux")]
            recv: recv::Recv::default(),
            #[cfg(target_os = "linux")]
            zero_copy: io.zero_copy.clone(),
            #[cfg(target_os = "linux")]
            recv_empty: std::cell::Cell::new(false),
            #[cfg(target_os = "linux")]
            fixed: sealed::Scope::fixed_region(&io.scope).and_then(FixedRegion::for_stream),
        }
    }

    /// Submits `op`, which operates on this socket: on Linux by the socket's
    /// slot in the file table when it has one.
    #[cfg(unix)]
    async fn submit<T: ::compio::driver::OpCode + 'static>(&self, op: T) -> BufResult<usize, T> {
        #[cfg(target_os = "linux")]
        {
            self.file.submit(op).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.fd();
            ::compio::runtime::submit(op).await
        }
    }

    /// The socket's descriptor, for a call that names it by its number.
    ///
    /// Debug builds check first that the number still names the stream's
    /// socket, and panic if it does not (zen-rs/http-kit#159).
    #[cfg(unix)]
    #[track_caller]
    fn fd(&self) -> std::os::fd::BorrowedFd<'_> {
        let fd = self.inner.as_fd();
        #[cfg(debug_assertions)]
        self.identity.check(std::os::fd::AsRawFd::as_raw_fd(&fd));
        fd
    }
}

impl<S> Stream<S> {
    /// compio's stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.inner
    }
}

/// The socket operations, which compio's stream would submit with the
/// descriptor.
#[cfg(target_os = "linux")]
#[expect(
    private_bounds,
    reason = "every method is private: only this module drives a stream"
)]
impl<S: Socket> Stream<S> {
    async fn recv<B: IoBufMut>(&self, mut buf: B) -> BufResult<usize, B> {
        use ::compio::driver::{
            PollFirst as _,
            op::{Recv, RecvFlags},
        };
        use compio_buf::IntoInner as _;

        // compio writes from the start but only ever grows the length; the
        // contract is a length of exactly what was read.
        buf.clear();
        let mut op = Recv::new(self.inner.shared_fd(), buf, RecvFlags::empty());
        if self.recv_empty.get() {
            op.poll_first();
        }
        let (BufResult(res, op), extra) = self.file.submit_with_extra(op).await;
        if let Some(Ok(nonempty)) = extra.map(|extra| extra.sock_nonempty()) {
            self.recv_empty.set(!nonempty);
        }
        let mut buf = op.into_inner();
        if let Ok(n) = res {
            // SAFETY: the kernel received `n` bytes into the buffer's start.
            unsafe { buf.advance_to(n) };
        }
        BufResult(res, buf)
    }

    async fn send<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
        use ::compio::driver::op::{Send, SendFlags};
        use compio_buf::IntoInner as _;

        let op = Send::new(self.inner.shared_fd(), buf, SendFlags::empty());
        let BufResult(res, op) = self.file.submit(op).await;
        BufResult(res, op.into_inner())
    }

    async fn send_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
        use ::compio::driver::op::{SendFlags, SendVectored};
        use compio_buf::IntoInner as _;

        let op = SendVectored::new(self.inner.shared_fd(), buf, SendFlags::empty());
        let BufResult(res, op) = self.file.submit(op).await;
        BufResult(res, op.into_inner())
    }

    async fn shutdown_write(&self) -> io::Result<()> {
        use ::compio::driver::op::ShutdownSocket;

        let op = ShutdownSocket::new(self.inner.shared_fd(), std::net::Shutdown::Write);
        match self.file.submit(op).await.0 {
            // A socket that is not connected has nothing to shut down, as
            // compio's stream has it.
            Err(e) if e.kind() == io::ErrorKind::NotConnected => Ok(()),
            res => res.map(drop),
        }
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
        let fd = self.inner.as_fd();
        #[cfg(debug_assertions)]
        self.identity.check(std::os::fd::AsRawFd::as_raw_fd(&fd));
        fd
    }
}

impl<S: Socket> SharedStream for Stream<S> {
    #[cfg(target_os = "linux")]
    type Buf = RecvBuf;
    #[cfg(not(target_os = "linux"))]
    type Buf = crate::NoBuf;

    async fn read<B: IoBufMut>(&self, buf: B) -> BufResult<usize, B> {
        #[cfg(target_os = "linux")]
        {
            let buf = match self.recv.read_ahead(&self.inner, &self.file, buf).await {
                recv::Copied::Done(result) => return result,
                recv::Copied::ReadInstead(buf) => buf,
            };
            self.recv(buf).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            read_single(&self.inner, buf).await
        }
    }

    async fn read_owned(&self) -> io::Result<crate::Received<Self::Buf>> {
        #[cfg(target_os = "linux")]
        {
            self.recv.read_owned(&self.inner, &self.file).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(crate::Received::ReadInstead)
        }
    }

    async fn stop_read_ahead(&self) -> Vec<u8> {
        #[cfg(target_os = "linux")]
        {
            self.recv.stop().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Vec::new()
        }
    }

    async fn write<B: IoBuf>(&self, buf: B) -> BufResult<usize, B> {
        #[cfg(target_os = "linux")]
        {
            self.send(buf).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.inner.write(buf).await
        }
    }

    async fn write_vectored<B: IoVectoredBuf>(&self, buf: B) -> BufResult<usize, B> {
        #[cfg(target_os = "linux")]
        {
            self.send_vectored(buf).await
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.inner.write_vectored(buf).await
        }
    }

    #[cfg(target_os = "linux")]
    async fn write_all_owned<B: IoVectoredBuf>(&self, buf: B) -> BufResult<(), Option<B>> {
        let threshold = self.zero_copy.threshold();
        if S::ZERO_COPY && buf.total_len() >= threshold {
            // Bytes that would not go out zero-copy on their own, a head or
            // framing, are worth copying into the region beside its bytes.
            let buf = match &self.fixed {
                Some(region) => match fixed::write_all(self, region, buf, threshold).await {
                    fixed::Sent::Done(result) => return result,
                    fixed::Sent::Declined(buf) => buf,
                },
                None => buf,
            };
            return zero_copy::write_all(self, buf).await;
        }
        let BufResult(res, buf) =
            crate::stream::write_all_vectored(&mut crate::stream::ByRef(self), buf).await;
        BufResult(res, Some(buf))
    }

    async fn shutdown(&self) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.shutdown_write().await
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.inner.shutdown().await
        }
    }

    /// `sendmsg(2)` of `buf` with the control messages in `control`.
    #[cfg(unix)]
    async fn write_control<B: IoBuf, C: IoBuf>(
        &self,
        buf: B,
        control: C,
    ) -> BufResult<usize, (B, C)> {
        use ::compio::driver::op::{SendFlags, SendMsg};
        use compio_buf::IntoInner as _;

        let op = SendMsg::new(self.inner.clone(), [buf], control, None, SendFlags::empty());
        let BufResult(res, op) = self.submit(op).await;
        let ([buf], control) = op.into_inner();
        BufResult(res, (buf, control))
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

/// One receive into the caller's buffer, with a submission of its own.
#[cfg(not(target_os = "linux"))]
async fn read_single<S: Socket, B: IoBufMut>(socket: &S, mut buf: B) -> BufResult<usize, B> {
    // compio writes from the start but only ever grows the length; the
    // contract is a length of exactly what was read.
    buf.clear();
    socket.read(buf).await
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
    /// all of it from the pipe into the socket, or as much as the socket
    /// took before an error, which is then what the round reports.
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
        let error = loop {
            if drained == filled {
                stream.pipe.set(Some(pipe));
                return BufResult(Ok(filled), file);
            }
            match crate::sys::pipe::splice(pipe.read.as_fd(), stream.fd(), filled - drained) {
                Ok(0) => {
                    break io::Error::new(io::ErrorKind::WriteZero, "stream accepted no bytes");
                }
                Ok(n) => drained += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if let Err(e) = ready(stream, Interest::Writable).await {
                        break e;
                    }
                }
                Err(e) => break e,
            }
        };
        // The pipe may still hold bytes, so it goes with this round. What was
        // drained before the error is in the socket: that is what this call
        // sent, as `send_file` reports it, and the error is the next call's
        // to report. Reporting the error instead would have a caller that
        // retries it (`Interrupted`, in `send_file_all`) send those bytes
        // again.
        if drained > 0 {
            BufResult(Ok(drained), file)
        } else {
            BufResult(Err(error), file)
        }
    }

    /// Makes the socket `O_NONBLOCK`, once.
    fn nonblocking<S: Socket + AsFd>(stream: &Stream<S>) -> io::Result<()> {
        if !stream.nonblocking.get() {
            crate::sys::pipe::set_nonblocking(stream.fd())?;
            stream.nonblocking.set(true);
        }
        Ok(())
    }

    /// Waits for the socket to be ready for `interest` with a poll the
    /// driver arms, which holds no thread.
    async fn ready<S: Socket + AsFd>(stream: &Stream<S>, interest: Interest) -> io::Result<()> {
        stream
            .submit(PollOnce::new(stream.inner.clone(), interest))
            .await
            .0
            .map(drop)
    }

    /// Socket to pipe: waits for readability, then one non-blocking
    /// `splice(2)`. io_uring would run the splice on an io-wq worker, which
    /// an idle peer would hold.
    ///
    /// What the multishot receive took from the socket ahead of the reader
    /// goes into the pipe first, from memory; only once nothing is held, and
    /// the receive is no longer armed to take more, does the socket splice.
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
        #[cfg(target_os = "linux")]
        let pipe = match stream.recv.splice_held(pipe, max).await {
            super::recv::Held::Spliced(spliced) => return spliced,
            super::recv::Held::None(pipe) => pipe,
        };
        if let Err(e) = nonblocking(stream) {
            return Err((e, pipe));
        }
        let len = max.min(pipe.capacity());
        loop {
            match crate::sys::pipe::splice(stream.fd(), pipe.write_fd(), len) {
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
            match crate::sys::pipe::splice(filled.pipe().read_fd(), stream.fd(), left) {
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

/// Registered files on io_uring: each stream's slot in its ring's file
/// table, and compio's operations naming the socket by it.
///
/// compio registers a table (`register_files`, where `-1` entries are empty
/// slots) but builds every operation on a descriptor, so [`Addressed`] wraps
/// its operation and rewrites the entry it builds: everything else, the
/// multishot and buffer-ring handling included, stays compio's.
#[cfg(target_os = "linux")]
mod files {
    use std::{
        cell::Cell,
        io,
        os::fd::{AsRawFd as _, RawFd},
        rc::Rc,
        task::{Poll, Waker},
    };

    use ::compio::{
        driver::{
            Decision, Extra, IourOpCode, OpCode, OpEntry, OpType, PollOpCode, SharedFd, TakeBuffer,
        },
        runtime::Runtime,
    };
    use compio_buf::BufResult;
    use linux_raw_sys::io_uring::{IORING_FILE_INDEX_ALLOC, io_uring_sqe};

    // An entry is the kernel's submission entry, which the ring copies it
    // into as it is.
    const _: () = assert!(size_of::<io_uring::squeue::Entry>() == size_of::<io_uring_sqe>());

    /// compio's operation `op` on a stream's socket, naming the socket by its
    /// slot when it has one.
    pub(super) struct Addressed<T> {
        op: T,
        /// The slot, and the descriptor `op` names, which the slot replaces.
        slot: Option<(u32, RawFd)>,
    }

    /// `entry`, naming its socket by `slot` (`IOSQE_FIXED_FILE`) when there
    /// is one.
    fn fixed(entry: OpEntry, slot: Option<(u32, RawFd)>) -> OpEntry {
        match (entry, slot) {
            (OpEntry::Submission(entry), Some((index, fd))) => {
                let mut entry = entry.flags(io_uring::squeue::Flags::FIXED_FILE);
                let sqe = (&raw mut entry).cast::<io_uring_sqe>();
                // SAFETY: an entry is a kernel submission entry (asserted
                // above); compio sets its fields the same way
                // (`set_poll_first`).
                unsafe {
                    debug_assert_eq!((*sqe).fd, fd, "the operation names another descriptor");
                    (*sqe).fd = index.cast_signed();
                }
                OpEntry::Submission(entry)
            }
            (entry, _) => entry,
        }
    }

    // SAFETY: every method is `op`'s own; the entries differ only in naming
    // the same socket by its slot, which holds the socket while the stream
    // lives.
    unsafe impl<T: IourOpCode> IourOpCode for Addressed<T> {
        type Control = T::Control;

        unsafe fn init(&mut self, control: &mut Self::Control) {
            // SAFETY: the caller's guarantee covers `op`, which `self` holds.
            unsafe { self.op.init(control) }
        }

        fn create_entry(&mut self, control: &mut Self::Control) -> OpEntry {
            fixed(self.op.create_entry(control), self.slot)
        }

        fn create_entry_fallback(&mut self, control: &mut Self::Control) -> OpEntry {
            fixed(self.op.create_entry_fallback(control), self.slot)
        }

        fn call_blocking(&mut self, control: &mut Self::Control) -> io::Result<usize> {
            self.op.call_blocking(control)
        }

        unsafe fn set_result(
            &mut self,
            control: &mut Self::Control,
            res: &io::Result<usize>,
            extra: &Extra,
        ) {
            // SAFETY: the result is `op`'s, as the caller guarantees.
            unsafe { IourOpCode::set_result(&mut self.op, control, res, extra) }
        }

        unsafe fn push_multishot(
            &mut self,
            control: &mut Self::Control,
            res: io::Result<usize>,
            extra: Extra,
        ) {
            // SAFETY: the result is `op`'s, as the caller guarantees.
            unsafe { self.op.push_multishot(control, res, extra) }
        }

        fn pop_multishot(
            &mut self,
            control: &mut Self::Control,
        ) -> Option<BufResult<usize, Extra>> {
            self.op.pop_multishot(control)
        }
    }

    // SAFETY: every method is `op`'s own; the polling driver uses the
    // descriptor, which `op` holds.
    unsafe impl<T: PollOpCode> PollOpCode for Addressed<T> {
        type Control = T::Control;

        unsafe fn init(&mut self, control: &mut Self::Control) {
            // SAFETY: the caller's guarantee covers `op`, which `self` holds.
            unsafe { self.op.init(control) }
        }

        fn pre_submit(&mut self, control: &mut Self::Control) -> io::Result<Decision> {
            self.op.pre_submit(control)
        }

        fn op_type(&mut self, control: &mut Self::Control) -> Option<OpType> {
            self.op.op_type(control)
        }

        fn operate(&mut self, control: &mut Self::Control) -> Poll<io::Result<usize>> {
            self.op.operate(control)
        }

        unsafe fn set_result(
            &mut self,
            control: &mut Self::Control,
            res: &io::Result<usize>,
            extra: &Extra,
        ) {
            // SAFETY: the result is `op`'s, as the caller guarantees.
            unsafe { PollOpCode::set_result(&mut self.op, control, res, extra) }
        }
    }

    impl<T: TakeBuffer> TakeBuffer for Addressed<T> {
        type Buffer = T::Buffer;

        fn take_buffer(self) -> Option<T::Buffer> {
            self.op.take_buffer()
        }
    }

    /// A stream's hold on its slot.
    pub(super) struct File {
        slot: Rc<Slot>,
        /// The socket's descriptor, which the slot replaces in an entry.
        fd: RawFd,
        /// The socket `fd` names, which an operation naming the descriptor
        /// checks it still does (debug builds, zen-rs/http-kit#159).
        #[cfg(debug_assertions)]
        identity: crate::sys::unix::Identity,
    }

    /// What a stream and its slot's keeper share.
    #[derive(Default)]
    struct Slot {
        state: Cell<State>,
        /// The keeper, waiting for the stream to go once it holds the slot.
        keeper: Cell<Option<Waker>>,
    }

    #[derive(Default)]
    enum State {
        /// The keeper has not taken the slot yet; operations name the
        /// descriptor.
        Installing,
        /// The socket holds this slot.
        Fixed(u32),
        /// No slot; operations name the descriptor.
        #[default]
        Descriptor,
        /// Taking a slot failed other than for want of room: the next
        /// operation reports it, and the rest name the descriptor.
        Failed(io::Error),
        /// The stream is gone: the keeper gives back the slot it holds or
        /// takes.
        Dropped,
    }

    impl File {
        /// Starts the keeper of a slot for `socket`, a task of the runtime
        /// that takes the slot, so that no operation of the stream waits for
        /// it and none abandoned midway loses the slot (and with it the
        /// socket, which the slot keeps open), and gives it back once the
        /// stream is gone, so that dropping a stream starts no task: a
        /// runtime being dropped drops its tasks, and may be handed no new
        /// one meanwhile.
        pub(super) fn new(socket: SharedFd<socket2::Socket>, table: &super::FileTable) -> Self {
            let fd = socket.as_raw_fd();
            let slot = Rc::new(Slot::default());
            let slots = table.slots();
            if slots > 0 {
                Runtime::with_current(|runtime| {
                    if runtime.driver_type().is_iouring() {
                        slot.state.set(State::Installing);
                        runtime
                            .spawn(keep(Rc::clone(&slot), socket, slots))
                            .detach();
                    }
                });
            }
            Self {
                slot,
                fd,
                #[cfg(debug_assertions)]
                identity: crate::sys::unix::Identity::of(fd)
                    .expect("a stream's socket is open when the stream is made"),
            }
        }

        fn slot(&self) -> io::Result<Option<u32>> {
            let state = &self.slot.state;
            match state.take() {
                State::Fixed(index) => {
                    state.set(State::Fixed(index));
                    Ok(Some(index))
                }
                State::Failed(error) => Err(error),
                other => {
                    state.set(other);
                    Ok(None)
                }
            }
        }

        /// `op`, naming the socket by its slot when it has one; or, with
        /// `op` back, the error taking a slot failed with.
        ///
        /// Without a slot `op` names the descriptor's number, which debug
        /// builds check still names the socket.
        #[track_caller]
        pub(super) fn address<T>(&self, op: T) -> Result<Addressed<T>, (io::Error, T)> {
            match self.slot() {
                Ok(slot) => {
                    #[cfg(debug_assertions)]
                    if slot.is_none() {
                        self.identity.check(self.fd);
                    }
                    Ok(Addressed {
                        op,
                        slot: slot.map(|index| (index, self.fd)),
                    })
                }
                Err(error) => Err((error, op)),
            }
        }

        pub(super) async fn submit<T: OpCode + 'static>(&self, op: T) -> BufResult<usize, T> {
            match self.address(op) {
                Ok(op) => {
                    let BufResult(res, op) = ::compio::runtime::submit(op).await;
                    BufResult(res, op.op)
                }
                Err((error, op)) => BufResult(Err(error), op),
            }
        }

        /// [`submit`](Self::submit), with what the driver reports beside the
        /// result.
        pub(super) async fn submit_with_extra<T: OpCode + 'static>(
            &self,
            op: T,
        ) -> (BufResult<usize, T>, Option<Extra>) {
            match self.address(op) {
                Ok(op) => {
                    let (BufResult(res, op), extra) =
                        ::compio::runtime::submit(op).with_extra().await;
                    (BufResult(res, op.op), Some(extra))
                }
                Err((error, op)) => (BufResult(Err(error), op), None),
            }
        }
    }

    impl Drop for File {
        fn drop(&mut self) {
            self.slot.state.set(State::Dropped);
            if let Some(keeper) = self.slot.keeper.take() {
                keeper.wake();
            }
        }
    }

    /// Takes a slot for `socket` and leaves the outcome in `slot`; while
    /// the stream holds the slot, waits for the stream to go, and gives the
    /// slot back then, or at once when the stream is gone by the time the
    /// slot is taken.
    ///
    /// A keeper dropped with its runtime leaves the slot taken, which is
    /// right: the ring goes with the runtime, and its table with it.
    async fn keep(slot: Rc<Slot>, socket: SharedFd<socket2::Socket>, slots: u32) {
        let taken = take_slot(socket, slots).await;
        if let State::Dropped = slot.state.take() {
            if let Ok(Some(index)) = taken {
                remove(index).await;
            }
            return;
        }
        let index = match taken {
            Ok(Some(index)) => index,
            Ok(None) => {
                slot.state.set(State::Descriptor);
                return;
            }
            Err(error) => {
                slot.state.set(State::Failed(error));
                return;
            }
        };
        slot.state.set(State::Fixed(index));
        std::future::poll_fn(|cx| match slot.state.take() {
            State::Dropped => Poll::Ready(()),
            held => {
                slot.state.set(held);
                slot.keeper.set(Some(cx.waker().clone()));
                Poll::Pending
            }
        })
        .await;
        remove(index).await;
    }

    /// The slot the kernel allocates for `socket`, registering the ring's
    /// table first if it has none; `None` where there is no room or no
    /// allocation.
    async fn take_slot(socket: SharedFd<socket2::Socket>, slots: u32) -> io::Result<Option<u32>> {
        let mut registered = false;
        loop {
            let op = FilesUpdate::install(socket.clone());
            let BufResult(res, op) = ::compio::runtime::submit(op).await;
            let Err(error) = res else {
                return Ok(Some(op.slot()));
            };
            match error.raw_os_error() {
                // The table is full (`io_fixed_fd_install`).
                Some(libc::ENFILE) => return Ok(None),
                // A kernel that does not allocate slots (before 5.19) reads
                // the allocation marker as an offset, which overflows
                // (`__io_register_rsrc_update`).
                Some(libc::EOVERFLOW) => return Ok(None),
                // The ring has no table yet.
                Some(libc::ENXIO) if !registered => {
                    register(slots)?;
                    registered = true;
                }
                // A kernel without the operation (before 5.6).
                None if error.kind() == io::ErrorKind::Unsupported => return Ok(None),
                _ => return Err(error),
            }
        }
    }

    /// Registers the current ring's table, of `slots` empty slots.
    fn register(slots: u32) -> io::Result<()> {
        let table = vec![-1; slots as usize];
        match Runtime::with_current(|runtime| runtime.register_files(&table)) {
            // Another stream's keeper registered it meanwhile.
            Err(error) if error.raw_os_error() == Some(libc::EBUSY) => Ok(()),
            res => res.map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("registering a file table of {slots} slots: {error}"),
                )
            }),
        }
    }

    /// Gives `index` back to the table, which drops its hold on the socket.
    async fn remove(index: u32) {
        let res = ::compio::runtime::submit(FilesUpdate::remove(index))
            .await
            .0;
        debug_assert!(
            res.is_ok(),
            "giving back slot {index} of the file table: {res:?}"
        );
    }

    /// `IORING_OP_FILES_UPDATE` of one slot.
    struct FilesUpdate {
        /// The descriptor to install, or `-1` to empty the slot; once a
        /// descriptor is installed, the slot the kernel allocated for it.
        fd: RawFd,
        offset: i32,
        /// The socket being installed, open until the kernel holds it.
        _socket: Option<SharedFd<socket2::Socket>>,
    }

    impl FilesUpdate {
        fn install(socket: SharedFd<socket2::Socket>) -> Self {
            Self {
                fd: socket.as_raw_fd(),
                offset: IORING_FILE_INDEX_ALLOC,
                _socket: Some(socket),
            }
        }

        fn remove(index: u32) -> Self {
            Self {
                fd: -1,
                offset: index.cast_signed(),
                _socket: None,
            }
        }

        /// The slot an install took.
        const fn slot(&self) -> u32 {
            self.fd.cast_unsigned()
        }
    }

    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "a file table needs io_uring")
    }

    // SAFETY: the entry points at `fd`, which the operation owns and compio
    // keeps in place until the operation completes.
    unsafe impl IourOpCode for FilesUpdate {
        type Control = ();

        fn create_entry(&mut self, (): &mut ()) -> OpEntry {
            // The kernel writes the slot it allocates back into `fd`.
            io_uring::opcode::FilesUpdate::new((&raw mut self.fd).cast_const(), 1)
                .offset(self.offset)
                .build()
                .into()
        }

        fn call_blocking(&mut self, (): &mut ()) -> io::Result<usize> {
            Err(unsupported())
        }
    }

    // SAFETY: nothing is submitted; a stream takes a slot only on io_uring.
    unsafe impl PollOpCode for FilesUpdate {
        type Control = ();

        fn pre_submit(&mut self, (): &mut ()) -> io::Result<Decision> {
            Err(unsupported())
        }

        fn operate(&mut self, (): &mut ()) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(unsupported()))
        }
    }
}

/// Zero-copy sends on io_uring.
#[cfg(target_os = "linux")]
mod zero_copy {
    use std::{io, rc::Rc};

    use ::compio::driver::{
        OpCode,
        op::{SendFlags, SendVectoredZc},
    };
    use compio_buf::{BufResult, IoVectoredBuf};
    use futures_core::stream::FusedStream as _;
    use futures_lite::StreamExt as _;

    use super::{Socket, Stream};

    /// The caller's buffers, shared by the sends of one write: a short send
    /// is continued by another while the first still holds what it sent.
    pub(super) struct Shared<B>(pub(super) Rc<B>);

    impl<B: IoVectoredBuf> IoVectoredBuf for Shared<B> {
        fn iter_slice(&self) -> impl Iterator<Item = &[u8]> {
            self.0.iter_slice()
        }
    }

    /// [`Write::write_all_owned`](crate::Write::write_all_owned) through
    /// zero-copy sends.
    ///
    /// With `MSG_WAITALL` io_uring finishes a short send itself, waiting for
    /// room in the socket with a poll (`io_net_retry`), so a write is one
    /// send and one notification unless an error cuts it short.
    pub(super) async fn write_all<S: Socket, B: IoVectoredBuf>(
        stream: &Stream<S>,
        buf: B,
    ) -> BufResult<(), Option<B>> {
        let flags = SendFlags::from_bits_retain(libc::MSG_WAITALL.cast_unsigned());
        let len = buf.total_len();
        let buf = Rc::new(buf);
        let mut written = 0;
        let mut zero_copy = true;
        let res = loop {
            if written == len {
                break Ok(());
            }
            let rest = Shared(Rc::clone(&buf)).slice(written);
            let res = if zero_copy {
                let op = SendVectoredZc::new(stream.inner.shared_fd(), rest, flags);
                match stream.file.address(op) {
                    Ok(op) => send(op).await,
                    Err((e, _)) => Err(e),
                }
            } else {
                stream.send_vectored(rest).await.0
            };
            match res {
                Ok(0) => {
                    break Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "stream accepted no bytes",
                    ));
                }
                Ok(n) => written += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // The pages would exceed `RLIMIT_MEMLOCK`: the kernel refused
                // the send before sending anything, so the rest copies.
                Err(e) if zero_copy && e.raw_os_error() == Some(libc::ENOMEM) => {
                    zero_copy = false;
                }
                Err(e) => break Err(e),
            }
        };
        BufResult(res, Rc::into_inner(buf))
    }

    /// Submits a zero-copy send and returns what the send itself completed
    /// with, as soon as it has. The operation, with the buffers it holds,
    /// goes to a task of the runtime until the kernel's notification that it
    /// no longer reads them, which drops them.
    ///
    /// It takes any zero-copy operation, whatever buffers it sends from.
    pub(super) async fn send<T: OpCode + 'static>(op: T) -> io::Result<usize> {
        let mut op = ::compio::runtime::submit_multi(op);
        let BufResult(res, _) = op
            .next()
            .await
            .expect("a submitted operation completes at least once");
        // The send's own completion carries `IORING_CQE_F_MORE` when a
        // notification follows. Without one (an error the kernel posts
        // alone, or a kernel without the operation, where compio sends by
        // copying) the first completion is the last.
        if !op.is_terminated() {
            ::compio::runtime::spawn(async move { while op.next().await.is_some() {} }).detach();
        }
        res
    }
}

/// Bytes a multishot receive put in a buffer of the runtime's ring, lent to
/// the reader by [`ReadOwned`](crate::ReadOwned). Dropping it releases them,
/// handing the buffer back to the ring unless the kernel still fills it or
/// other bytes lent out of it are held, so a reader holds it only as long as
/// it needs the bytes.
#[cfg(target_os = "linux")]
pub struct RecvBuf {
    buf: ::compio::driver::BufferRef,
    /// How much of the buffer was already read.
    start: usize,
}

#[cfg(target_os = "linux")]
impl RecvBuf {
    const fn new(buf: ::compio::driver::BufferRef) -> Self {
        Self { buf, start: 0 }
    }

    const fn advance(&mut self, n: usize) {
        self.start += n;
    }
}

#[cfg(target_os = "linux")]
impl std::ops::Deref for RecvBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.buf[self.start..]
    }
}

#[cfg(target_os = "linux")]
impl fmt::Debug for RecvBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvBuf")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Multishot receive on io_uring into the runtime's provided buffer ring.
///
/// The operation belongs to the stream, not to a read, so a read a caller
/// abandons (one raced against a timeout) leaves it armed with whatever it
/// already received. It is ended (cancelled, then drained, so nothing it
/// received is lost) only before the socket goes to someone else: a splice,
/// or for good when the reader stops reading ahead.
#[cfg(target_os = "linux")]
mod recv {
    use std::{cell::RefCell, collections::VecDeque, io};

    use ::compio::{
        driver::{
            SharedFd,
            op::{RecvFlags, RecvMulti},
        },
        runtime::{
            BufferPool, CancelToken, Runtime, StreamExt as _, SubmitMultiManaged, WithCancel,
        },
    };
    use compio_buf::{BufResult, IoBufMut};
    use futures_lite::StreamExt as _;

    use super::{RecvBuf, Socket, files};
    use crate::{
        Received,
        splice::{Pipe, Spliced},
    };

    type Op =
        WithCancel<SubmitMultiManaged<files::Addressed<RecvMulti<SharedFd<socket2::Socket>>>>>;

    /// The receive side of one stream.
    #[derive(Default)]
    pub(super) struct Recv(RefCell<State>);

    #[derive(Default)]
    struct State {
        /// The thread's ring, looked up on the first read: `Some(None)` where
        /// there is none (the runtime is not on io_uring, or the kernel
        /// refused the ring).
        ring: Option<Option<BufferPool>>,
        armed: Option<Armed>,
        /// Bytes received ahead of the reader, in order; the first may be
        /// partly read.
        held: VecDeque<RecvBuf>,
        /// How the receive ended, reported once `held` is read.
        end: Option<End>,
        /// The last receive ended for want of a free ring buffer: the next
        /// read takes the caller's buffer instead of arming again at once.
        exhausted: bool,
        /// The reader stopped reading ahead.
        stopped: bool,
    }

    /// The armed receive and the token that cancels it.
    struct Armed {
        op: Op,
        cancel: CancelToken,
    }

    enum End {
        /// Sticky, like the end of a socket.
        Eof,
        /// Reported once; the next read arms again.
        Error(io::Error),
    }

    enum Next {
        Buf(RecvBuf),
        Eof,
        ReadInstead,
    }

    /// What a copying read came to.
    pub(super) enum Copied<B> {
        Done(BufResult<usize, B>),
        /// Read into the caller's buffer with a receive of its own.
        ReadInstead(B),
    }

    /// What a splice found held.
    pub(super) enum Held {
        Spliced(Result<Spliced, (io::Error, Pipe)>),
        /// Nothing: the socket holds everything not yet read.
        None(Pipe),
    }

    impl Armed {
        fn new<S: Socket>(socket: &S, file: &files::File, ring: &BufferPool) -> io::Result<Self> {
            // A length of 0 receives up to a whole ring buffer at a time.
            let op = RecvMulti::new(socket.shared_fd(), ring, 0, RecvFlags::empty())?;
            let op = file.address(op).map_err(|(e, _)| e)?;
            let cancel = CancelToken::new();
            let op = ::compio::runtime::submit_multi(op)
                .into_managed(ring.clone())
                .with_cancel(cancel.clone());
            Ok(Self { op, cancel })
        }
    }

    /// Whether a receive ended because the ring had no free buffer: compio's
    /// io_uring driver reports `ENOBUFS` as a [`io::ErrorKind::ResourceBusy`]
    /// error of its own, without the OS code (compio-driver 0.12,
    /// `create_result`), which a real `EBUSY` would carry.
    fn ring_dry(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::ResourceBusy && error.raw_os_error().is_none()
    }

    /// The thread's ring, looked up once per stream.
    fn ring(ring: &mut Option<Option<BufferPool>>) -> Option<BufferPool> {
        ring.get_or_insert_with(|| {
            Runtime::with_current(|runtime| {
                if runtime.driver_type().is_iouring() {
                    runtime.buffer_pool().ok()
                } else {
                    None
                }
            })
        })
        .clone()
    }

    impl State {
        /// The next received bytes, waiting for them if none are held.
        async fn next<S: Socket>(&mut self, socket: &S, file: &files::File) -> io::Result<Next> {
            loop {
                if let Some(buf) = self.held.pop_front() {
                    return Ok(Next::Buf(buf));
                }
                match self.end.take() {
                    Some(End::Eof) => {
                        self.end = Some(End::Eof);
                        return Ok(Next::Eof);
                    }
                    Some(End::Error(error)) => return Err(error),
                    None => {}
                }
                if self.stopped || self.exhausted {
                    if self.armed.is_some() {
                        self.disarm().await;
                        continue;
                    }
                    self.exhausted = false;
                    return Ok(Next::ReadInstead);
                }
                let armed = match &mut self.armed {
                    Some(armed) => armed,
                    slot @ None => {
                        let Some(ring) = ring(&mut self.ring) else {
                            return Ok(Next::ReadInstead);
                        };
                        slot.insert(Armed::new(socket, file, &ring)?)
                    }
                };
                match armed.op.next().await {
                    // The kernel ended the receive with its last completion:
                    // arm another.
                    None => self.armed = None,
                    Some(Ok(Some(buf))) if !buf.is_empty() => {
                        return Ok(Next::Buf(RecvBuf::new(buf)));
                    }
                    Some(Ok(_)) => {
                        self.armed = None;
                        self.end = Some(End::Eof);
                    }
                    Some(Err(error)) if ring_dry(&error) => {
                        self.armed = None;
                        self.exhausted = true;
                    }
                    Some(Err(error)) => {
                        self.armed = None;
                        return Err(error);
                    }
                }
            }
        }

        /// Ends the armed receive, keeping everything it received.
        async fn disarm(&mut self) {
            while let Some(armed) = &mut self.armed {
                if !armed.cancel.is_cancelled() {
                    armed.cancel.clone().cancel();
                }
                match armed.op.next().await {
                    None => self.armed = None,
                    Some(Ok(Some(buf))) if !buf.is_empty() => {
                        self.held.push_back(RecvBuf::new(buf));
                    }
                    Some(Ok(_)) => self.end = Some(End::Eof),
                    Some(Err(error))
                        if ring_dry(&error) || error.raw_os_error() == Some(libc::ECANCELED) => {}
                    Some(Err(error)) => self.end = Some(End::Error(error)),
                }
            }
        }
    }

    impl Recv {
        /// [`Read::read`](crate::Read::read): copies what was received into
        /// `buf`, keeping what does not fit.
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side for the read, released when the read ends or is dropped"
        )]
        pub(super) async fn read_ahead<S: Socket, B: IoBufMut>(
            &self,
            socket: &S,
            file: &files::File,
            mut buf: B,
        ) -> Copied<B> {
            if buf.as_uninit().is_empty() {
                buf.clear();
                return Copied::Done(BufResult(Ok(0), buf));
            }
            let mut state = self.0.borrow_mut();
            match state.next(socket, file).await {
                Ok(Next::Buf(mut held)) => {
                    let n = copy_into(&mut buf, &held);
                    held.advance(n);
                    if !held.is_empty() {
                        state.held.push_front(held);
                    }
                    Copied::Done(BufResult(Ok(n), buf))
                }
                Ok(Next::Eof) => {
                    buf.clear();
                    Copied::Done(BufResult(Ok(0), buf))
                }
                Ok(Next::ReadInstead) => Copied::ReadInstead(buf),
                Err(error) => Copied::Done(BufResult(Err(error), buf)),
            }
        }

        /// [`ReadOwned::read_owned`](crate::ReadOwned::read_owned).
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side for the read, released when the read ends or is dropped"
        )]
        pub(super) async fn read_owned<S: Socket>(
            &self,
            socket: &S,
            file: &files::File,
        ) -> io::Result<Received<RecvBuf>> {
            Ok(match self.0.borrow_mut().next(socket, file).await? {
                Next::Buf(buf) => Received::Lent(buf),
                Next::Eof => Received::End,
                Next::ReadInstead => Received::ReadInstead,
            })
        }

        /// [`ReadAhead::stop_read_ahead`](crate::ReadAhead::stop_read_ahead).
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side while the receive drains"
        )]
        pub(super) async fn stop(&self) -> Vec<u8> {
            let mut state = self.0.borrow_mut();
            state.stopped = true;
            state.disarm().await;
            let mut bytes = Vec::with_capacity(state.held.iter().map(|buf| buf.len()).sum());
            for buf in state.held.drain(..) {
                bytes.extend_from_slice(&buf);
            }
            bytes
        }

        /// Puts held bytes, at most `max`, into `pipe` ahead of anything the
        /// socket splices. With none held, ends the armed receive first, so
        /// that the socket holds everything not yet read.
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the stream's one reader holds its receive side while the receive drains"
        )]
        pub(super) async fn splice_held(&self, pipe: Pipe, max: usize) -> Held {
            let mut state = self.0.borrow_mut();
            if state.held.is_empty() {
                state.disarm().await;
            }
            if let Some(mut buf) = state.held.pop_front() {
                let n = buf.len().min(max);
                let filled = pipe.fill(&buf[..n]).map(|filled| {
                    buf.advance(filled.len());
                    Spliced::Filled(filled)
                });
                if !buf.is_empty() {
                    state.held.push_front(buf);
                }
                return Held::Spliced(filled);
            }
            match state.end.take() {
                Some(End::Eof) => {
                    state.end = Some(End::Eof);
                    Held::Spliced(Ok(Spliced::End(pipe)))
                }
                Some(End::Error(error)) => Held::Spliced(Err((error, pipe))),
                None => Held::None(pipe),
            }
        }
    }

    /// Copies as much of `bytes` as fits into `buf`, from its start, and sets
    /// its length to that.
    fn copy_into<B: IoBufMut>(buf: &mut B, bytes: &[u8]) -> usize {
        let room = buf.as_uninit();
        let n = room.len().min(bytes.len());
        // SAFETY: `room` has at least `n` bytes, and a ring buffer never
        // overlaps the caller's.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), room.as_mut_ptr().cast(), n) };
        // SAFETY: the first `n` bytes were initialized just now.
        unsafe { buf.set_len(n) };
        n
    }
}

/// Multishot accept on io_uring: one submission stays armed on the
/// listener and completes once per connection, until the kernel ends it.
///
/// The operation belongs to the listener, not to an `accept` call, so an
/// accept a caller abandons (a server racing it against shutdown drops one
/// every time) leaves it armed with whatever it has already accepted. compio
/// accepts once per submission where the kernel predates multishot accept
/// (5.19) or io_uring is unavailable; the next accept then submits again.
#[cfg(target_os = "linux")]
mod multishot {
    use std::{
        cell::RefCell,
        io,
        os::fd::{FromRawFd as _, OwnedFd},
    };

    use ::compio::{
        driver::{SharedFd, ToSharedFd, op::AcceptMulti},
        runtime::SubmitMulti,
    };
    use compio_buf::{BufResult, IntoInner as _};
    use futures_core::stream::FusedStream as _;
    use futures_lite::StreamExt as _;

    type Op = SubmitMulti<AcceptMulti<SharedFd<socket2::Socket>>>;

    fn arm(listener: &impl ToSharedFd<socket2::Socket>) -> Op {
        ::compio::runtime::submit_multi(AcceptMulti::new(listener.to_shared_fd()))
    }

    /// The listener's armed accept, borrowed by the `accept` polling it.
    pub(super) struct Accepts(RefCell<Op>);

    impl Accepts {
        /// An accept not yet submitted: the first `next` submits it.
        pub(super) fn new(listener: &impl ToSharedFd<socket2::Socket>) -> Self {
            Self(RefCell::new(arm(listener)))
        }

        /// The next connection the armed accept completes with, or `None`
        /// while another `accept` on this listener is polling it; that caller
        /// then accepts with a submission of its own, since the operation
        /// wakes one waiter only.
        #[expect(
            clippy::await_holding_refcell_ref,
            reason = "the borrow is the accept's exclusive hold on the operation, released when the accept ends or is dropped"
        )]
        pub(super) async fn next(
            &self,
            listener: &impl ToSharedFd<socket2::Socket>,
        ) -> Option<io::Result<OwnedFd>> {
            let mut op = self.0.try_borrow_mut().ok()?;
            let BufResult(res, _) = op
                .next()
                .await
                .expect("a terminated accept is replaced in the poll that ends it");
            if !op.is_terminated() {
                // SAFETY: a multishot completion hands over the accepted
                // descriptor, which nothing else owns.
                return Some(res.map(|fd| unsafe { OwnedFd::from_raw_fd(fd as _) }));
            }
            // The kernel ended the multishot (or there was none): a successful
            // last completion leaves the socket in the operation.
            let finished = std::mem::replace(&mut *op, arm(listener));
            Some(res.map(|_| {
                let op = finished
                    .try_take()
                    .map_err(drop)
                    .expect("a terminated accept has completed");
                OwnedFd::from(op.into_inner())
            }))
        }
    }

    impl std::fmt::Debug for Accepts {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Accepts").finish_non_exhaustive()
        }
    }
}

/// A listening TCP socket.
#[derive(Debug)]
pub struct TcpListener<R = Shared> {
    inner: net::TcpListener,
    #[cfg(target_os = "linux")]
    accepts: multishot::Accepts,
    /// The settings each accepted stream shares.
    io: Compio<R>,
}

impl<R: Scope> TcpListener<R> {
    fn new(inner: net::TcpListener, io: Compio<R>) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            accepts: multishot::Accepts::new(&inner),
            inner,
            io,
        }
    }

    /// compio's listener.
    #[must_use]
    pub fn get_ref(&self) -> &net::TcpListener {
        &self.inner
    }
}

#[cfg(unix)]
impl<R> std::os::fd::AsFd for TcpListener<R> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

impl<R: Scope> Listener for TcpListener<R> {
    type Stream = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        #[cfg(target_os = "linux")]
        if let Some(accepted) = self.accepts.next(&self.inner).await {
            // A multishot accept shares one address buffer between its
            // completions, so it reports no peer.
            let stream = net::TcpStream::from_std(accepted?.into())?;
            let peer = stream.peer_addr()?;
            return Ok((self.io.tcp_stream(stream), peer));
        }
        let (stream, peer) = self.inner.accept().await?;
        Ok((self.io.tcp_stream(stream), peer))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// A listening Unix-domain socket.
#[cfg(unix)]
#[derive(Debug)]
pub struct UnixListener<R = Shared> {
    inner: net::UnixListener,
    #[cfg(target_os = "linux")]
    accepts: multishot::Accepts,
    /// The settings each accepted stream shares.
    io: Compio<R>,
}

#[cfg(unix)]
impl<R: Scope> UnixListener<R> {
    fn new(inner: net::UnixListener, io: Compio<R>) -> Self {
        Self {
            #[cfg(target_os = "linux")]
            accepts: multishot::Accepts::new(&inner),
            inner,
            io,
        }
    }

    /// compio's listener.
    #[must_use]
    pub fn get_ref(&self) -> &net::UnixListener {
        &self.inner
    }
}

#[cfg(unix)]
impl<R> std::os::fd::AsFd for UnixListener<R> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

#[cfg(unix)]
impl<R: Scope> Listener for UnixListener<R> {
    type Stream = UnixStream;
    type Addr = std::os::unix::net::SocketAddr;

    async fn accept(&self) -> io::Result<(UnixStream, Self::Addr)> {
        #[cfg(target_os = "linux")]
        let stream = match self.accepts.next(&self.inner).await {
            Some(accepted) => net::UnixStream::from_std(accepted?.into())?,
            None => self.inner.accept().await?.0,
        };
        #[cfg(not(target_os = "linux"))]
        let (stream, _) = self.inner.accept().await?;
        let stream = UnixStream::new(stream, &self.io);
        let peer = stream.peer_addr()?;
        Ok((stream, peer))
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        crate::sys::unix::listener_addr(&self.inner)
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
