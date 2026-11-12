//! A ring's region of registered (fixed) buffers.
//!
//! The region is one anonymous mapping registered as the ring's buffer `0`,
//! so that any slices of it can go out in one vectored send: the kernel
//! requires every iovec of a send from registered buffers to lie in the one
//! buffer its index names (`io_vec_fill_bvec`). Its allocator lives on the
//! ring's thread and hands it out in [`FixedBufMut`]s, which freeze into
//! [`Bytes`] that any thread may hold and drop: a span dropped elsewhere
//! comes back to the ring's thread over a channel.
//!
//! A zero-copy send from the region skips what a send from other memory
//! costs on each call: pinning every page (`zerocopy_fill_skb_from_iter`),
//! and charging them to the user's `RLIMIT_MEMLOCK` with a compare-and-swap
//! on a counter every thread's ring shares, undone by another at the
//! notification (`io_notif_account_mem`).

use std::{
    cell::RefCell,
    fmt, io,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd as _, OwnedFd, RawFd},
    ptr::NonNull,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::ThreadId,
};

use ::compio::{
    driver::{
        SharedFd,
        op::{ReadFixedAt, SendFlags, SendVectoredZcFixed, SendZcFixed},
    },
    runtime::Runtime,
};
use bytes::Bytes;
use compio_buf::{BufResult, IntoInner as _, IoBuf, IoBufMut, IoVectoredBuf, SetLen};
use offset_allocator::{Allocation, Allocator};

use super::{Socket, Stream};

/// The bytes one unit of the allocator stands for. The allocator counts in
/// `u32` units, and the kernel registers a buffer of at most 1 TiB
/// (`io_validate_user_buf_range`): 2^40 / 2^32 bytes per unit lets the
/// allocator cover the largest region the kernel takes.
const UNIT: usize = 256;

/// The index the region is registered at: it is the ring's only buffer.
const INDEX: u16 = 0;

/// A ring's region of registered buffers, which
/// [`Compio::register_fixed_region`] registers on the ring's thread and
/// [`Compio::fixed_region`] hands out. It stays on that thread (it is neither
/// `Send` nor `Sync`); what it hands out does not.
///
/// [`Compio::register_fixed_region`]: super::Compio::register_fixed_region
/// [`Compio::fixed_region`]: super::Compio::fixed_region
#[derive(Clone)]
pub struct FixedRegion(Rc<Region>);

struct Region {
    mapping: Arc<Mapping>,
    /// The free space, in [`UNIT`]s, which only the ring's thread touches.
    allocator: RefCell<Allocator>,
    /// The spans given back, from any thread, since the last allocation.
    freed: mpsc::Receiver<Allocation>,
    free: mpsc::Sender<Allocation>,
    /// The ring the region is registered on: its thread, and its descriptor,
    /// which no other ring has while it lives.
    ring: (ThreadId, RawFd),
    /// Whether the kernel takes a registered buffer on a vectored zero-copy
    /// send (Linux 6.15), as a probe at registration found.
    vectored: bool,
}

/// The region's memory, which outlives the region while a span of it is
/// held.
struct Mapping {
    base: NonNull<u8>,
    len: usize,
    /// Whether a ring may still hold it registered, in which case it is
    /// never unmapped: the kernel would read and write whatever the address
    /// space later maps there.
    registered: AtomicBool,
}

// SAFETY: the mapping is plain memory: each span is written only through the
// one `FixedBufMut` that holds it, and read through `Bytes` once frozen.
unsafe impl Send for Mapping {}
// SAFETY: as above.
unsafe impl Sync for Mapping {}

impl Drop for Mapping {
    fn drop(&mut self) {
        if !self.registered.load(Ordering::Acquire) {
            // SAFETY: no ring holds the mapping and no span of it is held.
            unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
        }
    }
}

/// A broken contract: a panic in a debug build, and in a release build,
/// where this runs inside a user's application, a log.
#[track_caller]
fn violated(what: &str) {
    if cfg!(debug_assertions) {
        panic!("{what}");
    }
    tracing::error!("{what}");
}

impl FixedRegion {
    /// Maps and registers the current ring's region of `bytes` bytes, and
    /// probes whether the kernel takes it on vectored sends; `None` without a
    /// region to register.
    pub(super) async fn register(bytes: usize) -> io::Result<Option<Self>> {
        if bytes == 0 {
            return Ok(None);
        }
        let Some(ring) = Runtime::with_current(|runtime| {
            runtime
                .driver_type()
                .is_iouring()
                .then(|| (std::thread::current().id(), runtime.as_raw_fd()))
        }) else {
            return Ok(None);
        };
        // SAFETY: `sysconf` reads a constant of the system.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .expect("the page size is positive");
        let len = bytes.next_multiple_of(page);
        let units = u32::try_from(len / UNIT).unwrap_or(u32::MAX);
        // SAFETY: an anonymous private mapping, which nothing else aliases.
        let base = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            let error = io::Error::last_os_error();
            return Err(io::Error::new(
                error.kind(),
                format!("mapping a region of {len} registered bytes: {error}"),
            ));
        }
        let mapping = Arc::new(Mapping {
            base: NonNull::new(base.cast::<u8>()).expect("a mapping is not at address 0"),
            len,
            registered: AtomicBool::new(false),
        });
        Runtime::with_current(|runtime| {
            // SAFETY: the mapping is unmapped only once nothing holds it
            // registered (`Mapping::registered`).
            unsafe {
                runtime.register_buffers(&[std::io::IoSliceMut::new(
                    std::slice::from_raw_parts_mut(mapping.base.as_ptr(), len),
                )])
            }
        })
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("registering a region of {len} bytes: {error}"),
            )
        })?;
        mapping.registered.store(true, Ordering::Release);
        let (free, freed) = mpsc::channel();
        let mut region = Region {
            mapping,
            // offset-allocator's default bound on live allocations; past it
            // an allocation fails like one the region has no room for.
            allocator: RefCell::new(Allocator::new(units)),
            freed,
            free,
            ring,
            vectored: false,
        };
        region.vectored = probe_vectored(&region).await?;
        Ok(Some(Self(Rc::new(region))))
    }

    /// The region's size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.mapping.len
    }

    /// Whether the region is empty, which a registered region never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.mapping.len == 0
    }

    /// `len` bytes of the region to fill, or `None` when it has no room for
    /// them: the caller then uses memory of its own.
    #[must_use]
    pub fn alloc(&self, len: usize) -> Option<FixedBufMut> {
        let units = u32::try_from(len.div_ceil(UNIT).max(1)).ok()?;
        let mut allocator = self.0.allocator.borrow_mut();
        self.0.reclaim(&mut allocator);
        let allocation = allocator.allocate(units).or_else(|| {
            // A span may have come back meanwhile.
            self.0.reclaim(&mut allocator);
            allocator.allocate(units)
        })?;
        Some(FixedBufMut {
            lease: Lease {
                mapping: Arc::clone(&self.0.mapping),
                offset: allocation.offset as usize * UNIT,
                allocation,
                capacity: len,
                free: self.0.free.clone(),
            },
            len: 0,
        })
    }

    /// Reads `len` bytes of `file` from `offset` into the region, through
    /// reads into the registered buffer (`IORING_OP_READ_FIXED`), which pin
    /// nothing either. `None` when the region has no room for them.
    ///
    /// Call it inside the region's ring's runtime: anywhere else is a
    /// contract violation.
    ///
    /// # Errors
    ///
    /// Fails if a read fails, if the file ends before `len` bytes, or if this
    /// is not the region's ring.
    pub async fn read_at<F: AsFd + Clone + 'static>(
        &self,
        file: F,
        offset: u64,
        len: usize,
    ) -> io::Result<Option<Bytes>> {
        if !self.is_current_ring() {
            violated("reading into a region of registered buffers on another ring");
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reading into a region of registered buffers on another ring",
            ));
        }
        let Some(mut buf) = self.alloc(len) else {
            return Ok(None);
        };
        while buf.len < len {
            let from = buf.len;
            let op = ReadFixedAt::new(
                file.clone(),
                offset + from as u64,
                Tail { buf, from },
                INDEX,
            );
            let BufResult(res, op) = ::compio::runtime::submit(op).await;
            buf = op.into_inner().buf;
            match res {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!("the file ended {from} bytes into a read of {len}"),
                    ));
                }
                Ok(n) => buf.len = from + n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    refused(&e);
                    return Err(e);
                }
            }
        }
        Ok(Some(buf.freeze()))
    }

    /// The region for a stream being made: a stream on another ring than the
    /// region's is a contract violation, and gets none.
    pub(super) fn for_stream(&self) -> Option<Self> {
        if self.is_current_ring() {
            return Some(self.clone());
        }
        violated("a stream made from a ring's Compio on another ring");
        None
    }

    /// Whether the current runtime is the ring the region is registered on.
    fn is_current_ring(&self) -> bool {
        let (thread, fd) = self.0.ring;
        thread == std::thread::current().id()
            && Runtime::try_with_current(|runtime| runtime.as_raw_fd() == fd).unwrap_or(false)
    }

    /// Whether `slice` lies in the region whole.
    fn contains(&self, slice: &[u8]) -> bool {
        let base = self.0.mapping.base.as_ptr() as usize;
        let start = slice.as_ptr() as usize;
        start >= base && start + slice.len() <= base + self.0.mapping.len
    }
}

impl Region {
    fn reclaim(&self, allocator: &mut Allocator) {
        while let Ok(allocation) = self.freed.try_recv() {
            allocator.free(allocation);
        }
    }
}

impl fmt::Debug for FixedRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedRegion")
            .field("len", &self.0.mapping.len)
            .field("vectored", &self.0.vectored)
            .finish_non_exhaustive()
    }
}

impl Drop for Region {
    fn drop(&mut self) {
        let (thread, fd) = self.ring;
        let unregistered = thread == std::thread::current().id()
            && Runtime::try_with_current(|runtime| {
                runtime.as_raw_fd() == fd && runtime.unregister_buffers().is_ok()
            })
            .unwrap_or(false);
        // Outside its ring's runtime the ring may still hold the mapping
        // registered: it stays mapped, and goes with the process.
        if unregistered {
            self.mapping.registered.store(false, Ordering::Release);
        }
    }
}

/// An error the kernel gave an operation on the region. `EFAULT` says the
/// operation named memory outside the ring's registered buffer: the region
/// sent or read a span it does not hold, or the ring is not the region's.
fn refused(error: &io::Error) {
    if error.raw_os_error() == Some(libc::EFAULT) {
        violated(&format!(
            "the ring refused a span of its region of registered buffers: {error}"
        ));
    }
}

/// Whether the kernel takes a registered buffer on a vectored zero-copy
/// send: one sent on a socket that cannot send zero-copy, a Unix datagram
/// socket, so that nothing goes out. A kernel before 6.15 refuses the
/// registered buffer with `EINVAL` when it prepares the operation
/// (`io_send_zc_prep`); a later one prepares it and refuses the socket,
/// which lacks `SOCK_SUPPORT_ZC`, with `EOPNOTSUPP` (`io_sendmsg_zc`).
async fn probe_vectored(region: &Region) -> io::Result<bool> {
    // The region is registered and nothing else holds it yet: its first
    // unit is free to send.
    // SAFETY: the unit lies in the mapping, which stays mapped while it is
    // registered, and it is until the region is dropped, after the probe.
    let unit: &'static [u8] =
        unsafe { std::slice::from_raw_parts(region.mapping.base.as_ptr(), 1) };
    let socket = OwnedFd::from(std::os::unix::net::UnixDatagram::unbound()?);
    let op = SendVectoredZcFixed::new(
        SharedFd::new(socket2::Socket::from(socket)),
        [unit],
        INDEX,
        SendFlags::empty(),
    );
    let res = super::zero_copy::send(op).await;
    Ok(!matches!(res, Err(e) if e.raw_os_error() == Some(libc::EINVAL)))
}

/// Bytes of a region to fill: initialized up to [`len`](IoBuf::buf_len),
/// with room up to its capacity. [`freeze`](Self::freeze) turns it into
/// [`Bytes`]; dropping it gives its span back.
pub struct FixedBufMut {
    lease: Lease,
    len: usize,
}

/// A span of the region, given back to the ring's thread once dropped, from
/// any thread.
struct Lease {
    mapping: Arc<Mapping>,
    allocation: Allocation,
    offset: usize,
    capacity: usize,
    free: mpsc::Sender<Allocation>,
}

impl FixedBufMut {
    /// How many bytes it holds at most.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.lease.capacity
    }

    /// The initialized bytes, as [`Bytes`] that keep the span until the last
    /// clone is dropped, on whatever thread.
    #[must_use]
    pub fn freeze(self) -> Bytes {
        let len = self.len;
        let mut bytes = Bytes::from_owner(self.lease);
        bytes.truncate(len);
        bytes
    }

    fn full(&mut self) -> &mut [MaybeUninit<u8>] {
        // SAFETY: the span lies in the mapping, which the lease keeps, and
        // only this buffer refers to it.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.lease
                    .mapping
                    .base
                    .as_ptr()
                    .add(self.lease.offset)
                    .cast::<MaybeUninit<u8>>(),
                self.lease.capacity,
            )
        }
    }
}

impl std::ops::Deref for FixedBufMut {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.lease.as_ref()[..self.len]
    }
}

impl std::ops::DerefMut for FixedBufMut {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        // SAFETY: the first `len` bytes are initialized.
        unsafe { self.full()[..len].assume_init_mut() }
    }
}

impl fmt::Debug for FixedBufMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedBufMut")
            .field("len", &self.len)
            .field("capacity", &self.lease.capacity)
            .finish()
    }
}

impl IoBuf for FixedBufMut {
    fn as_init(&self) -> &[u8] {
        self
    }
}

impl SetLen for FixedBufMut {
    unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= self.lease.capacity);
        self.len = len;
    }
}

impl IoBufMut for FixedBufMut {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        self.full()
    }
}

impl AsRef<[u8]> for Lease {
    fn as_ref(&self) -> &[u8] {
        // SAFETY: the span lies in the mapping, which the lease keeps; the
        // mapping starts zeroed, so every byte is initialized.
        unsafe {
            std::slice::from_raw_parts(self.mapping.base.as_ptr().add(self.offset), self.capacity)
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // A region already gone has no allocator to give the span back to.
        let _ = self.free.send(self.allocation);
    }
}

/// The room of `buf` from `from` on, which a short read continues into.
struct Tail {
    buf: FixedBufMut,
    from: usize,
}

impl IoBuf for Tail {
    fn as_init(&self) -> &[u8] {
        &[]
    }
}

impl SetLen for Tail {
    unsafe fn set_len(&mut self, _: usize) {}
}

impl IoBufMut for Tail {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        let from = self.from;
        &mut self.buf.full()[from..]
    }
}

/// A write's slices as one send from the region: the caller's buffers,
/// whose memory those of its slices in the region are, and the small rest
/// copied into a span of the region.
struct Parts<B> {
    slices: Vec<(usize, usize)>,
    _owner: Rc<B>,
    _copied: Option<Bytes>,
}

impl<B: 'static> IoVectoredBuf for Parts<B> {
    fn iter_slice(&self) -> impl Iterator<Item = &[u8]> {
        // SAFETY: each slice lies in the caller's buffers or the copied
        // span, which `self` keeps.
        self.slices
            .iter()
            .map(|&(ptr, len)| unsafe { std::slice::from_raw_parts(ptr as *const u8, len) })
    }
}

/// The one slice of a write's [`Parts`].
struct Only<B>(Rc<Parts<B>>);

impl<B: 'static> IoBuf for Only<B> {
    fn as_init(&self) -> &[u8] {
        let (ptr, len) = self.0.slices[0];
        // SAFETY: as for `Parts::iter_slice`.
        unsafe { std::slice::from_raw_parts(ptr as *const u8, len) }
    }
}

/// What [`write_all`] did with a write.
pub(super) enum Sent<B> {
    /// It sent the write from the region, or failed doing so.
    Done(BufResult<(), Option<B>>),
    /// The write does not go out from the region: the caller sends it.
    Declined(B),
}

/// Sends `buf` from the stream's region, when its bytes lie in it: the
/// slices that do not, as long as they are fewer than `copy_below` bytes in
/// all, are copied into a span of the region, so that the write is one send
/// from the registered buffer. Declined when no slice lies in the region,
/// when the rest is too large to copy, when the region has no room for it,
/// or when the kernel cannot send several slices from a registered buffer.
pub(super) async fn write_all<S: Socket, B: IoVectoredBuf>(
    stream: &Stream<S>,
    region: &FixedRegion,
    buf: B,
    copy_below: usize,
) -> Sent<B> {
    let mut inside = false;
    let mut outside = 0;
    let mut count = 0;
    for slice in buf.iter_slice() {
        if slice.is_empty() {
            continue;
        }
        count += 1;
        if region.contains(slice) {
            inside = true;
        } else {
            outside += slice.len();
        }
    }
    if !inside || outside >= copy_below || (count > 1 && !region.0.vectored) {
        return Sent::Declined(buf);
    }
    let copied = if outside == 0 {
        None
    } else {
        let Some(mut span) = region.alloc(outside) else {
            return Sent::Declined(buf);
        };
        // The span is initialized: the mapping starts zeroed.
        span.len = outside;
        let mut at = 0;
        for slice in buf.iter_slice() {
            if region.contains(slice) {
                continue;
            }
            span[at..at + slice.len()].copy_from_slice(slice);
            at += slice.len();
        }
        Some(span.freeze())
    };
    let mut slices = Vec::with_capacity(count);
    let mut copied_at = copied.as_ref().map_or(0, |copied| copied.as_ptr() as usize);
    for slice in buf.iter_slice() {
        if slice.is_empty() {
            continue;
        }
        if region.contains(slice) {
            slices.push((slice.as_ptr() as usize, slice.len()));
        } else {
            slices.push((copied_at, slice.len()));
            copied_at += slice.len();
        }
    }
    let len = slices.iter().map(|&(_, len)| len).sum::<usize>();
    let buf = Rc::new(buf);
    let parts = Rc::new(Parts {
        slices,
        _owner: Rc::clone(&buf),
        _copied: copied,
    });
    let flags = SendFlags::from_bits_retain(libc::MSG_WAITALL.cast_unsigned());
    let mut written = 0;
    let res = loop {
        if written == len {
            break Ok(());
        }
        let res = if count == 1 {
            // A single slice needs no vectored send, which a kernel before
            // 6.15 refuses from a registered buffer.
            let rest = Only(Rc::clone(&parts)).slice(written..);
            send(
                stream,
                SendZcFixed::new(stream.inner.shared_fd(), rest, INDEX, flags),
            )
            .await
        } else {
            let rest = super::zero_copy::Shared(Rc::clone(&parts)).slice(written);
            send(
                stream,
                SendVectoredZcFixed::new(stream.inner.shared_fd(), rest, INDEX, flags),
            )
            .await
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
            Err(e) => {
                refused(&e);
                break Err(e);
            }
        }
    };
    drop(parts);
    Sent::Done(BufResult(res, Rc::into_inner(buf)))
}

/// Submits a zero-copy send from the region on the stream's socket.
async fn send<S: Socket, T: ::compio::driver::OpCode + 'static>(
    stream: &Stream<S>,
    op: T,
) -> io::Result<usize> {
    match stream.file.address(op) {
        Ok(op) => super::zero_copy::send(op).await,
        Err((e, _)) => Err(e),
    }
}
