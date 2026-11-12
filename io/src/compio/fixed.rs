//! A ring's region of registered (fixed) buffers.
//!
//! The region is one anonymous mapping registered as the ring's buffer `0`,
//! so that any slices of it can go out in one vectored send: the kernel
//! requires every iovec of a send from registered buffers to lie in the one
//! buffer its index names (`io_vec_fill_bvec`). An allocator hands it out in
//! [`FixedBufMut`]s, which freeze into [`Bytes`] that any thread may hold and
//! drop.
//!
//! A zero-copy send from the region skips what a send from other memory
//! costs on each call: pinning every page (`zerocopy_fill_skb_from_iter`),
//! and charging them to the user's `RLIMIT_MEMLOCK` with a compare-and-swap
//! on a counter every thread's ring shares, undone by another at the
//! notification (`io_notif_account_mem`).

use std::{
    fmt, io,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd as _, OwnedFd, RawFd},
    ptr::NonNull,
    rc::Rc,
    sync::{Arc, Mutex},
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

/// A ring's region of registered buffers, which [`Compio::register_fixed_region`]
/// registers on the ring's thread. Clones share the region; it is `Send` and
/// `Sync`, but only the ring it was registered on can read into it or send
/// from it by its index.
///
/// [`Compio::register_fixed_region`]: super::Compio::register_fixed_region
#[derive(Clone)]
pub struct FixedRegion(Arc<Region>);

struct Region {
    base: NonNull<u8>,
    len: usize,
    /// Free space, in [`UNIT`]s. A lock, because a [`Bytes`] handed out of
    /// the region is `Send` and gives its span back from whatever thread
    /// drops it; the ring's thread is the only one that allocates, so the
    /// lock is contended only by such a release.
    allocator: Mutex<Allocator>,
    /// The ring the region is registered on: the thread, and the ring's
    /// descriptor, which a later ring on the thread may reuse; a send that
    /// then finds no registered buffer fails before sending anything, and the
    /// stream drops the region.
    ring: (ThreadId, RawFd),
    /// Whether the kernel takes a registered buffer on a vectored zero-copy
    /// send (Linux 6.15), as a probe at registration found.
    vectored: bool,
}

// SAFETY: the region is plain memory: each span is written only through the
// one `FixedBufMut` that holds it, and read through `Bytes` once frozen; the
// allocator is behind its lock.
unsafe impl Send for Region {}
// SAFETY: as above.
unsafe impl Sync for Region {}

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
        let base = NonNull::new(base.cast::<u8>()).expect("a mapping is not at address 0");
        let registered = Runtime::with_current(|runtime| {
            // SAFETY: the mapping is unmapped only once it is unregistered,
            // or never (`Region`'s `Drop`).
            unsafe {
                runtime.register_buffers(&[std::io::IoSliceMut::new(
                    std::slice::from_raw_parts_mut(base.as_ptr(), len),
                )])
            }
        });
        if let Err(error) = registered {
            // SAFETY: the mapping is unregistered and unused.
            unsafe { libc::munmap(base.as_ptr().cast(), len) };
            return Err(io::Error::new(
                error.kind(),
                format!("registering a region of {len} bytes: {error}"),
            ));
        }
        let mut region = Region {
            base,
            len,
            // offset-allocator's default bound on live allocations; past it
            // an allocation fails like one the region has no room for.
            allocator: Mutex::new(Allocator::new(units)),
            ring,
            vectored: false,
        };
        region.vectored = probe_vectored(&region).await?;
        Ok(Some(Self(Arc::new(region))))
    }

    /// The region's size in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len
    }

    /// Whether the region is empty, which a registered region never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }

    /// `len` bytes of the region to fill, or `None` when it has no room for
    /// them: the caller then uses memory of its own.
    #[must_use]
    pub fn alloc(&self, len: usize) -> Option<FixedBufMut> {
        FixedBufMut::alloc(Arc::clone(&self.0), len)
    }

    /// Reads `len` bytes of `file` from `offset` into the region, through
    /// reads into the registered buffer (`IORING_OP_READ_FIXED`), which pin
    /// nothing either. `None` when the region has no room for them.
    ///
    /// Call it on the region's ring.
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
                Err(e) => return Err(e),
            }
        }
        Ok(Some(buf.freeze()))
    }

    /// Whether the current thread's ring is the one the region is registered
    /// on, as far as its thread and descriptor tell.
    pub(super) fn is_current_ring(&self) -> bool {
        let (thread, fd) = self.0.ring;
        thread == std::thread::current().id()
            && Runtime::try_with_current(|runtime| runtime.as_raw_fd() == fd).unwrap_or(false)
    }

    /// Where in the region `slice` lies, if it lies in it whole.
    fn contains(&self, slice: &[u8]) -> bool {
        let base = self.0.base.as_ptr() as usize;
        let start = slice.as_ptr() as usize;
        start >= base && start + slice.len() <= base + self.0.len
    }
}

impl fmt::Debug for FixedRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixedRegion")
            .field("len", &self.0.len)
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
        if unregistered {
            // SAFETY: the mapping is unregistered, and nothing refers to it:
            // every buffer out of it holds the region.
            unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
        }
        // Otherwise the ring may still hold the mapping registered, and the
        // kernel would read and write whatever the address space later maps
        // there: the mapping stays, and goes with the process.
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
    // SAFETY: the unit lies in the mapping, which outlives the operation:
    // the caller holds the region until the probe returns, and the operation
    // completes before it does.
    let unit: &'static [u8] = unsafe { std::slice::from_raw_parts(region.base.as_ptr(), 1) };
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

/// A span of the region, given back once dropped, from any thread.
struct Lease {
    region: Arc<Region>,
    allocation: Allocation,
    offset: usize,
    capacity: usize,
}

impl FixedBufMut {
    fn alloc(region: Arc<Region>, len: usize) -> Option<Self> {
        let units = u32::try_from(len.div_ceil(UNIT).max(1)).ok()?;
        let allocation = region
            .allocator
            .lock()
            .expect("the region's allocator is not poisoned")
            .allocate(units)?;
        let offset = allocation.offset as usize * UNIT;
        Some(Self {
            lease: Lease {
                region,
                allocation,
                offset,
                capacity: len,
            },
            len: 0,
        })
    }

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
                    .region
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
        // SAFETY: the span lies in the mapping, which `region` keeps; the
        // mapping starts zeroed, so every byte is initialized.
        unsafe {
            std::slice::from_raw_parts(self.region.base.as_ptr().add(self.offset), self.capacity)
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.region
            .allocator
            .lock()
            .expect("the region's allocator is not poisoned")
            .free(self.allocation);
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
    for slice in buf.iter_slice().filter(|slice| !slice.is_empty()) {
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
        for slice in buf.iter_slice().filter(|slice| !region.contains(slice)) {
            span[at..at + slice.len()].copy_from_slice(slice);
            at += slice.len();
        }
        Some(span.freeze())
    };
    let mut slices = Vec::with_capacity(count);
    let mut copied_at = copied.as_ref().map_or(0, |copied| copied.as_ptr() as usize);
    for slice in buf.iter_slice().filter(|slice| !slice.is_empty()) {
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
    let mut refused = false;
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
            // The ring holds no such registered buffer: the region's ring is
            // gone and this is another one on the same thread and descriptor.
            // The kernel refused before sending anything, so the write goes
            // out the usual way, and the stream keeps away from the region.
            Err(e) if written == 0 && e.raw_os_error() == Some(libc::EFAULT) => {
                stream.drop_fixed_region();
                refused = true;
                break Err(e);
            }
            Err(e) => break Err(e),
        }
    };
    drop(parts);
    match Rc::into_inner(buf) {
        Some(buf) if refused => Sent::Declined(buf),
        buf => Sent::Done(BufResult(res, buf)),
    }
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
