//! Linux platform calls: UDP segmentation offload and receive coalescing,
//! and the kernel file-to-socket paths.

use std::{
    io,
    mem::{self, MaybeUninit},
    num::NonZeroU16,
    os::fd::{AsRawFd, BorrowedFd},
    ptr, slice,
};

use compio_buf::{IoBuf, IoBufMut, SetLen};

/// The most segments one GSO send may carry (`UDP_MAX_SEGMENTS` in
/// `include/linux/udp.h`).
const UDP_MAX_SEGMENTS: usize = 64;

/// The GSO segment limit on `socket`: [`UDP_MAX_SEGMENTS`] where the kernel
/// supports `UDP_SEGMENT` (Linux 4.18 and later), `1` where it does not.
///
/// # Errors
///
/// Fails on any error other than the option being unknown to the kernel.
pub(crate) fn max_gso_segments(socket: BorrowedFd<'_>) -> io::Result<usize> {
    let mut value: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are valid out-pointers of the sizes passed.
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_SEGMENT,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if ret == 0 {
        return Ok(UDP_MAX_SEGMENTS);
    }
    unknown_option(io::Error::last_os_error()).map(|()| 1)
}

/// Turns on receive coalescing (`UDP_GRO`, Linux 5.0 and later) for
/// `socket`, returning whether the kernel supports it.
///
/// # Errors
///
/// Fails on any error other than the option being unknown to the kernel.
pub(crate) fn enable_gro(socket: BorrowedFd<'_>) -> io::Result<bool> {
    let on: libc::c_int = 1;
    // SAFETY: `on` is a valid pointer to an option of the size passed.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_UDP,
            libc::UDP_GRO,
            (&raw const on).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        return Ok(true);
    }
    unknown_option(io::Error::last_os_error()).map(|()| false)
}

/// `Ok` if `err` says the kernel does not know the socket option.
fn unknown_option(err: io::Error) -> io::Result<()> {
    if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
        Ok(())
    } else {
        Err(err)
    }
}

/// Room for the one control message either direction carries: `UDP_SEGMENT`
/// (a `u16`) on send, `UDP_GRO` (a `c_int`) on receive.
// SAFETY: `CMSG_SPACE` is pure arithmetic.
const CONTROL_LEN: usize =
    unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as libc::c_uint) } as usize;

/// An owned control-message buffer, aligned for `cmsghdr` as `sendmsg` and
/// `recvmsg` require. Every byte is initialized.
#[repr(C, align(8))]
pub(crate) struct ControlBuf {
    bytes: [MaybeUninit<u8>; CONTROL_LEN],
    len: usize,
}

impl ControlBuf {
    /// An empty buffer to receive control messages into.
    pub(crate) fn new() -> Self {
        Self {
            bytes: [MaybeUninit::new(0); CONTROL_LEN],
            len: 0,
        }
    }

    /// The `UDP_SEGMENT` message asking the kernel to split a send into
    /// `size`-byte datagrams.
    pub(crate) fn segment(size: NonZeroU16) -> Self {
        let mut buf = Self::new();
        // SAFETY: `CMSG_SPACE` is pure arithmetic.
        let space = unsafe { libc::CMSG_SPACE(mem::size_of::<u16>() as libc::c_uint) } as usize;
        // SAFETY: an all-zero `msghdr` is a valid value.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_control = buf.bytes.as_mut_ptr().cast();
        hdr.msg_controllen = space as _;
        // SAFETY: the control area is `space <= CONTROL_LEN` bytes, aligned
        // for `cmsghdr`, so the first header and its `u16` payload fit in it.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const hdr);
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<u16>() as libc::c_uint) as _;
            ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), size.get());
        }
        buf.len = space;
        buf
    }

    /// The coalesced segment size from the first `len` bytes of control data
    /// a receive returned, or `None` if the kernel did not coalesce.
    pub(crate) fn gro_segment(&self, len: usize) -> Option<usize> {
        assert!(len <= CONTROL_LEN, "control length beyond the buffer");
        // SAFETY: an all-zero `msghdr` is a valid value.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_control = self.bytes.as_ptr().cast_mut().cast();
        hdr.msg_controllen = len as _;
        // SAFETY: `hdr` describes `len` initialized, aligned bytes of
        // control data; the macros return null or a header inside them.
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const hdr) };
        while !cmsg.is_null() {
            // SAFETY: as above, `cmsg` points at a header inside the data.
            let header = unsafe { &*cmsg };
            if header.cmsg_level == libc::SOL_UDP && header.cmsg_type == libc::UDP_GRO {
                // SAFETY: a `UDP_GRO` message carries one `c_int`.
                let size =
                    unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>()) };
                return Some(
                    usize::try_from(size).expect("the kernel reports a positive segment size"),
                );
            }
            // SAFETY: as above.
            cmsg = unsafe { libc::CMSG_NXTHDR(&raw const hdr, cmsg) };
        }
        None
    }
}

impl IoBuf for ControlBuf {
    fn as_init(&self) -> &[u8] {
        // SAFETY: every byte of `bytes` is initialized, and `len` never
        // exceeds it (`set_len` callers guarantee as much).
        unsafe { slice::from_raw_parts(self.bytes.as_ptr().cast(), self.len) }
    }
}

impl IoBufMut for ControlBuf {
    fn as_uninit(&mut self) -> &mut [MaybeUninit<u8>] {
        &mut self.bytes
    }
}

impl SetLen for ControlBuf {
    unsafe fn set_len(&mut self, len: usize) {
        debug_assert!(len <= CONTROL_LEN);
        self.len = len;
    }
}

/// One non-blocking `sendfile(2)` of up to `len` bytes of `file` at `offset`
/// to the stream socket `socket`.
#[cfg(any(feature = "tokio", feature = "async-io"))]
pub(crate) fn sendfile(
    socket: BorrowedFd<'_>,
    file: BorrowedFd<'_>,
    offset: u64,
    len: usize,
) -> io::Result<usize> {
    let mut offset = libc::off_t::try_from(offset)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "file offset exceeds off_t"))?;
    // SAFETY: both descriptors are open for the duration of the call and
    // `offset` is a valid in/out pointer.
    let sent =
        unsafe { libc::sendfile(socket.as_raw_fd(), file.as_raw_fd(), &raw mut offset, len) };
    usize::try_from(sent).map_err(|_| io::Error::last_os_error())
}

/// A pipe for `splice(2)`, with its capacity: a splice from a file into it
/// moves at most that many bytes.
#[cfg(feature = "compio")]
pub(crate) fn pipe() -> io::Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd, usize)> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let mut fds = [0; 2];
    // SAFETY: `fds` is a valid out-pointer for two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe2` succeeded, so both descriptors are open and ours.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: `F_GETPIPE_SZ` takes no argument and only reads the pipe.
    let capacity = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETPIPE_SZ) };
    let capacity = usize::try_from(capacity).map_err(|_| io::Error::last_os_error())?;
    Ok((read, write, capacity))
}
