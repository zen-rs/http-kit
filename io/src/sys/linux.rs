//! Linux platform calls: UDP segmentation offload and receive coalescing,
//! and the kernel file-to-socket paths.

use std::{
    io, mem,
    os::fd::{AsRawFd, BorrowedFd},
};

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
