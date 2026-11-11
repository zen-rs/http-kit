//! Pipes and `splice(2)`, which the splice API needs on Linux whichever
//! runtime is enabled, or none.

use std::{
    io,
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
};

/// A pipe for `splice(2)`, with its capacity: a splice into it moves at most
/// that many bytes.
pub(crate) fn pipe() -> io::Result<(OwnedFd, OwnedFd, usize)> {
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

/// Sets `O_NONBLOCK` on `fd`'s open file description.
#[cfg(feature = "compio")]
pub(crate) fn set_nonblocking(fd: BorrowedFd<'_>) -> io::Result<()> {
    let mut on: libc::c_int = 1;
    // SAFETY: `FIONBIO` reads one `c_int` through the pointer passed.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::FIONBIO, &raw mut on) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One `splice(2)` of up to `len` bytes from `from` to `to`, neither of
/// which has an offset (a pipe or a socket), that never waits:
/// `SPLICE_F_NONBLOCK` covers the pipe end, and a socket end must itself be
/// `O_NONBLOCK`, since a socket's wait is decided by its own flag alone
/// (`splice_to_socket` and `tcp_splice_read`). A call interrupted by a
/// signal is repeated.
#[cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]
pub(crate) fn splice(from: BorrowedFd<'_>, to: BorrowedFd<'_>, len: usize) -> io::Result<usize> {
    loop {
        // SAFETY: both descriptors are open for the duration of the call, and
        // the offsets are null, so the kernel writes through neither.
        let moved = unsafe {
            libc::splice(
                from.as_raw_fd(),
                std::ptr::null_mut(),
                to.as_raw_fd(),
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_NONBLOCK,
            )
        };
        match usize::try_from(moved) {
            Ok(moved) => return Ok(moved),
            Err(_) => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}

/// `read(2)` into `buf` from the read end of a pipe that holds at least
/// `buf.len()` bytes, so it never waits.
pub(crate) fn read_pipe(pipe: BorrowedFd<'_>, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        // SAFETY: `buf` is valid for writes of its length and the descriptor
        // is open for the duration of the call.
        let read = unsafe { libc::read(pipe.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        match usize::try_from(read) {
            Ok(read) => return Ok(read),
            Err(_) => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}
