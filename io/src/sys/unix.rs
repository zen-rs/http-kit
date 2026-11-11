//! Unix-domain socket addresses.
//!
//! `std`'s address type has no constructor, so an address a driver reports as
//! raw `sockaddr` bytes is read back through a duplicate of the descriptor
//! wrapped in `std`'s own socket type.

use std::{
    io,
    os::{
        fd::{AsFd, OwnedFd},
        unix::net::{SocketAddr, UnixStream},
    },
};

fn duplicate(fd: impl AsFd) -> io::Result<OwnedFd> {
    fd.as_fd().try_clone_to_owned()
}

/// The address a listening socket is bound to, for a driver that reports it
/// as raw bytes.
#[cfg(feature = "compio")]
pub(crate) fn listener_addr(fd: impl AsFd) -> io::Result<SocketAddr> {
    std::os::unix::net::UnixListener::from(duplicate(fd)?).local_addr()
}

/// The local address of a connected socket.
pub(crate) fn local_addr(fd: impl AsFd) -> io::Result<SocketAddr> {
    UnixStream::from(duplicate(fd)?).local_addr()
}

/// The peer's address of a connected socket.
pub(crate) fn peer_addr(fd: impl AsFd) -> io::Result<SocketAddr> {
    UnixStream::from(duplicate(fd)?).peer_addr()
}

/// The open file a descriptor names, as `fstat(2)` identifies it: its device
/// and inode, which stay the same for as long as the descriptor names that
/// file and differ for any other file open at the same time.
///
/// A stream records its socket's at creation and compares before each use
/// of the descriptor's number, so that a number closed and reused behind the
/// stream's back (zen-rs/http-kit#159) fails at the use instead of moving
/// bytes to whatever file now holds it. It costs an `fstat` per use, so only
/// debug builds keep it.
#[cfg(all(feature = "compio", debug_assertions))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Identity {
    dev: libc::dev_t,
    ino: libc::ino_t,
    /// The file type bits of `st_mode`, which name what a reused number
    /// now holds.
    kind: libc::mode_t,
}

#[cfg(all(feature = "compio", debug_assertions))]
impl Identity {
    /// The identity of the file `fd` names.
    pub(crate) fn of(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<Self> {
        use std::os::fd::AsRawFd as _;

        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `stat` is valid for the write of one `struct stat`, and
        // `fd` is borrowed, so the call reads a descriptor that is open.
        if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `fstat` succeeded, so it filled `stat`.
        let stat = unsafe { stat.assume_init() };
        Ok(Self {
            dev: stat.st_dev,
            ino: stat.st_ino,
            kind: stat.st_mode & libc::S_IFMT,
        })
    }

    /// Panics unless `fd` still names the file `self` identifies.
    #[track_caller]
    pub(crate) fn check(self, fd: std::os::fd::BorrowedFd<'_>) {
        use std::os::fd::AsRawFd as _;

        match Self::of(fd) {
            Ok(now) if now == self => {}
            Ok(now) => panic!(
                "descriptor {} no longer names the stream's socket ({self:?}): it names a {} \
                 ({now:?}), so the number was closed and reused while the stream held it",
                fd.as_raw_fd(),
                now.kind_name(),
            ),
            Err(error) => panic!(
                "descriptor {} no longer names the stream's socket ({self:?}): {error}, so the \
                 number was closed while the stream held it",
                fd.as_raw_fd(),
            ),
        }
    }

    fn kind_name(self) -> &'static str {
        match self.kind {
            libc::S_IFSOCK => "socket",
            libc::S_IFREG => "regular file",
            libc::S_IFIFO => "pipe",
            libc::S_IFCHR => "character device",
            libc::S_IFDIR => "directory",
            libc::S_IFBLK => "block device",
            libc::S_IFLNK => "symbolic link",
            _ => "file of an unknown type",
        }
    }
}
