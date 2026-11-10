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
