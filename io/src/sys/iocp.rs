//! Errors of socket operations completed through an I/O completion port.

use std::io;

use windows_sys::Win32::{
    Foundation::{
        ERROR_CONNECTION_REFUSED, ERROR_HOST_UNREACHABLE, ERROR_NETWORK_UNREACHABLE,
        ERROR_PORT_UNREACHABLE,
    },
    Networking::WinSock::{WSAECONNREFUSED, WSAECONNRESET, WSAEHOSTUNREACH, WSAENETUNREACH},
};

/// The Winsock error a completed socket operation's Win32 error stands for.
///
/// A completion port reports the Win32 code an ICMP error maps to, where a
/// synchronous Winsock call (and `WSAGetOverlappedResult`) reports the
/// Winsock one. `io::ErrorKind` decodes only the latter, so without this an
/// unreachable peer surfaces as `Uncategorized` instead of a per-peer error.
pub(crate) fn socket_error(error: io::Error) -> io::Error {
    let winsock = match error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
    {
        Some(ERROR_PORT_UNREACHABLE) => WSAECONNRESET,
        Some(ERROR_HOST_UNREACHABLE) => WSAEHOSTUNREACH,
        Some(ERROR_NETWORK_UNREACHABLE) => WSAENETUNREACH,
        Some(ERROR_CONNECTION_REFUSED) => WSAECONNREFUSED,
        _ => return error,
    };
    io::Error::from_raw_os_error(winsock)
}
