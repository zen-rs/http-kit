//! `WSARecvMsg` for the readiness implementations, whose sockets expose no
//! `recvmsg`. (compio's driver calls it itself.)

use std::{
    io,
    mem::{self, MaybeUninit},
    os::windows::io::{AsRawSocket, BorrowedSocket},
    ptr,
};

use socket2::{SockAddr, SockAddrStorage, socklen_t};
use windows_sys::{
    Win32::{
        Networking::WinSock::{
            LPFN_WSARECVMSG, LPWSAOVERLAPPED_COMPLETION_ROUTINE,
            SIO_GET_EXTENSION_FUNCTION_POINTER, SOCKADDR, SOCKET, SOCKET_ERROR, WSABUF,
            WSAEMSGSIZE, WSAID_WSARECVMSG, WSAIoctl, WSAMSG,
        },
        System::IO::OVERLAPPED,
    },
    core::GUID,
};

/// `WSARecvMsg`, which Winsock hands out by pointer (through
/// `SIO_GET_EXTENSION_FUNCTION_POINTER`) instead of exporting it. The
/// pointer is looked up once, when a socket is adopted, and travels with it.
#[derive(Clone, Copy)]
pub(crate) struct RecvMsg(
    unsafe extern "system" fn(
        SOCKET,
        *mut WSAMSG,
        *mut u32,
        *mut OVERLAPPED,
        LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    ) -> i32,
);

impl RecvMsg {
    /// Looks `WSARecvMsg` up through `socket`'s provider.
    ///
    /// # Errors
    ///
    /// Fails if the provider does not have it.
    pub(crate) fn load(socket: BorrowedSocket<'_>) -> io::Result<Self> {
        let guid: GUID = WSAID_WSARECVMSG;
        let mut function: LPFN_WSARECVMSG = None;
        let mut returned = 0;
        // SAFETY: `guid` is a valid input buffer of the size passed, and
        // `function` a valid output buffer for one function pointer, whose
        // size is passed; no overlapped operation or completion routine.
        let ret = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                SIO_GET_EXTENSION_FUNCTION_POINTER,
                (&raw const guid).cast(),
                mem::size_of::<GUID>() as u32,
                (&raw mut function).cast(),
                mem::size_of_val(&function) as u32,
                &raw mut returned,
                ptr::null_mut(),
                None,
            )
        };
        if ret == SOCKET_ERROR {
            return Err(io::Error::last_os_error());
        }
        function.map(Self).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "the network provider has no WSARecvMsg",
            )
        })
    }

    /// One non-blocking `WSARecvMsg` into `data` and `control`: the bytes
    /// received, the bytes of control data, and the sender. Like
    /// `recv_from`, a datagram longer than `data` is truncated, not an
    /// error.
    ///
    /// # Errors
    ///
    /// Fails with [`io::ErrorKind::WouldBlock`] if no datagram is queued.
    pub(crate) fn recv(
        &self,
        socket: BorrowedSocket<'_>,
        data: &mut [MaybeUninit<u8>],
        control: &mut [MaybeUninit<u8>],
    ) -> io::Result<(usize, usize, SockAddr)> {
        let mut from = SockAddrStorage::zeroed();
        let mut buffer = WSABUF {
            len: data.len().min(u32::MAX as usize) as u32,
            buf: data.as_mut_ptr().cast(),
        };
        let mut msg = WSAMSG {
            name: (&raw mut from).cast::<SOCKADDR>(),
            namelen: mem::size_of::<SockAddrStorage>() as socklen_t,
            lpBuffers: &raw mut buffer,
            dwBufferCount: 1,
            Control: WSABUF {
                len: control.len().min(u32::MAX as usize) as u32,
                buf: control.as_mut_ptr().cast(),
            },
            dwFlags: 0,
        };
        let mut received = 0;
        // SAFETY: `msg` points at `from`, `buffer` and the two slices, all
        // alive and writable for the call, with the lengths it states; the
        // socket is non-blocking, so with no overlapped operation or
        // completion routine the call returns at once.
        let ret = unsafe {
            (self.0)(
                socket.as_raw_socket() as SOCKET,
                &raw mut msg,
                &raw mut received,
                ptr::null_mut(),
                None,
            )
        };
        if ret == SOCKET_ERROR {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(WSAEMSGSIZE) {
                return Err(err);
            }
        }
        // SAFETY: the call stored `msg.namelen` bytes of address in `from`
        // (a datagram socket always reports its sender).
        let from = unsafe { SockAddr::new(from, msg.namelen) };
        Ok((received as usize, msg.Control.len as usize, from))
    }
}
