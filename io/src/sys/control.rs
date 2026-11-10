//! Datagram control messages: the destination address of a received datagram
//! and the source address of a sent one (`IP_PKTINFO`, `IPV6_PKTINFO`), plus
//! Linux's segmentation offload (`UDP_SEGMENT`, `UDP_GRO`).
//!
//! The buffer, the parsed result and the send-side recipe are shared. What
//! differs is the wire layout: `cmsghdr` and its `CMSG_*` macros on Unix,
//! `WSACMSGHDR` and its `WSA_CMSG_*` macros on Windows, where receiving also
//! needs `WSARecvMsg`, which Winsock hands out by pointer (see `winsock`).

#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, BorrowedSocket};
use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    ptr, slice,
};

use compio_buf::{IoBuf, IoBufMut, SetLen};
#[cfg(windows)]
use windows_sys::Win32::Networking::WinSock::{
    CMSGHDR, IN_ADDR, IN_ADDR_0, IN_PKTINFO, IN6_ADDR, IN6_ADDR_0, IN6_PKTINFO, IP_PKTINFO,
    IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, IPV6_V6ONLY, SOCKET, getsockopt, setsockopt,
};

#[cfg(unix)]
const fn space<T>() -> usize {
    // SAFETY: `CMSG_SPACE` is pure arithmetic.
    unsafe { libc::CMSG_SPACE(mem::size_of::<T>() as libc::c_uint) as usize }
}

/// Room for every control message either direction carries: `UDP_SEGMENT`
/// (a `u16`) or `UDP_GRO` (a `c_int`), and one packet-info message of either
/// family.
#[cfg(unix)]
const CONTROL_LEN: usize =
    space::<libc::c_int>() + space::<libc::in_pktinfo>() + space::<libc::in6_pktinfo>();

/// `WSA_CMSGHDR_ALIGN`: Winsock pads a message's payload to the header's
/// alignment.
#[cfg(windows)]
const fn cmsghdr_align(length: usize) -> usize {
    let align = mem::align_of::<CMSGHDR>();
    (length + align - 1) & !(align - 1)
}

/// `WSA_CMSGDATA_ALIGN`: Winsock pads a message to the natural alignment
/// (`MAX_NATURAL_ALIGNMENT`, the size of a pointer).
#[cfg(windows)]
const fn cmsgdata_align(length: usize) -> usize {
    let align = mem::align_of::<usize>();
    (length + align - 1) & !(align - 1)
}

/// The size of a message header.
#[cfg(windows)]
const HEADER_LEN: usize = mem::size_of::<CMSGHDR>();

/// Where a message's payload starts (`WSA_CMSG_DATA`).
#[cfg(windows)]
const DATA_OFFSET: usize = cmsgdata_align(HEADER_LEN);

/// The bytes a message with a `T` payload takes up (`WSA_CMSG_SPACE`).
#[cfg(windows)]
const fn space<T>() -> usize {
    cmsgdata_align(HEADER_LEN + cmsghdr_align(mem::size_of::<T>()))
}

/// Room for one packet-info message of either family.
#[cfg(windows)]
const CONTROL_LEN: usize = space::<IN_PKTINFO>() + space::<IN6_PKTINFO>();

/// [`ControlBuf`]'s alignment is that of its `repr`; a message header must
/// not need more.
#[cfg(windows)]
const _: () = assert!(mem::align_of::<CMSGHDR>() <= mem::align_of::<ControlBuf>());

#[cfg(unix)]
fn set_int(
    socket: BorrowedFd<'_>,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    // SAFETY: `value` is a valid pointer to an option of the size passed.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn set_int(socket: BorrowedSocket<'_>, level: i32, name: i32, value: i32) -> io::Result<()> {
    // SAFETY: `value` is a valid pointer to an option of the size passed.
    let ret = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            name,
            (&raw const value).cast(),
            mem::size_of::<i32>() as i32,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn get_int(socket: BorrowedFd<'_>, level: libc::c_int, name: libc::c_int) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut len = mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `value` and `len` are valid out-pointers of the sizes passed.
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if ret == 0 {
        Ok(value)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn get_int(socket: BorrowedSocket<'_>, level: i32, name: i32) -> io::Result<i32> {
    let mut value: i32 = 0;
    let mut len = mem::size_of::<i32>() as i32;
    // SAFETY: `value` and `len` are valid out-pointers of the sizes passed.
    let ret = unsafe {
        getsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            name,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    if ret == 0 {
        Ok(value)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Asks the kernel to report the destination address of every datagram
/// `socket` receives. `local` is the socket's bound address, which names its
/// family. A dual-stack IPv6 socket also gets the IPv4 option, since IPv4
/// datagrams reach it through that.
///
/// # Errors
///
/// Fails if the kernel refuses an option.
#[cfg(unix)]
pub(crate) fn enable_pktinfo(socket: BorrowedFd<'_>, local: SocketAddr) -> io::Result<()> {
    match local {
        SocketAddr::V4(_) => set_int(socket, libc::IPPROTO_IP, libc::IP_PKTINFO, 1),
        SocketAddr::V6(_) => {
            set_int(socket, libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO, 1)?;
            // Darwin refuses `IP_PKTINFO` on an IPv6 socket and reports IPv4
            // datagrams through the IPv6 message with a mapped address.
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if get_int(socket, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)? == 0 {
                set_int(socket, libc::IPPROTO_IP, libc::IP_PKTINFO, 1)?;
            }
            Ok(())
        }
    }
}

/// Asks Winsock to report the destination address of every datagram `socket`
/// receives. `local` is the socket's bound address, which names its family.
/// A dual-stack IPv6 socket (`IPV6_V6ONLY` off; Windows sockets default to
/// on) also gets the IPv4 option, since IPv4 datagrams reach it through that.
///
/// # Errors
///
/// Fails if Winsock refuses an option.
#[cfg(windows)]
pub(crate) fn enable_pktinfo(socket: BorrowedSocket<'_>, local: SocketAddr) -> io::Result<()> {
    match local {
        SocketAddr::V4(_) => set_int(socket, IPPROTO_IP, IP_PKTINFO, 1),
        SocketAddr::V6(_) => {
            set_int(socket, IPPROTO_IPV6, IPV6_PKTINFO, 1)?;
            if get_int(socket, IPPROTO_IPV6, IPV6_V6ONLY)? == 0 {
                set_int(socket, IPPROTO_IP, IP_PKTINFO, 1)?;
            }
            Ok(())
        }
    }
}

/// What the control messages of one receive said.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Received {
    /// The coalesced segment size, if the kernel coalesced (Linux GRO).
    pub(crate) segment: Option<usize>,
    /// The address the datagram was sent to, with an IPv4-mapped IPv6
    /// address reported as the IPv4 address it stands for.
    pub(crate) destination: Option<IpAddr>,
}

/// An owned control-message buffer, aligned for the message header as
/// `sendmsg` and `recvmsg` require. Every byte is initialized.
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

    /// The messages for one send: `UDP_SEGMENT` asking the kernel to split
    /// it into `segment`-byte datagrams, and packet info naming `source` as
    /// the address to send from.
    pub(crate) fn send(segment: Option<NonZeroU16>, source: Option<IpAddr>) -> Self {
        let mut buf = Self::new();
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(size) = segment {
            buf.push(libc::SOL_UDP, libc::UDP_SEGMENT, size.get());
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        assert!(
            segment.is_none(),
            "segmented sends need segmentation offload"
        );
        if let Some(source) = source {
            buf.push_source(source);
        }
        buf
    }
}

#[cfg(unix)]
impl ControlBuf {
    /// Appends the packet-info message naming `source` as the address to
    /// send from.
    fn push_source(&mut self, source: IpAddr) {
        match source {
            IpAddr::V4(addr) => self.push(
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from(addr).to_be(),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                },
            ),
            IpAddr::V6(addr) => self.push(
                libc::IPPROTO_IPV6,
                libc::IPV6_PKTINFO,
                libc::in6_pktinfo {
                    ipi6_addr: libc::in6_addr {
                        s6_addr: addr.octets(),
                    },
                    ipi6_ifindex: 0,
                },
            ),
        }
    }

    /// Appends one control message carrying `value`.
    fn push<T>(&mut self, level: libc::c_int, kind: libc::c_int, value: T) {
        let space = space::<T>();
        assert!(self.len + space <= CONTROL_LEN, "control buffer is full");
        // SAFETY: `CMSG_LEN` is pure arithmetic.
        let cmsg_len = unsafe { libc::CMSG_LEN(mem::size_of::<T>() as libc::c_uint) };
        // SAFETY: `len` is a sum of `CMSG_SPACE`s, so it keeps the alignment
        // of the 8-aligned buffer, and the `space` bytes from it are inside
        // the buffer (asserted above): room for the header, its padding and
        // the payload. An all-zero `cmsghdr` is a valid value.
        unsafe {
            let at = self
                .bytes
                .as_mut_ptr()
                .add(self.len)
                .cast::<libc::cmsghdr>();
            let mut hdr: libc::cmsghdr = mem::zeroed();
            hdr.cmsg_level = level;
            hdr.cmsg_type = kind;
            hdr.cmsg_len = cmsg_len as _;
            ptr::write(at, hdr);
            ptr::write_unaligned(libc::CMSG_DATA(at).cast::<T>(), value);
        }
        self.len += space;
    }

    /// What the first `len` bytes of control data a receive returned say.
    pub(crate) fn parse(&self, len: usize) -> Received {
        assert!(len <= CONTROL_LEN, "control length beyond the buffer");
        let mut received = Received::default();
        // SAFETY: an all-zero `msghdr` is a valid value.
        let mut hdr: libc::msghdr = unsafe { mem::zeroed() };
        hdr.msg_control = self.bytes.as_ptr().cast_mut().cast();
        hdr.msg_controllen = len as _;
        // SAFETY: `hdr` describes `len` initialized, aligned bytes of
        // control data; the macros return null or a header inside them.
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const hdr) };
        while !cmsg.is_null() {
            // SAFETY: `cmsg` points at a header inside the data.
            let (level, kind) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
            // SAFETY (every read below): the kernel attaches a message of
            // each of these types with the payload the type defines.
            match (level, kind) {
                #[cfg(any(target_os = "linux", target_os = "android"))]
                (libc::SOL_UDP, libc::UDP_GRO) => {
                    let size =
                        unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>()) };
                    received.segment = Some(
                        usize::try_from(size).expect("the kernel reports a positive segment size"),
                    );
                }
                (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                    let info = unsafe {
                        ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in_pktinfo>())
                    };
                    received.destination = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        info.ipi_addr.s_addr,
                    ))));
                }
                (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                    let info = unsafe {
                        ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::in6_pktinfo>())
                    };
                    let addr = Ipv6Addr::from(info.ipi6_addr.s6_addr);
                    received.destination =
                        Some(addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4));
                }
                _ => {}
            }
            // SAFETY: as above.
            cmsg = unsafe { libc::CMSG_NXTHDR(&raw const hdr, cmsg) };
        }
        received
    }
}

#[cfg(windows)]
impl ControlBuf {
    /// Appends the packet-info message naming `source` as the address to
    /// send from. Winsock takes the address itself in `ipi_addr` and
    /// `ipi6_addr`, and interface 0 lets the stack choose the interface.
    fn push_source(&mut self, source: IpAddr) {
        match source {
            IpAddr::V4(addr) => self.push(
                IPPROTO_IP,
                IP_PKTINFO,
                IN_PKTINFO {
                    ipi_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(addr.octets()),
                        },
                    },
                    ipi_ifindex: 0,
                },
            ),
            IpAddr::V6(addr) => self.push(
                IPPROTO_IPV6,
                IPV6_PKTINFO,
                IN6_PKTINFO {
                    ipi6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 {
                            Byte: addr.octets(),
                        },
                    },
                    ipi6_ifindex: 0,
                },
            ),
        }
    }

    /// Appends one control message carrying `value`.
    fn push<T>(&mut self, level: i32, kind: i32, value: T) {
        let space = space::<T>();
        assert!(self.len + space <= CONTROL_LEN, "control buffer is full");
        let header = CMSGHDR {
            cmsg_len: DATA_OFFSET + mem::size_of::<T>(),
            cmsg_level: level,
            cmsg_type: kind,
        };
        // SAFETY: `len` is a sum of `WSA_CMSG_SPACE`s, each a multiple of the
        // natural alignment, so it keeps the alignment of the buffer, which
        // is at least the header's (asserted at the constant). The `space`
        // bytes from it are inside the buffer (asserted above): room for the
        // header, its padding and the payload at `DATA_OFFSET`.
        unsafe {
            let at = self.bytes.as_mut_ptr().add(self.len);
            ptr::write(at.cast::<CMSGHDR>(), header);
            ptr::write_unaligned(at.add(DATA_OFFSET).cast::<T>(), value);
        }
        self.len += space;
    }

    /// What the first `len` bytes of control data a receive returned say.
    pub(crate) fn parse(&self, len: usize) -> Received {
        assert!(len <= CONTROL_LEN, "control length beyond the buffer");
        let mut received = Received::default();
        let mut at = 0;
        // `WSA_CMSG_FIRSTHDR` and `WSA_CMSG_NXTHDR`: a message follows as
        // long as a header fits in what is left.
        while at + HEADER_LEN <= len {
            // SAFETY: the header's bytes `at..at + HEADER_LEN` are inside the
            // `len` initialized bytes (the loop condition); an unaligned read
            // needs no alignment.
            let header =
                unsafe { ptr::read_unaligned(self.bytes.as_ptr().add(at).cast::<CMSGHDR>()) };
            assert!(
                (HEADER_LEN..=len - at).contains(&header.cmsg_len),
                "the stack reports well-formed control messages"
            );
            match (header.cmsg_level, header.cmsg_type) {
                (IPPROTO_IP, IP_PKTINFO) => {
                    let info = self.payload::<IN_PKTINFO>(at, &header);
                    // SAFETY: every variant of the union is plain integers.
                    let octets = unsafe { info.ipi_addr.S_un.S_addr }.to_ne_bytes();
                    received.destination = Some(IpAddr::V4(Ipv4Addr::from(octets)));
                }
                (IPPROTO_IPV6, IPV6_PKTINFO) => {
                    let info = self.payload::<IN6_PKTINFO>(at, &header);
                    // SAFETY: every variant of the union is plain integers.
                    let addr = Ipv6Addr::from(unsafe { info.ipi6_addr.u.Byte });
                    received.destination =
                        Some(addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4));
                }
                _ => {}
            }
            at += cmsghdr_align(header.cmsg_len);
        }
        received
    }

    /// The payload of the message at `at`, which `header` heads.
    fn payload<T>(&self, at: usize, header: &CMSGHDR) -> T {
        assert!(
            header.cmsg_len >= DATA_OFFSET + mem::size_of::<T>(),
            "the control message is shorter than its type"
        );
        // SAFETY: the payload's bytes `at + DATA_OFFSET` for `size_of::<T>()`
        // lie inside the message, which `parse` checked lies inside the
        // initialized bytes; `T` is plain integers, valid in every bit
        // pattern, and an unaligned read needs no alignment.
        unsafe { ptr::read_unaligned(self.bytes.as_ptr().add(at + DATA_OFFSET).cast::<T>()) }
    }
}

impl IoBuf for ControlBuf {
    fn as_init(&self) -> &[u8] {
        // SAFETY: every byte of `bytes` is initialized, and `len` never
        // exceeds it (`push` and `set_len` callers guarantee as much).
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
