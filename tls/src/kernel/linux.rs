//! The switch to kernel TLS, and the halves of a connection the kernel
//! encrypts.
//!
//! Once the handshake completes, the traffic secrets go to the socket
//! (`TCP_ULP "tls"`, then `TLS_TX` and `TLS_RX`), and the socket reads and
//! writes plaintext: data, `sendfile` and `splice` alike are sealed into
//! records by the kernel. What the kernel does not handle comes back to user
//! space:
//!
//! - A received record other than application data fails a plain read with
//!   `EIO`; `recvmsg` with a control buffer then returns it with its type
//!   (`TLS_GET_RECORD_TYPE`). A `close_notify` ends the stream, any other
//!   alert fails it, a TLS 1.3 `KeyUpdate` installs the peer's next key as
//!   the new `TLS_RX` (Linux 6.13 and later; older kernels refuse, and the
//!   read fails saying so), and a `NewSessionTicket` goes to rustls.
//! - A record we send other than data (a `close_notify`, a `KeyUpdate`)
//!   goes out with `sendmsg` and a `TLS_SET_RECORD_TYPE` control message.
//!   Our own `KeyUpdate`, which a requested update or the cipher's record
//!   limit calls for, is sent by the writing half before its next write, and
//!   only then is the next `TLS_TX` installed, so no data is sealed with a
//!   key the peer does not expect.

use std::{
    borrow::Borrow,
    cell::RefCell,
    fs::File,
    io, mem,
    net::{TcpListener, TcpStream},
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    rc::Rc,
};

use http_kit_io::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, Read, SendFile, Write, WriteControl};
use ktls_sys::bindings as uapi;
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion, kernel::KernelConnection};
use zeroize::Zeroize;

use super::KernelTls;
use crate::{
    engine::{Engine, copy_into, tls_error},
    record::{self, Boundary, CLOSE_NOTIFY, Cipher, Control, KEY_UPDATE, MAX_FRAGMENT, Message},
    side::Side,
};

/// What the halves share: rustls's key schedule, which both directions
/// advance.
pub(crate) struct Shared<D: Side> {
    conn: KernelConnection<D::Data>,
    version: ProtocolVersion,
    cipher: Cipher,
    /// The peer asked for our next key; it is sent before our next write.
    tx_update_owed: bool,
}

/// How the switch came out.
pub(crate) enum Switched<D: Side> {
    /// The kernel cannot take this connection; rustls keeps it.
    User(Engine<D>),
    /// The kernel has both directions, and these bytes were decrypted
    /// before it took over.
    Kernel(Box<Shared<D>>, Vec<u8>),
}

/// Moves a connection that finished its handshake to kernel TLS, when the
/// kernel supports its suite.
///
/// The kernel must start at a record boundary: everything buffered is
/// decrypted here first, and a record that only partly arrived is read to
/// its end, no further. The plaintext comes back to be read before the
/// socket.
pub(crate) async fn switch<D: Side, R: Read, W: Write + AsFd>(
    mut engine: Engine<D>,
    reader: &mut R,
    writer: &mut W,
    kernel: &KernelTls,
) -> io::Result<Switched<D>> {
    let version = engine
        .conn
        .protocol_version()
        .expect("a completed handshake has a version");
    let suite = engine
        .conn
        .negotiated_cipher_suite()
        .expect("a completed handshake has a cipher suite")
        .suite();
    let Some(cipher) = Cipher::of(suite).filter(|&cipher| kernel.supports(version, cipher)) else {
        tracing::debug!(?suite, ?version, "kernel TLS cannot take this suite");
        return Ok(Switched::User(engine));
    };
    if engine.peer_closed {
        return Ok(Switched::User(engine));
    }
    match setup_ulp(writer.as_fd()) {
        Ok(()) => {}
        Err(error) if ulp_unsupported(&error) => {
            // No `tls` module, or a socket that is not TCP. The ULP alone
            // changes nothing about the socket.
            tracing::debug!(%error, "the socket cannot take kernel TLS");
            return Ok(Switched::User(engine));
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => {
            // The ULP attaches only to an established connection, and the
            // peer has already closed this one. Nothing has changed on the
            // socket; rustls serves what is left and reports how it ended.
            tracing::debug!("the peer closed before kernel TLS could take over");
            return Ok(Switched::User(engine));
        }
        Err(error) => return Err(kernel_error("could not set TCP_ULP \"tls\"", &error)),
    }
    loop {
        engine.pump()?;
        if engine.peer_closed {
            return Ok(Switched::User(engine));
        }
        match record::boundary(&engine.incoming) {
            Boundary::Reached => break,
            Boundary::Short(missing) => engine.fill(reader, missing).await?,
            Boundary::Held => {
                tracing::debug!(
                    "rustls holds part of a handshake message; kernel TLS cannot start here"
                );
                return Ok(Switched::User(engine));
            }
        }
    }
    // Records reading produced (a key update's answer) leave before the
    // kernel seals anything.
    engine.owed.send(writer).await?;
    let carried = engine.take_unread();
    let (secrets, conn) = D::into_kernel(engine.conn).map_err(tls_error)?;
    let fd = writer.as_fd();
    install(fd, Direction::Tx, version, secrets.tx)?;
    install(fd, Direction::Rx, version, secrets.rx)?;
    tracing::trace!(
        ?suite,
        ?version,
        carried = carried.len(),
        "kernel TLS installed"
    );
    Ok(Switched::Kernel(
        Box::new(Shared {
            conn,
            version,
            cipher,
            tx_update_owed: false,
        }),
        carried,
    ))
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Tx,
    Rx,
}

fn kernel_error(what: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("kernel TLS: {what}: {error}"))
}

/// Attaches the `tls` upper layer protocol to a connected TCP socket.
fn setup_ulp(fd: BorrowedFd<'_>) -> io::Result<()> {
    const NAME: &[u8] = b"tls";
    // SAFETY: `NAME` is `NAME.len()` readable bytes, live across the call.
    let ret = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_ULP,
            NAME.as_ptr().cast(),
            NAME.len() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the ULP was refused because the kernel or the socket cannot do
/// kernel TLS at all, which leaves the connection in user space.
fn ulp_unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENOENT | libc::ENOPROTOOPT | libc::EOPNOTSUPP)
    )
}

/// The `tls12_crypto_info_*` structs the kernel takes, by cipher.
enum CryptoInfo {
    Aes128Gcm(uapi::tls12_crypto_info_aes_gcm_128),
    Aes256Gcm(uapi::tls12_crypto_info_aes_gcm_256),
    Chacha20Poly1305(uapi::tls12_crypto_info_chacha20_poly1305),
}

impl CryptoInfo {
    /// The kernel's form of rustls's traffic secrets.
    fn from_secrets(
        version: ProtocolVersion,
        seq: u64,
        secrets: &ConnectionTrafficSecrets,
    ) -> io::Result<Self> {
        let (cipher, key, iv) = match secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                (Cipher::Aes128Gcm, key.as_ref(), iv.as_ref())
            }
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
                (Cipher::Aes256Gcm, key.as_ref(), iv.as_ref())
            }
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
                (Cipher::Chacha20Poly1305, key.as_ref(), iv.as_ref())
            }
            _ => return Err(io::Error::other("the negotiated keys have no kernel form")),
        };
        Self::new(version, seq, cipher, key, iv)
    }

    /// A direction's key, 12-byte nonce IV and sequence number.
    ///
    /// For AES-GCM the kernel wants the nonce IV split into a 4-byte salt and
    /// the 8-byte explicit IV; ChaCha20-Poly1305 takes it whole.
    fn new(
        version: ProtocolVersion,
        seq: u64,
        cipher: Cipher,
        key: &[u8],
        iv: &[u8],
    ) -> io::Result<Self> {
        let version = match version {
            ProtocolVersion::TLSv1_2 => {
                (uapi::TLS_1_2_VERSION_MAJOR << 8 | uapi::TLS_1_2_VERSION_MINOR) as u16
            }
            ProtocolVersion::TLSv1_3 => {
                (uapi::TLS_1_3_VERSION_MAJOR << 8 | uapi::TLS_1_3_VERSION_MINOR) as u16
            }
            version => {
                return Err(io::Error::other(format!(
                    "kernel TLS cannot take {version:?}"
                )));
            }
        };
        let header = |cipher_type: u32| uapi::tls_crypto_info {
            version,
            cipher_type: cipher_type as u16,
        };
        let rec_seq = seq.to_be_bytes();
        Ok(match cipher {
            Cipher::Aes128Gcm => {
                let mut info = uapi::tls12_crypto_info_aes_gcm_128 {
                    info: header(uapi::TLS_CIPHER_AES_GCM_128),
                    iv: [0; 8],
                    key: [0; 16],
                    salt: [0; 4],
                    rec_seq,
                };
                info.salt.copy_from_slice(&iv[..4]);
                info.iv.copy_from_slice(&iv[4..]);
                info.key.copy_from_slice(key);
                Self::Aes128Gcm(info)
            }
            Cipher::Aes256Gcm => {
                let mut info = uapi::tls12_crypto_info_aes_gcm_256 {
                    info: header(uapi::TLS_CIPHER_AES_GCM_256),
                    iv: [0; 8],
                    key: [0; 32],
                    salt: [0; 4],
                    rec_seq,
                };
                info.salt.copy_from_slice(&iv[..4]);
                info.iv.copy_from_slice(&iv[4..]);
                info.key.copy_from_slice(key);
                Self::Aes256Gcm(info)
            }
            Cipher::Chacha20Poly1305 => {
                let mut info = uapi::tls12_crypto_info_chacha20_poly1305 {
                    info: header(uapi::TLS_CIPHER_CHACHA20_POLY1305),
                    iv: [0; 12],
                    key: [0; 32],
                    salt: uapi::__IncompleteArrayField::new(),
                    rec_seq,
                };
                info.iv.copy_from_slice(iv);
                info.key.copy_from_slice(key);
                Self::Chacha20Poly1305(info)
            }
        })
    }

    /// The struct's bytes, as `setsockopt` takes them.
    fn bytes_mut(&mut self) -> &mut [u8] {
        fn bytes<T>(info: &mut T) -> &mut [u8] {
            // SAFETY: the kernel structs are `repr(C)` and made only of byte
            // arrays and `u16`s with no padding, so every byte of them is
            // initialized.
            unsafe { std::slice::from_raw_parts_mut((info as *mut T).cast(), mem::size_of::<T>()) }
        }
        match self {
            Self::Aes128Gcm(info) => bytes(info),
            Self::Aes256Gcm(info) => bytes(info),
            Self::Chacha20Poly1305(info) => bytes(info),
        }
    }

    /// Hands the key to the kernel under `option` (`TLS_TX` or `TLS_RX`).
    fn set(&mut self, fd: BorrowedFd<'_>, option: u32) -> io::Result<()> {
        let bytes = self.bytes_mut();
        // SAFETY: `bytes` is `bytes.len()` readable bytes, live across the
        // call.
        let ret = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_TLS,
                option as libc::c_int,
                bytes.as_ptr().cast(),
                bytes.len() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for CryptoInfo {
    fn drop(&mut self) {
        // The kernel holds its own copy; ours must not outlive the call.
        self.bytes_mut().zeroize();
    }
}

/// What the kernel takes for one TLS version.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Suites {
    pub(crate) aes_128_gcm: bool,
    pub(crate) aes_256_gcm: bool,
    pub(crate) chacha20_poly1305: bool,
}

impl Suites {
    const fn any(self) -> bool {
        self.aes_128_gcm || self.aes_256_gcm || self.chacha20_poly1305
    }
}

/// What the kernel takes, per TLS version.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ciphers {
    pub(crate) tls12: Suites,
    pub(crate) tls13: Suites,
}

/// Asks the kernel which suites it takes a key for, on loopback sockets.
/// `None` when it has no TLS offload at all.
pub(crate) fn probe() -> io::Result<Option<Ciphers>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    let mut ciphers = Ciphers {
        tls12: Suites::default(),
        tls13: Suites::default(),
    };
    for (version, suites) in [
        (ProtocolVersion::TLSv1_2, &mut ciphers.tls12),
        (ProtocolVersion::TLSv1_3, &mut ciphers.tls13),
    ] {
        for (cipher, key_len, flag) in [
            (Cipher::Aes128Gcm, 16, &mut suites.aes_128_gcm),
            (Cipher::Aes256Gcm, 32, &mut suites.aes_256_gcm),
            (Cipher::Chacha20Poly1305, 32, &mut suites.chacha20_poly1305),
        ] {
            // Each try gets a socket of its own, as a ULP attaches once.
            let stream = TcpStream::connect(addr)?;
            match setup_ulp(stream.as_fd()) {
                Ok(()) => {}
                Err(error) if ulp_unsupported(&error) => return Ok(None),
                Err(error) => {
                    return Err(kernel_error("could not probe TCP_ULP \"tls\"", &error));
                }
            }
            let mut info = CryptoInfo::new(version, 0, cipher, &[0; 32][..key_len], &[0; 12])?;
            *flag = info.set(stream.as_fd(), uapi::TLS_TX).is_ok();
        }
    }
    if !ciphers.tls12.any() && !ciphers.tls13.any() {
        tracing::debug!("the kernel has TLS offload but takes no suite");
        return Ok(None);
    }
    Ok(Some(ciphers))
}

/// Installs a direction's key and sequence number on the socket.
fn install(
    fd: BorrowedFd<'_>,
    direction: Direction,
    version: ProtocolVersion,
    (seq, secrets): (u64, ConnectionTrafficSecrets),
) -> io::Result<()> {
    let option = match direction {
        Direction::Tx => uapi::TLS_TX,
        Direction::Rx => uapi::TLS_RX,
    };
    // `secrets` zeroizes its key on drop (rustls's `AeadKey`), and the
    // kernel's form of it zeroizes itself.
    CryptoInfo::from_secrets(version, seq, &secrets)
        .and_then(|mut info| info.set(fd, option))
        .map_err(|error| kernel_error(&format!("could not install the {direction:?} key"), &error))
}

/// A key update the kernel refused to install.
fn rekey_error(error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{error} (the peer changed TLS 1.3 keys; kernel TLS takes a new key from Linux 6.13 on)"
        ),
    )
}

pub(crate) fn split<R, W, D: Side>(
    shared: Box<Shared<D>>,
    carried: Vec<u8>,
    io: (R, W),
) -> (Reader<R, D>, Writer<W, D>) {
    let shared = Rc::new(RefCell::new(*shared));
    (
        Reader {
            io: io.0,
            shared: shared.clone(),
            carried,
            carried_read: 0,
            closed: false,
            record: Vec::new(),
        },
        Writer {
            io: io.1,
            shared,
            records: 0,
        },
    )
}

/// The reading half: plain reads of the socket, and the records the kernel
/// hands back.
pub(crate) struct Reader<R, D: Side> {
    io: R,
    shared: Rc<RefCell<Shared<D>>>,
    /// Plaintext rustls decrypted before the switch, read first.
    carried: Vec<u8>,
    carried_read: usize,
    /// The peer sent `close_notify`.
    closed: bool,
    /// The last record other than data.
    record: Vec<u8>,
}

impl<R, D: Side> Reader<R, D> {
    pub(crate) const fn get_ref(&self) -> &R {
        &self.io
    }
}

impl<R: Read + AsFd, D: Side> Reader<R, D> {
    pub(crate) async fn read<B: IoBufMut>(&mut self, mut buf: B) -> BufResult<usize, B> {
        if buf.as_uninit().is_empty() {
            return BufResult(Ok(0), buf);
        }
        if self.carried_read < self.carried.len() {
            let n = copy_into(buf.as_uninit(), &self.carried[self.carried_read..]);
            self.carried_read += n;
            if self.carried_read == self.carried.len() {
                self.carried = Vec::new();
                self.carried_read = 0;
            }
            // SAFETY: `copy_into` initialized the first `n` bytes.
            unsafe { buf.set_len(n) };
            return BufResult(Ok(n), buf);
        }
        loop {
            if self.closed {
                // SAFETY: an empty length initializes nothing.
                unsafe { buf.set_len(0) };
                return BufResult(Ok(0), buf);
            }
            let BufResult(res, returned) = self.io.read(buf).await;
            buf = returned;
            match res {
                Ok(0) => {
                    return BufResult(
                        Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the peer closed the connection without a TLS close_notify",
                        )),
                        buf,
                    );
                }
                Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                    if let Err(error) = self.control() {
                        return BufResult(Err(error), buf);
                    }
                }
                res => return BufResult(res, buf),
            }
        }
    }

    /// Takes the record that failed the read, and does what it asks.
    fn control(&mut self) -> io::Result<()> {
        let content_type = recv_record(self.io.as_fd(), &mut self.record)?;
        let mut shared = self.shared.borrow_mut();
        let shared = &mut *shared;
        match record::parse(content_type, &self.record, shared.version)? {
            Control::CloseNotify => self.closed = true,
            Control::Ignored => {}
            Control::Handshake(messages) => {
                for message in messages {
                    match message {
                        Message::KeyUpdate { update_requested } => {
                            let next = shared.conn.update_rx_secret().map_err(tls_error)?;
                            install(self.io.as_fd(), Direction::Rx, shared.version, next)
                                .map_err(rekey_error)?;
                            shared.tx_update_owed |= update_requested;
                        }
                        Message::NewSessionTicket(ticket) => {
                            D::new_session_ticket(&mut shared.conn, ticket).map_err(tls_error)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Receives the record the kernel holds back, returning its content type.
fn recv_record(fd: BorrowedFd<'_>, record: &mut Vec<u8>) -> io::Result<u8> {
    record.clear();
    record.reserve(MAX_FRAGMENT);
    // `u64`s, so the buffer is aligned for a `cmsghdr`.
    let mut control = [0_u64; 8];
    let mut iov = libc::iovec {
        iov_base: record.as_mut_ptr().cast(),
        iov_len: record.capacity(),
    };
    // SAFETY: an all-zero `msghdr` is valid; the fields used are set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &raw mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control) as _;
    // SAFETY: `msg` points at a buffer of `iov_len` bytes and a control
    // buffer of `msg_controllen` bytes, both live across the call. The
    // record is already decrypted, so the call does not wait.
    let n = unsafe { libc::recvmsg(fd.as_raw_fd(), &raw mut msg, libc::MSG_DONTWAIT) };
    let n = usize::try_from(n).map_err(|_| io::Error::last_os_error())?;
    // SAFETY: `recvmsg` initialized the first `n` bytes.
    unsafe { record.set_len(n) };
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::other("kernel TLS truncated a record's type"));
    }
    // SAFETY: `msg` is the header `recvmsg` filled in.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&raw const msg) };
    if cmsg.is_null() {
        return Err(io::Error::other(
            "kernel TLS failed a read but returned no record type",
        ));
    }
    // SAFETY: a non-null `CMSG_FIRSTHDR` points at a header inside `control`.
    let (level, kind) = unsafe { ((*cmsg).cmsg_level, (*cmsg).cmsg_type) };
    if level != libc::SOL_TLS || kind != libc::TLS_GET_RECORD_TYPE {
        return Err(io::Error::other(format!(
            "kernel TLS returned an unexpected control message ({level}, {kind})"
        )));
    }
    // SAFETY: `TLS_GET_RECORD_TYPE` carries one byte of data.
    Ok(unsafe { *libc::CMSG_DATA(cmsg) })
}

/// A control-message buffer giving the record type of one `sendmsg`.
fn record_type(content_type: ContentType) -> Vec<u8> {
    // SAFETY: `CMSG_SPACE` and `CMSG_LEN` only compute sizes.
    let (space, len, data) = unsafe {
        (
            libc::CMSG_SPACE(1) as usize,
            libc::CMSG_LEN(1),
            libc::CMSG_LEN(0) as usize,
        )
    };
    let mut control = vec![0_u8; space];
    // SAFETY: an all-zero `cmsghdr` is valid; the fields used are set below.
    let mut header: libc::cmsghdr = unsafe { mem::zeroed() };
    header.cmsg_level = libc::SOL_TLS;
    header.cmsg_type = libc::TLS_SET_RECORD_TYPE;
    header.cmsg_len = len as _;
    // SAFETY: `control` is `CMSG_SPACE(1)` bytes, room for the header; the
    // write does not need alignment.
    unsafe {
        control
            .as_mut_ptr()
            .cast::<libc::cmsghdr>()
            .write_unaligned(header)
    };
    control[data] = u8::from(content_type);
    control
}

/// Sends one record other than data through the kernel.
async fn send_record<W: WriteControl>(
    io: &mut W,
    content_type: ContentType,
    payload: &[u8],
) -> io::Result<()> {
    let BufResult(res, _) = io
        .write_control(payload.to_vec(), record_type(content_type))
        .await;
    match res? {
        n if n == payload.len() => Ok(()),
        n => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!(
                "kernel TLS took {n} bytes of a {}-byte {content_type:?} record",
                payload.len()
            ),
        )),
    }
}

/// The writing half: plain writes and file transfers, sealed by the kernel.
pub(crate) struct Writer<W, D: Side> {
    io: W,
    shared: Rc<RefCell<Shared<D>>>,
    /// The most records sealed under the current key.
    records: u64,
}

impl<W, D: Side> Writer<W, D> {
    pub(crate) const fn get_ref(&self) -> &W {
        &self.io
    }
}

impl<W: Write + SendFile + WriteControl + AsFd, D: Side> Writer<W, D> {
    /// Moves to our next key before `len` more bytes go out, if the peer
    /// asked for it or they could take the key past its record limit.
    async fn prepare(&mut self, len: usize) -> io::Result<()> {
        let (owed, version, limit) = {
            let shared = RefCell::borrow(&self.shared);
            (
                shared.tx_update_owed,
                shared.version,
                shared.cipher.record_limit(),
            )
        };
        let exhausted = self.records.saturating_add(record::records_for(len)) > limit;
        if !owed && !exhausted {
            return Ok(());
        }
        if version != ProtocolVersion::TLSv1_3 {
            return Err(io::Error::other(
                "the TLS 1.2 connection sealed as many records as one key allows, \
                 and TLS 1.2 cannot change keys",
            ));
        }
        send_record(&mut self.io, ContentType::Handshake, &KEY_UPDATE).await?;
        let mut shared = self.shared.borrow_mut();
        let next = shared.conn.update_tx_secret().map_err(tls_error)?;
        install(self.io.as_fd(), Direction::Tx, shared.version, next).map_err(rekey_error)?;
        shared.tx_update_owed = false;
        self.records = 0;
        Ok(())
    }

    fn count(&mut self, res: &io::Result<usize>) {
        if let Ok(n) = res {
            self.records = self.records.saturating_add(record::records_for(*n));
        }
    }

    pub(crate) async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        if let Err(error) = self.prepare(buf.buf_len()).await {
            return BufResult(Err(error), buf);
        }
        let res = self.io.write(buf).await;
        self.count(&res.0);
        res
    }

    pub(crate) async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        if let Err(error) = self.prepare(buf.total_len()).await {
            return BufResult(Err(error), buf);
        }
        let res = self.io.write_vectored(buf).await;
        self.count(&res.0);
        res
    }

    pub(crate) async fn flush(&mut self) -> io::Result<()> {
        self.io.flush().await
    }

    pub(crate) async fn shutdown(&mut self) -> io::Result<()> {
        send_record(&mut self.io, ContentType::Alert, &CLOSE_NOTIFY).await?;
        self.io.shutdown().await
    }

    /// The socket's own file-to-socket path: `splice` or `sendfile` into a
    /// socket the kernel encrypts.
    pub(crate) async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        if let Err(error) = self.prepare(len).await {
            return BufResult(Err(error), file);
        }
        let res = self.io.send_file(file, offset, len).await;
        self.count(&res.0);
        res
    }
}
