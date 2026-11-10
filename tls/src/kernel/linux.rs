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
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    rc::Rc,
};

use http_kit_io::{BufResult, IoBuf, IoBufMut, IoVectoredBuf, Read, SendFile, Write, WriteControl};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion, kernel::KernelConnection};

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
    Kernel(Shared<D>, Vec<u8>),
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
    match ktls_core::setup_ulp(&writer.as_fd()) {
        Ok(()) => {}
        Err(ktls_core::Error::Ulp(error))
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT | libc::ENOPROTOOPT | libc::EOPNOTSUPP)
            ) =>
        {
            // No `tls` module, or a socket that is not TCP. The ULP alone
            // changes nothing about the socket.
            tracing::debug!(%error, "the socket cannot take kernel TLS");
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
        Shared {
            conn,
            version,
            cipher,
            tx_update_owed: false,
        },
        carried,
    ))
}

#[derive(Debug, Clone, Copy)]
enum Direction {
    Tx,
    Rx,
}

fn kernel_error(what: &str, error: &ktls_core::Error) -> io::Error {
    io::Error::other(format!("kernel TLS: {what}: {error}"))
}

/// Installs a direction's key and sequence number on the socket.
fn install(
    fd: BorrowedFd<'_>,
    direction: Direction,
    version: ProtocolVersion,
    (seq, secrets): (u64, ConnectionTrafficSecrets),
) -> io::Result<()> {
    let secrets = ktls_core::ConnectionTrafficSecrets::try_from(secrets)
        .map_err(|error| kernel_error("the negotiated keys have no kernel form", &error))?;
    let installed = match direction {
        Direction::Tx => ktls_core::TlsCryptoInfoTx::new(version.into(), secrets, seq)
            .and_then(|info| info.set(&fd)),
        Direction::Rx => ktls_core::TlsCryptoInfoRx::new(version.into(), secrets, seq)
            .and_then(|info| info.set(&fd)),
    };
    installed
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
    shared: Shared<D>,
    carried: Vec<u8>,
    io: (R, W),
) -> (Reader<R, D>, Writer<W, D>) {
    let shared = Rc::new(RefCell::new(shared));
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
            let shared = self.shared.borrow();
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
