//! rustls's unbuffered connection, and the buffers it reads from and writes
//! into.
//!
//! rustls keeps no ciphertext of its own: it deframes and decrypts the
//! records in the caller's buffer in place, and remembers how far it got by
//! offsets into that buffer. Every call into it therefore passes the same
//! buffer, [`Engine::incoming`], holding exactly the bytes it has not yet
//! told the caller to discard. That buffer is never lent to the kernel: a
//! read lands in a buffer of its own and is joined to it afterwards, so the
//! writing half can ask rustls to encrypt while a read is in flight.

use std::{fmt, io, mem, mem::MaybeUninit};

use http_kit_io::{BufResult, IntoInner as _, IoBuf as _, Read, Write};
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedStatus,
    WriteTraffic,
};

use crate::{error::Fault, side::Side};

/// The most one socket read asks for: four full records.
pub(crate) const READ_SIZE: usize = 4 * MAX_RECORD;

/// The largest record on the wire: a 16 KiB fragment, its 5-byte header and
/// the most expansion RFC 8446 §5.2 allows.
const MAX_RECORD: usize = 5 + (1 << 14) + 256;

/// A rustls failure as the I/O error an established stream reports.
#[cfg(all(target_os = "linux", feature = "kernel"))]
pub(crate) fn tls_error(error: rustls::Error) -> io::Error {
    Fault::Tls(error).into()
}

/// Copies as much of `src` into `dest` as fits, returning how much.
pub(crate) fn copy_into(dest: &mut [MaybeUninit<u8>], src: &[u8]) -> usize {
    let n = dest.len().min(src.len());
    dest[..n].write_copy_of_slice(&src[..n]);
    n
}

/// A connection's rustls state and the bytes around it.
pub struct Engine<D: Side> {
    pub(crate) conn: D::Connection,
    /// Ciphertext rustls has not yet had discarded.
    pub(crate) incoming: Vec<u8>,
    /// Decrypted bytes not yet read, from `plaintext_read` on.
    pub(crate) plaintext: Vec<u8>,
    plaintext_read: usize,
    /// Records rustls produced while reading (a key update's answer, an
    /// alert), owed to the peer ahead of anything encrypted after them.
    pub(crate) owed: Records,
    /// The peer sent `close_notify`.
    pub(crate) peer_closed: bool,
}

/// What a pass over the incoming records left the connection waiting for.
enum Waiting {
    /// Records rustls has queued need encoding; process again.
    Nothing,
    /// The incoming bytes are used up: more must be read.
    Input,
    /// Handshake records were encoded and must be sent now.
    Transmit,
    /// rustls can encrypt: the connection is past the handshake, or far
    /// enough into it to send its next flight.
    Writable,
}

impl<D: Side> Engine<D> {
    pub(crate) fn new(conn: D::Connection) -> Self {
        Self {
            conn,
            incoming: Vec::new(),
            plaintext: Vec::new(),
            plaintext_read: 0,
            owed: Records::default(),
            peer_closed: false,
        }
    }

    /// The decrypted bytes not yet read.
    pub(crate) fn unread(&self) -> &[u8] {
        &self.plaintext[self.plaintext_read..]
    }

    /// Takes all unread decrypted bytes.
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    pub(crate) fn take_unread(&mut self) -> Vec<u8> {
        let mut plaintext = mem::take(&mut self.plaintext);
        plaintext.drain(..mem::take(&mut self.plaintext_read));
        plaintext
    }

    /// Hands decrypted bytes to `dest`: those already decrypted first, then
    /// whatever the incoming records hold. Records that do not fit wait in
    /// [`plaintext`](Self::plaintext).
    pub(crate) fn read_into(&mut self, dest: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        let queued = copy_into(dest, self.unread());
        if queued > 0 {
            self.plaintext_read += queued;
            if self.plaintext_read == self.plaintext.len() {
                self.plaintext.clear();
                self.plaintext_read = 0;
            }
            return Ok(queued);
        }
        let mut delivered = 0;
        loop {
            match self.step(&mut dest[delivered..], &mut delivered)? {
                Waiting::Nothing | Waiting::Transmit => {}
                Waiting::Input | Waiting::Writable => return Ok(delivered),
            }
        }
    }

    /// Processes every complete record buffered, queueing what they decrypt
    /// to.
    #[cfg(all(target_os = "linux", feature = "kernel"))]
    pub(crate) fn pump(&mut self) -> Result<(), Fault> {
        let mut delivered = 0;
        loop {
            match self.step(&mut [], &mut delivered)? {
                Waiting::Nothing | Waiting::Transmit => {}
                Waiting::Input | Waiting::Writable => return Ok(()),
            }
        }
    }

    /// Runs `seal` with rustls ready to encrypt.
    pub(crate) fn with_writer<T>(
        &mut self,
        seal: impl FnOnce(&mut WriteTraffic<'_, D::Data>) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut seal = Some(seal);
        let mut delivered = 0;
        loop {
            let UnbufferedStatus { discard, state } =
                D::process(&mut self.conn, &mut self.incoming);
            let handled = match state {
                Ok(ConnectionState::WriteTraffic(mut writer)) => {
                    let seal = seal.take().expect("rustls is ready to encrypt once");
                    let sealed = seal(&mut writer);
                    self.incoming.drain(..discard);
                    return sealed;
                }
                state => {
                    let sink = Sink {
                        plaintext: &mut self.plaintext,
                        owed: &mut self.owed,
                        peer_closed: &mut self.peer_closed,
                    };
                    handle(state, sink, &mut [], &mut delivered)
                }
            };
            let waiting = self.discard(discard, handled)?;
            if matches!(waiting, Waiting::Input) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the TLS connection cannot send application data",
                ));
            }
        }
    }

    /// Encrypts `data` onto the end of `out`.
    pub(crate) fn encrypt(&mut self, data: &[u8], out: &mut Records) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.with_writer(|writer| out.append(|buf| writer.encrypt(data, buf)))
    }

    /// Encrypts a `close_notify` alert onto the end of `out`.
    pub(crate) fn close_notify(&mut self, out: &mut Records) -> io::Result<()> {
        self.with_writer(|writer| out.append(|buf| writer.queue_close_notify(buf)))
    }

    /// One call into rustls: what it asked for is done, `delivered` counts
    /// the bytes of `dest` decrypted records filled.
    fn step(
        &mut self,
        dest: &mut [MaybeUninit<u8>],
        delivered: &mut usize,
    ) -> Result<Waiting, Fault> {
        let UnbufferedStatus { discard, state } = D::process(&mut self.conn, &mut self.incoming);
        let sink = Sink {
            plaintext: &mut self.plaintext,
            owed: &mut self.owed,
            peer_closed: &mut self.peer_closed,
        };
        let handled = handle(state, sink, dest, delivered);
        self.discard(discard, handled)
    }

    /// Drops what rustls is done with from the front of the incoming bytes,
    /// whether or not handling its state succeeded.
    fn discard(
        &mut self,
        discard: usize,
        handled: Result<(Waiting, usize), Fault>,
    ) -> Result<Waiting, Fault> {
        match handled {
            Ok((waiting, more)) => {
                self.incoming.drain(..discard + more);
                Ok(waiting)
            }
            Err(error) => {
                self.incoming.drain(..discard);
                Err(error)
            }
        }
    }

    /// Reads more ciphertext straight onto the end of
    /// [`incoming`](Self::incoming), at most `limit` bytes. Only for when
    /// nothing else can call into rustls meanwhile: the handshake, and the
    /// switch to kernel TLS.
    pub(crate) async fn fill<R: Read>(&mut self, reader: &mut R, limit: usize) -> io::Result<()> {
        let len = self.incoming.len();
        self.incoming.reserve(limit);
        let BufResult(res, slice) = reader
            .read(mem::take(&mut self.incoming).slice(len..len + limit))
            .await;
        self.incoming = slice.into_inner();
        match res {
            Ok(0) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the peer closed the connection mid-handshake",
            )),
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Drives the handshake to its end, sending each flight as rustls
    /// produces it.
    pub(crate) async fn handshake<R: Read, W: Write>(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> Result<(), Fault> {
        let mut delivered = 0;
        loop {
            match self.step(&mut [], &mut delivered)? {
                Waiting::Nothing => {}
                Waiting::Transmit => self.owed.send(writer).await?,
                Waiting::Input => {
                    if !self.conn.is_handshaking() {
                        return Ok(());
                    }
                    if self.peer_closed {
                        return Err(Fault::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the peer closed the connection mid-handshake",
                        )));
                    }
                    self.fill(reader, READ_SIZE).await?;
                }
                Waiting::Writable if self.conn.is_handshaking() => {
                    // A server past its own Finished can write, but the
                    // handshake ends with the client's.
                    self.fill(reader, READ_SIZE).await?;
                }
                Waiting::Writable => {
                    self.owed.send(writer).await?;
                    return Ok(());
                }
            }
        }
    }
}

/// The fields a rustls state is handled into: everything but the connection
/// and the incoming bytes, which the state borrows.
struct Sink<'a> {
    plaintext: &'a mut Vec<u8>,
    owed: &'a mut Records,
    peer_closed: &'a mut bool,
}

/// Does what one rustls state asks, returning what the connection waits for
/// next and how many more incoming bytes the decrypted records free.
fn handle<Data>(
    state: Result<ConnectionState<'_, '_, Data>, rustls::Error>,
    sink: Sink<'_>,
    dest: &mut [MaybeUninit<u8>],
    delivered: &mut usize,
) -> Result<(Waiting, usize), Fault> {
    let mut discard = 0;
    let waiting = match state? {
        ConnectionState::ReadTraffic(mut traffic) => {
            let mut room = dest;
            while let Some(record) = traffic.next_record() {
                let record = record?;
                discard += record.discard;
                let n = copy_into(room, record.payload);
                room = &mut room[n..];
                *delivered += n;
                sink.plaintext.extend_from_slice(&record.payload[n..]);
            }
            Waiting::Nothing
        }
        ConnectionState::EncodeTlsData(mut encode) => {
            sink.owed.append(|buf| encode.encode(buf))?;
            Waiting::Nothing
        }
        ConnectionState::TransmitTlsData(transmit) => {
            // The encoded records wait in `owed`, which goes out before
            // anything encrypted later.
            transmit.done();
            Waiting::Transmit
        }
        ConnectionState::PeerClosed => {
            *sink.peer_closed = true;
            Waiting::Nothing
        }
        ConnectionState::Closed => {
            *sink.peer_closed = true;
            Waiting::Input
        }
        ConnectionState::BlockedHandshake => Waiting::Input,
        ConnectionState::WriteTraffic(_) => Waiting::Writable,
        ConnectionState::ReadEarlyData(_) => {
            return Err(Fault::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "TLS early data is not supported; set `max_early_data_size` to 0",
            )));
        }
        state => {
            return Err(Fault::Io(io::Error::other(format!(
                "unexpected TLS connection state {state:?}"
            ))));
        }
    };
    Ok((waiting, discard))
}

/// Encrypted records waiting to be written, in a buffer that stays
/// initialized between uses so rustls is never handed fresh zeroes.
#[derive(Default)]
pub(crate) struct Records {
    buf: Vec<u8>,
    len: usize,
}

/// How a rustls encoding call fell short.
pub(crate) enum Shortfall {
    /// The buffer needs at least this many bytes.
    Needs(usize),
    Failed(io::Error),
}

impl From<EncodeError> for Shortfall {
    fn from(error: EncodeError) -> Self {
        match error {
            EncodeError::InsufficientSize(InsufficientSizeError { required_size }) => {
                Self::Needs(required_size)
            }
            error => Self::Failed(io::Error::new(io::ErrorKind::InvalidData, error)),
        }
    }
}

impl From<EncryptError> for Shortfall {
    fn from(error: EncryptError) -> Self {
        match error {
            EncryptError::InsufficientSize(InsufficientSizeError { required_size }) => {
                Self::Needs(required_size)
            }
            error => Self::Failed(io::Error::new(io::ErrorKind::InvalidData, error)),
        }
    }
}

impl Records {
    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Appends what `encode` writes into the free space, growing it to the
    /// size rustls asks for.
    pub(crate) fn append<E: Into<Shortfall>>(
        &mut self,
        mut encode: impl FnMut(&mut [u8]) -> Result<usize, E>,
    ) -> io::Result<()> {
        loop {
            match encode(&mut self.buf[self.len..]).map_err(Into::into) {
                Ok(n) => {
                    self.len += n;
                    return Ok(());
                }
                Err(Shortfall::Needs(size)) if size > self.buf.len() - self.len => {
                    self.buf.resize(self.len + size, 0);
                }
                Err(Shortfall::Needs(size)) => {
                    return Err(io::Error::other(format!(
                        "rustls asked for {size} bytes and was given more"
                    )));
                }
                Err(Shortfall::Failed(error)) => return Err(error),
            }
        }
    }

    /// Moves `other`'s records onto the end of these.
    pub(crate) fn take_from(&mut self, other: &mut Self) {
        if other.is_empty() {
            return;
        }
        if self.is_empty() {
            mem::swap(self, other);
            return;
        }
        let end = self.len + other.len;
        if self.buf.len() < end {
            self.buf.resize(end, 0);
        }
        self.buf[self.len..end].copy_from_slice(other.as_slice());
        self.len = end;
        other.len = 0;
    }

    /// Writes every record out.
    pub(crate) async fn send<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        if self.is_empty() {
            return Ok(());
        }
        let buf = mem::take(&mut self.buf);
        let BufResult(res, slice) = writer.write_all(buf.slice(..self.len)).await;
        self.buf = slice.into_inner();
        self.len = 0;
        res
    }
}

impl<D: Side> fmt::Debug for Engine<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}
