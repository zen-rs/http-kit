//! What kernel TLS leaves to user space, as pure functions: which suites it
//! can take, where the record boundary is at the switch, and what a record
//! other than application data asks for.
//!
//! Nothing here touches a socket, so it is built and tested on every
//! platform even though only Linux runs it.

use std::io;

use rustls::{AlertDescription, CipherSuite, ContentType, HandshakeType, ProtocolVersion};

/// The record header: content type, legacy version, length.
const HEADER: usize = 5;

/// The largest plaintext fragment one record carries (RFC 8446 §5.1).
pub(crate) const MAX_FRAGMENT: usize = 1 << 14;

/// The AEAD a cipher suite seals records with, as kernel TLS names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cipher {
    Aes128Gcm,
    Aes256Gcm,
    Chacha20Poly1305,
}

impl Cipher {
    /// The AEAD of a TLS 1.2 or 1.3 suite kernel TLS can take.
    pub(crate) const fn of(suite: CipherSuite) -> Option<Self> {
        Some(match suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Self::Aes128Gcm,
            CipherSuite::TLS13_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Self::Aes256Gcm,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => Self::Chacha20Poly1305,
            _ => return None,
        })
    }

    /// How many records one key may seal. RFC 8446 §5.5 allows AES-GCM
    /// 2^24.5 full-size records; ChaCha20-Poly1305 has no practical limit.
    pub(crate) const fn record_limit(self) -> u64 {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm => 1 << 24,
            Self::Chacha20Poly1305 => u64::MAX,
        }
    }
}

/// The most records a write of `len` bytes can seal: one per full fragment,
/// and one more for a record a previous write left open.
pub(crate) const fn records_for(len: usize) -> u64 {
    len.div_ceil(MAX_FRAGMENT) as u64 + 1
}

/// Where the record that `incoming` ends inside is complete, for a buffer
/// that starts at a record boundary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Boundary {
    /// `incoming` is empty: the stream is at a record boundary.
    Reached,
    /// This many more bytes finish the header, or the record.
    Short(usize),
    /// `incoming` holds a whole record rustls kept: a handshake message it
    /// is still joining across records.
    Held,
}

pub(crate) fn boundary(incoming: &[u8]) -> Boundary {
    if incoming.is_empty() {
        return Boundary::Reached;
    }
    if incoming.len() < HEADER {
        return Boundary::Short(HEADER - incoming.len());
    }
    let end = HEADER + usize::from(u16::from_be_bytes([incoming[3], incoming[4]]));
    if incoming.len() < end {
        Boundary::Short(end - incoming.len())
    } else {
        Boundary::Held
    }
}

/// A record the kernel handed over because it is not application data.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Control<'a> {
    /// `close_notify`: the peer sends nothing more.
    CloseNotify,
    /// An alert that changes nothing: a TLS 1.2 warning, or TLS 1.3's
    /// `user_canceled`, which a `close_notify` follows.
    Ignored,
    /// Post-handshake messages, in order.
    Handshake(Vec<Message<'a>>),
}

/// A post-handshake message.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Message<'a> {
    /// The peer moved to its next sending key; if `update_requested`, ours
    /// must follow before we send more data.
    KeyUpdate { update_requested: bool },
    /// A session ticket, its body without the message header.
    NewSessionTicket(&'a [u8]),
}

/// The `KeyUpdate` message that answers a requested update, or makes one of
/// our own: `update_not_requested`.
pub(crate) const KEY_UPDATE: [u8; 5] = [24, 0, 0, 1, 0];

/// A warning-level `close_notify` alert.
pub(crate) const CLOSE_NOTIFY: [u8; 2] = [1, 0];

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// Reads a record of `content_type` with `payload`, on a connection of
/// `version`.
///
/// # Errors
///
/// A fatal alert ([`io::ErrorKind::ConnectionAborted`]), a malformed or
/// unexpected record, or a TLS 1.2 renegotiation, which is refused.
pub(crate) fn parse(
    content_type: u8,
    payload: &[u8],
    version: ProtocolVersion,
) -> io::Result<Control<'_>> {
    let tls13 = version == ProtocolVersion::TLSv1_3;
    match ContentType::from(content_type) {
        ContentType::Alert => {
            let &[level, description] = payload else {
                return Err(invalid(format!(
                    "a TLS alert of {} bytes, not 2",
                    payload.len()
                )));
            };
            let description = AlertDescription::from(description);
            match description {
                AlertDescription::CloseNotify => Ok(Control::CloseNotify),
                AlertDescription::UserCanceled if tls13 => Ok(Control::Ignored),
                // A warning level in TLS 1.2; TLS 1.3 has no warnings.
                _ if !tls13 && level == 1 => Ok(Control::Ignored),
                description => Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    format!("the peer sent a fatal TLS alert: {description:?}"),
                )),
            }
        }
        ContentType::Handshake if tls13 => messages(payload).map(Control::Handshake),
        ContentType::Handshake => Err(invalid(
            "the peer started a TLS 1.2 renegotiation, which is not supported",
        )),
        other => Err(invalid(format!(
            "an unexpected TLS record of type {other:?} after the handshake"
        ))),
    }
}

/// Splits a TLS 1.3 handshake record into its post-handshake messages.
fn messages(mut payload: &[u8]) -> io::Result<Vec<Message<'_>>> {
    let mut messages = Vec::new();
    while !payload.is_empty() {
        let &[kind, a, b, c, ref rest @ ..] = payload else {
            return Err(invalid("a truncated TLS handshake message header"));
        };
        let len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
        let Some((body, rest)) = rest.split_at_checked(len) else {
            return Err(invalid(
                "a TLS handshake message split across records after the handshake",
            ));
        };
        payload = rest;
        messages.push(match HandshakeType::from(kind) {
            HandshakeType::KeyUpdate => {
                // RFC 8446 §5.1: no message may follow a key change in its
                // record.
                if !payload.is_empty() {
                    return Err(invalid("a TLS KeyUpdate that is not last in its record"));
                }
                match body {
                    [0] => Message::KeyUpdate {
                        update_requested: false,
                    },
                    [1] => Message::KeyUpdate {
                        update_requested: true,
                    },
                    _ => return Err(invalid("a malformed TLS KeyUpdate")),
                }
            }
            HandshakeType::NewSessionTicket => Message::NewSessionTicket(body),
            other => {
                return Err(invalid(format!(
                    "an unexpected TLS {other:?} message after the handshake"
                )));
            }
        });
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALERT: u8 = 21;
    const HANDSHAKE: u8 = 22;

    #[test]
    fn kernel_suites() {
        assert_eq!(
            Cipher::of(CipherSuite::TLS13_AES_128_GCM_SHA256),
            Some(Cipher::Aes128Gcm)
        );
        assert_eq!(
            Cipher::of(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            Some(Cipher::Aes256Gcm)
        );
        assert_eq!(
            Cipher::of(CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            Some(Cipher::Chacha20Poly1305)
        );
        assert_eq!(Cipher::of(CipherSuite::TLS13_AES_128_CCM_SHA256), None);
    }

    #[test]
    fn record_accounting() {
        assert_eq!(records_for(0), 1);
        assert_eq!(records_for(MAX_FRAGMENT), 2);
        assert_eq!(records_for(MAX_FRAGMENT + 1), 3);
        assert!(Cipher::Aes128Gcm.record_limit() < Cipher::Chacha20Poly1305.record_limit());
    }

    #[test]
    fn record_boundary() {
        assert_eq!(boundary(&[]), Boundary::Reached);
        assert_eq!(boundary(&[23, 3, 3]), Boundary::Short(2));
        // A 300-byte record of which 10 payload bytes arrived.
        let mut partial = vec![23, 3, 3, 1, 44];
        partial.extend([0; 10]);
        assert_eq!(boundary(&partial), Boundary::Short(290));
        partial.extend([0; 290]);
        assert_eq!(boundary(&partial), Boundary::Held);
    }

    #[test]
    fn alerts() {
        let v13 = ProtocolVersion::TLSv1_3;
        let v12 = ProtocolVersion::TLSv1_2;
        assert_eq!(
            parse(ALERT, &CLOSE_NOTIFY, v13).unwrap(),
            Control::CloseNotify
        );
        assert_eq!(parse(ALERT, &[2, 0], v12).unwrap(), Control::CloseNotify);
        assert_eq!(parse(ALERT, &[1, 90], v13).unwrap(), Control::Ignored);
        assert_eq!(parse(ALERT, &[1, 100], v12).unwrap(), Control::Ignored);
        let fatal = parse(ALERT, &[2, 40], v13).unwrap_err();
        assert_eq!(fatal.kind(), io::ErrorKind::ConnectionAborted);
        assert!(fatal.to_string().contains("HandshakeFailure"), "{fatal}");
        assert!(parse(ALERT, &[1, 100], v13).is_err());
        assert!(parse(ALERT, &[1], v13).is_err());
    }

    #[test]
    fn post_handshake_messages() {
        let v13 = ProtocolVersion::TLSv1_3;
        assert_eq!(
            parse(HANDSHAKE, &[24, 0, 0, 1, 1], v13).unwrap(),
            Control::Handshake(vec![Message::KeyUpdate {
                update_requested: true
            }])
        );
        assert_eq!(
            parse(HANDSHAKE, &KEY_UPDATE, v13).unwrap(),
            Control::Handshake(vec![Message::KeyUpdate {
                update_requested: false
            }])
        );
        // Two tickets in one record.
        let tickets = [4, 0, 0, 2, 7, 8, 4, 0, 0, 1, 9];
        assert_eq!(
            parse(HANDSHAKE, &tickets, v13).unwrap(),
            Control::Handshake(vec![
                Message::NewSessionTicket(&[7, 8]),
                Message::NewSessionTicket(&[9]),
            ])
        );
        // A ticket after a key update spans the key change.
        assert!(parse(HANDSHAKE, &[24, 0, 0, 1, 0, 4, 0, 0, 0], v13).is_err());
        assert!(parse(HANDSHAKE, &[24, 0, 0, 1, 2], v13).is_err());
        assert!(parse(HANDSHAKE, &[4, 0, 0, 9, 1], v13).is_err());
        // A ClientHello after the handshake.
        assert!(parse(HANDSHAKE, &[1, 0, 0, 0], v13).is_err());
        // TLS 1.2: a HelloRequest asks for a renegotiation.
        assert!(parse(HANDSHAKE, &[0, 0, 0, 0], ProtocolVersion::TLSv1_2).is_err());
        assert!(parse(20, &[1], v13).is_err());
    }
}
