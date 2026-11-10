//! Address validation with a stateless Retry (RFC 9000 §8.1.2).
//!
//! A server that requires validation answers a client's first Initial with a
//! Retry carrying a token, and opens a connection only for an Initial that
//! echoes a token it minted, from the address it minted it for. Everything
//! the check needs travels in the token, so sending a Retry costs the server
//! no state, and an Initial from a spoofed source never reaches a connection.
//!
//! # Token format
//!
//! ```text
//! issued (8, big-endian ms since the Unix epoch) | len (1) | odcid (len) | tag (32)
//! ```
//!
//! `odcid` is the destination connection ID of the client's first Initial,
//! which the connection's transport parameters must name. `tag` is
//! HMAC-SHA256 under the [`TokenKey`] over the client's address, the Retry's
//! source connection ID (the next Initial's destination ID) and the bytes
//! before it. The address and the Retry ID are bound without being carried:
//! the next Initial supplies both. The issue time is wall-clock time, so
//! servers sharing a key check each other's tokens.

use std::{
    fmt,
    net::SocketAddr,
    num::NonZeroU32,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use quiche::ConnectionId;

/// Bytes of the issue time.
const ISSUED_LEN: usize = 8;
/// Bytes of the authentication tag.
const TAG_LEN: usize = 32;

/// The secret that authenticates address-validation tokens.
///
/// Every server that may receive a client's next Initial — each instance
/// behind one address — must hold the same key, so it is the operator's to
/// distribute; [`TokenKey::generate`] suits a single server process.
#[derive(Clone)]
pub struct TokenKey([u8; 32]);

impl TokenKey {
    /// A key from 32 secret bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// A key drawn from BoringSSL's random generator.
    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = [0; 32];
        boring::rand::rand_bytes(&mut bytes).expect("BoringSSL's random generator does not fail");
        Self(bytes)
    }

    /// The tag over `peer`, `retry_scid` and the token body.
    fn tag(&self, peer: SocketAddr, retry_scid: &[u8], body: &[u8]) -> [u8; TAG_LEN] {
        let mut input = Vec::with_capacity(1 + 16 + 2 + 1 + retry_scid.len() + body.len());
        match peer {
            SocketAddr::V4(peer) => {
                input.push(4);
                input.extend_from_slice(&peer.ip().octets());
            }
            SocketAddr::V6(peer) => {
                input.push(6);
                input.extend_from_slice(&peer.ip().octets());
            }
        }
        input.extend_from_slice(&peer.port().to_be_bytes());
        input.push(u8::try_from(retry_scid.len()).expect("a connection ID is at most 20 bytes"));
        input.extend_from_slice(retry_scid);
        input.extend_from_slice(body);
        boring::hash::hmac_sha256(&self.0, &input).expect("HMAC-SHA256 over memory does not fail")
    }
}

impl PartialEq for TokenKey {
    fn eq(&self, other: &Self) -> bool {
        boring::memcmp::eq(&self.0, &other.0)
    }
}

impl Eq for TokenKey {}

impl fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenKey(<redacted>)")
    }
}

/// When a new connection must first validate its address with a Retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RetryWhen {
    /// Every new connection: a spoofed source never costs connection state,
    /// and every handshake takes one more round trip.
    Always,
    /// Once more than `connections` connections opened without validation
    /// within the current `window`: the round trip is paid only while new
    /// connections arrive faster than that.
    AboveRate {
        /// How many unvalidated connections a window admits.
        connections: NonZeroU32,
        /// The length of a window.
        window: Duration,
    },
}

/// Stateless Retry settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetryConfig {
    /// When a Retry is required.
    pub when: RetryWhen,
    /// The key new tokens are minted with.
    pub key: TokenKey,
    /// A key tokens are still accepted under, so the key can rotate without
    /// failing handshakes already past their Retry.
    pub previous_key: Option<TokenKey>,
    /// How long a token is accepted after it was minted. A client echoes it
    /// one round trip later; an Initial whose token is older is dropped.
    pub validity: Duration,
}

impl RetryConfig {
    /// Retry for every new connection, with tokens minted under `key` and
    /// accepted for 10 seconds.
    #[must_use]
    pub const fn new(key: TokenKey) -> Self {
        Self {
            when: RetryWhen::Always,
            key,
            previous_key: None,
            validity: Duration::from_secs(10),
        }
    }
}

/// Why a token was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Not minted under either key for this address and connection ID, or
    /// not a token at all.
    Invalid,
    /// Authentic, but older than the validity window.
    Expired,
}

/// A server's Retry state: its settings and the current rate window.
#[derive(Debug)]
pub(crate) struct Validator {
    config: RetryConfig,
    window_start: Instant,
    window_count: u32,
}

impl Validator {
    pub(crate) fn new(config: RetryConfig, now: Instant) -> Self {
        Self {
            config,
            window_start: now,
            window_count: 0,
        }
    }

    /// Whether a new connection with no token must be sent a Retry; one that
    /// need not is counted against the window.
    pub(crate) fn requires(&mut self, now: Instant) -> bool {
        match self.config.when {
            RetryWhen::Always => true,
            RetryWhen::AboveRate {
                connections,
                window,
            } => {
                if now.duration_since(self.window_start) >= window {
                    self.window_start = now;
                    self.window_count = 0;
                }
                if self.window_count >= connections.get() {
                    true
                } else {
                    self.window_count += 1;
                    false
                }
            }
        }
    }

    /// A token for a client at `peer` whose first Initial was sent to
    /// `odcid`, to be echoed to `retry_scid`.
    pub(crate) fn mint(
        &self,
        peer: SocketAddr,
        odcid: &[u8],
        retry_scid: &[u8],
        now: SystemTime,
    ) -> Vec<u8> {
        let mut token = Vec::with_capacity(ISSUED_LEN + 1 + odcid.len() + TAG_LEN);
        token.extend_from_slice(&millis(now).to_be_bytes());
        token.push(u8::try_from(odcid.len()).expect("a connection ID is at most 20 bytes"));
        token.extend_from_slice(odcid);
        let tag = self.config.key.tag(peer, retry_scid, &token);
        token.extend_from_slice(&tag);
        token
    }

    /// Checks a token echoed from `peer` to `dcid`, returning the original
    /// destination connection ID it names.
    pub(crate) fn check(
        &self,
        token: &[u8],
        peer: SocketAddr,
        dcid: &[u8],
        now: SystemTime,
    ) -> Result<ConnectionId<'static>, Refused> {
        let odcid_len = usize::from(*token.get(ISSUED_LEN).ok_or(Refused::Invalid)?);
        if odcid_len > quiche::MAX_CONN_ID_LEN
            || token.len() != ISSUED_LEN + 1 + odcid_len + TAG_LEN
        {
            return Err(Refused::Invalid);
        }
        let (body, tag) = token.split_at(token.len() - TAG_LEN);
        let authentic = |key: &TokenKey| boring::memcmp::eq(&key.tag(peer, dcid, body), tag);
        if !(authentic(&self.config.key)
            || self.config.previous_key.as_ref().is_some_and(authentic))
        {
            return Err(Refused::Invalid);
        }
        let issued = u64::from_be_bytes(body[..ISSUED_LEN].try_into().expect("checked length"));
        // A token from a server whose clock runs ahead is authentic and new.
        let age = Duration::from_millis(millis(now).saturating_sub(issued));
        if age >= self.config.validity {
            return Err(Refused::Expired);
        }
        Ok(ConnectionId::from_vec(body[ISSUED_LEN + 1..].to_vec()))
    }
}

fn millis(time: SystemTime) -> u64 {
    let since = time
        .duration_since(UNIX_EPOCH)
        .expect("the system clock is set after 1970");
    u64::try_from(since.as_millis()).expect("milliseconds since 1970 fit in 64 bits")
}

#[cfg(test)]
mod tests {
    use super::{Refused, RetryConfig, RetryWhen, TokenKey, Validator};
    use std::{
        net::SocketAddr,
        num::NonZeroU32,
        time::{Duration, Instant, SystemTime},
    };

    const ODCID: &[u8] = b"original-dcid-012345";
    const RETRY_SCID: &[u8] = b"retry-scid-012345678";

    fn peer() -> SocketAddr {
        "192.0.2.7:4433".parse().unwrap()
    }

    fn validator(key: TokenKey) -> Validator {
        Validator::new(RetryConfig::new(key), Instant::now())
    }

    #[test]
    fn round_trip_names_the_original_id() {
        let validator = validator(TokenKey::generate());
        let now = SystemTime::now();
        let token = validator.mint(peer(), ODCID, RETRY_SCID, now);
        let odcid = validator.check(&token, peer(), RETRY_SCID, now).unwrap();
        assert_eq!(odcid.as_ref(), ODCID);
    }

    #[test]
    fn bound_to_address_and_retry_id() {
        let validator = validator(TokenKey::generate());
        let now = SystemTime::now();
        let token = validator.mint(peer(), ODCID, RETRY_SCID, now);
        let other_port: SocketAddr = "192.0.2.7:4434".parse().unwrap();
        let other_host: SocketAddr = "[2001:db8::7]:4433".parse().unwrap();
        for from in [other_port, other_host] {
            assert_eq!(
                validator.check(&token, from, RETRY_SCID, now),
                Err(Refused::Invalid)
            );
        }
        assert_eq!(
            validator.check(&token, peer(), b"another-retry-scid", now),
            Err(Refused::Invalid)
        );
    }

    #[test]
    fn tampering_and_garbage_are_invalid() {
        let validator = validator(TokenKey::generate());
        let now = SystemTime::now();
        let token = validator.mint(peer(), ODCID, RETRY_SCID, now);
        for at in [0, 8, 9, token.len() - 1] {
            let mut forged = token.clone();
            forged[at] ^= 1;
            assert_eq!(
                validator.check(&forged, peer(), RETRY_SCID, now),
                Err(Refused::Invalid),
                "byte {at} flipped"
            );
        }
        for garbage in [&[][..], &[0; 8], &token[..token.len() - 1], &[0xff; 64]] {
            assert_eq!(
                validator.check(garbage, peer(), RETRY_SCID, now),
                Err(Refused::Invalid)
            );
        }
    }

    #[test]
    fn expires_after_its_validity() {
        let validator = validator(TokenKey::generate());
        let issued = SystemTime::now();
        let token = validator.mint(peer(), ODCID, RETRY_SCID, issued);
        let late = issued + validator.config.validity;
        assert_eq!(
            validator.check(&token, peer(), RETRY_SCID, late),
            Err(Refused::Expired)
        );
        let early = issued - Duration::from_secs(1);
        assert!(validator.check(&token, peer(), RETRY_SCID, early).is_ok());
    }

    #[test]
    fn previous_key_still_accepted() {
        let old = TokenKey::generate();
        let now = SystemTime::now();
        let token = validator(old.clone()).mint(peer(), ODCID, RETRY_SCID, now);
        let mut rotated = RetryConfig::new(TokenKey::generate());
        assert_eq!(
            Validator::new(rotated.clone(), Instant::now()).check(&token, peer(), RETRY_SCID, now),
            Err(Refused::Invalid)
        );
        rotated.previous_key = Some(old);
        let odcid = Validator::new(rotated, Instant::now())
            .check(&token, peer(), RETRY_SCID, now)
            .unwrap();
        assert_eq!(odcid.as_ref(), ODCID);
    }

    #[test]
    fn rate_admits_a_window_then_retries() {
        let start = Instant::now();
        let mut config = RetryConfig::new(TokenKey::generate());
        let window = Duration::from_secs(1);
        config.when = RetryWhen::AboveRate {
            connections: NonZeroU32::new(2).unwrap(),
            window,
        };
        let mut validator = Validator::new(config, start);
        assert!(!validator.requires(start));
        assert!(!validator.requires(start));
        assert!(validator.requires(start));
        assert!(!validator.requires(start + window));
    }

    #[test]
    fn keys_are_redacted() {
        let key = TokenKey::from_bytes([7; 32]);
        assert_eq!(format!("{key:?}"), "TokenKey(<redacted>)");
        assert_eq!(key, TokenKey::from_bytes([7; 32]));
        assert_ne!(key, TokenKey::from_bytes([8; 32]));
    }
}
