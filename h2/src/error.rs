//! Error types and HTTP/2 wire error codes.

use std::{fmt, io, sync::Arc};

use bytes::Bytes;
use http::StatusCode;
use http_kit::{BodyError, ReceiveError};

use crate::proto::StreamId;

/// An HTTP/2 32-bit wire error code (RFC 9113 §7).
///
/// Unknown codes received from a peer preserve their raw `u32` value; per
/// RFC 9113 §7 they carry no special semantics beyond `INTERNAL_ERROR`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reason(u32);

impl Reason {
    /// Graceful shutdown (`0x0`).
    pub const NO_ERROR: Self = Self(0x0);
    /// Unspecific protocol error (`0x1`).
    pub const PROTOCOL_ERROR: Self = Self(0x1);
    /// Unexpected internal error (`0x2`).
    pub const INTERNAL_ERROR: Self = Self(0x2);
    /// Flow-control limits violated (`0x3`).
    pub const FLOW_CONTROL_ERROR: Self = Self(0x3);
    /// `SETTINGS` not acknowledged in time (`0x4`).
    pub const SETTINGS_TIMEOUT: Self = Self(0x4);
    /// Frame received for a closed stream (`0x5`).
    pub const STREAM_CLOSED: Self = Self(0x5);
    /// Frame size invalid (`0x6`).
    pub const FRAME_SIZE_ERROR: Self = Self(0x6);
    /// Stream not processed (`0x7`).
    pub const REFUSED_STREAM: Self = Self(0x7);
    /// Stream cancelled (`0x8`).
    pub const CANCEL: Self = Self(0x8);
    /// HPACK compression state unable to be maintained (`0x9`).
    pub const COMPRESSION_ERROR: Self = Self(0x9);
    /// TCP connection for `CONNECT` failed or closed abnormally (`0xa`).
    pub const CONNECT_ERROR: Self = Self(0xa);
    /// Peer is generating excessive load (`0xb`).
    pub const ENHANCE_YOUR_CALM: Self = Self(0xb);
    /// Transport properties do not meet minimum security requirements (`0xc`).
    pub const INADEQUATE_SECURITY: Self = Self(0xc);
    /// Endpoint requires HTTP/1.1 instead (`0xd`).
    pub const HTTP_1_1_REQUIRED: Self = Self(0xd);

    /// Wraps a raw 32-bit HTTP/2 error code.
    #[must_use]
    pub const fn from_code(code: u32) -> Self {
        Self(code)
    }

    /// The raw 32-bit wire value.
    #[must_use]
    pub const fn code(self) -> u32 {
        self.0
    }

    /// Short RFC 9113 name of known codes, or `None` for unknown codes.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x0 => "NO_ERROR",
            0x1 => "PROTOCOL_ERROR",
            0x2 => "INTERNAL_ERROR",
            0x3 => "FLOW_CONTROL_ERROR",
            0x4 => "SETTINGS_TIMEOUT",
            0x5 => "STREAM_CLOSED",
            0x6 => "FRAME_SIZE_ERROR",
            0x7 => "REFUSED_STREAM",
            0x8 => "CANCEL",
            0x9 => "COMPRESSION_ERROR",
            0xa => "CONNECT_ERROR",
            0xb => "ENHANCE_YOUR_CALM",
            0xc => "INADEQUATE_SECURITY",
            0xd => "HTTP_1_1_REQUIRED",
            _ => return None,
        })
    }
}

impl From<u32> for Reason {
    fn from(code: u32) -> Self {
        Self(code)
    }
}

impl From<Reason> for u32 {
    fn from(reason: Reason) -> Self {
        reason.0
    }
}

impl fmt::Debug for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "Reason({:#x})", self.0),
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "unknown error code {:#x}", self.0),
        }
    }
}

/// A received HTTP/2 message that violates RFC 9113 §8 or RFC 8441.
///
/// Each one is a stream error (RFC 9113 §8.1.1): the offending stream is
/// reset with `PROTOCOL_ERROR` while the connection continues serving other
/// streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Malformed {
    /// A required pseudo-header field is absent or empty.
    #[error("missing or empty {0} pseudo-header field")]
    MissingPseudoHeader(&'static str),
    /// A pseudo-header field appears twice, after a regular field, in a
    /// trailer section, or is not defined for this kind of message.
    #[error("misplaced, repeated or unknown pseudo-header field")]
    InvalidPseudoHeader,
    /// A field name has uppercase letters or non-token bytes, or a value has
    /// control characters or leading/trailing whitespace (RFC 9113 §8.2.1).
    #[error("invalid header field")]
    InvalidField,
    /// A connection-specific field (`connection`, `keep-alive`,
    /// `proxy-connection`, `transfer-encoding`, `upgrade`, or `te` other than
    /// `trailers`), forbidden by RFC 9113 §8.2.2.
    #[error("connection-specific header field")]
    ConnectionSpecificField,
    /// The `:method` pseudo-header is not a valid HTTP token.
    #[error("invalid request method")]
    InvalidMethod,
    /// The `:scheme` or `:path` pseudo-header does not form a valid target.
    #[error("invalid request target")]
    InvalidTarget,
    /// `:authority` or `host` is invalid, contains `userinfo`, or conflicts.
    #[error("invalid or conflicting authority")]
    InvalidAuthority,
    /// `:status` is not a three-digit HTTP status code, or is `101`.
    #[error("invalid response status")]
    InvalidStatus,
    /// `content-length` is not a non-negative decimal integer, or appears with
    /// conflicting values.
    #[error("invalid Content-Length")]
    InvalidContentLength,
    /// Received `DATA` byte count differs from declared `content-length`
    /// (RFC 9113 §8.1.1).
    #[error("body length differs from its Content-Length")]
    ContentLengthMismatch,
    /// Uncompressed header or trailer section exceeds
    /// [`Limits::max_header_list_size`](crate::Limits::max_header_list_size).
    #[error("header section exceeds {limit} bytes")]
    HeaderListTooLarge {
        /// Configured `SETTINGS_MAX_HEADER_LIST_SIZE`.
        limit: u32,
    },
}

impl Malformed {
    const fn detail(self) -> &'static str {
        match self {
            Self::MissingPseudoHeader(_) => "missing or empty pseudo-header field",
            Self::InvalidPseudoHeader => "misplaced, repeated or unknown pseudo-header field",
            Self::InvalidField => "invalid header field",
            Self::ConnectionSpecificField => "connection-specific header field",
            Self::InvalidMethod => "invalid request method",
            Self::InvalidTarget => "invalid request target",
            Self::InvalidAuthority => "invalid or conflicting authority",
            Self::InvalidStatus => "invalid response status",
            Self::InvalidContentLength => "invalid Content-Length",
            Self::ContentLengthMismatch => "body length differs from its Content-Length",
            Self::HeaderListTooLarge { .. } => "header section too large",
        }
    }
}

/// Which configured connection or per-request deadline expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Timeout {
    /// Connection preface and initial `SETTINGS` did not complete in time.
    #[error("HTTP/2 handshake timed out")]
    Handshake,
    /// Final response head did not arrive within
    /// [`Deadlines::response_head`](http_kit::Deadlines::response_head).
    #[error("response head not received in time")]
    ResponseHead,
    /// A demanded read of a message body stalled past its idle deadline.
    #[error("message body stalled")]
    BodyIdle,
    /// Peer did not acknowledge a `SETTINGS` frame in time (`SETTINGS_TIMEOUT`).
    #[error("peer did not acknowledge SETTINGS in time")]
    SettingsAck,
    /// Peer did not acknowledge a keep-alive `PING` in time.
    #[error("keep-alive PING timed out")]
    KeepAlive,
}

/// An error on an HTTP/2 connection or stream.
///
/// Cloning is cheap; a clone reaches both the connection driver and the
/// affected exchange or body.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The underlying transport failed.
    #[error("I/O error: {0}")]
    Io(#[source] Arc<io::Error>),
    /// The peer violated HTTP/2 framing, HPACK, or connection state, so this
    /// endpoint closed the connection with `GOAWAY(reason)`.
    #[error("connection protocol error ({reason}): {detail}")]
    Protocol {
        /// The HTTP/2 error code queued in `GOAWAY`.
        reason: Reason,
        /// Short description of the violated invariant.
        detail: &'static str,
    },
    /// The peer closed the connection with `GOAWAY`.
    #[error("peer sent GOAWAY ({reason}, last_stream_id={})", last_stream_id.get())]
    PeerGoAway {
        /// Highest locally initiated stream identifier the peer may have
        /// processed.
        last_stream_id: StreamId,
        /// The error code in the peer's `GOAWAY`.
        reason: Reason,
        /// Optional diagnostic payload carried by the `GOAWAY` frame.
        debug_data: Bytes,
    },
    /// The peer reset the stream with `RST_STREAM`.
    #[error("stream reset by peer ({0})")]
    StreamReset(Reason),
    /// The server did not process the request: it was reset with
    /// `REFUSED_STREAM`, or its stream identifier exceeded the peer's
    /// `GOAWAY` `last_stream_id`. Safe to retry on another connection
    /// (RFC 9113 §8.7).
    #[error("request rejected before processing; safe to retry")]
    RequestRejected,
    /// The peer sent a malformed HTTP message on the stream.
    #[error("invalid message from peer: {0}")]
    Malformed(#[from] Malformed),
    /// An outgoing body failed while being sent.
    #[error("outgoing body failed: {0}")]
    Body(#[source] Arc<BodyError>),
    /// A body yielded a frame this build cannot send (`fs` or `pipe` feature
    /// disabled).
    #[error(
        "unsupported body frame (file regions need the `fs` feature, pipes the `pipe` feature)"
    )]
    UnsupportedFrame,
    /// Only final (`2xx`–`5xx`) responses can complete an exchange; `101` is
    /// forbidden in HTTP/2.
    #[error("{0} is not a valid final HTTP/2 response")]
    InformationalResponse(StatusCode),
    /// An outgoing body's byte count differed from its declared
    /// `Content-Length`.
    #[error("body length differs from its Content-Length of {declared}")]
    ContentLengthMismatch {
        /// The declared `Content-Length`.
        declared: u64,
    },
    /// An outgoing request lacks both URI authority and `Host` header.
    #[error("request has neither an authority nor a Host field")]
    MissingAuthority,
    /// An outgoing Extended `CONNECT` (`:protocol`) is malformed or the peer
    /// has not advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`.
    #[error("extended CONNECT is not supported by peer or request is invalid")]
    UnsupportedExtendedConnect,
    /// All 31-bit stream identifiers on this connection have been used.
    #[error("HTTP/2 stream identifiers exhausted")]
    StreamsExhausted,
    /// A configured deadline passed.
    #[error("timed out: {0}")]
    Timeout(Timeout),
    /// The connection closed before the exchange completed.
    #[error("connection closed")]
    ConnectionClosed,
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(Arc::new(error))
    }
}

impl From<BodyError> for Error {
    fn from(error: BodyError) -> Self {
        Self::Body(Arc::new(error))
    }
}

impl From<Error> for BodyError {
    /// Classifies receive-side failures into [`BodyError::Receive`] and boxes
    /// send-side errors.
    fn from(error: Error) -> Self {
        match error {
            Error::Timeout(Timeout::BodyIdle) => ReceiveError::Stalled.into(),
            Error::StreamReset(_)
            | Error::PeerGoAway { .. }
            | Error::ConnectionClosed
            | Error::RequestRejected => ReceiveError::Incomplete.into(),
            Error::Malformed(Malformed::HeaderListTooLarge { limit }) => {
                ReceiveError::TrailersTooLarge {
                    limit: limit as usize,
                }
                .into()
            }
            Error::Malformed(malformed) => ReceiveError::Framing {
                detail: malformed.detail(),
            }
            .into(),
            Error::Protocol { detail, .. } => ReceiveError::Framing { detail }.into(),
            Error::Io(error) => ReceiveError::Connection(error).into(),
            other => Self::Other(Box::new(other)),
        }
    }
}

/// A request that failed, carrying back the original [`http_kit::Request`]
/// whenever none of it was processed by the server.
///
/// When the handle was closed, the connection ended or received `GOAWAY`
/// before opening a stream, or the stream was rejected unprocessed
/// ([`Error::RequestRejected`]) while its body remained untouched,
/// [`take_request`](Self::take_request) returns the request so a connection
/// pool can retry any method (including `POST`) on a fresh connection.
pub struct TrySendError {
    error: Error,
    request: Option<Box<http_kit::Request>>,
}

impl TrySendError {
    /// Wraps `error` together with an unwritten/unprocessed `request`.
    #[must_use]
    pub fn unsent(error: Error, request: http_kit::Request) -> Self {
        Self {
            error,
            request: Some(Box::new(request)),
        }
    }

    /// Why the request failed.
    #[must_use]
    pub const fn error(&self) -> &Error {
        &self.error
    }

    /// Why the request failed, dropping any recoverable request.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.error
    }

    /// Returns the original request once, if none of it was processed.
    pub fn take_request(&mut self) -> Option<http_kit::Request> {
        self.request.take().map(|request| *request)
    }
}

impl From<Error> for TrySendError {
    fn from(error: Error) -> Self {
        Self {
            error,
            request: None,
        }
    }
}

impl From<TrySendError> for Error {
    fn from(error: TrySendError) -> Self {
        error.error
    }
}

impl fmt::Debug for TrySendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrySendError")
            .field("error", &self.error)
            .field("unsent", &self.request.is_some())
            .finish()
    }
}

impl fmt::Display for TrySendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl std::error::Error for TrySendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
