//! Error types.

use std::{io, sync::Arc};

use http::{StatusCode, Version};
use http_kit::{BodyError, ReceiveError};

/// A received message that violates HTTP/1.1 or a configured limit.
///
/// Every one of these ends the connection: once framing is in doubt, nothing
/// after it on the connection can be trusted (RFC 9112 §6.3).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The head is larger than [`Limits::max_head_size`](crate::Limits::max_head_size).
    #[error("message head exceeds {limit} bytes")]
    HeadTooLarge {
        /// The configured limit.
        limit: usize,
    },
    /// The head has more fields than [`Limits::max_headers`](crate::Limits::max_headers).
    #[error("message head has more than {limit} fields")]
    TooManyHeaders {
        /// The configured limit.
        limit: usize,
    },
    /// The start line or a field line is malformed. This covers obs-fold in
    /// a request, a bare CR, whitespace before a field's colon in a request,
    /// and invalid characters.
    #[error("malformed message head: {0}")]
    MalformedHead(httparse::Error),
    /// The message is neither HTTP/1.0 nor HTTP/1.1.
    #[error("unsupported HTTP version")]
    UnsupportedVersion,
    /// The request method is not a valid token.
    #[error("invalid request method")]
    InvalidMethod,
    /// The request target is malformed or does not fit the method (RFC 9112 §3.2).
    #[error("invalid request target")]
    InvalidTarget,
    /// The response status code is outside 100..=999.
    #[error("invalid response status")]
    InvalidStatus,
    /// A field name or value cannot be represented.
    #[error("invalid header field")]
    InvalidHeader,
    /// An HTTP/1.1 request has no `Host` field (RFC 9112 §3.2).
    #[error("HTTP/1.1 request without a Host field")]
    MissingHost,
    /// A request has more than one `Host` field (RFC 9112 §3.2).
    #[error("request with more than one Host field")]
    MultipleHost,
    /// A `Content-Length` value is not a non-negative decimal integer.
    #[error("invalid Content-Length")]
    InvalidContentLength,
    /// `Content-Length` appears with differing values (RFC 9112 §6.3).
    #[error("conflicting Content-Length values")]
    ConflictingContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` are present (RFC 9112 §6.3).
    #[error("both Content-Length and Transfer-Encoding are present")]
    ContentLengthWithTransferEncoding,
    /// An HTTP/1.0 message carries `Transfer-Encoding` (RFC 9112 §6.1).
    #[error("Transfer-Encoding in an HTTP/1.0 message")]
    TransferEncodingInHttp10,
    /// `chunked` is not the final transfer coding, or is applied more than
    /// once (RFC 9112 §6.1, §6.3).
    #[error("chunked is not the final transfer coding exactly once")]
    ChunkedNotFinal,
    /// A transfer coding other than `chunked` is applied.
    #[error("unsupported transfer coding")]
    UnsupportedTransferCoding,
    /// An `Expect` field other than `100-continue` (RFC 9110 §10.1.1).
    #[error("unsupported expectation")]
    UnsupportedExpectation,
    /// A chunk-size line is not a hexadecimal size, or the size overflows.
    #[error("invalid chunk size")]
    InvalidChunkSize,
    /// A chunk extension holds a control character or does not start with `;`.
    #[error("invalid chunk extension")]
    InvalidChunkExtension,
    /// A chunk-size line exceeds [`Limits::max_chunk_line_size`](crate::Limits::max_chunk_line_size).
    #[error("chunk-size line exceeds {limit} bytes")]
    ChunkLineTooLong {
        /// The configured limit.
        limit: usize,
    },
    /// A chunk-size line or chunk data is not terminated by CRLF.
    #[error("chunk not terminated by CRLF")]
    MissingChunkCrlf,
    /// The trailer section is malformed.
    #[error("malformed trailer section: {0}")]
    MalformedTrailers(httparse::Error),
    /// The peer closed the connection in the middle of a message.
    #[error("connection closed before the message was complete")]
    Incomplete,
}

impl ParseError {
    /// The status a server answers this violation with before closing, or
    /// `None` when no response should be sent (the peer is gone).
    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        Some(match self {
            Self::HeadTooLarge { .. } | Self::TooManyHeaders { .. } => {
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
            }
            Self::UnsupportedVersion => StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            Self::UnsupportedTransferCoding => StatusCode::NOT_IMPLEMENTED,
            Self::UnsupportedExpectation => StatusCode::EXPECTATION_FAILED,
            Self::Incomplete => return None,
            _ => StatusCode::BAD_REQUEST,
        })
    }
}

/// An error on a connection.
///
/// Cloning is cheap; a clone reaches both the connection's driver and the
/// body or request it affected.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The transport failed.
    #[error("I/O error: {0}")]
    Io(#[source] Arc<io::Error>),
    /// The peer sent an invalid message.
    #[error("invalid message from peer: {0}")]
    Parse(#[from] ParseError),
    /// An outgoing body failed while it was being sent.
    #[error("outgoing body failed: {0}")]
    Body(#[source] Arc<BodyError>),
    /// An outgoing body's length differs from the `Content-Length` it was
    /// announced with.
    #[error("body length differs from its Content-Length of {declared}")]
    ContentLengthMismatch {
        /// The announced length.
        declared: u64,
    },
    /// An outgoing body has trailers, but its message is not chunked.
    #[error("trailers on a message that is not chunked")]
    TrailersNotChunked,
    /// An outgoing message's own `Content-Length` is invalid.
    #[error("invalid outgoing Content-Length")]
    OutgoingContentLength,
    /// An outgoing message's own `Transfer-Encoding` is anything but a lone
    /// `chunked`, sits next to a `Content-Length`, or is addressed to HTTP/1.0.
    #[error("unsupported outgoing Transfer-Encoding")]
    OutgoingTransferEncoding,
    /// An HTTP/1.0 request has a body of unknown length, which HTTP/1.0 can
    /// only frame by closing the connection.
    #[error("HTTP/1.0 request with a body of unknown length")]
    UnknownLengthHttp10,
    /// An outgoing message's version is neither HTTP/1.0 nor HTTP/1.1.
    #[error("{0:?} cannot be sent over HTTP/1.1")]
    UnsupportedVersion(Version),
    /// An outgoing request has neither a `Host` field nor an authority.
    #[error("request has neither a Host field nor an authority")]
    MissingHost,
    /// An absolute-form request target was asked for, but the request's URI
    /// lacks a scheme or an authority.
    #[error("absolute-form request target needs a URI with scheme and authority")]
    AbsoluteTargetIncomplete,
    /// A response is informational; only final responses can be sent.
    #[error("{0} is not a final response")]
    InformationalResponse(StatusCode),
    /// A `101 Switching Protocols` answers a request that asked for no upgrade.
    #[error("101 Switching Protocols to a request that asked for no upgrade")]
    UnrequestedUpgrade,
    /// The protocol switched before the request body was fully transferred:
    /// read, on a server; sent, on a client.
    #[error("protocol switch before the request body was transferred")]
    UpgradeBeforeBodyRead,
    /// A body yielded a frame this connection cannot send: a file region
    /// needs the `fs` feature.
    #[error("unsupported body frame (file regions need the `fs` feature)")]
    UnsupportedFrame,
    /// The connection closed before the request was answered.
    #[error("connection closed")]
    ConnectionClosed,
    /// A deadline from the connection's configuration passed.
    #[error("timed out: {0}")]
    Timeout(Timeout),
}

/// Which deadline of a [`ServerConfig`](crate::ServerConfig) or of a client
/// request's [`Deadlines`](http_kit::Deadlines) passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Timeout {
    /// On a server, a request head did not arrive in full within
    /// [`header_read_timeout`](crate::ServerConfig::header_read_timeout); a
    /// server that had received part of the head answered `408 Request
    /// Timeout` before closing (RFC 9110 §15.5.9). On a client, the final
    /// response head did not arrive within
    /// [`Deadlines::response_head`](http_kit::Deadlines::response_head).
    #[error("message head not received in time")]
    HeadRead,
    /// A read of a message body delivered nothing within
    /// [`body_read_timeout`](crate::ServerConfig::body_read_timeout) on a
    /// server, or [`Deadlines::body_idle`](http_kit::Deadlines::body_idle) on
    /// a client.
    #[error("message body stalled")]
    BodyRead,
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
    /// A failure of a body being received is classified into
    /// [`BodyError::Receive`]; a send-side error stays boxed.
    fn from(error: Error) -> Self {
        match error {
            Error::Timeout(Timeout::BodyRead) => ReceiveError::Stalled.into(),
            Error::Parse(ParseError::Incomplete) | Error::ConnectionClosed => {
                ReceiveError::Incomplete.into()
            }
            // A head limit hit inside a body is the trailer section's.
            Error::Parse(ParseError::HeadTooLarge { limit }) => {
                ReceiveError::TrailersTooLarge { limit }.into()
            }
            Error::Parse(ParseError::TooManyHeaders { limit }) => {
                ReceiveError::TooManyTrailers { limit }.into()
            }
            Error::Parse(parse) => ReceiveError::Framing {
                detail: parse.framing_detail(),
            }
            .into(),
            Error::Io(error) => ReceiveError::Connection(error).into(),
            other => Self::Other(Box::new(other)),
        }
    }
}

impl ParseError {
    /// What the violation is, as the `detail` of [`ReceiveError::Framing`].
    const fn framing_detail(&self) -> &'static str {
        match self {
            Self::HeadTooLarge { .. } => "message head too large",
            Self::TooManyHeaders { .. } => "too many fields",
            Self::MalformedHead(_) => "malformed message head",
            Self::UnsupportedVersion => "unsupported HTTP version",
            Self::InvalidMethod => "invalid request method",
            Self::InvalidTarget => "invalid request target",
            Self::InvalidStatus => "invalid response status",
            Self::InvalidHeader => "invalid header field",
            Self::MissingHost => "missing Host field",
            Self::MultipleHost => "more than one Host field",
            Self::InvalidContentLength => "invalid Content-Length",
            Self::ConflictingContentLength => "conflicting Content-Length values",
            Self::ContentLengthWithTransferEncoding => "both Content-Length and Transfer-Encoding",
            Self::TransferEncodingInHttp10 => "Transfer-Encoding in an HTTP/1.0 message",
            Self::ChunkedNotFinal => "chunked is not the final transfer coding exactly once",
            Self::UnsupportedTransferCoding => "unsupported transfer coding",
            Self::UnsupportedExpectation => "unsupported expectation",
            Self::InvalidChunkSize => "invalid chunk size",
            Self::InvalidChunkExtension => "invalid chunk extension",
            Self::ChunkLineTooLong { .. } => "chunk-size line too long",
            Self::MissingChunkCrlf => "chunk not terminated by CRLF",
            Self::MalformedTrailers(_) => "malformed trailer section",
            Self::Incomplete => "message incomplete",
        }
    }
}
