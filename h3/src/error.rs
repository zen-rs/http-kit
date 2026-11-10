//! Error types.

use std::{fmt, io, sync::Arc};

use http::StatusCode;
use http_kit::BodyError;

/// A received message that violates HTTP/3 (RFC 9114 §4.1.2).
///
/// Each one is a stream error: the stream is reset with
/// `H3_MESSAGE_ERROR`, and the connection carries on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Malformed {
    /// A required pseudo-header field is absent, or empty.
    #[error("missing or empty {0} pseudo-header field")]
    MissingPseudoHeader(&'static str),
    /// A pseudo-header field appears twice, after a regular field, in a
    /// trailer section, or is not defined for this kind of message.
    #[error("misplaced, repeated or unknown pseudo-header field")]
    InvalidPseudoHeader,
    /// A field name has uppercase letters or invalid characters, or a value
    /// has invalid characters.
    #[error("invalid field")]
    InvalidField,
    /// A connection-specific field (`Connection`, `Keep-Alive`,
    /// `Proxy-Connection`, `Transfer-Encoding`, `Upgrade`, or `TE` other
    /// than `trailers`), which HTTP/3 forbids (RFC 9114 §4.2).
    #[error("connection-specific field")]
    ConnectionSpecificField,
    /// The method is not a valid token.
    #[error("invalid method")]
    InvalidMethod,
    /// The request target does not form a valid URI.
    #[error("invalid request target")]
    InvalidTarget,
    /// An `http` or `https` request has neither `:authority` nor `Host`, or
    /// both and they differ.
    #[error("missing or conflicting authority")]
    InvalidAuthority,
    /// The response status is not a three-digit code.
    #[error("invalid status")]
    InvalidStatus,
    /// `Content-Length` is not a decimal integer, or appears with differing
    /// values.
    #[error("invalid Content-Length")]
    InvalidContentLength,
    /// The body is longer or shorter than its `Content-Length`.
    #[error("body length differs from its Content-Length")]
    ContentLengthMismatch,
}

/// An error on an HTTP/3 endpoint, connection or stream.
///
/// Cloning is cheap; a clone reaches both the driver and the request or body
/// it affected.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The socket failed.
    #[error("I/O error: {0}")]
    Io(#[source] Arc<io::Error>),
    /// The TLS identity or trust roots could not be loaded.
    #[error("TLS configuration: {0}")]
    Tls(#[source] Arc<boring::error::ErrorStack>),
    /// The identity's certificate chain holds no certificate.
    #[error("the certificate chain holds no certificate")]
    NoCertificate,
    /// QUIC failed: a configuration value quiche rejects, or a transport error.
    #[error("QUIC: {0}")]
    Quic(#[source] quiche::Error),
    /// The HTTP/3 layer failed.
    #[error("HTTP/3: {0}")]
    H3(#[source] quiche::h3::Error),
    /// The peer sent an invalid message.
    #[error("invalid message from peer: {0}")]
    Malformed(#[from] Malformed),
    /// An outgoing body failed while it was being sent.
    #[error("outgoing body failed: {0}")]
    Body(#[source] Arc<BodyError>),
    /// A body yielded a frame this endpoint cannot send: a file region needs
    /// the `fs` feature.
    #[error("unsupported body frame (file regions need the `fs` feature)")]
    UnsupportedFrame,
    /// A response is informational; only final responses can be sent.
    #[error("{0} is not a final response")]
    InformationalResponse(StatusCode),
    /// An outgoing body's length differs from the `Content-Length` its head
    /// announced. The stream is reset.
    #[error("body length differs from its Content-Length of {declared}")]
    ContentLengthMismatch {
        /// The announced length.
        declared: u64,
    },
    /// An outgoing request has no authority, in its URI or a `Host` field.
    #[error("request has neither an authority nor a Host field")]
    MissingAuthority,
    /// The peer reset the stream with this HTTP/3 error code.
    #[error("stream reset by peer with code {0:#x}")]
    StreamReset(u64),
    /// The server did not process the request: it was refused with
    /// `H3_REQUEST_REJECTED`, or it was above the identifier of a GOAWAY.
    /// Sending it again, on another connection, is safe (RFC 9114 §4.1.1).
    #[error("request rejected before processing; safe to retry")]
    RequestRejected,
    /// The connection closed before the exchange completed.
    #[error("connection closed")]
    ConnectionClosed,
    /// The peer closed the connection with an error.
    #[error("peer closed the connection with error {code:#x} (application: {application})")]
    PeerClosed {
        /// Whether `code` is an HTTP/3 (application) code rather than a QUIC
        /// transport code.
        application: bool,
        /// The error code.
        code: u64,
    },
    /// This endpoint closed the connection with an error: the peer violated
    /// QUIC or HTTP/3, or exceeded a limit.
    #[error("connection closed locally with error {code:#x} (application: {application})")]
    LocallyClosed {
        /// Whether `code` is an HTTP/3 (application) code rather than a QUIC
        /// transport code.
        application: bool,
        /// The error code.
        code: u64,
    },
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(Arc::new(error))
    }
}

impl From<boring::error::ErrorStack> for Error {
    fn from(error: boring::error::ErrorStack) -> Self {
        Self::Tls(Arc::new(error))
    }
}

impl From<quiche::Error> for Error {
    fn from(error: quiche::Error) -> Self {
        Self::Quic(error)
    }
}

impl From<quiche::h3::Error> for Error {
    fn from(error: quiche::h3::Error) -> Self {
        Self::H3(error)
    }
}

impl From<BodyError> for Error {
    fn from(error: BodyError) -> Self {
        Self::Body(Arc::new(error))
    }
}

impl From<Error> for BodyError {
    fn from(error: Error) -> Self {
        Self::Other(Box::new(error))
    }
}

/// A request that failed, and the request itself if nothing of it was sent.
///
/// Like hyper's and `http-kit-h1`'s `TrySendError`: when the connection had
/// stopped taking requests, had not yet opened a stream for this one, or the
/// server refused it unprocessed ([`Error::RequestRejected`]),
/// [`take_request`](Self::take_request) returns the request as it was handed
/// in, its body unread, and it can be sent on another connection whatever
/// its method or body. A failure after the request's body began to be read
/// leaves nothing to give back.
pub struct TrySendError {
    error: Error,
    /// Boxed: a request is large, and an error is returned by value.
    request: Option<Box<http_kit::Request>>,
}

impl TrySendError {
    pub(crate) fn unsent(error: Error, request: http_kit::Request) -> Self {
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

    /// Why the request failed, dropping the request.
    #[must_use]
    pub fn into_error(self) -> Error {
        self.error
    }

    /// The request, if none of it was sent. It is returned once.
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
