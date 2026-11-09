//! Connection settings.
//!
//! Every value here is an operator setting: the defaults are a starting point
//! sized for typical traffic, not a ceiling the crate enforces.

use crate::proto::RequestTarget;

/// Limits on what a peer may send, applied to every message received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    /// The largest message head (start line and header section) and the
    /// largest trailer section, in bytes.
    pub max_head_size: usize,
    /// The most fields in a header section, and in a trailer section.
    pub max_headers: usize,
    /// The longest chunk-size line, chunk extensions included, in bytes.
    pub max_chunk_line_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_head_size: 64 * 1024,
            max_headers: 100,
            max_chunk_line_size: 4 * 1024,
        }
    }
}

/// Settings for one server connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    /// Limits on received requests.
    pub limits: Limits,
    /// How many bytes of room each read asks the socket to fill.
    pub read_buffer_size: usize,
    /// Whether a response without a `Date` field gets one (RFC 9110 §6.6.1
    /// requires it of an origin server with a clock).
    pub date_header: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            read_buffer_size: 16 * 1024,
            date_header: true,
        }
    }
}

/// Settings for one client connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// Limits on received responses.
    pub limits: Limits,
    /// How many bytes of room each read asks the socket to fill.
    pub read_buffer_size: usize,
    /// The form of the request target every request on the connection
    /// carries: [`RequestTarget::Absolute`] on a connection to a forward
    /// proxy, [`RequestTarget::Origin`] otherwise. `CONNECT` always carries
    /// the authority.
    pub request_target: RequestTarget,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            read_buffer_size: 16 * 1024,
            request_target: RequestTarget::Origin,
        }
    }
}
