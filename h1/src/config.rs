//! Connection settings.
//!
//! Every value here is an operator setting: the defaults are a starting point
//! sized for typical traffic, not a ceiling the crate enforces.

use std::time::Duration;

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
    /// How long a request head may take to arrive in full, counted from its
    /// first byte (from the start of serving, for the connection's first
    /// request). `None` waits without bound.
    pub header_read_timeout: Option<Duration>,
    /// How long a keep-alive connection may sit idle, with no byte of the
    /// next request received. At the deadline the connection closes
    /// normally ([`ServerOutcome::Closed`](crate::ServerOutcome::Closed)).
    /// `None` waits without bound.
    pub keep_alive_timeout: Option<Duration>,
    /// How long a single read of a request body may take to deliver bytes.
    /// It bounds the socket, not the consumer: time spent waiting for the
    /// service to ask for more data does not count. `None` waits without
    /// bound.
    pub body_read_timeout: Option<Duration>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            read_buffer_size: 16 * 1024,
            date_header: true,
            header_read_timeout: Some(Duration::from_secs(30)),
            keep_alive_timeout: Some(Duration::from_secs(60)),
            body_read_timeout: Some(Duration::from_secs(30)),
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
    /// How long a request with `Expect: 100-continue` waits for the server's
    /// `100 Continue` before sending its body anyway (RFC 9110 §10.1.1).
    /// `None` waits until the server answers.
    pub expect_continue_timeout: Option<Duration>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            read_buffer_size: 16 * 1024,
            expect_continue_timeout: Some(Duration::from_secs(1)),
        }
    }
}
