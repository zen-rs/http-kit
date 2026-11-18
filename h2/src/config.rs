//! Connection, flow-control and protocol settings.
//!
//! Every value here is an operator setting: the defaults are a starting point
//! sized for typical traffic, not a ceiling the crate enforces, except where
//! RFC 9113 fixes the wire representation's bounds (`MAX_FRAME_SIZE` in
//! `16_384..=16_777_215` and flow-control windows in `0..=2^31 - 1`).
//!
//! Each struct is `#[non_exhaustive]`, so adding a setting never breaks a
//! caller: start from `default()` and assign the fields that differ.

use std::time::Duration;

/// Limits on what a peer may send on one HTTP/2 connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// Largest uncompressed header or trailer section accepted, in bytes as
    /// RFC 9113 §6.5.2 counts them (`name.len() + value.len() + 32` per
    /// field), advertised as `SETTINGS_MAX_HEADER_LIST_SIZE`.
    pub max_header_list_size: u32,
    /// Largest frame payload accepted from the peer, advertised as
    /// `SETTINGS_MAX_FRAME_SIZE` (`16_384..=16_777_215`, RFC 9113 §6.5.2).
    pub max_frame_size: u32,
    /// Largest HPACK dynamic table capacity offered to the peer's encoder, in
    /// bytes (`SETTINGS_HEADER_TABLE_SIZE`).
    pub header_table_size: u32,
    /// Largest HPACK dynamic table capacity this endpoint's own encoder uses,
    /// even when the peer advertises a larger `SETTINGS_HEADER_TABLE_SIZE`.
    pub max_send_header_table_size: u32,
    /// Most peer-initiated streams open at once, advertised as
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`. `None` advertises no limit.
    pub max_concurrent_streams: Option<u32>,
    /// Most `CONTINUATION` frames accepted in one header block before the
    /// connection closes with `ENHANCE_YOUR_CALM`.
    pub max_continuation_frames: usize,
    /// Most peer `RST_STREAM` frames accepted on incomplete streams within
    /// [`rst_stream_window`](Self::rst_stream_window) before the connection
    /// closes with `ENHANCE_YOUR_CALM`.
    pub max_rst_streams_per_window: usize,
    /// Rolling window for [`max_rst_streams_per_window`](Self::max_rst_streams_per_window).
    pub rst_stream_window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_header_list_size: 64 * 1024,
            // RFC 9113 §6.5.2 initial value: 2^14 octets.
            max_frame_size: 16_384,
            // RFC 9113 §6.5.2 initial value: 4,096 octets.
            header_table_size: 4_096,
            max_send_header_table_size: 4_096,
            max_concurrent_streams: Some(100),
            max_continuation_frames: 32,
            max_rst_streams_per_window: 200,
            rst_stream_window: Duration::from_secs(10),
        }
    }
}

/// Receive flow-control windows advertised to the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FlowControlConfig {
    /// Initial receive window of each stream (`SETTINGS_INITIAL_WINDOW_SIZE`,
    /// `0..=2^31 - 1`), in bytes.
    pub initial_stream_window_size: u32,
    /// Initial connection-level receive window (`65_535..=2^31 - 1`), in
    /// bytes. Values above `65_535` are granted by a connection-level
    /// `WINDOW_UPDATE` sent with the connection preface.
    pub initial_connection_window_size: u32,
}

impl Default for FlowControlConfig {
    fn default() -> Self {
        Self {
            initial_stream_window_size: 1024 * 1024,
            initial_connection_window_size: 10 * 1024 * 1024,
        }
    }
}

/// Settings for one server connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ServerConfig {
    /// Limits on frames, header sections, concurrency and reset rate.
    pub limits: Limits,
    /// Receive flow-control windows.
    pub flow_control: FlowControlConfig,
    /// How many bytes of room each socket read reserves.
    pub read_buffer_size: usize,
    /// Whether a response without a `date` field gets one (RFC 9110 §6.6.1).
    pub date_header: bool,
    /// Whether RFC 8441 Extended `CONNECT` (`:protocol`) is advertised via
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1` and accepted on requests.
    pub enable_connect_protocol: bool,
    /// How long the client connection preface and initial `SETTINGS` may take
    /// to arrive. `None` waits without bound.
    pub handshake_timeout: Option<Duration>,
    /// How long an idle connection with no open streams may sit before
    /// closing cleanly. `None` waits without bound.
    pub keep_alive_timeout: Option<Duration>,
    /// How long a demanded read of a request body may stall without receiving
    /// bytes. `None` waits without bound.
    pub body_read_timeout: Option<Duration>,
    /// How long the server waits for the peer to acknowledge a `SETTINGS`
    /// frame before closing with `SETTINGS_TIMEOUT`. `None` disables the
    /// deadline.
    pub settings_ack_timeout: Option<Duration>,
    /// Fallback delay between the first `GOAWAY(2^31 - 1)` and the final
    /// `GOAWAY(last_stream_id)` during graceful shutdown (RFC 9113 §6.8) when
    /// the accompanying `PING` has not yet been acknowledged.
    pub graceful_shutdown_rtt: Duration,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            flow_control: FlowControlConfig::default(),
            read_buffer_size: 16 * 1024,
            date_header: true,
            enable_connect_protocol: true,
            handshake_timeout: Some(Duration::from_secs(10)),
            keep_alive_timeout: Some(Duration::from_secs(60)),
            body_read_timeout: Some(Duration::from_secs(30)),
            settings_ack_timeout: Some(Duration::from_secs(10)),
            graceful_shutdown_rtt: Duration::from_secs(1),
        }
    }
}

/// Settings for one client connection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClientConfig {
    /// Limits on frames, header sections and continuation count.
    pub limits: Limits,
    /// Receive flow-control windows.
    pub flow_control: FlowControlConfig,
    /// How many bytes of room each socket read reserves.
    pub read_buffer_size: usize,
    /// How long the server's initial `SETTINGS` frame may take to arrive.
    /// `None` waits without bound.
    pub handshake_timeout: Option<Duration>,
    /// How long the client waits for the server to acknowledge a `SETTINGS`
    /// frame before closing with `SETTINGS_TIMEOUT`. `None` disables the
    /// deadline.
    pub settings_ack_timeout: Option<Duration>,
    /// Interval between keep-alive `PING` frames when idle or active. `None`
    /// sends no periodic `PING`s.
    pub keep_alive_interval: Option<Duration>,
    /// How long a keep-alive `PING` waits for its `ACK` before failing the
    /// connection.
    pub keep_alive_timeout: Duration,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            flow_control: FlowControlConfig::default(),
            read_buffer_size: 16 * 1024,
            handshake_timeout: Some(Duration::from_secs(10)),
            settings_ack_timeout: Some(Duration::from_secs(10)),
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
        }
    }
}
