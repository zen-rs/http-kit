//! Sans-IO HTTP/2 connection and stream state machine (RFC 9113).
//!
//! [`ProtoConn`] processes incoming wire bytes from a [`BytesMut`] buffer,
//! emits typed [`ProtoEvent`]s, enforces RFC 9113 framing, HPACK, stream-state,
//! flow-control, `CONTINUATION`-flood, and Rapid-Reset invariants, and batches
//! outgoing control frames into a contiguous buffer for vectored I/O.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    marker::PhantomData,
    time::{Duration, Instant},
};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Method, StatusCode, request, response};

use crate::{
    config::{ClientConfig, FlowControlConfig, Limits, ServerConfig},
    error::{Error, Malformed, Reason, Timeout},
    fields,
    frame::{
        self, CLIENT_PREFACE, FRAME_HEADER_LEN, Frame, FrameError, FrameHeader,
        INITIAL_MAX_FRAME_SIZE, INITIAL_WINDOW_SIZE, MAX_WINDOW_SIZE, PeerSettings, kind,
        setting_id,
    },
    hpack::{DecodeOutcome, Decoder as HpackDecoder, Encoder as HpackEncoder},
};

/// Opaque payload used for the RTT-measurement `PING` sent alongside the first
/// graceful-shutdown `GOAWAY` (RFC 9113 §6.8).
const GRACEFUL_SHUTDOWN_PING: [u8; 8] = *b"h2grace!";

/// Opaque payload used for periodic keep-alive `PING` probes.
const KEEP_ALIVE_PING: [u8; 8] = *b"h2ka0001";

/// Bounded history of closed and locally-reset stream IDs so in-flight frames
/// and `STREAM_CLOSED` vs `PROTOCOL_ERROR` diagnostics remain accurate without
/// unbounded memory growth.
const STREAM_HISTORY_CAP: usize = 256;

/// A 31-bit HTTP/2 stream identifier (`0..=2^31 - 1`, RFC 9113 §5.1.1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StreamId(u32);

impl StreamId {
    /// Stream `0`, addressing the connection as a whole.
    pub const CONNECTION: Self = Self(0);

    /// Largest legal 31-bit stream identifier (`2^31 - 1`).
    pub const MAX: Self = Self(0x7FFF_FFFF);

    /// Wraps `raw` if it fits in 31 bits (`<= 0x7FFF_FFFF`).
    #[must_use]
    #[inline]
    pub const fn new(raw: u32) -> Option<Self> {
        if raw <= Self::MAX.0 {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// Masks off the reserved 32nd bit (`R`) of a wire stream identifier.
    #[must_use]
    #[inline]
    pub const fn from_raw_masked(raw: u32) -> Self {
        Self(raw & Self::MAX.0)
    }

    /// Returns the raw `u32` value (`0..=0x7FFF_FFFF`).
    #[must_use]
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Whether this is [`StreamId::CONNECTION`] (`0`).
    #[must_use]
    #[inline]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Whether this is an odd, client-initiated stream identifier (`1, 3, ...`).
    #[must_use]
    #[inline]
    pub const fn is_client_initiated(self) -> bool {
        self.0 != 0 && (self.0 & 1) == 1
    }

    /// Whether this is a non-zero even, server-initiated stream identifier.
    #[must_use]
    #[inline]
    pub const fn is_server_initiated(self) -> bool {
        self.0 != 0 && (self.0 & 1) == 0
    }
}

impl From<StreamId> for u32 {
    fn from(id: StreamId) -> Self {
        id.0
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamId({})", self.0)
    }
}

impl fmt::Display for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

mod private {
    pub trait Sealed {}
}

/// Marker trait distinguishing client and server HTTP/2 endpoints at the type
/// level.
pub trait Side: Copy + fmt::Debug + private::Sealed {
    /// `true` for [`ClientSide`], `false` for [`ServerSide`].
    const IS_CLIENT: bool;
}

/// Type-level marker for an HTTP/2 client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientSide;

impl private::Sealed for ClientSide {}
impl Side for ClientSide {
    const IS_CLIENT: bool = true;
}

/// Type-level marker for an HTTP/2 server connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSide;

impl private::Sealed for ServerSide {}
impl Side for ServerSide {
    const IS_CLIENT: bool = false;
}

/// Contiguous unpadded `DATA` payload bytes still waiting to be read off the
/// socket after the 9-byte `DATA` frame header was parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingData {
    /// Target stream of the active `DATA` frame.
    pub stream_id: StreamId,
    /// Remaining payload bytes in this `DATA` frame.
    pub remaining: usize,
}

/// Protocol events produced by [`ProtoConn::poll_recv`].
#[derive(Debug)]
pub enum ProtoEvent {
    /// Peer's initial `SETTINGS` frame arrived and `SETTINGS ACK` was queued.
    PrefaceComplete,
    /// Server: a complete, validated request head opened `stream_id`.
    Request {
        /// Newly opened client stream identifier.
        stream_id: StreamId,
        /// Validated request head (`Version::HTTP_2`, plus `Protocol` extension
        /// on Extended `CONNECT`).
        parts: request::Parts,
        /// True when no request body or trailers follow.
        end_stream: bool,
        /// Validated `Content-Length`, if declared.
        content_length: Option<u64>,
    },
    /// Client: a `1xx` informational response head arrived on `stream_id`.
    InformationalResponse {
        /// Request stream identifier.
        stream_id: StreamId,
        /// Validated informational response head.
        parts: response::Parts,
    },
    /// Client: the final (`2xx`–`5xx`) response head arrived on `stream_id`.
    Response {
        /// Request stream identifier.
        stream_id: StreamId,
        /// Validated final response head.
        parts: response::Parts,
        /// True when no response body or trailers follow.
        end_stream: bool,
        /// Effective `Content-Length` (`None` for `HEAD`, `204`, and `304`).
        content_length: Option<u64>,
    },
    /// A zero-copy slice of `DATA` payload arrived on `stream_id`.
    Data {
        /// Stream identifier.
        stream_id: StreamId,
        /// Payload bytes sliced from the receive buffer.
        data: Bytes,
        /// True if this chunk completed a `DATA` frame carrying `END_STREAM`.
        end_stream: bool,
    },
    /// Validated trailing fields arrived on `stream_id` (always `END_STREAM`).
    Trailers {
        /// Stream identifier.
        stream_id: StreamId,
        /// Validated trailer map.
        trailers: HeaderMap,
    },
    /// Peer reset `stream_id` via `RST_STREAM(reason)`.
    StreamReset {
        /// Reset stream identifier.
        stream_id: StreamId,
        /// Wire error code sent by peer.
        reason: Reason,
    },
    /// Peer violated a stream-scoped invariant on an already-open stream;
    /// `RST_STREAM` has already been queued in `control_buf`.
    StreamError {
        /// Affected stream identifier.
        stream_id: StreamId,
        /// Stream error classification.
        error: Error,
    },
    /// Send flow-control window or peer stream concurrency limit increased.
    SendWindowAvailable {
        /// `Some(id)` for a stream `WINDOW_UPDATE`, `None` for connection-wide
        /// window or `SETTINGS` updates.
        stream_id: Option<StreamId>,
    },
    /// Peer sent `GOAWAY`. Unprocessed locally initiated streams with
    /// `id > last_stream_id` have been closed and collected in
    /// `rejected_streams`.
    GoAway {
        /// Highest locally initiated stream ID the peer may process.
        last_stream_id: StreamId,
        /// Peer's termination reason.
        reason: Reason,
        /// Diagnostic payload from the `GOAWAY` frame.
        debug_data: Bytes,
        /// Locally initiated streams above `last_stream_id` that are safe to
        /// retry (`Error::RequestRejected`).
        rejected_streams: Vec<StreamId>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrefaceState {
    /// Server waiting for the 24-byte `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` magic.
    ClientMagic { matched: usize },
    /// Waiting for the peer's initial `SETTINGS` frame.
    InitialSettings,
    /// Handshake complete.
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalHalf {
    /// Server has not sent final response `HEADERS` yet.
    AwaitingResponseHeaders,
    /// Headers sent without `END_STREAM`; sending body/trailers.
    StreamingBody,
    /// `END_STREAM` sent.
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteHalf {
    /// Client waiting for `1xx` / final response `HEADERS`.
    AwaitingResponseHeaders,
    /// Initial `HEADERS` received without `END_STREAM`; expecting `DATA` or
    /// trailing `HEADERS(END_STREAM)`.
    StreamingBody,
    /// `END_STREAM` received.
    Closed,
}

#[derive(Debug)]
struct StreamState {
    local: LocalHalf,
    remote: RemoteHalf,
    send_window: i64,
    recv_window: i64,
    unreleased_recv: u64,
    expected_recv_len: Option<u64>,
    received_bytes: u64,
    declared_send_len: Option<u64>,
    sent_bytes: u64,
    is_head_request: bool,
    is_standard_connect: bool,
    peer_initiated: bool,
}

#[derive(Debug)]
struct PendingHeaderBlock {
    stream_id: StreamId,
    end_stream: bool,
    dependency: Option<StreamId>,
    buf: BytesMut,
    continuations: usize,
}

#[derive(Debug)]
enum ActiveData {
    Deliver {
        stream_id: StreamId,
        data_remaining: usize,
        pad_remaining: usize,
        end_stream: bool,
    },
    Discard {
        remaining: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GracefulShutdown {
    None,
    /// Sent `GOAWAY(2^31 - 1, NO_ERROR)` + `PING`; waiting for `PING ACK` or
    /// fallback RTT deadline before sending final `GOAWAY(max_peer_stream_id)`.
    Phase1 {
        deadline: Instant,
    },
    /// Sent final `GOAWAY(max_peer_stream_id, NO_ERROR)`; draining active streams.
    Phase2 {
        last_stream_id: u32,
    },
}

#[derive(Debug, Default)]
struct BoundedIdSet {
    ring: VecDeque<StreamId>,
}

impl BoundedIdSet {
    fn insert(&mut self, id: StreamId) {
        if self.ring.contains(&id) {
            return;
        }
        if self.ring.len() >= STREAM_HISTORY_CAP {
            self.ring.pop_front();
        }
        self.ring.push_back(id);
    }

    fn contains(&self, id: StreamId) -> bool {
        self.ring.contains(&id)
    }

    fn remove(&mut self, id: StreamId) {
        if let Some(pos) = self.ring.iter().position(|&x| x == id) {
            self.ring.remove(pos);
        }
    }
}

/// Sans-IO HTTP/2 connection state machine parameterized by [`Side`].
#[derive(Debug)]
pub struct ProtoConn<S: Side> {
    limits: Limits,
    flow_control: FlowControlConfig,
    enable_connect_protocol: bool,

    preface: PrefaceState,
    hpack_encoder: HpackEncoder,
    hpack_decoder: HpackDecoder,

    control_buf: BytesMut,
    scratch_block: BytesMut,
    events: VecDeque<ProtoEvent>,

    continuation: Option<PendingHeaderBlock>,
    active_data: Option<ActiveData>,

    streams: HashMap<StreamId, StreamState>,
    local_active_streams: usize,
    peer_active_streams: usize,
    next_local_stream_id: u32,
    max_local_stream_id: u32,
    max_peer_stream_id: u32,
    closed_streams: BoundedIdSet,
    locally_reset_streams: BoundedIdSet,

    conn_send_window: i64,
    conn_recv_window: i64,
    conn_unreleased_recv: u64,

    peer_initial_window_size: u32,
    peer_max_frame_size: u32,
    peer_max_concurrent_streams: u32,
    peer_max_header_list_size: Option<u32>,
    peer_enable_connect_protocol: bool,

    pending_settings_acks: VecDeque<Option<Instant>>,
    handshake_deadline: Option<Instant>,

    keep_alive_interval: Option<Duration>,
    keep_alive_timeout: Duration,
    next_keep_alive_at: Option<Instant>,
    keep_alive_ping_deadline: Option<Instant>,

    graceful_shutdown_rtt: Duration,
    graceful_shutdown: GracefulShutdown,

    rst_window_start: Instant,
    rst_count: usize,

    peer_goaway: Option<(StreamId, Reason)>,
    local_goaway_sent: bool,
    fatal_error_sent: bool,

    _side: PhantomData<S>,
}

impl ProtoConn<ClientSide> {
    /// Creates a client-side HTTP/2 state machine, immediately queuing the
    /// 24-octet client magic, initial `SETTINGS`, and any initial connection
    /// `WINDOW_UPDATE` into the outgoing control buffer.
    #[must_use]
    pub fn new_client(config: &ClientConfig, now: Instant) -> Self {
        let mut control_buf = BytesMut::with_capacity(128);
        control_buf.extend_from_slice(CLIENT_PREFACE);
        queue_initial_settings(
            &config.limits,
            &config.flow_control,
            true,
            false,
            &mut control_buf,
        );
        let conn_recv_window =
            queue_initial_conn_window_update(&config.flow_control, &mut control_buf);

        let mut pending_settings_acks = VecDeque::with_capacity(2);
        pending_settings_acks
            .push_back(config.settings_ack_timeout.and_then(|d| now.checked_add(d)));

        Self {
            limits: config.limits.clone(),
            flow_control: config.flow_control,
            enable_connect_protocol: false,
            preface: PrefaceState::InitialSettings,
            hpack_encoder: HpackEncoder::new(config.limits.max_send_header_table_size),
            hpack_decoder: HpackDecoder::new(config.limits.header_table_size),
            control_buf,
            scratch_block: BytesMut::with_capacity(256),
            events: VecDeque::with_capacity(8),
            continuation: None,
            active_data: None,
            streams: HashMap::new(),
            local_active_streams: 0,
            peer_active_streams: 0,
            next_local_stream_id: 1,
            max_local_stream_id: 0,
            max_peer_stream_id: 0,
            closed_streams: BoundedIdSet::default(),
            locally_reset_streams: BoundedIdSet::default(),
            conn_send_window: i64::from(INITIAL_WINDOW_SIZE),
            conn_recv_window,
            conn_unreleased_recv: 0,
            peer_initial_window_size: INITIAL_WINDOW_SIZE,
            peer_max_frame_size: INITIAL_MAX_FRAME_SIZE,
            peer_max_concurrent_streams: u32::MAX,
            peer_max_header_list_size: None,
            peer_enable_connect_protocol: false,
            pending_settings_acks,
            handshake_deadline: config.handshake_timeout.and_then(|d| now.checked_add(d)),
            keep_alive_interval: config.keep_alive_interval,
            keep_alive_timeout: config.keep_alive_timeout,
            next_keep_alive_at: config.keep_alive_interval.and_then(|d| now.checked_add(d)),
            keep_alive_ping_deadline: None,
            graceful_shutdown_rtt: Duration::from_secs(1),
            graceful_shutdown: GracefulShutdown::None,
            rst_window_start: now,
            rst_count: 0,
            peer_goaway: None,
            local_goaway_sent: false,
            fatal_error_sent: false,
            _side: PhantomData,
        }
    }

    /// Whether a new locally initiated request stream can be opened right now
    /// (not closing/GOAWAY, stream IDs remain, and below peer's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`).
    #[must_use]
    pub fn can_open_stream(&self) -> bool {
        !self.is_closing()
            && self.next_local_stream_id <= StreamId::MAX.0
            && (self.local_active_streams as u64) < u64::from(self.peer_max_concurrent_streams)
    }

    /// Validates `parts`, allocates the next odd [`StreamId`], and HPACK-encodes
    /// its `HEADERS` (+ `CONTINUATION` if needed) into `control_buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ConnectionClosed`] / [`Error::RequestRejected`] if the
    /// connection has closed or received `GOAWAY`, [`Error::StreamsExhausted`]
    /// if stream IDs are exhausted, or a request-shaping error before touching
    /// connection state.
    pub fn open_request(
        &mut self,
        parts: &request::Parts,
        body_len: Option<u64>,
        end_stream: bool,
    ) -> Result<StreamId, Error> {
        if self.fatal_error_sent {
            return Err(Error::ConnectionClosed);
        }
        if self.peer_goaway.is_some() {
            return Err(Error::RequestRejected);
        }
        if self.next_local_stream_id > StreamId::MAX.0 {
            return Err(Error::StreamsExhausted);
        }

        // Validate pre-HPACK conditions before allocating stream ID or mutating HPACK!
        let has_protocol = parts.extensions.get::<fields::Protocol>().is_some();
        if has_protocol && (parts.method != Method::CONNECT || !self.peer_enable_connect_protocol) {
            return Err(Error::UnsupportedExtendedConnect);
        }
        if parts.uri.authority().is_none() && !parts.headers.contains_key(http::header::HOST) {
            return Err(Error::MissingAuthority);
        }
        let pre_declared = fields::parse_outgoing_content_length(&parts.headers)?;
        if end_stream {
            let eff = pre_declared.or(body_len);
            if let Some(len) = eff
                && len != 0
            {
                return Err(Error::ContentLengthMismatch { declared: len });
            }
        }

        self.scratch_block.clear();
        let declared_send_len = fields::encode_request(
            &mut self.hpack_encoder,
            parts,
            body_len,
            end_stream,
            self.peer_enable_connect_protocol,
            &mut self.scratch_block,
        )?;
        let header_block = self.scratch_block.split().freeze();

        let stream_id = StreamId(self.next_local_stream_id);
        self.next_local_stream_id += 2;
        self.max_local_stream_id = stream_id.0;

        frame::encode_header_block(
            stream_id,
            header_block,
            end_stream,
            self.peer_max_frame_size as usize,
            &mut self.control_buf,
        );

        let is_standard_connect = parts.method == Method::CONNECT && !has_protocol;
        let state = StreamState {
            local: if end_stream {
                LocalHalf::Closed
            } else {
                LocalHalf::StreamingBody
            },
            remote: RemoteHalf::AwaitingResponseHeaders,
            send_window: i64::from(self.peer_initial_window_size),
            recv_window: i64::from(self.flow_control.initial_stream_window_size),
            unreleased_recv: 0,
            expected_recv_len: None,
            received_bytes: 0,
            declared_send_len,
            sent_bytes: 0,
            is_head_request: parts.method == Method::HEAD,
            is_standard_connect,
            peer_initiated: false,
        };
        self.streams.insert(stream_id, state);
        self.local_active_streams += 1;
        Ok(stream_id)
    }
}

impl ProtoConn<ServerSide> {
    /// Creates a server-side HTTP/2 state machine, immediately queuing the
    /// server's initial `SETTINGS` and any initial connection `WINDOW_UPDATE`
    /// while awaiting the client's 24-byte preface and initial `SETTINGS`.
    #[must_use]
    pub fn new_server(config: &ServerConfig, now: Instant) -> Self {
        let mut control_buf = BytesMut::with_capacity(128);
        queue_initial_settings(
            &config.limits,
            &config.flow_control,
            false,
            config.enable_connect_protocol,
            &mut control_buf,
        );
        let conn_recv_window =
            queue_initial_conn_window_update(&config.flow_control, &mut control_buf);

        let mut pending_settings_acks = VecDeque::with_capacity(2);
        pending_settings_acks
            .push_back(config.settings_ack_timeout.and_then(|d| now.checked_add(d)));

        Self {
            limits: config.limits.clone(),
            flow_control: config.flow_control,
            enable_connect_protocol: config.enable_connect_protocol,
            preface: PrefaceState::ClientMagic { matched: 0 },
            hpack_encoder: HpackEncoder::new(config.limits.max_send_header_table_size),
            hpack_decoder: HpackDecoder::new(config.limits.header_table_size),
            control_buf,
            scratch_block: BytesMut::with_capacity(256),
            events: VecDeque::with_capacity(8),
            continuation: None,
            active_data: None,
            streams: HashMap::new(),
            local_active_streams: 0,
            peer_active_streams: 0,
            next_local_stream_id: 2,
            max_local_stream_id: 0,
            max_peer_stream_id: 0,
            closed_streams: BoundedIdSet::default(),
            locally_reset_streams: BoundedIdSet::default(),
            conn_send_window: i64::from(INITIAL_WINDOW_SIZE),
            conn_recv_window,
            conn_unreleased_recv: 0,
            peer_initial_window_size: INITIAL_WINDOW_SIZE,
            peer_max_frame_size: INITIAL_MAX_FRAME_SIZE,
            peer_max_concurrent_streams: u32::MAX,
            peer_max_header_list_size: None,
            peer_enable_connect_protocol: false,
            pending_settings_acks,
            handshake_deadline: config.handshake_timeout.and_then(|d| now.checked_add(d)),
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            next_keep_alive_at: None,
            keep_alive_ping_deadline: None,
            graceful_shutdown_rtt: config.graceful_shutdown_rtt,
            graceful_shutdown: GracefulShutdown::None,
            rst_window_start: now,
            rst_count: 0,
            peer_goaway: None,
            local_goaway_sent: false,
            fatal_error_sent: false,
            _side: PhantomData,
        }
    }

    /// Queues a `1xx` informational response head (`100`, `102`, `103`, etc.)
    /// on `stream_id` without closing the local half.
    ///
    /// # Errors
    ///
    /// Fails if `parts.status` is not `1xx` (or is `101`), or if `stream_id` is
    /// no longer awaiting response headers.
    pub fn send_informational(
        &mut self,
        stream_id: StreamId,
        parts: &response::Parts,
    ) -> Result<(), Error> {
        let Some(stream) = self.streams.get(&stream_id) else {
            return Err(Error::ConnectionClosed);
        };
        if stream.local != LocalHalf::AwaitingResponseHeaders {
            return Err(Error::ConnectionClosed);
        }
        self.scratch_block.clear();
        fields::encode_informational_response(
            &mut self.hpack_encoder,
            parts,
            &mut self.scratch_block,
        )?;
        let block = self.scratch_block.split().freeze();
        frame::encode_header_block(
            stream_id,
            block,
            false,
            self.peer_max_frame_size as usize,
            &mut self.control_buf,
        );
        Ok(())
    }

    /// Queues the final (`2xx`–`5xx`) response head on `stream_id`.
    ///
    /// When `end_stream` is `true` and the client has not yet finished sending
    /// the request body (`remote != Closed`) on a non-`CONNECT` request, only
    /// the local half closes here; the caller may subsequently call
    /// [`send_reset`](Self::send_reset) with [`Reason::NO_ERROR`] if the
    /// remaining request body is unneeded (RFC 9113 §8.1).
    ///
    /// # Errors
    ///
    /// Fails if `parts.status` is `1xx`, `Content-Length` is invalid or
    /// mismatches `end_stream`, or `stream_id` is already closed/reset.
    pub fn send_response(
        &mut self,
        stream_id: StreamId,
        parts: &response::Parts,
        body_len: Option<u64>,
        end_stream: bool,
        date: Option<&HeaderValue>,
    ) -> Result<(), Error> {
        if parts.status.is_informational() {
            return Err(Error::InformationalResponse(parts.status));
        }
        let (is_head, is_standard_connect) = {
            let Some(stream) = self.streams.get(&stream_id) else {
                return Err(Error::ConnectionClosed);
            };
            if stream.local != LocalHalf::AwaitingResponseHeaders {
                return Err(Error::ConnectionClosed);
            }
            (stream.is_head_request, stream.is_standard_connect)
        };

        // Pre-validate Content-Length before mutating HPACK state.
        let pre_declared = fields::parse_outgoing_content_length(&parts.headers)?;
        let bodiless = is_head
            || parts.status == StatusCode::NO_CONTENT
            || parts.status == StatusCode::NOT_MODIFIED;
        if end_stream
            && !bodiless
            && let Some(len) = pre_declared.or(body_len)
            && len != 0
        {
            return Err(Error::ContentLengthMismatch { declared: len });
        }

        self.scratch_block.clear();
        let declared_send_len = fields::encode_response(
            &mut self.hpack_encoder,
            parts,
            is_head,
            if is_standard_connect && parts.status.is_success() {
                None
            } else {
                body_len
            },
            end_stream,
            date,
            &mut self.scratch_block,
        )?;
        let block = self.scratch_block.split().freeze();
        frame::encode_header_block(
            stream_id,
            block,
            end_stream,
            self.peer_max_frame_size as usize,
            &mut self.control_buf,
        );

        let close_completely = {
            let stream = self.streams.get_mut(&stream_id).expect("checked above");
            stream.declared_send_len = if is_standard_connect && parts.status.is_success() {
                None
            } else {
                declared_send_len
            };
            if end_stream {
                stream.local = LocalHalf::Closed;
                stream.remote == RemoteHalf::Closed
            } else {
                stream.local = LocalHalf::StreamingBody;
                false
            }
        };

        if close_completely {
            self.finish_stream(stream_id);
        }
        Ok(())
    }

    /// Initiates RFC 9113 §6.8 two-phase graceful shutdown: immediately queues
    /// `GOAWAY(2^31 - 1, NO_ERROR)` plus an RTT-probing `PING`, then queues the
    /// final `GOAWAY(last_peer_stream_id, NO_ERROR)` as soon as that `PING` is
    /// acknowledged or [`ServerConfig::graceful_shutdown_rtt`] elapses.
    pub fn initiate_graceful_shutdown(&mut self, now: Instant) {
        if self.graceful_shutdown != GracefulShutdown::None || self.fatal_error_sent {
            return;
        }
        self.local_goaway_sent = true;
        frame::encode_goaway(StreamId::MAX, Reason::NO_ERROR, b"", &mut self.control_buf);
        frame::encode_ping(false, GRACEFUL_SHUTDOWN_PING, &mut self.control_buf);
        let deadline = now.checked_add(self.graceful_shutdown_rtt).unwrap_or(now);
        if self.graceful_shutdown_rtt.is_zero() {
            self.enter_graceful_phase2();
        } else {
            self.graceful_shutdown = GracefulShutdown::Phase1 { deadline };
        }
    }

    /// True once the second (final) graceful `GOAWAY` has been queued and all
    /// accepted streams have completed.
    #[must_use]
    pub fn is_gracefully_drained(&self) -> bool {
        matches!(self.graceful_shutdown, GracefulShutdown::Phase2 { .. }) && self.streams.is_empty()
    }
}

impl<S: Side> ProtoConn<S> {
    /// True once the peer's initial `SETTINGS` frame (and client magic on
    /// servers) has been received and validated.
    #[must_use]
    #[inline]
    pub const fn is_handshake_complete(&self) -> bool {
        matches!(self.preface, PrefaceState::Done)
    }

    /// True when serialized control/header frames are waiting in `control_buf`.
    #[must_use]
    #[inline]
    pub fn has_pending_send(&self) -> bool {
        !self.control_buf.is_empty()
    }

    /// Moves any queued control and header frames out of `control_buf` into
    /// `out` as a single contiguous [`Bytes`] buffer.
    #[inline]
    pub fn drain_control(&mut self, out: &mut Vec<Bytes>) {
        if !self.control_buf.is_empty() {
            out.push(self.control_buf.split().freeze());
        }
    }

    /// Number of currently open streams (either half still open).
    #[must_use]
    #[inline]
    pub fn active_stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Whether the peer has sent a `GOAWAY` frame.
    #[must_use]
    #[inline]
    pub const fn is_peer_goaway(&self) -> bool {
        self.peer_goaway.is_some()
    }

    /// Whether the connection is closing or closed (peer `GOAWAY` received,
    /// local `GOAWAY` sent, or fatal protocol error emitted).
    #[must_use]
    #[inline]
    pub const fn is_closing(&self) -> bool {
        self.fatal_error_sent || self.local_goaway_sent || self.peer_goaway.is_some()
    }

    /// Maximum frame payload size currently accepted by the peer
    /// (`SETTINGS_MAX_FRAME_SIZE`).
    #[must_use]
    #[inline]
    pub const fn peer_max_frame_size(&self) -> usize {
        self.peer_max_frame_size as usize
    }

    /// Whether the peer has advertised `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`
    /// (RFC 8441).
    #[must_use]
    #[inline]
    pub const fn can_send_extended_connect(&self) -> bool {
        self.peer_enable_connect_protocol
    }

    /// Available flow-control send window for `stream_id` (`min(conn, stream)`
    /// clamped to `>= 0`, or `0` if `stream_id` is not open for sending).
    #[must_use]
    pub fn send_window(&self, stream_id: StreamId) -> usize {
        let Some(stream) = self.streams.get(&stream_id) else {
            return 0;
        };
        if stream.local != LocalHalf::StreamingBody {
            return 0;
        }
        let avail = self.conn_send_window.min(stream.send_window).max(0);
        usize::try_from(avail).unwrap_or(usize::MAX)
    }

    /// When positioned inside an unpadded `DATA` frame payload with `remaining`
    /// bytes still unread from the socket, returns `(stream_id, remaining)` so
    /// the I/O driver can `splice(2)` or pass owned read buffers directly
    /// without copying through `buf`.
    #[must_use]
    #[inline]
    pub const fn pending_data_run(&self) -> Option<PendingData> {
        match self.active_data {
            Some(ActiveData::Deliver {
                stream_id,
                data_remaining,
                pad_remaining: 0,
                ..
            }) if data_remaining > 0 => Some(PendingData {
                stream_id,
                remaining: data_remaining,
            }),
            _ => None,
        }
    }

    /// Advances an active [`pending_data_run`](Self::pending_data_run) by `len`
    /// externally transferred bytes (`splice_to_pipe` or zero-copy owned read),
    /// returning `Ok(true)` if the `DATA` frame finished with `END_STREAM`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] only if called without a matching
    /// `pending_data_run`. Stream-level `Content-Length` mismatches are handled
    /// as stream errors (`RST_STREAM` + [`ProtoEvent::StreamError`]).
    pub fn consume_external_data(&mut self, len: usize) -> Result<bool, Error> {
        let Some(ActiveData::Deliver {
            stream_id,
            mut data_remaining,
            pad_remaining: 0,
            end_stream,
        }) = self.active_data.take()
        else {
            return Err(self.conn_error(
                Reason::INTERNAL_ERROR,
                "consume_external_data called outside unpadded DATA payload",
            ));
        };
        if len > data_remaining {
            return Err(self.conn_error(
                Reason::INTERNAL_ERROR,
                "consume_external_data exceeded remaining DATA payload",
            ));
        }
        data_remaining -= len;
        if data_remaining > 0 {
            self.active_data = Some(ActiveData::Deliver {
                stream_id,
                data_remaining,
                pad_remaining: 0,
                end_stream,
            });
            return Ok(false);
        }
        if end_stream {
            if let Err(malformed) = self.complete_remote_stream(stream_id) {
                self.fail_open_stream(
                    stream_id,
                    Reason::PROTOCOL_ERROR,
                    Error::Malformed(malformed),
                );
                return Ok(true);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Validates connection state when the peer closes the underlying TCP/TLS
    /// read side (`read == 0`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] / [`Error::ConnectionClosed`] if `buf_empty`
    /// is false, a frame or `CONTINUATION` block was truncated mid-stream, or
    /// open streams were still awaiting peer frames.
    pub fn on_eof(&mut self, buf_empty: bool) -> Result<(), Error> {
        if !buf_empty
            || !self.is_handshake_complete()
            || self.continuation.is_some()
            || self.active_data.is_some()
        {
            return Err(Error::ConnectionClosed);
        }
        if !self.streams.is_empty() {
            return Err(Error::ConnectionClosed);
        }
        Ok(())
    }

    /// Credits `bytes` of consumed `DATA` back to the connection receive window
    /// and (when `stream_id` is still open on its receive half) to `stream_id`'s
    /// receive window, queuing `WINDOW_UPDATE` frames once the replenishment
    /// threshold is reached.
    ///
    /// Safe to call after `stream_id` has closed or reset: connection-level
    /// credit is still replenished while stream `WINDOW_UPDATE` is skipped.
    pub fn release_recv_capacity(&mut self, stream_id: StreamId, bytes: usize) {
        if bytes == 0 || self.fatal_error_sent {
            return;
        }
        self.release_conn_only(bytes);

        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return;
        };
        if stream.remote != RemoteHalf::StreamingBody {
            return;
        }
        stream.unreleased_recv = stream.unreleased_recv.saturating_add(bytes as u64);
        let target = self.flow_control.initial_stream_window_size;
        let threshold = u64::from((target / 2).max(1));
        if stream.unreleased_recv >= threshold
            || (stream.recv_window <= 0
                && stream
                    .recv_window
                    .saturating_add(stream.unreleased_recv as i64)
                    > 0)
        {
            let max_room = (i64::from(MAX_WINDOW_SIZE) - stream.recv_window).max(0) as u64;
            let grant = stream
                .unreleased_recv
                .min(max_room)
                .min(u64::from(MAX_WINDOW_SIZE));
            if grant > 0 {
                let inc = grant as u32;
                stream.unreleased_recv -= grant;
                stream.recv_window += i64::from(inc);
                frame::encode_window_update(stream_id, inc, &mut self.control_buf);
            }
        }
    }

    fn release_conn_only(&mut self, bytes: usize) {
        if bytes == 0 || self.fatal_error_sent {
            return;
        }
        self.conn_unreleased_recv = self.conn_unreleased_recv.saturating_add(bytes as u64);
        let target = self
            .flow_control
            .initial_connection_window_size
            .max(INITIAL_WINDOW_SIZE);
        let threshold = u64::from((target / 2).max(1));
        if self.conn_unreleased_recv >= threshold
            || (self.conn_recv_window <= 0 && self.conn_unreleased_recv > 0)
        {
            let max_room = (i64::from(MAX_WINDOW_SIZE) - self.conn_recv_window).max(0) as u64;
            let grant = self
                .conn_unreleased_recv
                .min(max_room)
                .min(u64::from(MAX_WINDOW_SIZE));
            if grant > 0 {
                let inc = grant as u32;
                self.conn_unreleased_recv -= grant;
                self.conn_recv_window += i64::from(inc);
                frame::encode_window_update(StreamId::CONNECTION, inc, &mut self.control_buf);
            }
        }
    }

    /// Encodes as much of `data` as flow control permits in `DATA` frames of at
    /// most `peer_max_frame_size` bytes into `out` (draining pending control
    /// frames first so wire ordering is preserved).
    ///
    /// Returns `Ok(true)` when all of `data` (and `END_STREAM`, if `end_stream`
    /// is true) has been queued, or `Ok(false)` when `data` still holds bytes
    /// blocked on send flow-control window.
    ///
    /// # Errors
    ///
    /// Fails if `stream_id` is closed/reset or outgoing `Content-Length` is
    /// violated (queuing `RST_STREAM(INTERNAL_ERROR)` on mismatch).
    pub fn encode_data(
        &mut self,
        stream_id: StreamId,
        data: &mut Bytes,
        end_stream: bool,
        out: &mut Vec<Bytes>,
    ) -> Result<bool, Error> {
        self.drain_control(out);

        if data.is_empty() {
            if !end_stream {
                return Ok(true);
            }
            let hdr = self.reserve_send_data(stream_id, 0, true)?;
            out.push(Bytes::copy_from_slice(&hdr));
            return Ok(true);
        }

        let max_frame = self.peer_max_frame_size as usize;
        while !data.is_empty() {
            let avail = self.send_window(stream_id);
            if avail == 0 {
                // Verify stream is still alive rather than closed/reset.
                if !self
                    .streams
                    .get(&stream_id)
                    .is_some_and(|s| s.local == LocalHalf::StreamingBody)
                {
                    return Err(Error::ConnectionClosed);
                }
                return Ok(false);
            }
            let chunk_len = data.len().min(avail).min(max_frame);
            let is_last = end_stream && chunk_len == data.len();
            let hdr = self.reserve_send_data(stream_id, chunk_len, is_last)?;
            out.push(Bytes::copy_from_slice(&hdr));
            out.push(data.split_to(chunk_len));
        }

        Ok(true)
    }

    /// Reserves `n = min(len, send_window, peer_max_frame_size)` bytes of send
    /// window for a zero-copy `SendFile` or `SpliceWrite` transfer, drains any
    /// pending control frames, and pushes the 9-byte `DATA` frame header for
    /// `n` bytes onto `out`.
    ///
    /// Returns `Ok(0)` without pushing a header when `len > 0` and the send
    /// window is `0` (caller waits for `WINDOW_UPDATE`).
    ///
    /// # Errors
    ///
    /// Fails if `stream_id` is closed/reset or outgoing `Content-Length` is
    /// violated.
    pub fn prepare_raw_data(
        &mut self,
        stream_id: StreamId,
        len: usize,
        end_stream_if_complete: bool,
        out: &mut Vec<Bytes>,
    ) -> Result<usize, Error> {
        self.drain_control(out);
        if len == 0 {
            if end_stream_if_complete {
                let hdr = self.reserve_send_data(stream_id, 0, true)?;
                out.push(Bytes::copy_from_slice(&hdr));
            }
            return Ok(0);
        }
        let avail = self.send_window(stream_id);
        if avail == 0 {
            if !self
                .streams
                .get(&stream_id)
                .is_some_and(|s| s.local == LocalHalf::StreamingBody)
            {
                return Err(Error::ConnectionClosed);
            }
            return Ok(0);
        }
        let n = len.min(avail).min(self.peer_max_frame_size as usize);
        let is_last = end_stream_if_complete && n == len;
        let hdr = self.reserve_send_data(stream_id, n, is_last)?;
        out.push(Bytes::copy_from_slice(&hdr));
        Ok(n)
    }

    fn reserve_send_data(
        &mut self,
        stream_id: StreamId,
        len: usize,
        end_stream: bool,
    ) -> Result<[u8; FRAME_HEADER_LEN], Error> {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            return Err(Error::ConnectionClosed);
        };
        if stream.local != LocalHalf::StreamingBody {
            return Err(Error::ConnectionClosed);
        }

        let next_sent = stream.sent_bytes.saturating_add(len as u64);
        if let Some(declared) = stream.declared_send_len
            && (next_sent > declared || (end_stream && next_sent != declared))
        {
            self.send_reset(stream_id, Reason::INTERNAL_ERROR);
            return Err(Error::ContentLengthMismatch { declared });
        }

        stream.sent_bytes = next_sent;
        self.conn_send_window -= len as i64;
        stream.send_window -= len as i64;

        let close_completely = if end_stream {
            stream.local = LocalHalf::Closed;
            stream.remote == RemoteHalf::Closed
        } else {
            false
        };
        if close_completely {
            self.finish_stream(stream_id);
        }

        Ok(frame::encode_data_header(stream_id, len as u32, end_stream))
    }

    /// HPACK-encodes outgoing `trailers` with `END_STREAM` on `stream_id`.
    ///
    /// # Errors
    ///
    /// Fails if `stream_id` is closed/reset or declared `Content-Length` has
    /// not been satisfied.
    pub fn send_trailers(
        &mut self,
        stream_id: StreamId,
        trailers: &HeaderMap,
    ) -> Result<(), Error> {
        let close_completely = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return Err(Error::ConnectionClosed);
            };
            if stream.local != LocalHalf::StreamingBody {
                return Err(Error::ConnectionClosed);
            }
            if let Some(declared) = stream.declared_send_len
                && stream.sent_bytes != declared
            {
                self.send_reset(stream_id, Reason::INTERNAL_ERROR);
                return Err(Error::ContentLengthMismatch { declared });
            }
            stream.local = LocalHalf::Closed;
            stream.remote == RemoteHalf::Closed
        };

        self.scratch_block.clear();
        fields::encode_trailers(&mut self.hpack_encoder, trailers, &mut self.scratch_block);
        let block = self.scratch_block.split().freeze();
        frame::encode_header_block(
            stream_id,
            block,
            true,
            self.peer_max_frame_size as usize,
            &mut self.control_buf,
        );

        if close_completely {
            self.finish_stream(stream_id);
        }
        Ok(())
    }

    /// Queues `RST_STREAM(stream_id, reason)` and removes `stream_id` from
    /// active streams, recording it in `locally_reset_streams` if the peer's
    /// send half was still open so in-flight peer frames do not trigger a
    /// spurious connection error.
    pub fn send_reset(&mut self, stream_id: StreamId, reason: Reason) {
        if stream_id.is_zero() || self.fatal_error_sent {
            return;
        }
        if let Some(removed) = self.remove_stream_entry(stream_id) {
            if removed.remote != RemoteHalf::Closed {
                self.locally_reset_streams.insert(stream_id);
            } else {
                self.closed_streams.insert(stream_id);
            }
            frame::encode_rst_stream(stream_id, reason, &mut self.control_buf);
        }
    }

    /// Queues a non-ACK `PING` frame.
    pub fn send_ping(&mut self, opaque: [u8; 8]) {
        if !self.fatal_error_sent {
            frame::encode_ping(false, opaque, &mut self.control_buf);
        }
    }

    /// Queues a `GOAWAY` frame.
    pub fn send_goaway(&mut self, last_stream_id: StreamId, reason: Reason, debug_data: &[u8]) {
        if !self.fatal_error_sent {
            self.local_goaway_sent = true;
            frame::encode_goaway(last_stream_id, reason, debug_data, &mut self.control_buf);
        }
    }

    /// Earliest protocol timer deadline (`handshake`, `SETTINGS ACK`,
    /// keep-alive `PING`, or two-phase graceful `GOAWAY`).
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        let settings_dl = self.pending_settings_acks.front().copied().flatten();
        let graceful_dl = match self.graceful_shutdown {
            GracefulShutdown::Phase1 { deadline } => Some(deadline),
            _ => None,
        };
        [
            self.handshake_deadline,
            settings_dl,
            self.keep_alive_ping_deadline,
            self.next_keep_alive_at,
            graceful_dl,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Advances time-driven protocol actions (`SETTINGS_TIMEOUT`, handshake
    /// timeout, keep-alive `PING`, and server graceful-shutdown Phase 2).
    ///
    /// # Errors
    ///
    /// Queues the appropriate `GOAWAY` into `control_buf` and returns
    /// [`Error::Timeout`] when a fatal deadline expires.
    pub fn poll_timeout(&mut self, now: Instant) -> Result<(), Error> {
        if let Some(dl) = self.handshake_deadline
            && now >= dl
        {
            self.handshake_deadline = None;
            if !self.is_handshake_complete() {
                self.queue_fatal_goaway(Reason::PROTOCOL_ERROR);
                return Err(Error::Timeout(Timeout::Handshake));
            }
        }

        if let Some(Some(dl)) = self.pending_settings_acks.front().copied()
            && now >= dl
        {
            self.pending_settings_acks.clear();
            self.queue_fatal_goaway(Reason::SETTINGS_TIMEOUT);
            return Err(Error::Timeout(Timeout::SettingsAck));
        }

        if let Some(dl) = self.keep_alive_ping_deadline
            && now >= dl
        {
            self.keep_alive_ping_deadline = None;
            self.queue_fatal_goaway(Reason::PROTOCOL_ERROR);
            return Err(Error::Timeout(Timeout::KeepAlive));
        }

        if self.keep_alive_ping_deadline.is_none()
            && let Some(next_at) = self.next_keep_alive_at
            && now >= next_at
        {
            self.next_keep_alive_at = None;
            if self.is_handshake_complete() && !self.fatal_error_sent {
                frame::encode_ping(false, KEEP_ALIVE_PING, &mut self.control_buf);
                self.keep_alive_ping_deadline = now.checked_add(self.keep_alive_timeout);
            }
        }

        if let GracefulShutdown::Phase1 { deadline } = self.graceful_shutdown
            && now >= deadline
        {
            self.enter_graceful_phase2();
        }

        Ok(())
    }

    /// Parses incoming bytes from `buf` and returns the next [`ProtoEvent`], or
    /// `Ok(None)` when more socket bytes are needed.
    ///
    /// Whenever a connection-wide error is detected, the matching `GOAWAY`
    /// frame is queued into `control_buf` before returning `Err(Error::Protocol)`,
    /// so flushing [`drain_control`](Self::drain_control) sends `GOAWAY` prior
    /// to closing the transport (RFC 9113 §5.4.1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Protocol`] on any connection-level framing, HPACK,
    /// stream-state, flow-control, or flood violation.
    pub fn poll_recv(
        &mut self,
        buf: &mut BytesMut,
        now: Instant,
    ) -> Result<Option<ProtoEvent>, Error> {
        if let Some(event) = self.events.pop_front() {
            return Ok(Some(event));
        }
        if self.fatal_error_sent {
            return Ok(None);
        }

        if let GracefulShutdown::Phase1 { deadline } = self.graceful_shutdown
            && now >= deadline
        {
            self.enter_graceful_phase2();
        }

        if !buf.is_empty()
            && self.keep_alive_ping_deadline.is_none()
            && let Some(interval) = self.keep_alive_interval
        {
            self.next_keep_alive_at = now.checked_add(interval);
        }

        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(Some(event));
            }

            // 1. Server 24-octet client magic check (validated byte-by-byte so a
            //    non-HTTP/2 peer fails on the very first mismatched byte!).
            if let PrefaceState::ClientMagic { mut matched } = self.preface {
                if buf.is_empty() {
                    return Ok(None);
                }
                let check_len = buf.len().min(CLIENT_PREFACE.len() - matched);
                if buf[..check_len] != CLIENT_PREFACE[matched..matched + check_len] {
                    return Err(self.conn_error(
                        Reason::PROTOCOL_ERROR,
                        "invalid HTTP/2 client connection preface",
                    ));
                }
                let _ = buf.split_to(check_len);
                matched += check_len;
                if matched < CLIENT_PREFACE.len() {
                    self.preface = PrefaceState::ClientMagic { matched };
                    return Ok(None);
                }
                self.preface = PrefaceState::InitialSettings;
            }

            // 2. Drain or deliver bytes of an in-progress `DATA` frame payload.
            if let Some(active) = self.active_data.take() {
                match active {
                    ActiveData::Discard { mut remaining } => {
                        let drop_n = buf.len().min(remaining);
                        let _ = buf.split_to(drop_n);
                        remaining -= drop_n;
                        if remaining > 0 {
                            self.active_data = Some(ActiveData::Discard { remaining });
                            return Ok(None);
                        }
                        continue;
                    }
                    ActiveData::Deliver {
                        stream_id,
                        mut data_remaining,
                        mut pad_remaining,
                        end_stream,
                    } => {
                        // If the stream was locally reset while mid-frame, switch
                        // remaining unread bytes to `Discard` and release conn window!
                        if !self.streams.contains_key(&stream_id) {
                            self.release_conn_only(data_remaining);
                            let rem = data_remaining + pad_remaining;
                            if rem > 0 {
                                self.active_data = Some(ActiveData::Discard { remaining: rem });
                                continue;
                            }
                            continue;
                        }

                        if data_remaining > 0 {
                            if buf.is_empty() {
                                self.active_data = Some(ActiveData::Deliver {
                                    stream_id,
                                    data_remaining,
                                    pad_remaining,
                                    end_stream,
                                });
                                return Ok(None);
                            }
                            let take = buf.len().min(data_remaining);
                            let chunk = buf.split_to(take).freeze();
                            data_remaining -= take;

                            if data_remaining == 0 && pad_remaining > 0 {
                                let drop_pad = buf.len().min(pad_remaining);
                                let _ = buf.split_to(drop_pad);
                                pad_remaining -= drop_pad;
                            }

                            let frame_done = data_remaining == 0 && pad_remaining == 0;
                            if !frame_done {
                                self.active_data = Some(ActiveData::Deliver {
                                    stream_id,
                                    data_remaining,
                                    pad_remaining,
                                    end_stream,
                                });
                            }

                            let emit_end = frame_done && end_stream;
                            if emit_end
                                && let Err(malformed) = self.complete_remote_stream(stream_id)
                            {
                                self.release_conn_only(chunk.len());
                                self.fail_open_stream(
                                    stream_id,
                                    Reason::PROTOCOL_ERROR,
                                    Error::Malformed(malformed),
                                );
                                continue;
                            }

                            return Ok(Some(ProtoEvent::Data {
                                stream_id,
                                data: chunk,
                                end_stream: emit_end,
                            }));
                        }

                        // Only trailing padding remains (`data_remaining == 0`).
                        let drop_pad = buf.len().min(pad_remaining);
                        let _ = buf.split_to(drop_pad);
                        pad_remaining -= drop_pad;
                        if pad_remaining > 0 {
                            self.active_data = Some(ActiveData::Deliver {
                                stream_id,
                                data_remaining: 0,
                                pad_remaining,
                                end_stream,
                            });
                            return Ok(None);
                        }
                        if end_stream {
                            if let Err(malformed) = self.complete_remote_stream(stream_id) {
                                self.fail_open_stream(
                                    stream_id,
                                    Reason::PROTOCOL_ERROR,
                                    Error::Malformed(malformed),
                                );
                                continue;
                            }
                            return Ok(Some(ProtoEvent::Data {
                                stream_id,
                                data: Bytes::new(),
                                end_stream: true,
                            }));
                        }
                        continue;
                    }
                }
            }

            // 3. Need at least 9 octets for the next frame header.
            if buf.len() < FRAME_HEADER_LEN {
                return Ok(None);
            }
            let raw_hdr: [u8; FRAME_HEADER_LEN] = buf[..FRAME_HEADER_LEN]
                .try_into()
                .expect("checked 9-byte slice");
            let header = FrameHeader::decode(raw_hdr);

            // RFC 9113 §3.4: peer's very first frame MUST be a non-ACK `SETTINGS`.
            if self.preface == PrefaceState::InitialSettings
                && (header.kind != kind::SETTINGS || (header.flags & frame::flags::ACK) != 0)
            {
                return Err(self.conn_error(
                    Reason::PROTOCOL_ERROR,
                    "first frame after preface was not SETTINGS",
                ));
            }

            let expected_cont = self.continuation.as_ref().map(|c| c.stream_id);
            if let Err(err) =
                frame::validate_header_early(header, self.limits.max_frame_size, expected_cont)
            {
                self.handle_frame_error(err)?;
                continue;
            }

            // 4. Streaming `DATA` frame handling (starts immediately without waiting
            //    for `header.length` payload bytes!).
            if header.kind == kind::DATA {
                if !self.begin_data_frame(header, buf)? {
                    return Ok(None);
                }
                continue;
            }

            // 5. All other frames wait for `9 + header.length` octets (bounded by
            //    `self.limits.max_frame_size`).
            let total_frame_len = FRAME_HEADER_LEN + (header.length as usize);
            if buf.len() < total_frame_len {
                return Ok(None);
            }
            let _ = buf.split_to(FRAME_HEADER_LEN);
            let payload = buf.split_to(header.length as usize).freeze();

            let decoded = match frame::decode_control_frame(
                header,
                payload,
                S::IS_CLIENT,
                self.peer_enable_connect_protocol,
            ) {
                Ok(frame) => frame,
                Err(err) => {
                    self.handle_frame_error(err)?;
                    continue;
                }
            };

            self.apply_control_frame(decoded, now)?;
        }
    }

    /// Processes the 9-byte `DATA` header (plus 1-byte `pad_len` if `PADDED`),
    /// returning `Ok(false)` only when `PADDED` is set and the 10th byte has
    /// not yet arrived in `buf`.
    fn begin_data_frame(&mut self, header: FrameHeader, buf: &mut BytesMut) -> Result<bool, Error> {
        let padded = (header.flags & frame::flags::PADDED) != 0;
        let end_stream = (header.flags & frame::flags::END_STREAM) != 0;

        let (pad_len, hdr_consume) = if padded {
            if header.length == 0 {
                return Err(self.conn_error(
                    Reason::PROTOCOL_ERROR,
                    "padded DATA frame has 0 payload length",
                ));
            }
            if buf.len() < FRAME_HEADER_LEN + 1 {
                return Ok(false);
            }
            let p = u32::from(buf[FRAME_HEADER_LEN]);
            if p >= header.length {
                return Err(self.conn_error(
                    Reason::PROTOCOL_ERROR,
                    "DATA frame pad length >= frame payload length",
                ));
            }
            (p, FRAME_HEADER_LEN + 1)
        } else {
            (0, FRAME_HEADER_LEN)
        };

        // Connection-level flow control applies to the entire `header.length`!
        if i64::from(header.length) > self.conn_recv_window {
            return Err(self.conn_error(
                Reason::FLOW_CONTROL_ERROR,
                "DATA frame exceeds connection flow-control window",
            ));
        }

        let _ = buf.split_to(hdr_consume);
        self.conn_recv_window -= i64::from(header.length);

        let data_len = header.length - (if padded { 1 + pad_len } else { 0 });
        let overhead = (header.length - data_len) as usize;
        if overhead > 0 {
            self.release_conn_only(overhead);
        }

        let stream_id = header.stream_id;
        let payload_rem = (data_len + pad_len) as usize;

        if !self.streams.contains_key(&stream_id) {
            if self.is_idle_stream(stream_id) {
                return Err(self.conn_error(Reason::PROTOCOL_ERROR, "DATA frame on idle stream"));
            }
            if self.locally_reset_streams.contains(stream_id) {
                self.release_conn_only(data_len as usize);
                if payload_rem > 0 {
                    self.active_data = Some(ActiveData::Discard {
                        remaining: payload_rem,
                    });
                }
                return Ok(true);
            }
            return Err(self.conn_error(Reason::STREAM_CLOSED, "DATA frame on closed stream"));
        }

        // Stream is present in `self.streams`.
        enum StreamVerdict {
            Ok,
            StreamErr { reason: Reason, error: Error },
        }

        let verdict = {
            let stream = self.streams.get_mut(&stream_id).expect("checked above");
            match stream.remote {
                RemoteHalf::Closed => StreamVerdict::StreamErr {
                    reason: Reason::STREAM_CLOSED,
                    error: Error::Protocol {
                        reason: Reason::STREAM_CLOSED,
                        detail: "DATA frame on half-closed (remote) stream",
                    },
                },
                RemoteHalf::AwaitingResponseHeaders => StreamVerdict::StreamErr {
                    reason: Reason::PROTOCOL_ERROR,
                    error: Error::Protocol {
                        reason: Reason::PROTOCOL_ERROR,
                        detail: "DATA frame received before response HEADERS",
                    },
                },
                RemoteHalf::StreamingBody => {
                    if i64::from(header.length) > stream.recv_window {
                        StreamVerdict::StreamErr {
                            reason: Reason::FLOW_CONTROL_ERROR,
                            error: Error::Protocol {
                                reason: Reason::FLOW_CONTROL_ERROR,
                                detail: "DATA frame exceeds stream flow-control window",
                            },
                        }
                    } else {
                        stream.recv_window -= i64::from(header.length);
                        if overhead > 0 {
                            stream.unreleased_recv =
                                stream.unreleased_recv.saturating_add(overhead as u64);
                        }
                        let next_recv = stream.received_bytes.saturating_add(u64::from(data_len));
                        if let Some(expected) = stream.expected_recv_len
                            && (next_recv > expected || (end_stream && next_recv != expected))
                        {
                            StreamVerdict::StreamErr {
                                reason: Reason::PROTOCOL_ERROR,
                                error: Error::Malformed(Malformed::ContentLengthMismatch),
                            }
                        } else {
                            stream.received_bytes = next_recv;
                            StreamVerdict::Ok
                        }
                    }
                }
            }
        };

        match verdict {
            StreamVerdict::StreamErr { reason, error } => {
                self.release_conn_only(data_len as usize);
                if payload_rem > 0 {
                    self.active_data = Some(ActiveData::Discard {
                        remaining: payload_rem,
                    });
                }
                self.fail_open_stream(stream_id, reason, error);
                Ok(true)
            }
            StreamVerdict::Ok => {
                if data_len == 0 && pad_len == 0 {
                    if end_stream {
                        if let Err(malformed) = self.complete_remote_stream(stream_id) {
                            self.fail_open_stream(
                                stream_id,
                                Reason::PROTOCOL_ERROR,
                                Error::Malformed(malformed),
                            );
                            return Ok(true);
                        }
                        self.events.push_back(ProtoEvent::Data {
                            stream_id,
                            data: Bytes::new(),
                            end_stream: true,
                        });
                    }
                } else {
                    self.active_data = Some(ActiveData::Deliver {
                        stream_id,
                        data_remaining: data_len as usize,
                        pad_remaining: pad_len as usize,
                        end_stream,
                    });
                }
                Ok(true)
            }
        }
    }

    fn apply_control_frame(&mut self, frame: Frame, now: Instant) -> Result<(), Error> {
        match frame {
            Frame::Settings { ack: true, .. } => {
                if self.pending_settings_acks.pop_front().is_none() {
                    return Err(self.conn_error(
                        Reason::PROTOCOL_ERROR,
                        "unexpected SETTINGS ACK with none pending",
                    ));
                }
            }
            Frame::Settings {
                ack: false,
                settings,
            } => {
                if self.preface == PrefaceState::InitialSettings {
                    self.preface = PrefaceState::Done;
                    self.handshake_deadline = None;
                    self.events.push_back(ProtoEvent::PrefaceComplete);
                }
                self.apply_peer_settings(settings)?;
                frame::encode_settings_ack(&mut self.control_buf);
            }
            Frame::Ping { ack: false, opaque } => {
                frame::encode_ping(true, opaque, &mut self.control_buf);
            }
            Frame::Ping { ack: true, opaque } => {
                if opaque == KEEP_ALIVE_PING && self.keep_alive_ping_deadline.is_some() {
                    self.keep_alive_ping_deadline = None;
                    if let Some(interval) = self.keep_alive_interval {
                        self.next_keep_alive_at = now.checked_add(interval);
                    }
                }
                if opaque == GRACEFUL_SHUTDOWN_PING
                    && matches!(self.graceful_shutdown, GracefulShutdown::Phase1 { .. })
                {
                    self.enter_graceful_phase2();
                }
            }
            Frame::Priority { .. } => {
                // Validated in `frame::decode_control_frame`; priority tree is
                // deprecated by RFC 9113 §5.3.2, so no state is stored.
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            } => {
                self.apply_window_update(stream_id, increment)?;
            }
            Frame::RstStream { stream_id, reason } => {
                self.apply_rst_stream(stream_id, reason, now)?;
            }
            Frame::GoAway {
                last_stream_id,
                reason,
                debug_data,
            } => {
                self.apply_goaway(last_stream_id, reason, debug_data)?;
            }
            Frame::Headers {
                stream_id,
                end_stream,
                end_headers,
                dependency,
                fragment,
            } => {
                self.on_headers_frame(stream_id, end_stream, end_headers, dependency, fragment)?;
            }
            Frame::Continuation {
                stream_id,
                end_headers,
                fragment,
            } => {
                self.on_continuation_frame(stream_id, end_headers, fragment)?;
            }
            Frame::Unknown { .. } => {}
        }
        Ok(())
    }

    fn apply_peer_settings(&mut self, settings: PeerSettings) -> Result<(), Error> {
        let mut window_grew = false;

        if let Some(table_size) = settings.header_table_size {
            self.hpack_encoder.set_peer_max_table_size(table_size);
        }
        if let Some(max_streams) = settings.max_concurrent_streams {
            if max_streams > self.peer_max_concurrent_streams {
                window_grew = true;
            }
            self.peer_max_concurrent_streams = max_streams;
        }
        if let Some(new_initial) = settings.initial_window_size {
            let delta = i64::from(new_initial) - i64::from(self.peer_initial_window_size);
            self.peer_initial_window_size = new_initial;
            if delta != 0 {
                for stream in self.streams.values_mut() {
                    let updated = stream.send_window + delta;
                    if updated > i64::from(MAX_WINDOW_SIZE) {
                        return Err(self.conn_error(
                            Reason::FLOW_CONTROL_ERROR,
                            "SETTINGS_INITIAL_WINDOW_SIZE overflowed stream send window",
                        ));
                    }
                    stream.send_window = updated;
                }
                if delta > 0 {
                    window_grew = true;
                }
            }
        }
        if let Some(max_frame) = settings.max_frame_size {
            self.peer_max_frame_size = max_frame;
        }
        if let Some(max_list) = settings.max_header_list_size {
            self.peer_max_header_list_size = Some(max_list);
        }
        if let Some(connect_proto) = settings.enable_connect_protocol {
            self.peer_enable_connect_protocol = connect_proto;
        }

        if window_grew {
            self.events
                .push_back(ProtoEvent::SendWindowAvailable { stream_id: None });
        }
        Ok(())
    }

    fn apply_window_update(&mut self, stream_id: StreamId, increment: u32) -> Result<(), Error> {
        if stream_id.is_zero() {
            let updated = self.conn_send_window + i64::from(increment);
            if updated > i64::from(MAX_WINDOW_SIZE) {
                return Err(self.conn_error(
                    Reason::FLOW_CONTROL_ERROR,
                    "connection WINDOW_UPDATE overflowed 2^31 - 1",
                ));
            }
            self.conn_send_window = updated;
            self.events
                .push_back(ProtoEvent::SendWindowAvailable { stream_id: None });
            return Ok(());
        }

        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let updated = stream.send_window + i64::from(increment);
            if updated > i64::from(MAX_WINDOW_SIZE) {
                self.fail_open_stream(
                    stream_id,
                    Reason::FLOW_CONTROL_ERROR,
                    Error::Protocol {
                        reason: Reason::FLOW_CONTROL_ERROR,
                        detail: "stream WINDOW_UPDATE overflowed 2^31 - 1",
                    },
                );
                return Ok(());
            }
            stream.send_window = updated;
            if stream.local == LocalHalf::StreamingBody && updated > 0 && self.conn_send_window > 0
            {
                self.events.push_back(ProtoEvent::SendWindowAvailable {
                    stream_id: Some(stream_id),
                });
            }
            return Ok(());
        }

        if self.is_idle_stream(stream_id) {
            return Err(self.conn_error(
                Reason::PROTOCOL_ERROR,
                "WINDOW_UPDATE received on idle stream",
            ));
        }

        // Stream is neither open (`self.streams`) nor idle (`is_idle_stream`), so
        // by RFC 9113 §5.1.1 it is closed (including streams evicted past
        // `STREAM_HISTORY_CAP`), where late `WINDOW_UPDATE` frames must be ignored.
        Ok(())
    }

    fn apply_rst_stream(
        &mut self,
        stream_id: StreamId,
        reason: Reason,
        now: Instant,
    ) -> Result<(), Error> {
        if let Some(removed) = self.remove_stream_entry(stream_id) {
            self.closed_streams.insert(stream_id);
            // Rapid Reset budget applies when peer resets a peer-initiated stream
            // before we finished sending our response (`local != Closed`).
            if removed.peer_initiated && removed.local != LocalHalf::Closed {
                if now.saturating_duration_since(self.rst_window_start)
                    >= self.limits.rst_stream_window
                {
                    self.rst_window_start = now;
                    self.rst_count = 0;
                }
                self.rst_count += 1;
                if self.rst_count > self.limits.max_rst_streams_per_window {
                    return Err(self.conn_error(
                        Reason::ENHANCE_YOUR_CALM,
                        "peer exceeded RST_STREAM rate limit",
                    ));
                }
            }
            self.events
                .push_back(ProtoEvent::StreamReset { stream_id, reason });
            return Ok(());
        }

        if self.is_idle_stream(stream_id) {
            return Err(
                self.conn_error(Reason::PROTOCOL_ERROR, "RST_STREAM received on idle stream")
            );
        }

        if self.locally_reset_streams.contains(stream_id) {
            self.locally_reset_streams.remove(stream_id);
            self.closed_streams.insert(stream_id);
        }

        // Any non-open, non-idle stream is closed (RFC 9113 §5.1.1), including
        // older closed streams evicted past `STREAM_HISTORY_CAP`.
        Ok(())
    }

    fn apply_goaway(
        &mut self,
        last_stream_id: StreamId,
        reason: Reason,
        debug_data: Bytes,
    ) -> Result<(), Error> {
        // RFC 9113 §6.8: peer MUST NOT increase `last_stream_id` in a subsequent GOAWAY.
        if let Some((prev_last, _)) = self.peer_goaway
            && last_stream_id > prev_last
        {
            return Err(self.conn_error(
                Reason::PROTOCOL_ERROR,
                "subsequent GOAWAY increased last_stream_id",
            ));
        }
        self.peer_goaway = Some((last_stream_id, reason));

        // Any locally initiated stream with `id > last_stream_id` is guaranteed
        // unprocessed by the peer and safe to retry (`RequestRejected`).
        let mut rejected: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|&(id, st)| !st.peer_initiated && *id > last_stream_id)
            .map(|(&id, _)| id)
            .collect();
        rejected.sort_unstable();
        for &id in &rejected {
            self.remove_stream_entry(id);
            self.closed_streams.insert(id);
        }

        self.events.push_back(ProtoEvent::GoAway {
            last_stream_id,
            reason,
            debug_data,
            rejected_streams: rejected,
        });
        Ok(())
    }

    fn on_headers_frame(
        &mut self,
        stream_id: StreamId,
        end_stream: bool,
        end_headers: bool,
        dependency: Option<StreamId>,
        fragment: Bytes,
    ) -> Result<(), Error> {
        // Pre-check fatal connection-level stream-ID violations before buffering
        // any `CONTINUATION` state!
        if !self.streams.contains_key(&stream_id) && !self.locally_reset_streams.contains(stream_id)
        {
            if self.closed_streams.contains(stream_id) {
                return Err(self.conn_error(
                    Reason::STREAM_CLOSED,
                    "HEADERS frame received on closed stream",
                ));
            }
            if S::IS_CLIENT {
                // Clients disable push; server cannot open even streams or send
                // HEADERS on unopened odd streams.
                return Err(self.conn_error(
                    Reason::PROTOCOL_ERROR,
                    "unexpected HEADERS frame on idle or closed stream",
                ));
            }
            if !stream_id.is_client_initiated() {
                return Err(self.conn_error(
                    Reason::PROTOCOL_ERROR,
                    "client sent even-numbered stream identifier",
                ));
            }
            if stream_id.get() <= self.max_peer_stream_id {
                return Err(self.conn_error(
                    Reason::PROTOCOL_ERROR,
                    "stream identifier numerically smaller than previous stream",
                ));
            }
        }

        if end_headers {
            self.complete_header_block(stream_id, end_stream, dependency, fragment)
        } else {
            let mut buf = BytesMut::with_capacity(fragment.len() * 2);
            buf.extend_from_slice(&fragment);
            self.continuation = Some(PendingHeaderBlock {
                stream_id,
                end_stream,
                dependency,
                buf,
                continuations: 0,
            });
            Ok(())
        }
    }

    fn on_continuation_frame(
        &mut self,
        stream_id: StreamId,
        end_headers: bool,
        fragment: Bytes,
    ) -> Result<(), Error> {
        let Some(mut pending) = self.continuation.take() else {
            return Err(self.conn_error(
                Reason::PROTOCOL_ERROR,
                "CONTINUATION without active HEADERS block",
            ));
        };
        debug_assert_eq!(pending.stream_id, stream_id);
        pending.continuations += 1;
        if pending.continuations > self.limits.max_continuation_frames {
            return Err(self.conn_error(
                Reason::ENHANCE_YOUR_CALM,
                "header block exceeded max_continuation_frames",
            ));
        }
        pending.buf.extend_from_slice(&fragment);
        if end_headers {
            let block = pending.buf.freeze();
            self.complete_header_block(stream_id, pending.end_stream, pending.dependency, block)
        } else {
            self.continuation = Some(pending);
            Ok(())
        }
    }

    fn complete_header_block(
        &mut self,
        stream_id: StreamId,
        end_stream: bool,
        dependency: Option<StreamId>,
        block: Bytes,
    ) -> Result<(), Error> {
        // ALWAYS run HPACK decoding first so connection-wide dynamic table state
        // remains synchronized even when the stream itself is rejected!
        let outcome = self
            .hpack_decoder
            .decode(&block, self.limits.max_header_list_size)
            .map_err(|_| {
                self.conn_error(Reason::COMPRESSION_ERROR, "HPACK decompression failed")
            })?;

        // Stream was locally reset while peer still had trailing HEADERS in flight.
        if self.locally_reset_streams.contains(stream_id) {
            return Ok(());
        }

        // Case A: Existing open stream (client response headers, or trailers on
        // either side, or illegal HEADERS on `half-closed (remote)`!).
        if self.streams.contains_key(&stream_id) {
            if dependency == Some(stream_id) {
                self.fail_open_stream(
                    stream_id,
                    Reason::PROTOCOL_ERROR,
                    Error::Protocol {
                        reason: Reason::PROTOCOL_ERROR,
                        detail: "HEADERS frame depends on itself",
                    },
                );
                return Ok(());
            }

            let remote_state = self.streams[&stream_id].remote;
            match remote_state {
                RemoteHalf::Closed => {
                    self.fail_open_stream(
                        stream_id,
                        Reason::STREAM_CLOSED,
                        Error::Protocol {
                            reason: Reason::STREAM_CLOSED,
                            detail: "HEADERS frame on half-closed (remote) stream",
                        },
                    );
                    return Ok(());
                }
                RemoteHalf::AwaitingResponseHeaders => {
                    let fields = match outcome {
                        DecodeOutcome::Fields(fields) => fields,
                        DecodeOutcome::TooLarge { limit } => {
                            self.fail_open_stream(
                                stream_id,
                                Reason::PROTOCOL_ERROR,
                                Error::Malformed(Malformed::HeaderListTooLarge { limit }),
                            );
                            return Ok(());
                        }
                    };
                    let (parts, declared_len) = match fields::decode_response(fields) {
                        Ok(res) => res,
                        Err(malformed) => {
                            self.fail_open_stream(
                                stream_id,
                                Reason::PROTOCOL_ERROR,
                                Error::Malformed(malformed),
                            );
                            return Ok(());
                        }
                    };

                    if parts.status.is_informational() {
                        if end_stream {
                            self.fail_open_stream(
                                stream_id,
                                Reason::PROTOCOL_ERROR,
                                Error::Malformed(Malformed::InvalidStatus),
                            );
                            return Ok(());
                        }
                        self.events
                            .push_back(ProtoEvent::InformationalResponse { stream_id, parts });
                        return Ok(());
                    }

                    let (bodiless, is_connect_2xx) = {
                        let st = &self.streams[&stream_id];
                        let bodiless = st.is_head_request
                            || parts.status == StatusCode::NO_CONTENT
                            || parts.status == StatusCode::NOT_MODIFIED;
                        let is_connect_2xx = st.is_standard_connect && parts.status.is_success();
                        (bodiless, is_connect_2xx)
                    };
                    if is_connect_2xx && declared_len.is_some() {
                        self.fail_open_stream(
                            stream_id,
                            Reason::PROTOCOL_ERROR,
                            Error::Malformed(Malformed::InvalidContentLength),
                        );
                        return Ok(());
                    }
                    let effective_len = if bodiless || is_connect_2xx {
                        None
                    } else {
                        declared_len
                    };

                    if end_stream
                        && let Some(len) = effective_len
                        && len != 0
                    {
                        self.fail_open_stream(
                            stream_id,
                            Reason::PROTOCOL_ERROR,
                            Error::Malformed(Malformed::ContentLengthMismatch),
                        );
                        return Ok(());
                    }

                    let close_completely = {
                        let st = self.streams.get_mut(&stream_id).expect("checked above");
                        st.expected_recv_len = effective_len;
                        if end_stream {
                            st.remote = RemoteHalf::Closed;
                            st.local == LocalHalf::Closed
                        } else {
                            st.remote = RemoteHalf::StreamingBody;
                            false
                        }
                    };
                    if close_completely {
                        self.finish_stream(stream_id);
                    }
                    self.events.push_back(ProtoEvent::Response {
                        stream_id,
                        parts,
                        end_stream,
                        content_length: effective_len,
                    });
                    return Ok(());
                }
                RemoteHalf::StreamingBody => {
                    // Trailers MUST carry `END_STREAM` (RFC 9113 §8.1).
                    if !end_stream {
                        self.fail_open_stream(
                            stream_id,
                            Reason::PROTOCOL_ERROR,
                            Error::Malformed(Malformed::InvalidPseudoHeader),
                        );
                        return Ok(());
                    }
                    let fields = match outcome {
                        DecodeOutcome::Fields(fields) => fields,
                        DecodeOutcome::TooLarge { limit } => {
                            self.fail_open_stream(
                                stream_id,
                                Reason::PROTOCOL_ERROR,
                                Error::Malformed(Malformed::HeaderListTooLarge { limit }),
                            );
                            return Ok(());
                        }
                    };
                    let trailers = match fields::decode_trailers(fields) {
                        Ok(map) => map,
                        Err(malformed) => {
                            self.fail_open_stream(
                                stream_id,
                                Reason::PROTOCOL_ERROR,
                                Error::Malformed(malformed),
                            );
                            return Ok(());
                        }
                    };
                    if let Err(malformed) = self.complete_remote_stream(stream_id) {
                        self.fail_open_stream(
                            stream_id,
                            Reason::PROTOCOL_ERROR,
                            Error::Malformed(malformed),
                        );
                        return Ok(());
                    }
                    self.events.push_back(ProtoEvent::Trailers {
                        stream_id,
                        trailers,
                    });
                    return Ok(());
                }
            }
        }

        // Case B: Server opening a brand-new client-initiated request stream!
        debug_assert!(!S::IS_CLIENT);
        if let GracefulShutdown::Phase2 { last_stream_id } = self.graceful_shutdown
            && stream_id.get() > last_stream_id
        {
            // Peer opened a stream above our final GOAWAY `last_stream_id`;
            // reject unprocessed without advancing `max_peer_stream_id`!
            if !end_stream {
                self.locally_reset_streams.insert(stream_id);
            }
            frame::encode_rst_stream(stream_id, Reason::REFUSED_STREAM, &mut self.control_buf);
            return Ok(());
        }

        self.max_peer_stream_id = stream_id.get();

        if dependency == Some(stream_id) {
            self.reject_new_peer_stream(stream_id, end_stream, Reason::PROTOCOL_ERROR);
            return Ok(());
        }

        if let Some(max_conc) = self.limits.max_concurrent_streams
            && (self.peer_active_streams as u64) >= u64::from(max_conc)
        {
            self.reject_new_peer_stream(stream_id, end_stream, Reason::REFUSED_STREAM);
            return Ok(());
        }

        let fields = match outcome {
            DecodeOutcome::Fields(fields) => fields,
            DecodeOutcome::TooLarge { .. } => {
                self.reject_new_peer_stream(stream_id, end_stream, Reason::PROTOCOL_ERROR);
                return Ok(());
            }
        };

        let (parts, content_length) =
            match fields::decode_request(fields, self.enable_connect_protocol) {
                Ok(req) => req,
                Err(_) => {
                    self.reject_new_peer_stream(stream_id, end_stream, Reason::PROTOCOL_ERROR);
                    return Ok(());
                }
            };

        if end_stream
            && let Some(len) = content_length
            && len != 0
        {
            self.reject_new_peer_stream(stream_id, end_stream, Reason::PROTOCOL_ERROR);
            return Ok(());
        }

        let is_standard_connect =
            parts.method == Method::CONNECT && parts.extensions.get::<fields::Protocol>().is_none();
        if is_standard_connect && end_stream {
            // Standard CONNECT tunnel cannot close on the request head itself?
            // Actually RFC 9113 §8.5 permits empty CONNECT tunnel -> allow!
        }

        let state = StreamState {
            local: LocalHalf::AwaitingResponseHeaders,
            remote: if end_stream {
                RemoteHalf::Closed
            } else {
                RemoteHalf::StreamingBody
            },
            send_window: i64::from(self.peer_initial_window_size),
            recv_window: i64::from(self.flow_control.initial_stream_window_size),
            unreleased_recv: 0,
            expected_recv_len: content_length,
            received_bytes: 0,
            declared_send_len: None,
            sent_bytes: 0,
            is_head_request: parts.method == Method::HEAD,
            is_standard_connect,
            peer_initiated: true,
        };
        self.streams.insert(stream_id, state);
        self.peer_active_streams += 1;

        self.events.push_back(ProtoEvent::Request {
            stream_id,
            parts,
            end_stream,
            content_length,
        });
        Ok(())
    }

    fn reject_new_peer_stream(&mut self, stream_id: StreamId, end_stream: bool, reason: Reason) {
        if end_stream {
            self.closed_streams.insert(stream_id);
        } else {
            self.locally_reset_streams.insert(stream_id);
        }
        frame::encode_rst_stream(stream_id, reason, &mut self.control_buf);
    }

    fn complete_remote_stream(&mut self, stream_id: StreamId) -> Result<(), Malformed> {
        let close_completely = {
            let Some(stream) = self.streams.get_mut(&stream_id) else {
                return Ok(());
            };
            if let Some(expected) = stream.expected_recv_len
                && stream.received_bytes != expected
            {
                return Err(Malformed::ContentLengthMismatch);
            }
            stream.remote = RemoteHalf::Closed;
            stream.local == LocalHalf::Closed
        };
        if close_completely {
            self.finish_stream(stream_id);
        }
        Ok(())
    }

    fn fail_open_stream(&mut self, stream_id: StreamId, reason: Reason, error: Error) {
        if let Some(removed) = self.remove_stream_entry(stream_id) {
            if removed.remote != RemoteHalf::Closed {
                self.locally_reset_streams.insert(stream_id);
            } else {
                self.closed_streams.insert(stream_id);
            }
            frame::encode_rst_stream(stream_id, reason, &mut self.control_buf);
            self.events
                .push_back(ProtoEvent::StreamError { stream_id, error });
        }
    }

    fn finish_stream(&mut self, stream_id: StreamId) {
        if self.remove_stream_entry(stream_id).is_some() {
            self.closed_streams.insert(stream_id);
        }
    }

    fn remove_stream_entry(&mut self, stream_id: StreamId) -> Option<StreamState> {
        let removed = self.streams.remove(&stream_id)?;
        if removed.peer_initiated {
            self.peer_active_streams = self.peer_active_streams.saturating_sub(1);
        } else {
            self.local_active_streams = self.local_active_streams.saturating_sub(1);
        }
        Some(removed)
    }

    fn is_idle_stream(&self, stream_id: StreamId) -> bool {
        if S::IS_CLIENT {
            if stream_id.is_client_initiated() {
                stream_id.get() > self.max_local_stream_id
            } else {
                // Server push disabled; all even streams are permanently idle.
                true
            }
        } else if stream_id.is_client_initiated() {
            stream_id.get() > self.max_peer_stream_id
        } else {
            stream_id.get() > self.max_local_stream_id
        }
    }

    fn handle_frame_error(&mut self, err: FrameError) -> Result<(), Error> {
        match err {
            FrameError::Connection { reason, detail } => Err(self.conn_error(reason, detail)),
            FrameError::Stream {
                stream_id,
                reason,
                detail,
            } => {
                if self.is_idle_stream(stream_id) {
                    return Err(self.conn_error(reason, detail));
                }
                if self.streams.contains_key(&stream_id) {
                    self.fail_open_stream(stream_id, reason, Error::Protocol { reason, detail });
                } else if !self.locally_reset_streams.contains(stream_id) {
                    frame::encode_rst_stream(stream_id, reason, &mut self.control_buf);
                }
                Ok(())
            }
        }
    }

    fn enter_graceful_phase2(&mut self) {
        let last = self.max_peer_stream_id;
        self.graceful_shutdown = GracefulShutdown::Phase2 {
            last_stream_id: last,
        };
        frame::encode_goaway(
            StreamId::from_raw_masked(last),
            Reason::NO_ERROR,
            b"",
            &mut self.control_buf,
        );
    }

    fn queue_fatal_goaway(&mut self, reason: Reason) {
        if !self.fatal_error_sent {
            self.fatal_error_sent = true;
            self.local_goaway_sent = true;
            frame::encode_goaway(
                StreamId::from_raw_masked(self.max_peer_stream_id),
                reason,
                b"",
                &mut self.control_buf,
            );
        }
    }

    fn conn_error(&mut self, reason: Reason, detail: &'static str) -> Error {
        self.queue_fatal_goaway(reason);
        Error::Protocol { reason, detail }
    }
}

fn queue_initial_settings(
    limits: &Limits,
    flow: &FlowControlConfig,
    is_client: bool,
    enable_connect_protocol: bool,
    out: &mut BytesMut,
) {
    let mut params = Vec::with_capacity(6);
    if limits.header_table_size != 4_096 {
        params.push((setting_id::HEADER_TABLE_SIZE, limits.header_table_size));
    }
    if is_client {
        params.push((setting_id::ENABLE_PUSH, 0));
    } else if let Some(max_conc) = limits.max_concurrent_streams {
        params.push((setting_id::MAX_CONCURRENT_STREAMS, max_conc));
    }
    if flow.initial_stream_window_size != INITIAL_WINDOW_SIZE {
        let clamped = flow.initial_stream_window_size.min(MAX_WINDOW_SIZE);
        params.push((setting_id::INITIAL_WINDOW_SIZE, clamped));
    }
    let max_frame = limits
        .max_frame_size
        .clamp(INITIAL_MAX_FRAME_SIZE, frame::MAX_MAX_FRAME_SIZE);
    if max_frame != INITIAL_MAX_FRAME_SIZE {
        params.push((setting_id::MAX_FRAME_SIZE, max_frame));
    }
    params.push((
        setting_id::MAX_HEADER_LIST_SIZE,
        limits.max_header_list_size,
    ));
    if !is_client && enable_connect_protocol {
        params.push((setting_id::ENABLE_CONNECT_PROTOCOL, 1));
    }
    frame::encode_settings(&params, out);
}

fn queue_initial_conn_window_update(flow: &FlowControlConfig, out: &mut BytesMut) -> i64 {
    let desired = flow
        .initial_connection_window_size
        .clamp(INITIAL_WINDOW_SIZE, MAX_WINDOW_SIZE);
    if desired > INITIAL_WINDOW_SIZE {
        let delta = desired - INITIAL_WINDOW_SIZE;
        frame::encode_window_update(StreamId::CONNECTION, delta, out);
    }
    i64::from(desired)
}
