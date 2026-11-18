//! HTTP/2 wire frame codec (RFC 9113 §4, §6), implemented in safe Rust.

use bytes::{BufMut as _, Bytes, BytesMut};

use crate::{error::Reason, proto::StreamId};

/// The 24-octet client connection preface magic string (RFC 9113 §3.4).
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Wire size of every HTTP/2 frame header, in octets.
pub const FRAME_HEADER_LEN: usize = 9;

/// Initial `SETTINGS_MAX_FRAME_SIZE` (`16_384` octets, RFC 9113 §6.5.2).
pub const INITIAL_MAX_FRAME_SIZE: u32 = 16_384;

/// Maximum legal `SETTINGS_MAX_FRAME_SIZE` (`16_777_215` octets, `2^24 - 1`).
pub const MAX_MAX_FRAME_SIZE: u32 = 16_777_215;

/// Initial connection and stream flow-control window (`65_535` octets, `2^16 - 1`).
pub const INITIAL_WINDOW_SIZE: u32 = 65_535;

/// Maximum legal flow-control window (`2_147_483_647` octets, `2^31 - 1`).
pub const MAX_WINDOW_SIZE: u32 = 0x7FFF_FFFF;

/// Wire frame type identifiers (RFC 9113 §6).
pub mod kind {
    /// `DATA` (`0x0`).
    pub const DATA: u8 = 0x0;
    /// `HEADERS` (`0x1`).
    pub const HEADERS: u8 = 0x1;
    /// `PRIORITY` (`0x2`).
    pub const PRIORITY: u8 = 0x2;
    /// `RST_STREAM` (`0x3`).
    pub const RST_STREAM: u8 = 0x3;
    /// `SETTINGS` (`0x4`).
    pub const SETTINGS: u8 = 0x4;
    /// `PUSH_PROMISE` (`0x5`).
    pub const PUSH_PROMISE: u8 = 0x5;
    /// `PING` (`0x6`).
    pub const PING: u8 = 0x6;
    /// `GOAWAY` (`0x7`).
    pub const GOAWAY: u8 = 0x7;
    /// `WINDOW_UPDATE` (`0x8`).
    pub const WINDOW_UPDATE: u8 = 0x8;
    /// `CONTINUATION` (`0x9`).
    pub const CONTINUATION: u8 = 0x9;
}

/// Wire frame flag bits (RFC 9113 §6).
pub mod flags {
    /// `END_STREAM` (`0x1`, on `DATA` and `HEADERS`).
    pub const END_STREAM: u8 = 0x1;
    /// `ACK` (`0x1`, on `SETTINGS` and `PING`).
    pub const ACK: u8 = 0x1;
    /// `END_HEADERS` (`0x4`, on `HEADERS` and `CONTINUATION`).
    pub const END_HEADERS: u8 = 0x4;
    /// `PADDED` (`0x8`, on `DATA` and `HEADERS`).
    pub const PADDED: u8 = 0x8;
    /// `PRIORITY` (`0x20`, on `HEADERS`).
    pub const PRIORITY: u8 = 0x20;
}

/// Defined `SETTINGS` parameter identifiers (RFC 9113 §6.5.2, RFC 8441 §3).
pub mod setting_id {
    /// `SETTINGS_HEADER_TABLE_SIZE` (`0x1`).
    pub const HEADER_TABLE_SIZE: u16 = 0x1;
    /// `SETTINGS_ENABLE_PUSH` (`0x2`).
    pub const ENABLE_PUSH: u16 = 0x2;
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` (`0x3`).
    pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
    /// `SETTINGS_INITIAL_WINDOW_SIZE` (`0x4`).
    pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
    /// `SETTINGS_MAX_FRAME_SIZE` (`0x5`).
    pub const MAX_FRAME_SIZE: u16 = 0x5;
    /// `SETTINGS_MAX_HEADER_LIST_SIZE` (`0x6`).
    pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`0x8`, RFC 8441).
    pub const ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
}

/// Decoded 9-octet HTTP/2 frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length (`0..=16_777_215`).
    pub length: u32,
    /// Raw frame type (`kind::*` or an unknown extension type).
    pub kind: u8,
    /// Raw flag bits (undefined bits are ignored per RFC 9113 §4.1).
    pub flags: u8,
    /// 31-bit stream identifier (reserved high bit masked off on receive).
    pub stream_id: StreamId,
}

impl FrameHeader {
    /// Decodes a 9-byte wire header, masking the reserved bit on `stream_id`.
    #[must_use]
    #[inline]
    pub const fn decode(bytes: [u8; FRAME_HEADER_LEN]) -> Self {
        let length = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        let raw_id = u32::from_be_bytes([bytes[5] & 0x7F, bytes[6], bytes[7], bytes[8]]);
        Self {
            length,
            kind: bytes[3],
            flags: bytes[4],
            stream_id: StreamId::from_raw_masked(raw_id),
        }
    }

    /// Encodes this 9-byte header into wire format (`R` bit cleared).
    #[must_use]
    #[inline]
    pub const fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        debug_assert!(self.length <= MAX_MAX_FRAME_SIZE);
        let id = self.stream_id.get().to_be_bytes();
        [
            ((self.length >> 16) & 0xFF) as u8,
            ((self.length >> 8) & 0xFF) as u8,
            (self.length & 0xFF) as u8,
            self.kind,
            self.flags,
            id[0] & 0x7F,
            id[1],
            id[2],
            id[3],
        ]
    }
}

/// Wire framing failure detected while decoding a frame header or payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Connection-wide framing violation; send `GOAWAY(reason)` and close.
    Connection {
        /// RFC 9113 error code.
        reason: Reason,
        /// Violated invariant description.
        detail: &'static str,
    },
    /// Stream-scoped framing violation; send `RST_STREAM(stream_id, reason)`.
    Stream {
        /// Offending stream identifier.
        stream_id: StreamId,
        /// RFC 9113 error code.
        reason: Reason,
        /// Violated invariant description.
        detail: &'static str,
    },
}

impl FrameError {
    #[inline]
    const fn conn(reason: Reason, detail: &'static str) -> Self {
        Self::Connection { reason, detail }
    }

    #[inline]
    const fn stream(stream_id: StreamId, reason: Reason, detail: &'static str) -> Self {
        Self::Stream {
            stream_id,
            reason,
            detail,
        }
    }
}

/// Parsed values from a peer's `SETTINGS` payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerSettings {
    /// `SETTINGS_HEADER_TABLE_SIZE`.
    pub header_table_size: Option<u32>,
    /// `SETTINGS_ENABLE_PUSH`.
    pub enable_push: Option<bool>,
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub max_concurrent_streams: Option<u32>,
    /// `SETTINGS_INITIAL_WINDOW_SIZE`.
    pub initial_window_size: Option<u32>,
    /// `SETTINGS_MAX_FRAME_SIZE`.
    pub max_frame_size: Option<u32>,
    /// `SETTINGS_MAX_HEADER_LIST_SIZE`.
    pub max_header_list_size: Option<u32>,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 8441).
    pub enable_connect_protocol: Option<bool>,
}

/// Decoded non-`DATA` control or header frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `HEADERS` frame (with any `PADDED` and 5-byte `PRIORITY` fields stripped).
    Headers {
        /// Non-zero stream identifier.
        stream_id: StreamId,
        /// True if `END_STREAM` (`0x1`) is set.
        end_stream: bool,
        /// True if `END_HEADERS` (`0x4`) is set.
        end_headers: bool,
        /// Optional stream dependency from the deprecated 5-byte priority prefix
        /// (retained solely to reject `dep_id == stream_id` per RFC 7540 §5.3.1).
        dependency: Option<StreamId>,
        /// HPACK header block fragment.
        fragment: Bytes,
    },
    /// `CONTINUATION` frame.
    Continuation {
        /// Non-zero stream identifier.
        stream_id: StreamId,
        /// True if `END_HEADERS` (`0x4`) is set.
        end_headers: bool,
        /// HPACK header block fragment.
        fragment: Bytes,
    },
    /// `PRIORITY` frame (deprecated in RFC 9113 §6.3; validated for length 5
    /// and self-dependency, then ignored).
    Priority {
        /// Non-zero stream identifier.
        stream_id: StreamId,
        /// Stream dependency identifier.
        dependency: StreamId,
    },
    /// `RST_STREAM` frame.
    RstStream {
        /// Non-zero stream identifier.
        stream_id: StreamId,
        /// Peer's reset reason.
        reason: Reason,
    },
    /// `SETTINGS` frame (`ACK` or parameter list).
    Settings {
        /// True if `ACK` (`0x1`) is set.
        ack: bool,
        /// Parsed known settings (empty when `ack == true`).
        settings: PeerSettings,
    },
    /// `PING` frame (`8` opaque octets).
    Ping {
        /// True if `ACK` (`0x1`) is set.
        ack: bool,
        /// Opaque 8-byte payload.
        opaque: [u8; 8],
    },
    /// `GOAWAY` frame.
    GoAway {
        /// Last peer-initiated stream ID processed by the sender.
        last_stream_id: StreamId,
        /// Termination reason.
        reason: Reason,
        /// Additional diagnostic bytes.
        debug_data: Bytes,
    },
    /// `WINDOW_UPDATE` frame (`increment` validated in `1..=2^31 - 1`).
    WindowUpdate {
        /// `StreamId::CONNECTION` (`0`) or a stream identifier.
        stream_id: StreamId,
        /// Non-zero window increment (`1..=0x7FFF_FFFF`).
        increment: u32,
    },
    /// Unknown extension frame type, ignored per RFC 9113 §5.5.
    Unknown {
        /// Raw frame type byte.
        kind: u8,
        /// Stream identifier.
        stream_id: StreamId,
    },
}

/// Validates a 9-byte [`FrameHeader`] immediately upon receipt, before waiting
/// for `header.length` payload octets.
///
/// Checking `max_frame_size`, `CONTINUATION` lock-in, stream-0 invariants, and
/// fixed-length connection errors up front ensures an oversized or out-of-state
/// frame fails immediately without buffering `header.length` bytes.
///
/// # Errors
///
/// Returns [`FrameError::Connection`] if the header alone violates connection
/// framing rules.
pub fn validate_header_early(
    header: FrameHeader,
    local_max_frame_size: u32,
    expected_continuation: Option<StreamId>,
) -> Result<(), FrameError> {
    if header.length > local_max_frame_size {
        return Err(FrameError::conn(
            Reason::FRAME_SIZE_ERROR,
            "frame payload exceeds SETTINGS_MAX_FRAME_SIZE",
        ));
    }

    if let Some(expected_stream) = expected_continuation {
        if header.kind != kind::CONTINUATION || header.stream_id != expected_stream {
            return Err(FrameError::conn(
                Reason::PROTOCOL_ERROR,
                "expected CONTINUATION frame for active header block",
            ));
        }
        return Ok(());
    }

    match header.kind {
        kind::DATA => {
            if header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "DATA frame on stream 0",
                ));
            }
        }
        kind::HEADERS => {
            if header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "HEADERS frame on stream 0",
                ));
            }
        }
        kind::PRIORITY => {
            if header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "PRIORITY frame on stream 0",
                ));
            }
            // Note: `length != 5` on `PRIORITY` (`stream_id != 0`) is a stream
            // error (RFC 9113 §6.3), so its payload bytes must be consumed
            // before emitting `FrameError::Stream`.
        }
        kind::RST_STREAM => {
            if header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "RST_STREAM frame on stream 0",
                ));
            }
            if header.length != 4 {
                return Err(FrameError::conn(
                    Reason::FRAME_SIZE_ERROR,
                    "RST_STREAM frame length is not 4",
                ));
            }
        }
        kind::SETTINGS => {
            if !header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "SETTINGS frame on non-zero stream",
                ));
            }
            if (header.flags & flags::ACK) != 0 && header.length != 0 {
                return Err(FrameError::conn(
                    Reason::FRAME_SIZE_ERROR,
                    "SETTINGS ACK frame with non-zero payload",
                ));
            }
            if !header.length.is_multiple_of(6) {
                return Err(FrameError::conn(
                    Reason::FRAME_SIZE_ERROR,
                    "SETTINGS payload length is not a multiple of 6",
                ));
            }
        }
        kind::PUSH_PROMISE => {
            // Clients advertise `SETTINGS_ENABLE_PUSH = 0` and servers cannot
            // receive `PUSH_PROMISE` from clients (RFC 9113 §6.6, §8.4).
            return Err(FrameError::conn(
                Reason::PROTOCOL_ERROR,
                "PUSH_PROMISE is disabled and forbidden",
            ));
        }
        kind::PING => {
            if !header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "PING frame on non-zero stream",
                ));
            }
            if header.length != 8 {
                return Err(FrameError::conn(
                    Reason::FRAME_SIZE_ERROR,
                    "PING frame length is not 8",
                ));
            }
        }
        kind::GOAWAY => {
            if !header.stream_id.is_zero() {
                return Err(FrameError::conn(
                    Reason::PROTOCOL_ERROR,
                    "GOAWAY frame on non-zero stream",
                ));
            }
            if header.length < 8 {
                return Err(FrameError::conn(
                    Reason::FRAME_SIZE_ERROR,
                    "GOAWAY frame length is less than 8",
                ));
            }
        }
        kind::WINDOW_UPDATE => {
            if header.length != 4 {
                return Err(FrameError::conn(
                    Reason::FRAME_SIZE_ERROR,
                    "WINDOW_UPDATE frame length is not 4",
                ));
            }
        }
        kind::CONTINUATION => {
            return Err(FrameError::conn(
                Reason::PROTOCOL_ERROR,
                "unexpected CONTINUATION frame outside header block",
            ));
        }
        _ => {}
    }

    Ok(())
}

/// Decodes a complete non-`DATA` frame whose `header` passed
/// [`validate_header_early`] and whose `payload` has `header.length` bytes.
///
/// # Errors
///
/// Returns [`FrameError`] on any payload syntax, padding, settings range,
/// self-dependency, or zero `WINDOW_UPDATE` violation.
pub fn decode_control_frame(
    header: FrameHeader,
    mut payload: Bytes,
    is_client: bool,
    peer_prev_connect_protocol: bool,
) -> Result<Frame, FrameError> {
    debug_assert_eq!(payload.len(), header.length as usize);

    match header.kind {
        kind::HEADERS => {
            let padded = (header.flags & flags::PADDED) != 0;
            let has_priority = (header.flags & flags::PRIORITY) != 0;
            let pad_len = if padded {
                if payload.is_empty() {
                    return Err(FrameError::conn(
                        Reason::PROTOCOL_ERROR,
                        "padded HEADERS frame has 0 length",
                    ));
                }
                let p = payload[0] as usize;
                payload.advance_head(1);
                if p > payload.len() {
                    return Err(FrameError::conn(
                        Reason::PROTOCOL_ERROR,
                        "HEADERS pad length exceeds remaining payload",
                    ));
                }
                p
            } else {
                0
            };

            let dependency = if has_priority {
                if payload.len() < 5 + pad_len {
                    return Err(FrameError::conn(
                        Reason::PROTOCOL_ERROR,
                        "HEADERS frame truncated before priority or padding",
                    ));
                }
                let dep = StreamId::from_raw_masked(u32::from_be_bytes([
                    payload[0] & 0x7F,
                    payload[1],
                    payload[2],
                    payload[3],
                ]));
                payload.advance_head(5);
                Some(dep)
            } else {
                None
            };

            let frag_len = payload.len() - pad_len;
            let fragment = payload.slice(..frag_len);
            Ok(Frame::Headers {
                stream_id: header.stream_id,
                end_stream: (header.flags & flags::END_STREAM) != 0,
                end_headers: (header.flags & flags::END_HEADERS) != 0,
                dependency,
                fragment,
            })
        }
        kind::CONTINUATION => Ok(Frame::Continuation {
            stream_id: header.stream_id,
            end_headers: (header.flags & flags::END_HEADERS) != 0,
            fragment: payload,
        }),
        kind::PRIORITY => {
            if payload.len() != 5 {
                return Err(FrameError::stream(
                    header.stream_id,
                    Reason::FRAME_SIZE_ERROR,
                    "PRIORITY frame length is not 5",
                ));
            }
            let dep = StreamId::from_raw_masked(u32::from_be_bytes([
                payload[0] & 0x7F,
                payload[1],
                payload[2],
                payload[3],
            ]));
            if dep == header.stream_id {
                return Err(FrameError::stream(
                    header.stream_id,
                    Reason::PROTOCOL_ERROR,
                    "PRIORITY frame depends on itself",
                ));
            }
            Ok(Frame::Priority {
                stream_id: header.stream_id,
                dependency: dep,
            })
        }
        kind::RST_STREAM => {
            let code = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            Ok(Frame::RstStream {
                stream_id: header.stream_id,
                reason: Reason::from_code(code),
            })
        }
        kind::SETTINGS => {
            if (header.flags & flags::ACK) != 0 {
                return Ok(Frame::Settings {
                    ack: true,
                    settings: PeerSettings::default(),
                });
            }
            let mut settings = PeerSettings::default();
            let mut connect_proto_seen = peer_prev_connect_protocol;
            for chunk in payload.as_chunks::<6>().0 {
                let id = u16::from_be_bytes([chunk[0], chunk[1]]);
                let val = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
                match id {
                    setting_id::HEADER_TABLE_SIZE => settings.header_table_size = Some(val),
                    setting_id::ENABLE_PUSH => {
                        if val > 1 || (is_client && val != 0) {
                            return Err(FrameError::conn(
                                Reason::PROTOCOL_ERROR,
                                "invalid SETTINGS_ENABLE_PUSH value",
                            ));
                        }
                        settings.enable_push = Some(val == 1);
                    }
                    setting_id::MAX_CONCURRENT_STREAMS => {
                        settings.max_concurrent_streams = Some(val);
                    }
                    setting_id::INITIAL_WINDOW_SIZE => {
                        if val > MAX_WINDOW_SIZE {
                            return Err(FrameError::conn(
                                Reason::FLOW_CONTROL_ERROR,
                                "SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31 - 1",
                            ));
                        }
                        settings.initial_window_size = Some(val);
                    }
                    setting_id::MAX_FRAME_SIZE => {
                        if !(INITIAL_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&val) {
                            return Err(FrameError::conn(
                                Reason::PROTOCOL_ERROR,
                                "SETTINGS_MAX_FRAME_SIZE outside 16384..=16777215",
                            ));
                        }
                        settings.max_frame_size = Some(val);
                    }
                    setting_id::MAX_HEADER_LIST_SIZE => {
                        settings.max_header_list_size = Some(val);
                    }
                    setting_id::ENABLE_CONNECT_PROTOCOL => {
                        if val > 1 || (connect_proto_seen && val == 0) {
                            return Err(FrameError::conn(
                                Reason::PROTOCOL_ERROR,
                                "invalid SETTINGS_ENABLE_CONNECT_PROTOCOL transition",
                            ));
                        }
                        if val == 1 {
                            connect_proto_seen = true;
                        }
                        settings.enable_connect_protocol = Some(val == 1);
                    }
                    _ => {}
                }
            }
            Ok(Frame::Settings {
                ack: false,
                settings,
            })
        }
        kind::PING => {
            let opaque: [u8; 8] = payload
                .as_ref()
                .try_into()
                .expect("validated 8-byte PING payload");
            Ok(Frame::Ping {
                ack: (header.flags & flags::ACK) != 0,
                opaque,
            })
        }
        kind::GOAWAY => {
            let last_stream_id = StreamId::from_raw_masked(u32::from_be_bytes([
                payload[0] & 0x7F,
                payload[1],
                payload[2],
                payload[3],
            ]));
            let code = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            let debug_data = payload.slice(8..);
            Ok(Frame::GoAway {
                last_stream_id,
                reason: Reason::from_code(code),
                debug_data,
            })
        }
        kind::WINDOW_UPDATE => {
            let increment =
                u32::from_be_bytes([payload[0] & 0x7F, payload[1], payload[2], payload[3]]);
            if increment == 0 {
                return if header.stream_id.is_zero() {
                    Err(FrameError::conn(
                        Reason::PROTOCOL_ERROR,
                        "connection WINDOW_UPDATE increment is 0",
                    ))
                } else {
                    Err(FrameError::stream(
                        header.stream_id,
                        Reason::PROTOCOL_ERROR,
                        "stream WINDOW_UPDATE increment is 0",
                    ))
                };
            }
            Ok(Frame::WindowUpdate {
                stream_id: header.stream_id,
                increment,
            })
        }
        other => Ok(Frame::Unknown {
            kind: other,
            stream_id: header.stream_id,
        }),
    }
}

trait BytesAdvance {
    fn advance_head(&mut self, n: usize);
}

impl BytesAdvance for Bytes {
    #[inline]
    fn advance_head(&mut self, n: usize) {
        *self = self.slice(n..);
    }
}

/// Encodes a 9-byte `DATA` frame header.
#[must_use]
#[inline]
pub const fn encode_data_header(
    stream_id: StreamId,
    payload_len: u32,
    end_stream: bool,
) -> [u8; FRAME_HEADER_LEN] {
    FrameHeader {
        length: payload_len,
        kind: kind::DATA,
        flags: if end_stream { flags::END_STREAM } else { 0 },
        stream_id,
    }
    .encode()
}

/// Encodes an HPACK header block as one `HEADERS` frame plus zero or more
/// `CONTINUATION` frames, each at most `max_frame_size` bytes.
pub fn encode_header_block(
    stream_id: StreamId,
    mut block: Bytes,
    end_stream: bool,
    max_frame_size: usize,
    out: &mut BytesMut,
) {
    debug_assert!(!stream_id.is_zero());
    debug_assert!(max_frame_size >= INITIAL_MAX_FRAME_SIZE as usize);

    let first_len = block.len().min(max_frame_size);
    let is_single = first_len == block.len();
    let mut hdr_flags = if end_stream { flags::END_STREAM } else { 0 };
    if is_single {
        hdr_flags |= flags::END_HEADERS;
    }
    out.extend_from_slice(
        &FrameHeader {
            length: first_len as u32,
            kind: kind::HEADERS,
            flags: hdr_flags,
            stream_id,
        }
        .encode(),
    );
    out.extend_from_slice(&block.split_to(first_len));

    while !block.is_empty() {
        let chunk_len = block.len().min(max_frame_size);
        let cont_flags = if chunk_len == block.len() {
            flags::END_HEADERS
        } else {
            0
        };
        out.extend_from_slice(
            &FrameHeader {
                length: chunk_len as u32,
                kind: kind::CONTINUATION,
                flags: cont_flags,
                stream_id,
            }
            .encode(),
        );
        out.extend_from_slice(&block.split_to(chunk_len));
    }
}

/// Encodes a `SETTINGS` frame from `(id, value)` pairs.
pub fn encode_settings(params: &[(u16, u32)], out: &mut BytesMut) {
    let payload_len = (params.len() * 6) as u32;
    out.extend_from_slice(
        &FrameHeader {
            length: payload_len,
            kind: kind::SETTINGS,
            flags: 0,
            stream_id: StreamId::CONNECTION,
        }
        .encode(),
    );
    for &(id, val) in params {
        out.put_u16(id);
        out.put_u32(val);
    }
}

/// Encodes an empty `SETTINGS` `ACK` frame.
pub fn encode_settings_ack(out: &mut BytesMut) {
    out.extend_from_slice(
        &FrameHeader {
            length: 0,
            kind: kind::SETTINGS,
            flags: flags::ACK,
            stream_id: StreamId::CONNECTION,
        }
        .encode(),
    );
}

/// Encodes a `PING` or `PING ACK` frame.
pub fn encode_ping(ack: bool, opaque: [u8; 8], out: &mut BytesMut) {
    out.extend_from_slice(
        &FrameHeader {
            length: 8,
            kind: kind::PING,
            flags: if ack { flags::ACK } else { 0 },
            stream_id: StreamId::CONNECTION,
        }
        .encode(),
    );
    out.extend_from_slice(&opaque);
}

/// Encodes a `RST_STREAM` frame.
pub fn encode_rst_stream(stream_id: StreamId, reason: Reason, out: &mut BytesMut) {
    debug_assert!(!stream_id.is_zero());
    out.extend_from_slice(
        &FrameHeader {
            length: 4,
            kind: kind::RST_STREAM,
            flags: 0,
            stream_id,
        }
        .encode(),
    );
    out.put_u32(reason.code());
}

/// Encodes a `WINDOW_UPDATE` frame (`increment` in `1..=2^31 - 1`).
pub fn encode_window_update(stream_id: StreamId, increment: u32, out: &mut BytesMut) {
    debug_assert!((1..=MAX_WINDOW_SIZE).contains(&increment));
    out.extend_from_slice(
        &FrameHeader {
            length: 4,
            kind: kind::WINDOW_UPDATE,
            flags: 0,
            stream_id,
        }
        .encode(),
    );
    out.put_u32(increment & MAX_WINDOW_SIZE);
}

/// Encodes a `GOAWAY` frame.
pub fn encode_goaway(
    last_stream_id: StreamId,
    reason: Reason,
    debug_data: &[u8],
    out: &mut BytesMut,
) {
    let payload_len = (8 + debug_data.len()) as u32;
    out.extend_from_slice(
        &FrameHeader {
            length: payload_len,
            kind: kind::GOAWAY,
            flags: 0,
            stream_id: StreamId::CONNECTION,
        }
        .encode(),
    );
    out.put_u32(last_stream_id.get() & 0x7FFF_FFFF);
    out.put_u32(reason.code());
    out.extend_from_slice(debug_data);
}
