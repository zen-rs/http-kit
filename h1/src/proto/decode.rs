//! Decoding received message bodies.

use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue};

use crate::{Limits, ParseError, proto::BodyKind};

/// One step of a received body.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded {
    /// Body data: a slice split off the receive buffer, never a copy.
    Data(Bytes),
    /// The trailer section of a chunked body.
    Trailers(HeaderMap),
    /// The body is complete; whatever remains in the buffer belongs to the
    /// next message.
    End,
}

/// Decodes one message body out of a receive buffer.
///
/// Feed it the connection's buffer with [`decode`](Self::decode) whenever
/// bytes arrive, and with [`decode_eof`](Self::decode_eof) once the peer has
/// closed. Data is handed up as soon as it arrives, without waiting for a
/// chunk to complete.
#[derive(Debug)]
pub struct BodyDecoder {
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Length { remaining: u64 },
    ChunkSize,
    ChunkData { remaining: u64 },
    ChunkDataEnd,
    Trailers,
    CloseDelimited,
    Done,
}

impl BodyDecoder {
    /// A decoder for a body framed as `kind`.
    #[must_use]
    pub const fn new(kind: BodyKind) -> Self {
        let state = match kind {
            BodyKind::Empty | BodyKind::Length(0) => State::Done,
            BodyKind::Length(remaining) => State::Length { remaining },
            BodyKind::Chunked => State::ChunkSize,
            BodyKind::CloseDelimited => State::CloseDelimited,
        };
        Self { state }
    }

    /// Whether the body has been decoded to its end.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.state == State::Done
    }

    /// How many bytes the body continues with that are raw body data, which
    /// a caller may move from the socket without looking at them: the rest of
    /// the `Content-Length`, the rest of the current chunk, or
    /// [`u64::MAX`] for a close-delimited body, whose run ends only with the
    /// stream. `None` while the decoder is at framing (a chunk-size line,
    /// the CRLF after chunk data, trailers) or done.
    ///
    /// The caller may take the run only when nothing is buffered: whatever
    /// [`decode`](Self::decode) has not been given yet comes first.
    #[must_use]
    pub const fn raw_run(&self) -> Option<u64> {
        match self.state {
            State::Length { remaining } | State::ChunkData { remaining } => Some(remaining),
            State::CloseDelimited => Some(u64::MAX),
            State::ChunkSize | State::ChunkDataEnd | State::Trailers | State::Done => None,
        }
    }

    /// Records that `len` bytes of the [`raw_run`](Self::raw_run) were moved
    /// by the caller, as if [`decode`](Self::decode) had returned them as
    /// data.
    ///
    /// # Panics
    ///
    /// Panics if there is no raw run, or `len` is zero or beyond it.
    pub fn consume_raw(&mut self, len: u64) {
        assert!(len > 0, "a raw run is consumed by at least one byte");
        match &mut self.state {
            State::Length { remaining } => {
                *remaining = remaining
                    .checked_sub(len)
                    .expect("consumed past the end of the body");
                if *remaining == 0 {
                    self.state = State::Done;
                }
            }
            State::ChunkData { remaining } => {
                *remaining = remaining
                    .checked_sub(len)
                    .expect("consumed past the end of the chunk");
                if *remaining == 0 {
                    self.state = State::ChunkDataEnd;
                }
            }
            State::CloseDelimited => {}
            State::ChunkSize | State::ChunkDataEnd | State::Trailers | State::Done => {
                panic!("no raw run to consume");
            }
        }
    }

    /// Decodes the next step of the body from the front of `buf`, or returns
    /// `Ok(None)` when `buf` holds too little to make progress.
    ///
    /// # Errors
    ///
    /// A malformed chunked framing or trailer section, or one beyond `limits`.
    pub fn decode(
        &mut self,
        buf: &mut BytesMut,
        limits: &Limits,
    ) -> Result<Option<Decoded>, ParseError> {
        loop {
            match self.state {
                State::Done => return Ok(Some(Decoded::End)),
                State::Length { remaining } => {
                    let Some(data) = take(buf, remaining) else {
                        return Ok(None);
                    };
                    let remaining = remaining - data.len() as u64;
                    self.state = if remaining == 0 {
                        State::Done
                    } else {
                        State::Length { remaining }
                    };
                    return Ok(Some(Decoded::Data(data)));
                }
                State::CloseDelimited => {
                    return Ok(take(buf, u64::MAX).map(Decoded::Data));
                }
                State::ChunkSize => match chunk_size(buf, limits)? {
                    None => return Ok(None),
                    Some(0) => self.state = State::Trailers,
                    Some(remaining) => self.state = State::ChunkData { remaining },
                },
                State::ChunkData { remaining } => {
                    let Some(data) = take(buf, remaining) else {
                        return Ok(None);
                    };
                    let remaining = remaining - data.len() as u64;
                    self.state = if remaining == 0 {
                        State::ChunkDataEnd
                    } else {
                        State::ChunkData { remaining }
                    };
                    return Ok(Some(Decoded::Data(data)));
                }
                State::ChunkDataEnd => {
                    if !expect_crlf(buf)? {
                        return Ok(None);
                    }
                    self.state = State::ChunkSize;
                }
                State::Trailers => {
                    let Some(trailers) = trailer_section(buf, limits)? else {
                        return Ok(None);
                    };
                    self.state = State::Done;
                    if !trailers.is_empty() {
                        return Ok(Some(Decoded::Trailers(trailers)));
                    }
                }
            }
        }
    }

    /// Like [`decode`](Self::decode), after the peer closed the connection:
    /// ends a close-delimited body, and fails any other that is incomplete.
    ///
    /// # Errors
    ///
    /// As [`decode`](Self::decode), and [`ParseError::Incomplete`] when the
    /// body needed more bytes than arrived.
    pub fn decode_eof(
        &mut self,
        buf: &mut BytesMut,
        limits: &Limits,
    ) -> Result<Decoded, ParseError> {
        if self.state == State::CloseDelimited && buf.is_empty() {
            self.state = State::Done;
        }
        self.decode(buf, limits)?.ok_or(ParseError::Incomplete)
    }
}

/// Splits up to `limit` bytes off the front of `buf`, or `None` if it is
/// empty.
fn take(buf: &mut BytesMut, limit: u64) -> Option<Bytes> {
    if buf.is_empty() {
        return None;
    }
    let len = usize::try_from(limit).map_or(buf.len(), |limit| limit.min(buf.len()));
    Some(buf.split_to(len).freeze())
}

/// Consumes the CRLF that ends chunk data, `Ok(false)` if it has not arrived.
fn expect_crlf(buf: &mut BytesMut) -> Result<bool, ParseError> {
    match buf.as_ref() {
        [] | [b'\r'] => Ok(false),
        [b'\r', b'\n', ..] => {
            buf.advance(2);
            Ok(true)
        }
        _ => Err(ParseError::MissingChunkCrlf),
    }
}

/// Parses and consumes a chunk-size line (RFC 9112 §7.1):
/// `chunk-size [ chunk-ext ] CRLF`. Extensions are validated and ignored.
/// The line must end in CRLF: unlike the head, chunk framing grants no
/// leniency for a bare LF, a known source of request smuggling.
fn chunk_size(buf: &mut BytesMut, limits: &Limits) -> Result<Option<u64>, ParseError> {
    let window = &buf[..buf.len().min(limits.max_chunk_line_size)];
    let Some(lf) = window.iter().position(|&b| b == b'\n') else {
        return if buf.len() >= limits.max_chunk_line_size {
            Err(ParseError::ChunkLineTooLong {
                limit: limits.max_chunk_line_size,
            })
        } else {
            Ok(None)
        };
    };
    let line = match window[..lf].split_last() {
        Some((b'\r', line)) => line,
        _ => return Err(ParseError::MissingChunkCrlf),
    };
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return Err(ParseError::InvalidChunkSize);
    }
    let size = line[..digits].iter().try_fold(0u64, |acc, &b| {
        let digit = char::from(b).to_digit(16).expect("a hex digit");
        acc.checked_mul(16)?.checked_add(u64::from(digit))
    });
    let size = size.ok_or(ParseError::InvalidChunkSize)?;
    validate_extensions(&line[digits..])?;
    buf.advance(lf + 1);
    Ok(Some(size))
}

/// `*( BWS ";" ... )`: after optional whitespace the extensions begin with
/// `;`, and hold no control character other than HTAB.
fn validate_extensions(rest: &[u8]) -> Result<(), ParseError> {
    let ext = rest.trim_ascii_start();
    if ext.is_empty() {
        return if rest.is_empty() {
            Ok(())
        } else {
            // Whitespace after the size with no extension following it.
            Err(ParseError::InvalidChunkExtension)
        };
    }
    let valid = ext[0] == b';' && ext.iter().all(|&b| b == b'\t' || !(b < 0x20 || b == 0x7f));
    if valid {
        Ok(())
    } else {
        Err(ParseError::InvalidChunkExtension)
    }
}

/// Parses and consumes the trailer section and the empty line ending it.
fn trailer_section(buf: &mut BytesMut, limits: &Limits) -> Result<Option<HeaderMap>, ParseError> {
    let parsed = parse_trailers(buf, limits.max_headers).map_err(|error| match error {
        httparse::Error::TooManyHeaders => ParseError::TooManyHeaders {
            limit: limits.max_headers,
        },
        other => ParseError::MalformedTrailers(other),
    })?;
    let (len, fields) = match parsed {
        None if buf.len() > limits.max_head_size => {
            return Err(ParseError::HeadTooLarge {
                limit: limits.max_head_size,
            });
        }
        None => return Ok(None),
        Some((len, _)) if len > limits.max_head_size => {
            return Err(ParseError::HeadTooLarge {
                limit: limits.max_head_size,
            });
        }
        Some(parsed) => parsed,
    };
    let section = buf.split_to(len).freeze();
    let mut map = HeaderMap::with_capacity(fields.len());
    for (name, range) in fields {
        let name = HeaderName::from_bytes(&section[name]).map_err(|_| ParseError::InvalidHeader)?;
        let value = HeaderValue::from_maybe_shared(section.slice(range))
            .map_err(|_| ParseError::InvalidHeader)?;
        map.append(name, value);
    }
    Ok(Some(map))
}

type FieldRanges = Vec<(std::ops::Range<usize>, std::ops::Range<usize>)>;

/// The trailer section's length and the ranges of each field's name and
/// value, or `None` while it is incomplete.
fn parse_trailers(
    buf: &[u8],
    max_fields: usize,
) -> Result<Option<(usize, FieldRanges)>, httparse::Error> {
    let mut headers = vec![httparse::EMPTY_HEADER; max_fields];
    match httparse::parse_headers(buf, &mut headers)? {
        httparse::Status::Partial => Ok(None),
        httparse::Status::Complete((len, fields)) => {
            let base = buf.as_ptr().addr();
            let ranges = fields
                .iter()
                .map(|field| {
                    let name = field.name.as_bytes();
                    let name_start = name.as_ptr().addr() - base;
                    let value_start = field.value.as_ptr().addr() - base;
                    (
                        name_start..name_start + name.len(),
                        value_start..value_start + field.value.len(),
                    )
                })
                .collect();
            Ok(Some((len, ranges)))
        }
    }
}
