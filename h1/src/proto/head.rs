//! Parsing message heads and deciding how their bodies are framed.

use std::{mem::MaybeUninit, ops::Range};

use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
    header::{CONNECTION, CONTENT_LENGTH, EXPECT, HOST, TRANSFER_ENCODING, UPGRADE},
    request, response,
};

use crate::{Limits, ParseError};

/// How a received message's body is framed (RFC 9112 §6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// No body follows the head.
    Empty,
    /// Exactly this many bytes follow (`Content-Length`).
    Length(u64),
    /// The body is chunked (`Transfer-Encoding: chunked`).
    Chunked,
    /// The body runs until the connection closes (a response with neither).
    CloseDelimited,
}

/// A parsed request head.
#[derive(Debug)]
pub struct RequestHead {
    /// Method, target, version and fields. Field values share the receive
    /// buffer's allocation.
    pub parts: request::Parts,
    /// How the request body is framed.
    pub body: BodyKind,
    /// Whether the client allows the connection to persist after this
    /// exchange (RFC 9112 §9.3).
    pub keep_alive: bool,
    /// Whether the client waits for `100 Continue` before sending the body.
    pub expect_continue: bool,
    /// Whether the request may switch protocols: `CONNECT`, or an HTTP/1.1
    /// `Upgrade` listed in `Connection`.
    pub upgrade: bool,
}

impl RequestHead {
    /// What a response to this request needs to know about it.
    #[must_use]
    pub fn info(&self) -> RequestInfo {
        RequestInfo {
            method: self.parts.method.clone(),
            version: self.parts.version,
            keep_alive: self.keep_alive,
            upgrade: self.upgrade,
        }
    }
}

/// The facts about a request that frame its response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestInfo {
    /// The request method.
    pub method: Method,
    /// The request version.
    pub version: Version,
    /// Whether the client allows the connection to persist.
    pub keep_alive: bool,
    /// Whether the request may switch protocols.
    pub upgrade: bool,
}

/// A parsed response head.
#[derive(Debug)]
pub struct ResponseHead {
    /// Status, version and fields. Field values share the receive buffer's
    /// allocation.
    pub parts: response::Parts,
    /// How the response body is framed.
    pub body: BodyKind,
    /// Whether the server allows the connection to persist.
    pub keep_alive: bool,
    /// Whether the connection switches protocols after this head: a `101`,
    /// or a `2xx` to `CONNECT`.
    pub upgrade: bool,
}

impl ResponseHead {
    /// Whether this is an interim response (1xx other than 101), after which
    /// the final response to the same request follows.
    #[must_use]
    pub fn is_interim(&self) -> bool {
        self.parts.status.is_informational() && self.parts.status != StatusCode::SWITCHING_PROTOCOLS
    }
}

/// Fields located in a head that is about to be split off the buffer.
struct RawFields {
    len: usize,
    version: u8,
    fields: Vec<(HeaderName, Range<usize>)>,
}

fn version(raw: u8) -> Result<Version, ParseError> {
    match raw {
        0 => Ok(Version::HTTP_10),
        1 => Ok(Version::HTTP_11),
        _ => Err(ParseError::UnsupportedVersion),
    }
}

/// The range `part` occupies inside `base`, which it must borrow from.
fn range_in(base: &[u8], part: &[u8]) -> Range<usize> {
    let start = part.as_ptr().addr() - base.as_ptr().addr();
    start..start + part.len()
}

fn head_error(error: httparse::Error, limits: &Limits) -> ParseError {
    match error {
        httparse::Error::TooManyHeaders => ParseError::TooManyHeaders {
            limit: limits.max_headers,
        },
        httparse::Error::Version => ParseError::UnsupportedVersion,
        other => ParseError::MalformedHead(other),
    }
}

fn locate_fields(
    base: &[u8],
    headers: &[httparse::Header<'_>],
) -> Result<Vec<(HeaderName, Range<usize>)>, ParseError> {
    headers
        .iter()
        .map(|header| {
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| ParseError::InvalidHeader)?;
            Ok((name, range_in(base, header.value)))
        })
        .collect()
}

/// Builds the field map from slices of the frozen head. With `unfold`, a
/// value continued by obs-fold has each CR and LF replaced by SP, as RFC 9112
/// §5.2 requires of a user agent; that rare value alone is copied.
fn build_fields(
    head: &Bytes,
    fields: Vec<(HeaderName, Range<usize>)>,
    unfold: bool,
) -> Result<HeaderMap, ParseError> {
    let mut map = HeaderMap::with_capacity(fields.len());
    for (name, range) in fields {
        let mut value = head.slice(range);
        if unfold && value.iter().any(|&b| b == b'\r' || b == b'\n') {
            value = value
                .iter()
                .map(|&b| if b == b'\r' || b == b'\n' { b' ' } else { b })
                .collect::<Vec<u8>>()
                .into();
        }
        let value = HeaderValue::from_maybe_shared(value).map_err(|_| ParseError::InvalidHeader)?;
        map.append(name, value);
    }
    Ok(map)
}

/// Parses a request head off the front of `buf`.
///
/// Returns `Ok(None)` while the head is incomplete. On success the head's
/// bytes are split off `buf` without copying; whatever follows it (a body,
/// a pipelined request) stays in `buf`.
///
/// # Errors
///
/// Any violation of RFC 9112's message syntax or framing rules, or of
/// `limits`.
pub fn parse_request_head(
    buf: &mut BytesMut,
    limits: &Limits,
) -> Result<Option<RequestHead>, ParseError> {
    let (raw, method, target) = {
        let mut slots = vec![MaybeUninit::<httparse::Header<'_>>::uninit(); limits.max_headers];
        let mut request = httparse::Request::new(&mut []);
        let status = httparse::ParserConfig::default()
            .parse_request_with_uninit_headers(&mut request, buf, &mut slots)
            .map_err(|error| head_error(error, limits))?;
        let len = match status {
            httparse::Status::Partial => {
                return if buf.len() > limits.max_head_size {
                    Err(ParseError::HeadTooLarge {
                        limit: limits.max_head_size,
                    })
                } else {
                    Ok(None)
                };
            }
            httparse::Status::Complete(len) => len,
        };
        if len > limits.max_head_size {
            return Err(ParseError::HeadTooLarge {
                limit: limits.max_head_size,
            });
        }
        let method = request.method.expect("a complete request has a method");
        let method =
            Method::from_bytes(method.as_bytes()).map_err(|_| ParseError::InvalidMethod)?;
        let target = range_in(
            buf,
            request
                .path
                .expect("a complete request has a target")
                .as_bytes(),
        );
        let raw = RawFields {
            len,
            version: request.version.expect("a complete request has a version"),
            fields: locate_fields(buf, request.headers)?,
        };
        (raw, method, target)
    };

    let version = version(raw.version)?;
    let head = buf.split_to(raw.len).freeze();
    let uri = request_target(&method, head.slice(target))?;
    let headers = build_fields(&head, raw.fields, false)?;
    let semantics = request_semantics(version, &method, &headers)?;

    let mut parts = http::Request::new(()).into_parts().0;
    parts.method = method;
    parts.uri = uri;
    parts.version = version;
    parts.headers = headers;
    Ok(Some(RequestHead {
        parts,
        body: semantics.body,
        keep_alive: semantics.keep_alive,
        expect_continue: semantics.expect_continue,
        upgrade: semantics.upgrade,
    }))
}

/// Checks the request target's form against the method (RFC 9112 §3.2).
fn request_target(method: &Method, target: Bytes) -> Result<Uri, ParseError> {
    let origin_form = target.first() == Some(&b'/');
    let asterisk_form = target.as_ref() == b"*";
    let uri = Uri::from_maybe_shared(target).map_err(|_| ParseError::InvalidTarget)?;
    let valid = if method == Method::CONNECT {
        // authority-form: host and port, nothing else.
        uri.scheme().is_none()
            && uri.authority().is_some_and(|a| a.port().is_some())
            && !origin_form
    } else if asterisk_form {
        method == Method::OPTIONS
    } else {
        origin_form || (uri.scheme().is_some() && uri.authority().is_some())
    };
    if valid {
        Ok(uri)
    } else {
        Err(ParseError::InvalidTarget)
    }
}

struct RequestSemantics {
    body: BodyKind,
    keep_alive: bool,
    expect_continue: bool,
    upgrade: bool,
}

fn request_semantics(
    version: Version,
    method: &Method,
    headers: &HeaderMap,
) -> Result<RequestSemantics, ParseError> {
    match headers.get_all(HOST).iter().count() {
        0 if version == Version::HTTP_11 => return Err(ParseError::MissingHost),
        0 | 1 => {}
        _ => return Err(ParseError::MultipleHost),
    }

    let body = match (chunked(version, headers)?, content_length(headers)?) {
        (true, None) => BodyKind::Chunked,
        (true, Some(_)) => return Err(ParseError::ContentLengthWithTransferEncoding),
        (false, Some(0) | None) => BodyKind::Empty,
        (false, Some(len)) => BodyKind::Length(len),
    };

    let connection = ConnectionTokens::new(headers);
    let http11 = version == Version::HTTP_11;
    let mut expect_continue = false;
    if http11 {
        // RFC 9110 §10.1.1: an HTTP/1.0 request's expectation is ignored.
        for value in headers.get_all(EXPECT) {
            if value.as_bytes().eq_ignore_ascii_case(b"100-continue") {
                expect_continue = true;
            } else {
                return Err(ParseError::UnsupportedExpectation);
            }
        }
    }
    Ok(RequestSemantics {
        body,
        keep_alive: connection.keep_alive(version),
        expect_continue,
        upgrade: method == Method::CONNECT
            || (http11 && connection.upgrade && headers.contains_key(UPGRADE)),
    })
}

/// Parses a response head off the front of `buf`, for a request made with
/// `method`.
///
/// Returns `Ok(None)` while the head is incomplete. An interim response
/// ([`ResponseHead::is_interim`]) is returned like any other; the final one
/// follows it.
///
/// # Errors
///
/// Any violation of RFC 9112's message syntax or framing rules, or of
/// `limits`.
pub fn parse_response_head(
    buf: &mut BytesMut,
    limits: &Limits,
    method: &Method,
) -> Result<Option<ResponseHead>, ParseError> {
    let (raw, code) = {
        let mut slots = vec![MaybeUninit::<httparse::Header<'_>>::uninit(); limits.max_headers];
        let mut response = httparse::Response::new(&mut []);
        // RFC 9112 §5.1 and §5.2 let a client accept, and repair, two
        // obsolete forms in responses that a server must reject in requests.
        let status = httparse::ParserConfig::default()
            .allow_obsolete_multiline_headers_in_responses(true)
            .allow_spaces_after_header_name_in_responses(true)
            .parse_response_with_uninit_headers(&mut response, buf, &mut slots)
            .map_err(|error| head_error(error, limits))?;
        let len = match status {
            httparse::Status::Partial => {
                return if buf.len() > limits.max_head_size {
                    Err(ParseError::HeadTooLarge {
                        limit: limits.max_head_size,
                    })
                } else {
                    Ok(None)
                };
            }
            httparse::Status::Complete(len) => len,
        };
        if len > limits.max_head_size {
            return Err(ParseError::HeadTooLarge {
                limit: limits.max_head_size,
            });
        }
        let raw = RawFields {
            len,
            version: response.version.expect("a complete response has a version"),
            fields: locate_fields(buf, response.headers)?,
        };
        (
            raw,
            response.code.expect("a complete response has a status"),
        )
    };

    let version = version(raw.version)?;
    let status = StatusCode::from_u16(code).map_err(|_| ParseError::InvalidStatus)?;
    let head = buf.split_to(raw.len).freeze();
    let headers = build_fields(&head, raw.fields, true)?;

    let chunked = chunked(version, &headers)?;
    let length = content_length(&headers)?;
    if chunked && length.is_some() {
        return Err(ParseError::ContentLengthWithTransferEncoding);
    }
    let upgrade = status == StatusCode::SWITCHING_PROTOCOLS
        || (method == Method::CONNECT && status.is_success());
    let body = if upgrade
        || status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || method == Method::HEAD
    {
        BodyKind::Empty
    } else if chunked {
        BodyKind::Chunked
    } else {
        match length {
            Some(0) => BodyKind::Empty,
            Some(len) => BodyKind::Length(len),
            None => BodyKind::CloseDelimited,
        }
    };
    let keep_alive =
        ConnectionTokens::new(&headers).keep_alive(version) && body != BodyKind::CloseDelimited;

    let mut parts = http::Response::new(()).into_parts().0;
    parts.status = status;
    parts.version = version;
    parts.headers = headers;
    Ok(Some(ResponseHead {
        parts,
        body,
        keep_alive,
        upgrade,
    }))
}

/// The elements of a comma-separated field list, without surrounding
/// whitespace and without empty elements (RFC 9110 §5.6.1).
fn list_elements<'a>(
    values: impl Iterator<Item = &'a HeaderValue>,
) -> impl Iterator<Item = &'a [u8]> {
    values
        .flat_map(|value| value.as_bytes().split(|&b| b == b','))
        .map(|element| element.trim_ascii())
        .filter(|element| !element.is_empty())
}

/// Whether `Transfer-Encoding` makes the body chunked. The only coding
/// supported is a lone `chunked`, which must also be the last (RFC 9112 §6.3:
/// a request whose final coding is not chunked cannot be framed).
fn chunked(version: Version, headers: &HeaderMap) -> Result<bool, ParseError> {
    if !headers.contains_key(TRANSFER_ENCODING) {
        return Ok(false);
    }
    if version == Version::HTTP_10 {
        return Err(ParseError::TransferEncodingInHttp10);
    }
    let codings: Vec<&[u8]> = list_elements(headers.get_all(TRANSFER_ENCODING).iter()).collect();
    let is_chunked = |coding: &&[u8]| coding.eq_ignore_ascii_case(b"chunked");
    match codings.split_last() {
        Some((last, rest)) if is_chunked(last) => {
            if rest.iter().any(is_chunked) {
                Err(ParseError::ChunkedNotFinal)
            } else if rest.is_empty() {
                Ok(true)
            } else {
                Err(ParseError::UnsupportedTransferCoding)
            }
        }
        _ => Err(ParseError::ChunkedNotFinal),
    }
}

/// The value of every `Content-Length` field, which must agree (RFC 9110
/// §8.6 allows a list of identical values).
fn content_length(headers: &HeaderMap) -> Result<Option<u64>, ParseError> {
    let mut length = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        for element in value.as_bytes().split(|&b| b == b',') {
            let parsed =
                parse_decimal(element.trim_ascii()).ok_or(ParseError::InvalidContentLength)?;
            match length {
                None => length = Some(parsed),
                Some(previous) if previous == parsed => {}
                Some(_) => return Err(ParseError::ConflictingContentLength),
            }
        }
    }
    Ok(length)
}

/// `1*DIGIT` as a `u64`; `None` on anything else or on overflow.
pub(crate) fn parse_decimal(digits: &[u8]) -> Option<u64> {
    if digits.is_empty() {
        return None;
    }
    digits.iter().try_fold(0u64, |acc, &b| {
        let digit = b.checked_sub(b'0').filter(|d| *d <= 9)?;
        acc.checked_mul(10)?.checked_add(u64::from(digit))
    })
}

/// The tokens of every `Connection` field that bear on persistence.
pub(crate) struct ConnectionTokens {
    pub(crate) close: bool,
    pub(crate) keep_alive: bool,
    pub(crate) upgrade: bool,
}

impl ConnectionTokens {
    pub(crate) fn new(headers: &HeaderMap) -> Self {
        let mut tokens = Self {
            close: false,
            keep_alive: false,
            upgrade: false,
        };
        for token in list_elements(headers.get_all(CONNECTION).iter()) {
            if token.eq_ignore_ascii_case(b"close") {
                tokens.close = true;
            } else if token.eq_ignore_ascii_case(b"keep-alive") {
                tokens.keep_alive = true;
            } else if token.eq_ignore_ascii_case(b"upgrade") {
                tokens.upgrade = true;
            }
        }
        tokens
    }

    /// RFC 9112 §9.3: `close` ends the connection; otherwise HTTP/1.1
    /// persists and HTTP/1.0 persists only with `keep-alive`.
    pub(crate) fn keep_alive(&self, version: Version) -> bool {
        !self.close && (version == Version::HTTP_11 || self.keep_alive)
    }
}
