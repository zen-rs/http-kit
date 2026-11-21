//! HTTP/2 field-section encoding and validation (RFC 9113 §8.2–§8.6,
//! RFC 8441 Extended `CONNECT`).

use std::fmt;

use bytes::{Bytes, BytesMut};
use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
    header::{CONTENT_LENGTH, COOKIE, DATE, HOST, TE},
    request, response,
    uri::{Authority, PathAndQuery, Scheme},
};

use crate::{
    error::{Error, Malformed},
    hpack::{DecodedField, EncodeField, Encoder},
    simd,
};

/// Invalid RFC 8441 `:protocol` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid HTTP/2 :protocol token")]
pub struct InvalidProtocol;

/// The RFC 8441 `:protocol` pseudo-header value for Extended `CONNECT`
/// requests (e.g. `"websocket"`, `"webtransport"`, `"connect-udp"`).
///
/// Placed in [`http::Request::extensions`] by callers initiating an Extended
/// `CONNECT` stream and populated there on decoded incoming Extended `CONNECT`
/// requests.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Protocol(Bytes);

const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9'
            | b'A'..=b'Z' | b'^'..=b'z' | b'|' | b'~'
    )
}

const fn valid_protocol_token(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let mut i = 0usize;
    while i < bytes.len() {
        if !is_tchar(bytes[i]) {
            return false;
        }
        i += 1;
    }
    true
}

impl Protocol {
    /// Constructs a [`Protocol`] from a compile-time static token string.
    ///
    /// # Panics
    ///
    /// Panics if `value` is empty or contains non-token characters.
    #[must_use]
    pub const fn from_static(value: &'static str) -> Self {
        assert!(
            valid_protocol_token(value.as_bytes()),
            "Protocol::from_static requires a non-empty HTTP token"
        );
        Self(Bytes::from_static(value.as_bytes()))
    }

    /// Returns the protocol token as a `&str`.
    #[must_use]
    #[inline]
    pub fn as_str(&self) -> &str {
        // Every constructor validates ASCII `tchar`s (`0x21..=0x7E`).
        std::str::from_utf8(&self.0).expect("Protocol holds validated ASCII token bytes")
    }

    /// Returns the protocol token bytes.
    #[must_use]
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes `self`, returning the underlying [`Bytes`].
    #[must_use]
    #[inline]
    pub fn into_bytes(self) -> Bytes {
        self.0
    }
}

impl TryFrom<&str> for Protocol {
    type Error = InvalidProtocol;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !valid_protocol_token(value.as_bytes()) {
            return Err(InvalidProtocol);
        }
        Ok(Self(Bytes::copy_from_slice(value.as_bytes())))
    }
}

impl TryFrom<String> for Protocol {
    type Error = InvalidProtocol;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !valid_protocol_token(value.as_bytes()) {
            return Err(InvalidProtocol);
        }
        Ok(Self(Bytes::from(value)))
    }
}

impl TryFrom<Bytes> for Protocol {
    type Error = InvalidProtocol;

    fn try_from(value: Bytes) -> Result<Self, Self::Error> {
        if !valid_protocol_token(&value) {
            return Err(InvalidProtocol);
        }
        Ok(Self(value))
    }
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Protocol").field(&self.as_str()).finish()
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Connection-specific header names forbidden by RFC 9113 §8.2.2 (`te` is
/// checked separately because `"trailers"` is allowed on requests).
#[inline]
fn is_connection_specific(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

#[inline]
fn sendable_regular(name: &HeaderName, value: &HeaderValue, is_request: bool) -> bool {
    !is_connection_specific(name) && (name != TE || (is_request && value.as_bytes() == b"trailers"))
}

/// Parses an outgoing `Content-Length` header if present, returning an error if
/// malformed or conflicting.
pub(crate) fn parse_outgoing_content_length(headers: &HeaderMap) -> Result<Option<u64>, Error> {
    let mut declared = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let len = parse_decimal_u64(value.as_bytes())
            .ok_or(Error::Malformed(Malformed::InvalidContentLength))?;
        if declared.is_some_and(|prev| prev != len) {
            return Err(Error::Malformed(Malformed::InvalidContentLength));
        }
        declared = Some(len);
    }
    Ok(declared)
}

#[inline]
fn parse_decimal_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse::<u64>().ok()
}

/// Encodes an outgoing request head into `block`, returning any effective
/// `Content-Length` that outgoing `DATA` frames must match.
pub(crate) fn encode_request(
    encoder: &mut Encoder,
    parts: &request::Parts,
    body_len: Option<u64>,
    end_stream: bool,
    peer_enable_connect_protocol: bool,
    block: &mut BytesMut,
) -> Result<Option<u64>, Error> {
    let declared = parse_outgoing_content_length(&parts.headers)?;
    let protocol = parts.extensions.get::<Protocol>();

    if protocol.is_some() && (parts.method != Method::CONNECT || !peer_enable_connect_protocol) {
        return Err(Error::UnsupportedExtendedConnect);
    }

    let authority = match parts.uri.authority() {
        Some(auth) => auth.as_str().as_bytes(),
        None => parts
            .headers
            .get(HOST)
            .ok_or(Error::MissingAuthority)?
            .as_bytes(),
    };
    if authority.is_empty() {
        return Err(Error::MissingAuthority);
    }

    encoder.flush_size_updates(block);
    encoder.encode_one(
        EncodeField::new(b":method", parts.method.as_str().as_bytes()),
        block,
    );

    if parts.method == Method::CONNECT && protocol.is_none() {
        // Standard CONNECT (RFC 9113 §8.5): `:method` + `:authority` only.
        encoder.encode_one(EncodeField::new(b":authority", authority), block);
    } else {
        let scheme = parts.uri.scheme_str().unwrap_or("https");
        let path = if parts.uri == "*" {
            "*"
        } else {
            parts.uri.path_and_query().map_or("/", PathAndQuery::as_str)
        };
        if let Some(proto) = protocol {
            encoder.encode_one(EncodeField::new(b":protocol", proto.as_bytes()), block);
        }
        encoder.encode_one(EncodeField::new(b":scheme", scheme.as_bytes()), block);
        encoder.encode_one(EncodeField::new(b":authority", authority), block);
        encoder.encode_one(EncodeField::new(b":path", path.as_bytes()), block);
    }

    for (name, value) in &parts.headers {
        if name != HOST && sendable_regular(name, value, true) {
            encoder.encode_one(
                EncodeField {
                    name: name.as_str().as_bytes(),
                    value: value.as_bytes(),
                    sensitive: value.is_sensitive(),
                },
                block,
            );
        }
    }

    let effective_len = match declared {
        Some(len) => Some(len),
        None => match body_len {
            Some(len) if len > 0 || !end_stream => {
                let text = len.to_string();
                encoder.encode_one(EncodeField::new(b"content-length", text.as_bytes()), block);
                Some(len)
            }
            _ => None,
        },
    };

    Ok(if end_stream {
        if let Some(len) = effective_len
            && len != 0
        {
            return Err(Error::ContentLengthMismatch { declared: len });
        }
        None
    } else {
        effective_len
    })
}

/// Encodes a `1xx` informational response head (excluding `101`, which HTTP/2
/// forbids).
pub(crate) fn encode_informational_response(
    encoder: &mut Encoder,
    parts: &response::Parts,
    block: &mut BytesMut,
) -> Result<(), Error> {
    if !parts.status.is_informational() || parts.status == StatusCode::SWITCHING_PROTOCOLS {
        return Err(Error::InformationalResponse(parts.status));
    }
    encoder.flush_size_updates(block);
    encoder.encode_one(
        EncodeField::new(b":status", parts.status.as_str().as_bytes()),
        block,
    );
    for (name, value) in &parts.headers {
        if name != CONTENT_LENGTH && sendable_regular(name, value, false) {
            encoder.encode_one(
                EncodeField {
                    name: name.as_str().as_bytes(),
                    value: value.as_bytes(),
                    sensitive: value.is_sensitive(),
                },
                block,
            );
        }
    }
    Ok(())
}

/// Encodes a final (`2xx`–`5xx`) response head into `block`, returning any
/// effective `Content-Length` that outgoing `DATA` frames must match.
pub(crate) fn encode_response(
    encoder: &mut Encoder,
    parts: &response::Parts,
    is_head_request: bool,
    body_len: Option<u64>,
    end_stream: bool,
    date: Option<&HeaderValue>,
    block: &mut BytesMut,
) -> Result<Option<u64>, Error> {
    if parts.status.is_informational() {
        return Err(Error::InformationalResponse(parts.status));
    }
    let declared = parse_outgoing_content_length(&parts.headers)?;
    let bodiless = is_head_request
        || parts.status == StatusCode::NO_CONTENT
        || parts.status == StatusCode::NOT_MODIFIED;

    encoder.flush_size_updates(block);
    encoder.encode_one(
        EncodeField::new(b":status", parts.status.as_str().as_bytes()),
        block,
    );

    if let Some(date) = date
        && !parts.headers.contains_key(DATE)
    {
        encoder.encode_one(EncodeField::new(b"date", date.as_bytes()), block);
    }

    for (name, value) in &parts.headers {
        if sendable_regular(name, value, false) {
            encoder.encode_one(
                EncodeField {
                    name: name.as_str().as_bytes(),
                    value: value.as_bytes(),
                    sensitive: value.is_sensitive(),
                },
                block,
            );
        }
    }

    let effective_len = match declared {
        Some(len) => (!bodiless).then_some(len),
        None if !bodiless => {
            if let Some(len) = body_len {
                let text = len.to_string();
                encoder.encode_one(EncodeField::new(b"content-length", text.as_bytes()), block);
                Some(len)
            } else {
                None
            }
        }
        None => None,
    };

    if end_stream
        && let Some(len) = effective_len
        && len != 0
    {
        return Err(Error::ContentLengthMismatch { declared: len });
    }

    Ok(if end_stream { None } else { effective_len })
}

/// Encodes an outgoing trailer section into `block`.
pub(crate) fn encode_trailers(encoder: &mut Encoder, trailers: &HeaderMap, block: &mut BytesMut) {
    encoder.flush_size_updates(block);
    for (name, value) in trailers {
        if sendable_regular(name, value, false) {
            encoder.encode_one(
                EncodeField {
                    name: name.as_str().as_bytes(),
                    value: value.as_bytes(),
                    sensitive: value.is_sensitive(),
                },
                block,
            );
        }
    }
}

#[derive(Default)]
enum CookieAcc {
    #[default]
    None,
    One(HeaderValue),
    Many {
        joined: Vec<u8>,
        sensitive: bool,
    },
}

impl CookieAcc {
    fn push(&mut self, value: HeaderValue) {
        match std::mem::take(self) {
            Self::None => *self = Self::One(value),
            Self::One(first) => {
                let sensitive = first.is_sensitive() || value.is_sensitive();
                let mut joined = Vec::with_capacity(first.len() + 2 + value.len());
                joined.extend_from_slice(first.as_bytes());
                joined.extend_from_slice(b"; ");
                joined.extend_from_slice(value.as_bytes());
                *self = Self::Many { joined, sensitive };
            }
            Self::Many {
                mut joined,
                sensitive,
            } => {
                joined.extend_from_slice(b"; ");
                joined.extend_from_slice(value.as_bytes());
                *self = Self::Many {
                    joined,
                    sensitive: sensitive || value.is_sensitive(),
                };
            }
        }
    }

    fn finish(self, headers: &mut HeaderMap) -> Result<(), Malformed> {
        match self {
            Self::None => {}
            Self::One(cookie) => {
                headers.insert(COOKIE, cookie);
            }
            Self::Many { joined, sensitive } => {
                let mut cookie = HeaderValue::from_maybe_shared(Bytes::from(joined))
                    .map_err(|_| Malformed::InvalidField)?;
                cookie.set_sensitive(sensitive);
                headers.insert(COOKIE, cookie);
            }
        }
        Ok(())
    }
}

struct RegularFields {
    headers: HeaderMap,
    cookies: CookieAcc,
    content_length: Option<u64>,
    host_count: usize,
    is_request: bool,
}

impl RegularFields {
    fn new(capacity: usize, is_request: bool) -> Self {
        Self {
            headers: HeaderMap::with_capacity(capacity),
            cookies: CookieAcc::None,
            content_length: None,
            host_count: 0,
            is_request,
        }
    }

    fn push(&mut self, field: DecodedField) -> Result<(), Malformed> {
        let name = match field.parsed_name {
            Some(name) => name,
            None => {
                if !simd::validate_field_name(&field.name) {
                    return Err(Malformed::InvalidField);
                }
                HeaderName::from_bytes(&field.name).map_err(|_| Malformed::InvalidField)?
            }
        };

        if is_connection_specific(&name)
            || (name == TE && (!self.is_request || field.value.as_ref() != b"trailers"))
        {
            return Err(Malformed::ConnectionSpecificField);
        }

        let mut value = match field.parsed_value {
            Some(val) => val,
            None => {
                if !simd::validate_field_value(&field.value) {
                    return Err(Malformed::InvalidField);
                }
                HeaderValue::from_maybe_shared(field.value).map_err(|_| Malformed::InvalidField)?
            }
        };
        if field.sensitive {
            value.set_sensitive(true);
        }

        if name == HOST {
            self.host_count += 1;
            if self.host_count > 1 {
                return Err(Malformed::InvalidAuthority);
            }
        } else if name == CONTENT_LENGTH {
            let len = parse_decimal_u64(value.as_bytes()).ok_or(Malformed::InvalidContentLength)?;
            if self.content_length.is_some_and(|prev| prev != len) {
                return Err(Malformed::InvalidContentLength);
            }
            self.content_length = Some(len);
        } else if name == COOKIE {
            self.cookies.push(value);
            return Ok(());
        }

        self.headers.append(name, value);
        Ok(())
    }

    fn finish(mut self) -> Result<(HeaderMap, Option<u64>), Malformed> {
        self.cookies.finish(&mut self.headers)?;
        Ok((self.headers, self.content_length))
    }
}

/// Validates and converts decoded HPACK fields into an `http::request::Parts`
/// and optional `Content-Length` (RFC 9113 §8.3.1, §8.5, RFC 8441 §4).
pub(crate) fn decode_request(
    list: Vec<DecodedField>,
    enable_connect_protocol: bool,
) -> Result<(request::Parts, Option<u64>), Malformed> {
    let mut method: Option<Bytes> = None;
    let mut scheme: Option<Bytes> = None;
    let mut authority: Option<Bytes> = None;
    let mut path: Option<Bytes> = None;
    let mut protocol: Option<Bytes> = None;

    let mut regular = RegularFields::new(list.len(), true);
    let mut pseudo_done = false;

    for field in list {
        if let Some(pseudo) = field.name.strip_prefix(b":") {
            if pseudo_done || !simd::validate_field_value(&field.value) {
                return Err(Malformed::InvalidPseudoHeader);
            }
            let slot = match pseudo {
                b"method" => &mut method,
                b"scheme" => &mut scheme,
                b"authority" => &mut authority,
                b"path" => &mut path,
                b"protocol" if enable_connect_protocol => &mut protocol,
                _ => return Err(Malformed::InvalidPseudoHeader),
            };
            if slot.is_some() {
                return Err(Malformed::InvalidPseudoHeader);
            }
            *slot = Some(field.value);
        } else {
            pseudo_done = true;
            regular.push(field)?;
        }
    }

    let (mut headers, content_length) = regular.finish()?;

    let method_bytes = method
        .filter(|m| !m.is_empty())
        .ok_or(Malformed::MissingPseudoHeader(":method"))?;
    let method = Method::from_bytes(&method_bytes).map_err(|_| Malformed::InvalidMethod)?;

    let parsed_protocol = match protocol {
        Some(raw) => {
            if method != Method::CONNECT {
                return Err(Malformed::InvalidPseudoHeader);
            }
            if raw.is_empty() {
                return Err(Malformed::MissingPseudoHeader(":protocol"));
            }
            Some(Protocol::try_from(raw).map_err(|_| Malformed::InvalidPseudoHeader)?)
        }
        None => None,
    };

    let host_bytes = headers.get(HOST).map(HeaderValue::as_bytes);
    if let (Some(auth), Some(host)) = (authority.as_deref(), host_bytes)
        && !auth.eq_ignore_ascii_case(host)
    {
        return Err(Malformed::InvalidAuthority);
    }

    // RFC 9113 §8.3.1: empty `:authority` when present is invalid unless standard
    // non-CONNECT has neither; reject empty `:authority` / `Host` or `@` userinfo.
    if authority.as_ref().is_some_and(Bytes::is_empty) || host_bytes.is_some_and(<[u8]>::is_empty) {
        return Err(Malformed::InvalidAuthority);
    }

    let effective_auth_bytes = authority
        .clone()
        .or_else(|| host_bytes.map(Bytes::copy_from_slice));

    let uri = if method == Method::CONNECT && parsed_protocol.is_none() {
        // Standard CONNECT (RFC 9113 §8.5): `:authority` required (with port),
        // `:scheme` and `:path` forbidden.
        if scheme.is_some() || path.is_some() {
            return Err(Malformed::InvalidPseudoHeader);
        }
        let raw_auth = authority.ok_or(Malformed::MissingPseudoHeader(":authority"))?;
        if raw_auth.contains(&b'@') {
            return Err(Malformed::InvalidAuthority);
        }
        let auth =
            Authority::from_maybe_shared(raw_auth).map_err(|_| Malformed::InvalidAuthority)?;
        if auth.port().is_none() {
            return Err(Malformed::InvalidAuthority);
        }
        let mut uri_parts = http::uri::Parts::default();
        uri_parts.authority = Some(auth);
        Uri::from_parts(uri_parts).map_err(|_| Malformed::InvalidTarget)?
    } else {
        // Regular request or RFC 8441 Extended CONNECT.
        let raw_scheme = scheme
            .filter(|s| !s.is_empty())
            .ok_or(Malformed::MissingPseudoHeader(":scheme"))?;
        let parsed_scheme =
            Scheme::try_from(raw_scheme.as_ref()).map_err(|_| Malformed::InvalidTarget)?;
        let is_http = parsed_scheme == Scheme::HTTP || parsed_scheme == Scheme::HTTPS;

        if parsed_protocol.is_some() && effective_auth_bytes.is_none() {
            return Err(Malformed::MissingPseudoHeader(":authority"));
        }

        let parsed_auth = match effective_auth_bytes {
            Some(raw_auth) => {
                if is_http && raw_auth.contains(&b'@') {
                    return Err(Malformed::InvalidAuthority);
                }
                Some(
                    Authority::from_maybe_shared(raw_auth)
                        .map_err(|_| Malformed::InvalidAuthority)?,
                )
            }
            None => None,
        };

        let raw_path = path
            .filter(|p| !p.is_empty())
            .ok_or(Malformed::MissingPseudoHeader(":path"))?;

        if raw_path.as_ref() == b"*" {
            if method != Method::OPTIONS || parsed_protocol.is_some() {
                return Err(Malformed::InvalidTarget);
            }
            if let Some(auth) = &parsed_auth
                && !headers.contains_key(HOST)
                && let Ok(hv) = HeaderValue::from_str(auth.as_str())
            {
                headers.insert(HOST, hv);
            }
            Uri::from_static("*")
        } else {
            if is_http && !simd::validate_path(&raw_path) {
                return Err(Malformed::InvalidTarget);
            }
            let pq =
                PathAndQuery::from_maybe_shared(raw_path).map_err(|_| Malformed::InvalidTarget)?;
            let mut uri_parts = http::uri::Parts::default();
            if let Some(auth) = parsed_auth {
                uri_parts.scheme = Some(parsed_scheme);
                uri_parts.authority = Some(auth);
            }
            uri_parts.path_and_query = Some(pq);
            Uri::from_parts(uri_parts).map_err(|_| Malformed::InvalidTarget)?
        }
    };

    let mut parts = http::Request::new(()).into_parts().0;
    parts.method = method;
    parts.uri = uri;
    parts.version = Version::HTTP_2;
    parts.headers = headers;
    if let Some(proto) = parsed_protocol {
        parts.extensions.insert(proto);
    }
    Ok((parts, content_length))
}

/// Validates and converts decoded HPACK fields into an `http::response::Parts`
/// and optional `Content-Length` (RFC 9113 §8.3.2).
pub(crate) fn decode_response(
    list: Vec<DecodedField>,
) -> Result<(response::Parts, Option<u64>), Malformed> {
    let mut status: Option<Bytes> = None;
    let mut regular = RegularFields::new(list.len(), false);
    let mut pseudo_done = false;

    for field in list {
        if field.name.as_ref() == b":status" {
            if pseudo_done || status.is_some() || !simd::validate_field_value(&field.value) {
                return Err(Malformed::InvalidPseudoHeader);
            }
            status = Some(field.value);
        } else if field.name.starts_with(b":") {
            return Err(Malformed::InvalidPseudoHeader);
        } else {
            pseudo_done = true;
            regular.push(field)?;
        }
    }

    let raw_status = status.ok_or(Malformed::MissingPseudoHeader(":status"))?;
    if raw_status.len() != 3 || !raw_status.iter().all(u8::is_ascii_digit) {
        return Err(Malformed::InvalidStatus);
    }
    let status = StatusCode::from_bytes(&raw_status).map_err(|_| Malformed::InvalidStatus)?;
    if status == StatusCode::SWITCHING_PROTOCOLS {
        // RFC 9113 §8.6: HTTP/2 forbids 101 Switching Protocols.
        return Err(Malformed::InvalidStatus);
    }

    let (headers, content_length) = regular.finish()?;
    let mut parts = http::Response::new(()).into_parts().0;
    parts.status = status;
    parts.version = Version::HTTP_2;
    parts.headers = headers;
    Ok((parts, content_length))
}

/// Validates and converts decoded HPACK fields into trailer [`HeaderMap`]
/// (RFC 9113 §8.1).
pub(crate) fn decode_trailers(list: Vec<DecodedField>) -> Result<HeaderMap, Malformed> {
    let mut regular = RegularFields::new(list.len(), false);
    for field in list {
        if field.name.starts_with(b":") {
            return Err(Malformed::InvalidPseudoHeader);
        }
        regular.push(field)?;
    }
    Ok(regular.finish()?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack::{DecodeOutcome, Decoder};

    fn round_trip_request(
        parts: &request::Parts,
        body_len: Option<u64>,
        end_stream: bool,
        connect_proto: bool,
    ) -> Result<(request::Parts, Option<u64>), Malformed> {
        let mut enc = Encoder::default();
        let mut dec = Decoder::default();
        let mut block = BytesMut::new();
        encode_request(
            &mut enc,
            parts,
            body_len,
            end_stream,
            connect_proto,
            &mut block,
        )
        .unwrap();
        let DecodeOutcome::Fields(fields) = dec.decode(&block.freeze(), 64 * 1024).unwrap() else {
            panic!("unexpected TooLarge");
        };
        decode_request(fields, connect_proto)
    }

    #[test]
    fn request_cjk_headers_and_extended_connect_round_trip() {
        let greeting = "你好 / こんにちは / 안녕하세요";
        let req = http::Request::builder()
            .method(Method::POST)
            .uri("https://xn--r8jz45g.jp/%E6%A4%9C%E7%B4%A2?q=%EC%95%88%EB%85%95")
            .header(
                "x-greeting",
                HeaderValue::from_bytes(greeting.as_bytes()).unwrap(),
            )
            .header("te", "trailers")
            .header("connection", "keep-alive")
            .body(())
            .unwrap();
        let (parts, ()) = req.into_parts();
        let (decoded, len) = round_trip_request(&parts, Some(12), false, true).unwrap();
        assert_eq!(decoded.method, Method::POST);
        assert_eq!(decoded.uri, parts.uri);
        assert_eq!(decoded.version, Version::HTTP_2);
        assert_eq!(decoded.headers["x-greeting"], parts.headers["x-greeting"]);
        assert_eq!(decoded.headers["te"], "trailers");
        assert!(!decoded.headers.contains_key("connection"));
        assert_eq!(len, Some(12));

        // Extended CONNECT with `:protocol = websocket`
        let mut ext_parts = http::Request::builder()
            .method(Method::CONNECT)
            .uri("https://example.com/chat")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        ext_parts
            .extensions
            .insert(Protocol::from_static("websocket"));
        let (decoded_ext, _) = round_trip_request(&ext_parts, None, false, true).unwrap();
        assert_eq!(
            decoded_ext.extensions.get::<Protocol>(),
            Some(&Protocol::from_static("websocket"))
        );
        assert_eq!(decoded_ext.uri, "https://example.com/chat");

        // OPTIONS * with authority round-trips cleanly!
        let opt_parts = http::Request::builder()
            .method(Method::OPTIONS)
            .uri("*")
            .header(HOST, "example.com:8443")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let (decoded_opt, _) = round_trip_request(&opt_parts, None, true, true).unwrap();
        assert_eq!(decoded_opt.method, Method::OPTIONS);
        assert_eq!(decoded_opt.uri, "*");
        assert_eq!(decoded_opt.headers[HOST], "example.com:8443");
    }
}
