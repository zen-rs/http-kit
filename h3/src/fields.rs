//! HTTP/3 field sections to and from `http` message heads (RFC 9114 §4.2,
//! §4.3).

use http::{
    HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version,
    header::{CONTENT_LENGTH, COOKIE, HOST, TE},
    request, response,
    uri::{Authority, PathAndQuery, Scheme},
};
use quiche::h3::{Header, NameValue as _};

use crate::{Error, Malformed};

/// Fields HTTP/3 forbids, because QUIC already does their job
/// (RFC 9114 §4.2). `TE` is checked separately: `trailers` is allowed.
fn is_connection_specific(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    )
}

/// Whether a regular field may be sent: a message translated from HTTP/1.1
/// can carry connection-specific fields, and the endpoint that frames it
/// for HTTP/3 drops them (RFC 9114 §4.2).
fn sendable(name: &HeaderName, value: &HeaderValue) -> bool {
    !is_connection_specific(name) && (name != TE || value.as_bytes() == b"trailers")
}

fn push_regular(fields: &mut Vec<Header>, headers: &HeaderMap, skip: &[HeaderName]) {
    for (name, value) in headers {
        if sendable(name, value) && !skip.contains(name) {
            fields.push(Header::new(name.as_str().as_bytes(), value.as_bytes()));
        }
    }
}

/// The field section of an outgoing request.
///
/// `body_len` is the body's length when known; it becomes `Content-Length`
/// unless the request carries one.
pub(crate) fn encode_request(
    parts: &request::Parts,
    body_len: Option<u64>,
) -> Result<Vec<Header>, Error> {
    let authority = match parts.uri.authority() {
        Some(authority) => authority.as_str().as_bytes(),
        None => parts
            .headers
            .get(HOST)
            .ok_or(Error::MissingAuthority)?
            .as_bytes(),
    };
    let mut fields = Vec::with_capacity(parts.headers.len() + 5);
    fields.push(Header::new(b":method", parts.method.as_str().as_bytes()));
    if parts.method == Method::CONNECT {
        fields.push(Header::new(b":authority", authority));
    } else {
        let scheme = parts.uri.scheme_str().unwrap_or("https");
        let path = parts.uri.path_and_query().map_or("/", PathAndQuery::as_str);
        fields.push(Header::new(b":scheme", scheme.as_bytes()));
        fields.push(Header::new(b":authority", authority));
        fields.push(Header::new(b":path", path.as_bytes()));
    }
    // `:authority` replaces `Host` (RFC 9114 §4.3.1).
    push_regular(&mut fields, &parts.headers, &[HOST]);
    push_length(&mut fields, &parts.headers, body_len.filter(|&len| len > 0));
    Ok(fields)
}

/// The field section of an outgoing response.
pub(crate) fn encode_response(
    parts: &response::Parts,
    body_len: Option<u64>,
) -> Result<Vec<Header>, Error> {
    if parts.status.is_informational() {
        return Err(Error::InformationalResponse(parts.status));
    }
    let mut fields = Vec::with_capacity(parts.headers.len() + 2);
    fields.push(Header::new(b":status", parts.status.as_str().as_bytes()));
    push_regular(&mut fields, &parts.headers, &[]);
    let bodiless =
        parts.status == StatusCode::NO_CONTENT || parts.status == StatusCode::NOT_MODIFIED;
    push_length(&mut fields, &parts.headers, body_len.filter(|_| !bodiless));
    Ok(fields)
}

/// A trailer section.
pub(crate) fn encode_trailers(trailers: &HeaderMap) -> Vec<Header> {
    let mut fields = Vec::with_capacity(trailers.len());
    push_regular(&mut fields, trailers, &[]);
    fields
}

fn push_length(fields: &mut Vec<Header>, headers: &HeaderMap, len: Option<u64>) {
    if let Some(len) = len
        && !headers.contains_key(CONTENT_LENGTH)
    {
        fields.push(Header::new(b"content-length", len.to_string().as_bytes()));
    }
}

/// The `Content-Length` an outgoing head announces, if any.
pub(crate) fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
}

/// Regular fields of a received section, checked as RFC 9114 §4.2 requires.
#[derive(Default)]
struct Regular {
    headers: HeaderMap,
    cookies: Vec<u8>,
    content_length: Option<u64>,
}

impl Regular {
    fn push(&mut self, name: &[u8], value: &[u8]) -> Result<(), Malformed> {
        if name.iter().any(u8::is_ascii_uppercase) {
            return Err(Malformed::InvalidField);
        }
        let name = HeaderName::from_bytes(name).map_err(|_| Malformed::InvalidField)?;
        if is_connection_specific(&name) || (name == TE && value != b"trailers") {
            return Err(Malformed::ConnectionSpecificField);
        }
        let value = HeaderValue::from_bytes(value).map_err(|_| Malformed::InvalidField)?;
        if name == CONTENT_LENGTH {
            let len = value
                .to_str()
                .ok()
                .filter(|text| !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|text| text.parse().ok())
                .ok_or(Malformed::InvalidContentLength)?;
            if self.content_length.is_some_and(|seen| seen != len) {
                return Err(Malformed::InvalidContentLength);
            }
            self.content_length = Some(len);
        }
        if name == COOKIE {
            // HTTP/3 may split a cookie into several fields; HTTP/1.1 and
            // HTTP/2 consumers expect one (RFC 9114 §4.2.1).
            if !self.cookies.is_empty() {
                self.cookies.extend_from_slice(b"; ");
            }
            self.cookies.extend_from_slice(value.as_bytes());
            return Ok(());
        }
        self.headers.append(name, value);
        Ok(())
    }

    fn finish(mut self) -> Result<(HeaderMap, Option<u64>), Malformed> {
        if !self.cookies.is_empty() {
            let cookie =
                HeaderValue::from_bytes(&self.cookies).map_err(|_| Malformed::InvalidField)?;
            self.headers.insert(COOKIE, cookie);
        }
        Ok((self.headers, self.content_length))
    }
}

/// A received request head, and the `Content-Length` it declares.
pub(crate) fn decode_request(list: &[Header]) -> Result<(request::Parts, Option<u64>), Malformed> {
    let (mut method, mut scheme, mut authority, mut path) = (None, None, None, None);
    let mut regular = Regular::default();
    let mut pseudo_done = false;
    for field in list {
        if let Some(pseudo) = field.name().strip_prefix(b":") {
            let slot = match pseudo {
                b"method" => &mut method,
                b"scheme" => &mut scheme,
                b"authority" => &mut authority,
                b"path" => &mut path,
                _ => return Err(Malformed::InvalidPseudoHeader),
            };
            if pseudo_done || slot.is_some() {
                return Err(Malformed::InvalidPseudoHeader);
            }
            *slot = Some(field.value());
        } else {
            pseudo_done = true;
            regular.push(field.name(), field.value())?;
        }
    }
    let (headers, content_length) = regular.finish()?;
    let method = method
        .filter(|method| !method.is_empty())
        .ok_or(Malformed::MissingPseudoHeader(":method"))?;
    let method = Method::from_bytes(method).map_err(|_| Malformed::InvalidMethod)?;

    let host = headers.get(HOST).map(HeaderValue::as_bytes);
    if let (Some(authority), Some(host)) = (authority, host)
        && authority != host
    {
        return Err(Malformed::InvalidAuthority);
    }
    let authority = authority
        .or(host)
        .filter(|authority| !authority.is_empty())
        .map(|authority| Authority::try_from(authority).map_err(|_| Malformed::InvalidAuthority))
        .transpose()?;

    let mut uri = http::uri::Parts::default();
    if method == Method::CONNECT {
        if scheme.is_some() || path.is_some() {
            return Err(Malformed::InvalidPseudoHeader);
        }
        uri.authority = Some(authority.ok_or(Malformed::MissingPseudoHeader(":authority"))?);
    } else {
        let scheme = scheme
            .filter(|scheme| !scheme.is_empty())
            .ok_or(Malformed::MissingPseudoHeader(":scheme"))?;
        let scheme = Scheme::try_from(scheme).map_err(|_| Malformed::InvalidTarget)?;
        let path = path
            .filter(|path| !path.is_empty())
            .ok_or(Malformed::MissingPseudoHeader(":path"))?;
        let path = PathAndQuery::try_from(path).map_err(|_| Malformed::InvalidTarget)?;
        let needs_authority = scheme == Scheme::HTTP || scheme == Scheme::HTTPS;
        if needs_authority && authority.is_none() {
            return Err(Malformed::InvalidAuthority);
        }
        uri.scheme = Some(scheme);
        uri.authority = authority;
        uri.path_and_query = Some(path);
    }
    let uri = Uri::from_parts(uri).map_err(|_| Malformed::InvalidTarget)?;

    let mut parts = http::Request::new(()).into_parts().0;
    parts.method = method;
    parts.uri = uri;
    parts.version = Version::HTTP_3;
    parts.headers = headers;
    Ok((parts, content_length))
}

/// A received response head, and the `Content-Length` it declares.
pub(crate) fn decode_response(
    list: &[Header],
) -> Result<(response::Parts, Option<u64>), Malformed> {
    let mut status = None;
    let mut regular = Regular::default();
    let mut pseudo_done = false;
    for field in list {
        if field.name() == b":status" {
            if pseudo_done || status.is_some() {
                return Err(Malformed::InvalidPseudoHeader);
            }
            status = Some(field.value());
        } else if field.name().starts_with(b":") {
            return Err(Malformed::InvalidPseudoHeader);
        } else {
            pseudo_done = true;
            regular.push(field.name(), field.value())?;
        }
    }
    let status = status.ok_or(Malformed::MissingPseudoHeader(":status"))?;
    if status.len() != 3 {
        return Err(Malformed::InvalidStatus);
    }
    let status = StatusCode::from_bytes(status).map_err(|_| Malformed::InvalidStatus)?;
    let (headers, content_length) = regular.finish()?;
    let mut parts = http::Response::new(()).into_parts().0;
    parts.status = status;
    parts.version = Version::HTTP_3;
    parts.headers = headers;
    Ok((parts, content_length))
}

/// A received trailer section.
pub(crate) fn decode_trailers(list: &[Header]) -> Result<HeaderMap, Malformed> {
    let mut regular = Regular::default();
    for field in list {
        if field.name().starts_with(b":") {
            return Err(Malformed::InvalidPseudoHeader);
        }
        regular.push(field.name(), field.value())?;
    }
    Ok(regular.finish()?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(list: &[(&str, &str)]) -> Vec<Header> {
        list.iter()
            .map(|(name, value)| Header::new(name.as_bytes(), value.as_bytes()))
            .collect()
    }

    #[test]
    fn a_request_round_trips() {
        // 例え.jp/検索?q=안녕, as a URI carries it.
        let request = http::Request::builder()
            .method(Method::POST)
            .uri("https://xn--r8jz45g.jp/%E6%A4%9C%E7%B4%A2?q=%EC%95%88%EB%85%95")
            .header(
                "x-greeting",
                HeaderValue::from_bytes("你好、こんにちは、안녕하세요".as_bytes()).unwrap(),
            )
            .header("connection", "keep-alive")
            .body(())
            .unwrap();
        let (parts, ()) = request.into_parts();
        let encoded = encode_request(&parts, Some(5)).unwrap();
        assert!(encoded.iter().all(|field| field.name() != b"connection"));
        let (decoded, length) = decode_request(&encoded).unwrap();
        assert_eq!(decoded.method, Method::POST);
        assert_eq!(decoded.uri, parts.uri);
        assert_eq!(decoded.headers["x-greeting"], parts.headers["x-greeting"]);
        assert_eq!(length, Some(5));
    }

    #[test]
    fn malformed_requests_are_named() {
        let cases: &[(&[(&str, &str)], Malformed)] = &[
            (
                &[(":scheme", "https"), (":path", "/")],
                Malformed::MissingPseudoHeader(":method"),
            ),
            (
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "a"),
                    (":path", ""),
                ],
                Malformed::MissingPseudoHeader(":path"),
            ),
            (
                &[(":method", "GET"), (":scheme", "https"), (":path", "/")],
                Malformed::InvalidAuthority,
            ),
            (
                &[(":method", "GET"), ("x", "1"), (":scheme", "https")],
                Malformed::InvalidPseudoHeader,
            ),
            (
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "a"),
                    (":path", "/"),
                    ("X-Upper", "1"),
                ],
                Malformed::InvalidField,
            ),
            (
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "a"),
                    (":path", "/"),
                    ("transfer-encoding", "chunked"),
                ],
                Malformed::ConnectionSpecificField,
            ),
            (
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "a"),
                    (":path", "/"),
                    ("content-length", "1"),
                    ("content-length", "2"),
                ],
                Malformed::InvalidContentLength,
            ),
            (
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":authority", "a"),
                    (":path", "/"),
                    ("host", "b"),
                ],
                Malformed::InvalidAuthority,
            ),
        ];
        for (list, expected) in cases {
            assert_eq!(
                decode_request(&fields(list)).unwrap_err(),
                *expected,
                "{list:?}"
            );
        }
    }

    #[test]
    fn split_cookies_are_joined() {
        let list = fields(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "a"),
            (":path", "/"),
            ("cookie", "a=1"),
            ("cookie", "b=2"),
        ]);
        let (parts, _) = decode_request(&list).unwrap();
        assert_eq!(parts.headers[COOKIE], "a=1; b=2");
    }

    #[test]
    fn informational_responses_are_refused() {
        let mut parts = http::Response::new(()).into_parts().0;
        parts.status = StatusCode::CONTINUE;
        assert!(matches!(
            encode_response(&parts, None),
            Err(Error::InformationalResponse(StatusCode::CONTINUE))
        ));
    }
}
