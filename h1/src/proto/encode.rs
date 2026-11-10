//! Encoding outgoing message heads and framing their bodies.

use std::fmt::Write as _;

use bytes::{BufMut, Bytes, BytesMut};
use http::{
    HeaderMap, HeaderValue, Method, StatusCode, Version,
    header::{CONTENT_LENGTH, DATE, EXPECT, HOST, TRANSFER_ENCODING, UPGRADE},
    request, response,
};

use crate::{
    Error,
    proto::head::{ConnectionTokens, RequestInfo, parse_decimal},
};

/// The CRLF that ends a chunk's data.
const CRLF: &[u8] = b"\r\n";
/// The last chunk and the empty trailer section of a chunked body.
const LAST_CHUNK: &[u8] = b"0\r\n\r\n";

/// How an outgoing body is framed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// The message has no body; whatever body it was given is not sent.
    Omitted,
    /// Exactly this many bytes, announced in `Content-Length`.
    Length(u64),
    /// Chunked, with optional trailers.
    Chunked,
    /// The body ends when the connection closes.
    CloseDelimited,
}

/// Frames an outgoing body: turns data, file regions and trailers into the
/// bytes that go on the wire around them, and checks that the body matches
/// the length its head announced.
#[derive(Debug)]
pub struct BodyEncoder {
    framing: Framing,
    /// Bytes left under `Content-Length`.
    remaining: u64,
    /// Whether the chunked body's last chunk has been written.
    finished: bool,
    /// Room that chunk-size lines are written into and split off.
    scratch: BytesMut,
}

impl BodyEncoder {
    /// An encoder for a body framed as `framing`.
    #[must_use]
    pub fn new(framing: Framing) -> Self {
        Self {
            framing,
            remaining: match framing {
                Framing::Length(len) => len,
                _ => 0,
            },
            finished: false,
            scratch: BytesMut::new(),
        }
    }

    /// The body's framing.
    #[must_use]
    pub const fn framing(&self) -> Framing {
        self.framing
    }

    /// Whether the body is sent at all.
    #[must_use]
    pub fn sends_body(&self) -> bool {
        self.framing != Framing::Omitted
    }

    /// Frames `data` and appends the buffers to send to `out`. Empty data is
    /// skipped: a zero-size chunk would end a chunked body.
    ///
    /// # Errors
    ///
    /// [`Error::ContentLengthMismatch`] when `data` overruns `Content-Length`.
    pub fn data(&mut self, data: Bytes, out: &mut Vec<Bytes>) -> Result<(), Error> {
        if data.is_empty() {
            return Ok(());
        }
        let prefix = self.region_start(data.len() as u64)?;
        out.extend(prefix);
        out.push(data);
        out.extend(self.region_end());
        Ok(())
    }

    /// Starts a region of `len` bytes that the caller sends itself (a file
    /// region through sendfile), returning the bytes that go before it.
    ///
    /// # Errors
    ///
    /// [`Error::ContentLengthMismatch`] when the region overruns
    /// `Content-Length`.
    pub fn region_start(&mut self, len: u64) -> Result<Option<Bytes>, Error> {
        match self.framing {
            Framing::Length(declared) => {
                self.remaining = self
                    .remaining
                    .checked_sub(len)
                    .ok_or(Error::ContentLengthMismatch { declared })?;
                Ok(None)
            }
            Framing::Chunked if len > 0 => {
                write!(self.scratch, "{len:x}\r\n").expect("writing to memory cannot fail");
                Ok(Some(self.scratch.split().freeze()))
            }
            Framing::Chunked | Framing::CloseDelimited | Framing::Omitted => Ok(None),
        }
    }

    /// The bytes that go after a region started with
    /// [`region_start`](Self::region_start).
    #[must_use]
    pub fn region_end(&self) -> Option<Bytes> {
        (self.framing == Framing::Chunked).then(|| Bytes::from_static(CRLF))
    }

    /// Ends a chunked body with `trailers`, returning the bytes to send.
    ///
    /// # Errors
    ///
    /// [`Error::TrailersNotChunked`] when the body is not chunked.
    pub fn trailers(&mut self, trailers: &HeaderMap) -> Result<Bytes, Error> {
        if self.framing != Framing::Chunked {
            return Err(Error::TrailersNotChunked);
        }
        self.finished = true;
        let mut out = BytesMut::from(&b"0\r\n"[..]);
        write_fields(&mut out, trailers);
        out.put_slice(CRLF);
        Ok(out.freeze())
    }

    /// Ends the body, returning the bytes that close it, if any.
    ///
    /// # Errors
    ///
    /// [`Error::ContentLengthMismatch`] when fewer bytes than
    /// `Content-Length` were sent.
    pub fn finish(&mut self) -> Result<Option<Bytes>, Error> {
        match self.framing {
            Framing::Length(declared) if self.remaining != 0 => {
                Err(Error::ContentLengthMismatch { declared })
            }
            Framing::Chunked if !self.finished => {
                self.finished = true;
                Ok(Some(Bytes::from_static(LAST_CHUNK)))
            }
            _ => Ok(None),
        }
    }
}

fn write_fields(out: &mut BytesMut, fields: &HeaderMap) {
    for (name, value) in fields {
        write_field(out, name.as_str(), value.as_bytes());
    }
}

fn write_field(out: &mut BytesMut, name: &str, value: &[u8]) {
    out.put_slice(name.as_bytes());
    out.put_slice(b": ");
    out.put_slice(value);
    out.put_slice(CRLF);
}

/// The framing an outgoing message asked for in its own fields.
enum OwnFraming {
    None,
    Length(u64),
    Chunked,
}

fn own_framing(headers: &HeaderMap) -> Result<OwnFraming, Error> {
    let mut length = None;
    for value in headers.get_all(CONTENT_LENGTH) {
        let parsed =
            parse_decimal(value.as_bytes().trim_ascii()).ok_or(Error::OutgoingContentLength)?;
        if length.is_some_and(|previous| previous != parsed) {
            return Err(Error::OutgoingContentLength);
        }
        length = Some(parsed);
    }
    let mut encodings = headers.get_all(TRANSFER_ENCODING).iter();
    match (encodings.next(), length) {
        (None, None) => Ok(OwnFraming::None),
        (None, Some(len)) => Ok(OwnFraming::Length(len)),
        (Some(value), None)
            if encodings.next().is_none()
                && value
                    .as_bytes()
                    .trim_ascii()
                    .eq_ignore_ascii_case(b"chunked") =>
        {
            Ok(OwnFraming::Chunked)
        }
        (Some(_), _) => Err(Error::OutgoingTransferEncoding),
    }
}

/// What the head of a response decided about the exchange.
#[derive(Debug)]
pub struct ResponsePlan {
    /// Frames the response body.
    pub encoder: BodyEncoder,
    /// Whether the connection persists after this response.
    pub keep_alive: bool,
    /// Whether the connection switches protocols after this response.
    pub upgrade: bool,
}

/// Encodes a response head into `dst` and decides its body's framing.
///
/// `body_len` is the body's length when known. The fields the response
/// carries are written as they are, except that framing fields it lacks are
/// added: `Content-Length` when the length is known, otherwise
/// `Transfer-Encoding: chunked` to an HTTP/1.1 client, otherwise the body is
/// close-delimited. `close` forces the connection to close after this
/// response; `date`, when given, is added if the response has no `Date`.
///
/// # Errors
///
/// A response that cannot be sent as given: informational, an unrequested
/// `101`, framing fields that are invalid or contradict the body.
pub fn encode_response_head(
    request: &RequestInfo,
    response: &response::Parts,
    body_len: Option<u64>,
    close: bool,
    date: Option<&HeaderValue>,
    dst: &mut BytesMut,
) -> Result<ResponsePlan, Error> {
    let status = response.status;
    let switching = status == StatusCode::SWITCHING_PROTOCOLS;
    if status.is_informational() && !switching {
        return Err(Error::InformationalResponse(status));
    }
    let connect = request.method == Method::CONNECT;
    if switching && (!request.upgrade || connect) {
        return Err(Error::UnrequestedUpgrade);
    }
    let upgrade = switching || (connect && status.is_success());
    let omitted = upgrade
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
        || request.method == Method::HEAD;

    let own = own_framing(&response.headers)?;
    let mut added_length = None;
    let mut added_chunked = false;
    let framing = match own {
        _ if omitted => {
            if request.method == Method::HEAD && matches!(own, OwnFraming::None) {
                added_length = body_len;
            }
            Framing::Omitted
        }
        OwnFraming::Chunked if request.version == Version::HTTP_10 => {
            return Err(Error::OutgoingTransferEncoding);
        }
        OwnFraming::Chunked => Framing::Chunked,
        OwnFraming::Length(declared) => {
            if body_len.is_some_and(|len| len != declared) {
                return Err(Error::ContentLengthMismatch { declared });
            }
            Framing::Length(declared)
        }
        OwnFraming::None => match body_len {
            Some(len) => {
                added_length = Some(len);
                Framing::Length(len)
            }
            None if request.version == Version::HTTP_11 => {
                added_chunked = true;
                Framing::Chunked
            }
            None => Framing::CloseDelimited,
        },
    };

    let tokens = ConnectionTokens::new(&response.headers);
    let keep_alive = request.keep_alive
        && !close
        && !tokens.close
        && !upgrade
        && framing != Framing::CloseDelimited;

    dst.put_slice(b"HTTP/1.1 ");
    dst.put_slice(status.as_str().as_bytes());
    dst.put_u8(b' ');
    dst.put_slice(status.canonical_reason().unwrap_or("").as_bytes());
    dst.put_slice(CRLF);
    write_fields(dst, &response.headers);
    if let Some(len) = added_length {
        write_length(dst, len);
    }
    if added_chunked {
        write_field(dst, TRANSFER_ENCODING.as_str(), b"chunked");
    }
    if let Some(date) = date.filter(|_| !response.headers.contains_key(DATE)) {
        write_field(dst, DATE.as_str(), date.as_bytes());
    }
    if !keep_alive && !upgrade && !tokens.close {
        write_field(dst, "connection", b"close");
    } else if keep_alive && request.version == Version::HTTP_10 && !tokens.keep_alive {
        write_field(dst, "connection", b"keep-alive");
    }
    dst.put_slice(CRLF);

    Ok(ResponsePlan {
        encoder: BodyEncoder::new(framing),
        keep_alive,
        upgrade,
    })
}

fn write_length(dst: &mut BytesMut, len: u64) {
    dst.put_slice(b"content-length: ");
    write!(dst, "{len}").expect("writing to memory cannot fail");
    dst.put_slice(CRLF);
}

/// What the head of a request decided about the exchange.
#[derive(Debug)]
pub struct RequestPlan {
    /// Frames the request body.
    pub encoder: BodyEncoder,
    /// Whether the client asks the connection to persist after this exchange.
    pub keep_alive: bool,
    /// Whether the body waits for `100 Continue`.
    pub expect_continue: bool,
    /// Whether the request may switch protocols.
    pub upgrade: bool,
}

/// The form of the request target a client writes (RFC 9112 §3.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestTarget {
    /// The URI's path and query, for a request to the origin server.
    #[default]
    Origin,
    /// The whole URI, scheme and authority included, for a request to a
    /// forward proxy. The URI must carry both; a `userinfo` is left out, as
    /// RFC 9112 §3.2.2 requires.
    Absolute,
}

/// Encodes a request head into `dst` and decides its body's framing.
///
/// The request target is the URI's authority for `CONNECT` and otherwise,
/// per `form`, either its path and query or the whole URI. A `Host` field is added from the URI's authority when the
/// request has none. Framing fields it lacks are added: `Content-Length` when
/// the length is known (omitted for an empty body unless the method expects
/// one), otherwise `Transfer-Encoding: chunked`.
///
/// # Errors
///
/// A request that cannot be sent as given: an unsupported version, no host,
/// an absolute-form target without a scheme and authority, framing fields
/// that are invalid or contradict the body.
pub fn encode_request_head(
    request: &request::Parts,
    form: RequestTarget,
    body_len: Option<u64>,
    dst: &mut BytesMut,
) -> Result<RequestPlan, Error> {
    let version = request.version;
    if version != Version::HTTP_11 && version != Version::HTTP_10 {
        return Err(Error::UnsupportedVersion(version));
    }
    let method = &request.method;
    let connect = method == Method::CONNECT;
    let authority = request.uri.authority().map(|authority| {
        // A Host field never carries userinfo (RFC 9110 §7.2).
        let authority = authority.as_str();
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
    });
    let path = request.uri.path_and_query().map_or("/", |pq| pq.as_str());
    // The scheme that goes before `://` in an absolute-form target.
    let scheme = match (connect, form) {
        (false, RequestTarget::Absolute) => {
            if authority.is_none() {
                return Err(Error::AbsoluteTargetIncomplete);
            }
            Some(
                request
                    .uri
                    .scheme_str()
                    .ok_or(Error::AbsoluteTargetIncomplete)?,
            )
        }
        _ => None,
    };
    let target = if connect {
        authority.ok_or(Error::MissingHost)?
    } else {
        path
    };
    let host = if request.headers.contains_key(HOST) {
        None
    } else {
        Some(authority.ok_or(Error::MissingHost)?)
    };

    let mut added_length = None;
    let mut added_chunked = false;
    let framing = match own_framing(&request.headers)? {
        OwnFraming::Chunked if version == Version::HTTP_10 => {
            return Err(Error::OutgoingTransferEncoding);
        }
        OwnFraming::Chunked => Framing::Chunked,
        OwnFraming::Length(declared) => {
            if body_len.is_some_and(|len| len != declared) {
                return Err(Error::ContentLengthMismatch { declared });
            }
            Framing::Length(declared)
        }
        OwnFraming::None => match body_len {
            Some(0) => {
                // RFC 9110 §8.6: send `Content-Length: 0` only where the
                // method anticipates content.
                if method == Method::POST || method == Method::PUT || method == Method::PATCH {
                    added_length = Some(0);
                }
                Framing::Length(0)
            }
            Some(len) => {
                added_length = Some(len);
                Framing::Length(len)
            }
            None if version == Version::HTTP_11 => {
                added_chunked = true;
                Framing::Chunked
            }
            None => return Err(Error::UnknownLengthHttp10),
        },
    };

    let tokens = ConnectionTokens::new(&request.headers);
    let http11 = version == Version::HTTP_11;
    let expect_continue = http11
        && framing != Framing::Length(0)
        && request
            .headers
            .get_all(EXPECT)
            .iter()
            .any(|value| value.as_bytes().eq_ignore_ascii_case(b"100-continue"));

    dst.put_slice(method.as_str().as_bytes());
    dst.put_u8(b' ');
    if let Some(scheme) = scheme {
        dst.put_slice(scheme.as_bytes());
        dst.put_slice(b"://");
        dst.put_slice(authority.expect("checked above").as_bytes());
    }
    dst.put_slice(target.as_bytes());
    dst.put_slice(if http11 {
        b" HTTP/1.1\r\n"
    } else {
        b" HTTP/1.0\r\n"
    });
    if let Some(host) = host {
        write_field(dst, HOST.as_str(), host.as_bytes());
    }
    write_fields(dst, &request.headers);
    if let Some(len) = added_length {
        write_length(dst, len);
    }
    if added_chunked {
        write_field(dst, TRANSFER_ENCODING.as_str(), b"chunked");
    }
    dst.put_slice(CRLF);

    Ok(RequestPlan {
        encoder: BodyEncoder::new(framing),
        keep_alive: tokens.keep_alive(version),
        expect_continue,
        upgrade: connect || (http11 && tokens.upgrade && request.headers.contains_key(UPGRADE)),
    })
}
