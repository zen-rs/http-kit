//! The sans-IO core, exercised on byte buffers alone.

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version, header};
use http_kit_h1::{
    Error, Limits, ParseError,
    proto::{
        BodyDecoder, BodyEncoder, BodyKind, Decoded, Framing, RequestInfo, RequestTarget,
        encode_request_head, encode_response_head, parse_request_head, parse_response_head,
    },
};

const CJK: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

fn limits() -> Limits {
    Limits::default()
}

fn request(raw: &[u8]) -> Result<Option<http_kit_h1::proto::RequestHead>, ParseError> {
    parse_request_head(&mut BytesMut::from(raw), &limits())
}

fn request_err(raw: &[u8]) -> ParseError {
    request(raw).expect_err("the request must be rejected")
}

/// Decodes a whole body from `buf`, returning data and trailers.
fn decode_all(
    kind: BodyKind,
    buf: &mut BytesMut,
) -> Result<(Vec<Bytes>, Option<HeaderMap>), ParseError> {
    let mut decoder = BodyDecoder::new(kind);
    let mut data = Vec::new();
    let mut trailers = None;
    loop {
        match decoder
            .decode(buf, &limits())?
            .expect("the body is all in the buffer")
        {
            Decoded::Data(chunk) => data.push(chunk),
            Decoded::Trailers(fields) => trailers = Some(fields),
            Decoded::End => return Ok((data, trailers)),
        }
    }
}

#[test]
fn request_head_shares_the_receive_buffer() {
    let raw = format!(
        "GET /search?q=x HTTP/1.1\r\nHost: example.com\r\nX-Greeting: {CJK}\r\n\r\nGET / HTTP/1.1\r\n"
    );
    let mut buf = BytesMut::from(raw.as_bytes());
    let range = buf.as_ptr().addr()..buf.as_ptr().addr() + buf.len();
    let head = parse_request_head(&mut buf, &limits()).unwrap().unwrap();
    assert_eq!(head.parts.method, Method::GET);
    assert_eq!(head.parts.uri, "/search?q=x");
    assert_eq!(head.parts.version, Version::HTTP_11);
    assert_eq!(head.body, BodyKind::Empty);
    assert!(head.keep_alive);
    let greeting = head.parts.headers.get("x-greeting").unwrap();
    assert_eq!(greeting.as_bytes(), CJK.as_bytes());
    assert!(
        range.contains(&greeting.as_bytes().as_ptr().addr()),
        "the value was copied"
    );
    // The pipelined request after it is left in the buffer.
    assert_eq!(&buf[..], b"GET / HTTP/1.1\r\n");
}

#[test]
fn partial_head_waits_for_more() {
    assert!(request(b"GET / HTTP/1.1\r\nHost: a\r\n").unwrap().is_none());
}

#[test]
fn chunked_body_with_trailers_is_zero_copy() {
    let text = CJK.as_bytes();
    let (first, second) = text.split_at(9);
    let mut raw = Vec::new();
    raw.extend(format!("{:x};name=value\r\n", first.len()).as_bytes());
    raw.extend(first);
    raw.extend(format!("\r\n{:X}\r\n", second.len()).as_bytes());
    raw.extend(second);
    raw.extend(format!("\r\n0\r\nChecksum: abc\r\nX-Note: {CJK}\r\n\r\nNEXT").as_bytes());

    let mut buf = BytesMut::from(&raw[..]);
    let range = buf.as_ptr().addr()..buf.as_ptr().addr() + buf.len();
    let (data, trailers) = decode_all(BodyKind::Chunked, &mut buf).unwrap();
    assert_eq!(data.concat(), text);
    for chunk in &data {
        let start = chunk.as_ptr().addr();
        assert!(
            range.contains(&start) && start + chunk.len() <= range.end,
            "data was copied"
        );
    }
    let trailers = trailers.unwrap();
    assert_eq!(trailers["checksum"], "abc");
    assert_eq!(trailers["x-note"].as_bytes(), text);
    assert_eq!(&buf[..], b"NEXT");
}

#[test]
fn chunked_data_streams_before_the_chunk_completes() {
    let mut buf = BytesMut::from(&b"a\r\n01234"[..]);
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert_eq!(
        decoder.decode(&mut buf, &limits()).unwrap(),
        Some(Decoded::Data(Bytes::from_static(b"01234")))
    );
    assert_eq!(decoder.decode(&mut buf, &limits()).unwrap(), None);
    buf.extend_from_slice(b"56789\r\n0\r\n\r\n");
    assert_eq!(
        decoder.decode(&mut buf, &limits()).unwrap(),
        Some(Decoded::Data(Bytes::from_static(b"56789")))
    );
    assert_eq!(
        decoder.decode(&mut buf, &limits()).unwrap(),
        Some(Decoded::End)
    );
    assert!(decoder.is_done());
}

#[test]
fn content_length_body_is_zero_copy() {
    let raw = format!(
        "POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{CJK}",
        CJK.len()
    );
    let mut buf = BytesMut::from(raw.as_bytes());
    let range = buf.as_ptr().addr()..buf.as_ptr().addr() + buf.len();
    let head = parse_request_head(&mut buf, &limits()).unwrap().unwrap();
    assert_eq!(head.body, BodyKind::Length(CJK.len() as u64));
    let (data, trailers) = decode_all(head.body, &mut buf).unwrap();
    assert!(trailers.is_none());
    assert_eq!(data.len(), 1);
    assert_eq!(data[0], CJK.as_bytes());
    assert!(range.contains(&data[0].as_ptr().addr()), "data was copied");
}

#[test]
fn close_delimited_body_ends_at_eof() {
    let mut buf = BytesMut::from(CJK.as_bytes());
    let mut decoder = BodyDecoder::new(BodyKind::CloseDelimited);
    assert_eq!(
        decoder.decode(&mut buf, &limits()).unwrap(),
        Some(Decoded::Data(Bytes::from(CJK)))
    );
    assert_eq!(decoder.decode(&mut buf, &limits()).unwrap(), None);
    assert_eq!(
        decoder.decode_eof(&mut buf, &limits()).unwrap(),
        Decoded::End
    );
}

#[test]
fn truncated_body_fails_at_eof() {
    let mut buf = BytesMut::from(&b"abc"[..]);
    let mut decoder = BodyDecoder::new(BodyKind::Length(10));
    decoder.decode(&mut buf, &limits()).unwrap();
    assert_eq!(
        decoder.decode_eof(&mut buf, &limits()),
        Err(ParseError::Incomplete)
    );
}

// Request smuggling (RFC 9112 §6.3) and malformed framing.

#[test]
fn rejects_content_length_with_transfer_encoding() {
    assert_eq!(
        request_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ParseError::ContentLengthWithTransferEncoding
    );
}

#[test]
fn rejects_differing_content_lengths() {
    assert_eq!(
        request_err(
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\n"
        ),
        ParseError::ConflictingContentLength
    );
    assert_eq!(
        request_err(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4, 5\r\n\r\n"),
        ParseError::ConflictingContentLength
    );
}

#[test]
fn accepts_identical_content_lengths() {
    let head =
        request(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\nContent-Length: 4, 4\r\n\r\n")
            .unwrap()
            .unwrap();
    assert_eq!(head.body, BodyKind::Length(4));
}

#[test]
fn rejects_invalid_content_length() {
    for value in ["+4", "-1", "4x", "0x10", "", "18446744073709551616"] {
        let raw = format!("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {value}\r\n\r\n");
        assert_eq!(
            request_err(raw.as_bytes()),
            ParseError::InvalidContentLength,
            "{value:?}"
        );
    }
}

#[test]
fn rejects_transfer_encoding_not_ending_in_chunked() {
    assert_eq!(
        request_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n"),
        ParseError::ChunkedNotFinal
    );
    assert_eq!(
        request_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n"),
        ParseError::ChunkedNotFinal
    );
    assert_eq!(
        request_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ParseError::ChunkedNotFinal
    );
    assert_eq!(
        request_err(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
        ParseError::UnsupportedTransferCoding
    );
}

#[test]
fn transfer_encoding_is_case_insensitive() {
    let head = request(b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: Chunked\r\n\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(head.body, BodyKind::Chunked);
}

#[test]
fn rejects_transfer_encoding_in_http10() {
    assert_eq!(
        request_err(b"POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n"),
        ParseError::TransferEncodingInHttp10
    );
}

#[test]
fn rejects_obs_fold_in_requests() {
    assert!(matches!(
        request_err(b"GET / HTTP/1.1\r\nHost: a\r\nX-Folded: one\r\n two\r\n\r\n"),
        ParseError::MalformedHead(_)
    ));
}

#[test]
fn rejects_bare_cr_in_heads() {
    assert!(matches!(
        request_err(b"GET / HTTP/1.1\r\nHost: a\rX: b\r\n\r\n"),
        ParseError::MalformedHead(_)
    ));
}

#[test]
fn accepts_bare_lf_as_a_head_line_terminator() {
    // RFC 9112 §2.2 lets a recipient recognise a lone LF in the start line
    // and fields; the head is re-serialised with CRLF on every way out.
    let head = request(b"GET / HTTP/1.1\nHost: a\n\n").unwrap().unwrap();
    assert_eq!(head.parts.headers["host"], "a");
}

#[test]
fn rejects_whitespace_before_a_request_field_colon() {
    assert!(matches!(
        request_err(b"GET / HTTP/1.1\r\nHost : a\r\n\r\n"),
        ParseError::MalformedHead(_)
    ));
}

#[test]
fn rejects_bare_lf_in_chunk_lines() {
    let mut buf = BytesMut::from(&b"3\nabc\r\n0\r\n\r\n"[..]);
    assert_eq!(
        decode_all(BodyKind::Chunked, &mut buf),
        Err(ParseError::MissingChunkCrlf)
    );
    let mut buf = BytesMut::from(&b"3\r\nabc\n0\r\n\r\n"[..]);
    assert_eq!(
        decode_all(BodyKind::Chunked, &mut buf),
        Err(ParseError::MissingChunkCrlf)
    );
}

#[test]
fn rejects_bad_chunk_sizes_and_extensions() {
    for (raw, error) in [
        (&b"\r\n"[..], ParseError::InvalidChunkSize),
        (b"g\r\n", ParseError::InvalidChunkSize),
        (b"-1\r\n", ParseError::InvalidChunkSize),
        (b"10000000000000000\r\n", ParseError::InvalidChunkSize),
        (b"3 \r\n", ParseError::InvalidChunkExtension),
        (b"3x\r\n", ParseError::InvalidChunkExtension),
        (b"3;a=\x01\r\n", ParseError::InvalidChunkExtension),
        (b"3;a\rb\r\n", ParseError::InvalidChunkExtension),
    ] {
        let mut buf = BytesMut::from(raw);
        assert_eq!(
            decode_all(BodyKind::Chunked, &mut buf),
            Err(error),
            "{:?}",
            String::from_utf8_lossy(raw)
        );
    }
}

#[test]
fn accepts_chunk_extensions_with_whitespace() {
    let mut buf = BytesMut::from(&b"3 ; name=\"quoted value\"\r\nabc\r\n0\r\n\r\n"[..]);
    let (data, _) = decode_all(BodyKind::Chunked, &mut buf).unwrap();
    assert_eq!(data.concat(), b"abc");
}

#[test]
fn bounds_chunk_lines() {
    let mut limits = Limits::default();
    limits.max_chunk_line_size = 16;
    let mut buf = BytesMut::from(&b"3;aaaaaaaaaaaaaaaaaaaaaaaaaaaa"[..]);
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert_eq!(
        decoder.decode(&mut buf, &limits),
        Err(ParseError::ChunkLineTooLong { limit: 16 })
    );
}

#[test]
fn bounds_head_size_and_field_count() {
    let mut limits = Limits::default();
    limits.max_head_size = 64;
    limits.max_headers = 2;
    let long = format!("GET / HTTP/1.1\r\nHost: a\r\nX: {}\r\n", "a".repeat(80));
    assert_eq!(
        parse_request_head(&mut BytesMut::from(long.as_bytes()), &limits).map(|_| ()),
        Err(ParseError::HeadTooLarge { limit: 64 })
    );
    let many = b"GET / HTTP/1.1\r\nHost: a\r\nA: 1\r\nB: 2\r\n\r\n";
    assert_eq!(
        parse_request_head(&mut BytesMut::from(&many[..]), &limits).map(|_| ()),
        Err(ParseError::TooManyHeaders { limit: 2 })
    );
}

#[test]
fn parses_more_fields_than_the_stack_holds() {
    let mut limits = Limits::default();
    limits.max_headers = 300;
    let mut raw = String::from("GET / HTTP/1.1\r\nHost: a\r\n");
    for i in 0..200 {
        raw.push_str(&format!("X-{i}: v{i}\r\n"));
    }
    raw.push_str("\r\n");
    let head = parse_request_head(&mut BytesMut::from(raw.as_bytes()), &limits)
        .unwrap()
        .unwrap();
    assert_eq!(head.parts.headers.len(), 201);
    assert_eq!(head.parts.headers["x-199"], "v199");
    let mut over = Limits::default();
    over.max_headers = 150;
    assert_eq!(
        parse_request_head(&mut BytesMut::from(raw.as_bytes()), &over).map(|_| ()),
        Err(ParseError::TooManyHeaders { limit: 150 })
    );
}

#[test]
fn bounds_trailer_sections() {
    let mut limits = Limits::default();
    limits.max_headers = 1;
    let mut buf = BytesMut::from(&b"0\r\nA: 1\r\nB: 2\r\n\r\n"[..]);
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert_eq!(
        decoder.decode(&mut buf, &limits),
        Err(ParseError::TooManyHeaders { limit: 1 })
    );
}

#[test]
fn host_rules() {
    assert_eq!(
        request_err(b"GET / HTTP/1.1\r\n\r\n"),
        ParseError::MissingHost
    );
    assert_eq!(
        request_err(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"),
        ParseError::MultipleHost
    );
    // HTTP/1.0 has no Host requirement.
    assert!(request(b"GET / HTTP/1.0\r\n\r\n").unwrap().is_some());
}

#[test]
fn request_target_forms() {
    assert_eq!(
        request(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n")
            .unwrap()
            .unwrap()
            .parts
            .uri,
        "*"
    );
    assert_eq!(
        request_err(b"GET * HTTP/1.1\r\nHost: a\r\n\r\n"),
        ParseError::InvalidTarget
    );
    let connect = request(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .unwrap()
        .unwrap();
    assert!(connect.upgrade);
    assert_eq!(
        request_err(b"CONNECT /path HTTP/1.1\r\nHost: a\r\n\r\n"),
        ParseError::InvalidTarget
    );
    let absolute = request(b"GET http://example.com/x HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .unwrap()
        .unwrap();
    assert_eq!(absolute.parts.uri.host(), Some("example.com"));
}

#[test]
fn versions_and_persistence() {
    assert_eq!(
        request_err(b"GET / HTTP/2.0\r\nHost: a\r\n\r\n"),
        ParseError::UnsupportedVersion
    );
    assert!(
        !request(b"GET / HTTP/1.0\r\n\r\n")
            .unwrap()
            .unwrap()
            .keep_alive
    );
    assert!(
        request(b"GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n")
            .unwrap()
            .unwrap()
            .keep_alive
    );
    assert!(
        !request(b"GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
            .unwrap()
            .unwrap()
            .keep_alive
    );
}

#[test]
fn expectations() {
    let head =
        request(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: 100-Continue\r\nContent-Length: 3\r\n\r\n")
            .unwrap()
            .unwrap();
    assert!(head.expect_continue);
    assert_eq!(
        request_err(b"PUT / HTTP/1.1\r\nHost: a\r\nExpect: something-else\r\n\r\n"),
        ParseError::UnsupportedExpectation
    );
    assert_eq!(
        ParseError::UnsupportedExpectation.status(),
        Some(StatusCode::EXPECTATION_FAILED)
    );
}

#[test]
fn upgrade_needs_connection_upgrade() {
    let head = request(b"GET /ws HTTP/1.1\r\nHost: a\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n")
        .unwrap()
        .unwrap();
    assert!(head.upgrade);
    let head = request(b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n")
        .unwrap()
        .unwrap();
    assert!(!head.upgrade);
}

#[test]
fn error_statuses() {
    assert_eq!(
        ParseError::HeadTooLarge { limit: 1 }.status(),
        Some(StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE)
    );
    assert_eq!(
        ParseError::UnsupportedTransferCoding.status(),
        Some(StatusCode::NOT_IMPLEMENTED)
    );
    assert_eq!(
        ParseError::ConflictingContentLength.status(),
        Some(StatusCode::BAD_REQUEST)
    );
    assert_eq!(ParseError::Incomplete.status(), None);
}

// Responses.

fn response(raw: &[u8], method: &Method) -> http_kit_h1::proto::ResponseHead {
    parse_response_head(&mut BytesMut::from(raw), &limits(), method)
        .unwrap()
        .unwrap()
}

#[test]
fn response_framing() {
    assert_eq!(
        response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            &Method::GET
        )
        .body,
        BodyKind::Length(5)
    );
    assert_eq!(
        response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            &Method::HEAD
        )
        .body,
        BodyKind::Empty
    );
    assert_eq!(
        response(b"HTTP/1.1 204 No Content\r\n\r\n", &Method::GET).body,
        BodyKind::Empty
    );
    assert_eq!(
        response(
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n",
            &Method::GET
        )
        .body,
        BodyKind::Empty
    );
    let close = response(b"HTTP/1.1 200 OK\r\n\r\n", &Method::GET);
    assert_eq!(close.body, BodyKind::CloseDelimited);
    assert!(!close.keep_alive);
    let interim = response(
        b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n",
        &Method::GET,
    );
    assert!(interim.is_interim());
    let switched = response(
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        &Method::GET,
    );
    assert!(switched.upgrade && !switched.is_interim());
    let tunnel = response(b"HTTP/1.1 200 OK\r\n\r\n", &Method::CONNECT);
    assert!(tunnel.upgrade);
    assert_eq!(tunnel.body, BodyKind::Empty);
}

#[test]
fn response_smuggling_is_rejected_too() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
    assert_eq!(
        parse_response_head(&mut BytesMut::from(&raw[..]), &limits(), &Method::GET).map(|_| ()),
        Err(ParseError::ContentLengthWithTransferEncoding)
    );
}

#[test]
fn response_obs_fold_becomes_spaces() {
    let raw =
        format!("HTTP/1.1 200 OK\r\nX-Folded: {CJK}\r\n continued\r\nContent-Length: 0\r\n\r\n");
    let head = response(raw.as_bytes(), &Method::GET);
    let value = head.parts.headers["x-folded"].as_bytes();
    assert!(!value.contains(&b'\r') && !value.contains(&b'\n'));
    assert!(value.starts_with(CJK.as_bytes()) && value.ends_with(b"continued"));
}

// Encoding.

fn request_info(method: Method, version: Version) -> RequestInfo {
    RequestInfo {
        method,
        version,
        keep_alive: true,
        upgrade: false,
    }
}

fn response_parts(
    status: StatusCode,
    fields: &[(&'static str, &'static str)],
) -> http::response::Parts {
    let mut parts = http::Response::new(()).into_parts().0;
    parts.status = status;
    for (name, value) in fields {
        parts.headers.append(*name, HeaderValue::from_static(value));
    }
    parts
}

#[test]
fn chunked_encoding_with_trailers() {
    let mut head = BytesMut::new();
    let mut plan = encode_response_head(
        &request_info(Method::GET, Version::HTTP_11),
        &response_parts(StatusCode::OK, &[]),
        None,
        false,
        None,
        &mut head,
    )
    .unwrap();
    assert_eq!(
        &head[..],
        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n"
    );
    assert_eq!(plan.encoder.framing(), Framing::Chunked);
    assert!(plan.keep_alive);

    let mut out = Vec::new();
    plan.encoder.data(Bytes::from(CJK), &mut out).unwrap();
    plan.encoder.data(Bytes::new(), &mut out).unwrap();
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("0"));
    out.push(plan.encoder.trailers(&trailers).unwrap());
    assert_eq!(plan.encoder.finish().unwrap(), None);

    let wire = out.concat();
    let expected = format!("{:x}\r\n{CJK}\r\n0\r\ngrpc-status: 0\r\n\r\n", CJK.len());
    assert_eq!(wire, expected.as_bytes());
    // The data itself went out as the same allocation, not a copy.
    assert_eq!(out[1].as_ptr(), CJK.as_ptr());

    // And the decoder reads back exactly what the encoder wrote.
    let mut buf = BytesMut::from(&wire[..]);
    let (data, decoded_trailers) = decode_all(BodyKind::Chunked, &mut buf).unwrap();
    assert_eq!(data.concat(), CJK.as_bytes());
    assert_eq!(decoded_trailers.unwrap(), trailers);
}

#[test]
fn content_length_encoding_checks_the_length() {
    let mut head = BytesMut::new();
    let mut plan = encode_response_head(
        &request_info(Method::GET, Version::HTTP_11),
        &response_parts(StatusCode::OK, &[]),
        Some(4),
        false,
        None,
        &mut head,
    )
    .unwrap();
    assert_eq!(&head[..], b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\n");
    let mut out = Vec::new();
    assert!(matches!(
        plan.encoder.data(Bytes::from_static(b"12345"), &mut out),
        Err(Error::ContentLengthMismatch { declared: 4 })
    ));
    let mut short = BodyEncoder::new(Framing::Length(4));
    short.data(Bytes::from_static(b"12"), &mut out).unwrap();
    assert!(matches!(
        short.finish(),
        Err(Error::ContentLengthMismatch { declared: 4 })
    ));
    assert!(matches!(
        BodyEncoder::new(Framing::Length(4)).trailers(&HeaderMap::new()),
        Err(Error::TrailersNotChunked)
    ));
}

#[test]
fn response_head_connection_rules() {
    let encode =
        |info: &RequestInfo, parts: &http::response::Parts, len: Option<u64>, close: bool| {
            let mut head = BytesMut::new();
            let plan = encode_response_head(info, parts, len, close, None, &mut head).unwrap();
            (String::from_utf8(head.to_vec()).unwrap(), plan)
        };
    let ok = response_parts(StatusCode::OK, &[]);

    // HTTP/1.0 with keep-alive and a known length persists and says so.
    let mut info = request_info(Method::GET, Version::HTTP_10);
    let (head, plan) = encode(&info, &ok, Some(2), false);
    assert!(plan.keep_alive);
    assert!(head.contains("connection: keep-alive\r\n"));

    // HTTP/1.0 with an unknown length is close-delimited.
    let (head, plan) = encode(&info, &ok, None, false);
    assert_eq!(plan.encoder.framing(), Framing::CloseDelimited);
    assert!(!plan.keep_alive);
    assert!(head.contains("connection: close\r\n"));
    assert!(!head.contains("transfer-encoding"));

    // A forced close is announced.
    info.version = Version::HTTP_11;
    let (head, plan) = encode(&info, &ok, Some(0), true);
    assert!(!plan.keep_alive && head.contains("connection: close\r\n"));

    // HEAD keeps the length of the body it does not send.
    let head_info = request_info(Method::HEAD, Version::HTTP_11);
    let (head, plan) = encode(&head_info, &ok, Some(42), false);
    assert!(!plan.encoder.sends_body());
    assert!(head.contains("content-length: 42\r\n"));

    // 204 gets no framing at all.
    let (head, plan) = encode(
        &info,
        &response_parts(StatusCode::NO_CONTENT, &[]),
        Some(0),
        false,
    );
    assert!(!plan.encoder.sends_body());
    assert_eq!(head, "HTTP/1.1 204 No Content\r\n\r\n");
}

#[test]
fn response_head_rejects_what_cannot_be_sent() {
    let mut head = BytesMut::new();
    let info = request_info(Method::GET, Version::HTTP_11);
    let parts = response_parts(StatusCode::SWITCHING_PROTOCOLS, &[("upgrade", "websocket")]);
    assert!(matches!(
        encode_response_head(&info, &parts, Some(0), false, None, &mut head),
        Err(Error::UnrequestedUpgrade)
    ));
    let parts = response_parts(StatusCode::CONTINUE, &[]);
    assert!(matches!(
        encode_response_head(&info, &parts, Some(0), false, None, &mut head),
        Err(Error::InformationalResponse(_))
    ));
    let parts = response_parts(StatusCode::OK, &[("content-length", "3")]);
    assert!(matches!(
        encode_response_head(&info, &parts, Some(4), false, None, &mut head),
        Err(Error::ContentLengthMismatch { declared: 3 })
    ));
    let parts = response_parts(StatusCode::OK, &[("transfer-encoding", "gzip")]);
    assert!(matches!(
        encode_response_head(&info, &parts, None, false, None, &mut head),
        Err(Error::OutgoingTransferEncoding)
    ));
}

#[test]
fn request_head_encoding() {
    let request = http::Request::builder()
        .method(Method::POST)
        .uri("http://user:secret@example.com:8080/submit?lang=ko")
        .header(header::EXPECT, "100-continue")
        .body(())
        .unwrap();
    let (parts, ()) = request.into_parts();
    let mut head = BytesMut::new();
    let plan = encode_request_head(
        &parts,
        RequestTarget::Origin,
        Some(CJK.len() as u64),
        &mut head,
    )
    .unwrap();
    let expected = format!(
        "POST /submit?lang=ko HTTP/1.1\r\nhost: example.com:8080\r\nexpect: 100-continue\r\ncontent-length: {}\r\n\r\n",
        CJK.len()
    );
    assert_eq!(&head[..], expected.as_bytes());
    assert!(plan.expect_continue && plan.keep_alive);

    let connect = http::Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let mut head = BytesMut::new();
    let plan = encode_request_head(&connect, RequestTarget::Origin, Some(0), &mut head).unwrap();
    assert_eq!(
        &head[..],
        b"CONNECT example.com:443 HTTP/1.1\r\nhost: example.com:443\r\n\r\n"
    );
    assert!(plan.upgrade);

    let streaming = http::Request::builder()
        .method(Method::PUT)
        .uri("/x")
        .header("host", "a")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let mut head = BytesMut::new();
    let plan = encode_request_head(&streaming, RequestTarget::Origin, None, &mut head).unwrap();
    assert_eq!(plan.encoder.framing(), Framing::Chunked);
    assert_eq!(
        &head[..],
        b"PUT /x HTTP/1.1\r\nhost: a\r\ntransfer-encoding: chunked\r\n\r\n"
    );

    let no_host = http::Request::builder()
        .uri("/x")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    assert!(matches!(
        encode_request_head(
            &no_host,
            RequestTarget::Origin,
            Some(0),
            &mut BytesMut::new()
        ),
        Err(Error::MissingHost)
    ));
}

#[test]
fn absolute_form_request_target() {
    let request = http::Request::builder()
        .method(Method::GET)
        .uri("http://user:secret@example.com:8080/a%20b?lang=ko")
        .body(())
        .unwrap();
    let (parts, ()) = request.into_parts();
    let mut head = BytesMut::new();
    encode_request_head(&parts, RequestTarget::Absolute, Some(0), &mut head).unwrap();
    // The target carries the whole URI without its userinfo.
    assert_eq!(
        &head[..],
        b"GET http://example.com:8080/a%20b?lang=ko HTTP/1.1\r\nhost: example.com:8080\r\n\r\n"
    );

    let bare = http::Request::builder()
        .uri("https://example.com")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let mut head = BytesMut::new();
    encode_request_head(&bare, RequestTarget::Absolute, Some(0), &mut head).unwrap();
    assert!(head.starts_with(b"GET https://example.com/ HTTP/1.1\r\n"));

    // CONNECT keeps its authority-form.
    let connect = http::Request::builder()
        .method(Method::CONNECT)
        .uri("example.com:443")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let mut head = BytesMut::new();
    encode_request_head(&connect, RequestTarget::Absolute, Some(0), &mut head).unwrap();
    assert!(head.starts_with(b"CONNECT example.com:443 HTTP/1.1\r\n"));

    // A URI without a scheme or authority cannot be written absolute.
    for uri in ["/path", "example.com"] {
        let parts = http::Request::builder()
            .uri(uri)
            .header("host", "example.com")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert!(
            matches!(
                encode_request_head(
                    &parts,
                    RequestTarget::Absolute,
                    Some(0),
                    &mut BytesMut::new()
                ),
                Err(Error::AbsoluteTargetIncomplete)
            ),
            "{uri}"
        );
    }
}

#[test]
fn response_with_a_final_coding_other_than_chunked_is_close_delimited() {
    for coding in ["gzip", "chunked, gzip", "GZIP"] {
        let raw = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: {coding}\r\n\r\n");
        let head = response(raw.as_bytes(), &Method::GET);
        assert_eq!(head.body, BodyKind::CloseDelimited, "{coding}");
        assert!(!head.keep_alive, "{coding}");
    }
    // Still no body where the status or method says so.
    let head = response(
        b"HTTP/1.1 204 No Content\r\nTransfer-Encoding: gzip\r\n\r\n",
        &Method::GET,
    );
    assert_eq!(head.body, BodyKind::Empty);
    let head = response(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
        &Method::HEAD,
    );
    assert_eq!(head.body, BodyKind::Empty);
    // The smuggling rules hold: a length next to any coding is refused, and
    // so is a coding that is applied before `chunked`.
    for raw in [
        &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 4\r\n\r\n"[..],
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    ] {
        assert!(parse_response_head(&mut BytesMut::from(raw), &limits(), &Method::GET).is_err());
    }
}

#[test]
fn a_content_length_body_is_a_raw_run_to_its_end() {
    let mut decoder = BodyDecoder::new(BodyKind::Length(10));
    assert_eq!(decoder.raw_run(), Some(10));
    // A caller moved four bytes itself; the decoder carries on after them.
    decoder.consume_raw(4);
    assert_eq!(decoder.raw_run(), Some(6));
    let mut buf = BytesMut::from(&b"abcdef"[..]);
    assert_eq!(
        decoder.decode(&mut buf, &limits()).unwrap(),
        Some(Decoded::Data(Bytes::from_static(b"abcdef")))
    );
    assert!(decoder.is_done());
    assert_eq!(decoder.raw_run(), None);

    let mut decoder = BodyDecoder::new(BodyKind::Length(3));
    decoder.consume_raw(3);
    assert!(decoder.is_done(), "the run was the whole body");
    assert_eq!(
        decoder.decode(&mut BytesMut::new(), &limits()).unwrap(),
        Some(Decoded::End)
    );
}

#[test]
fn a_chunk_is_a_raw_run_between_its_size_line_and_its_crlf() {
    let mut decoder = BodyDecoder::new(BodyKind::Chunked);
    assert_eq!(decoder.raw_run(), None, "a chunk-size line is framing");
    let mut buf = BytesMut::from(&b"a\r\n"[..]);
    assert_eq!(decoder.decode(&mut buf, &limits()).unwrap(), None);
    assert_eq!(decoder.raw_run(), Some(10));
    decoder.consume_raw(7);
    assert_eq!(decoder.raw_run(), Some(3));
    decoder.consume_raw(3);
    assert_eq!(
        decoder.raw_run(),
        None,
        "the CRLF after the data is framing"
    );

    // The framing, the next chunk and the trailers still decode exactly.
    let mut buf = BytesMut::from(&b"\r\n2\r\nxy\r\n0\r\nx-sum: 1\r\n\r\n"[..]);
    let mut data = Vec::new();
    let mut trailers = None;
    loop {
        match decoder.decode(&mut buf, &limits()).unwrap().unwrap() {
            Decoded::Data(chunk) => data.push(chunk),
            Decoded::Trailers(fields) => trailers = Some(fields),
            Decoded::End => break,
        }
    }
    assert_eq!(data, [Bytes::from_static(b"xy")]);
    assert_eq!(trailers.unwrap()["x-sum"], "1");
    assert!(buf.is_empty());
}

#[test]
fn a_close_delimited_body_is_a_raw_run_that_never_ends_by_itself() {
    let mut decoder = BodyDecoder::new(BodyKind::CloseDelimited);
    assert_eq!(decoder.raw_run(), Some(u64::MAX));
    decoder.consume_raw(1 << 20);
    assert_eq!(decoder.raw_run(), Some(u64::MAX));
    assert!(!decoder.is_done());
    assert_eq!(
        decoder.decode_eof(&mut BytesMut::new(), &limits()).unwrap(),
        Decoded::End
    );
}

#[test]
#[should_panic(expected = "consumed past the end of the body")]
fn consuming_past_the_end_of_a_body_is_a_bug() {
    BodyDecoder::new(BodyKind::Length(3)).consume_raw(4);
}

#[test]
fn only_a_body_in_a_raw_run_has_one() {
    assert_eq!(BodyDecoder::new(BodyKind::Empty).raw_run(), None);
    assert_eq!(BodyDecoder::new(BodyKind::Length(0)).raw_run(), None);
}
