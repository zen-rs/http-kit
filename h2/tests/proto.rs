//! Comprehensive sans-IO conformance tests for `ProtoConn` covering RFC 9113
//! §3–§8, RFC 8441 Extended `CONNECT`, flow control, smuggling defenses, and
//! `CONTINUATION` / Rapid Reset flood limits.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Method, StatusCode, Version};
use http_kit_h2::{
    ClientConfig, Error, Malformed, Protocol, Reason, ServerConfig, StreamId, Timeout,
    frame::{self, FrameHeader, kind},
    hpack::{EncodeField, Encoder},
    proto::{ClientSide, PendingData, ProtoConn, ProtoEvent, ServerSide},
};

fn pump_control<S: http_kit_h2::proto::Side>(conn: &mut ProtoConn<S>, wire: &mut BytesMut) {
    let mut chunks = Vec::new();
    conn.drain_control(&mut chunks);
    for c in chunks {
        wire.extend_from_slice(&c);
    }
}

fn handshake_pair(
    client_cfg: &ClientConfig,
    server_cfg: &ServerConfig,
    now: Instant,
) -> (
    ProtoConn<ClientSide>,
    ProtoConn<ServerSide>,
    BytesMut,
    BytesMut,
) {
    let mut client = ProtoConn::new_client(client_cfg, now);
    let mut server = ProtoConn::new_server(server_cfg, now);
    let mut c2s = BytesMut::new();
    let mut s2c = BytesMut::new();

    pump_control(&mut client, &mut c2s);
    pump_control(&mut server, &mut s2c);

    assert!(matches!(
        server.poll_recv(&mut c2s, now).unwrap(),
        Some(ProtoEvent::PrefaceComplete)
    ));
    assert!(server.is_handshake_complete());

    assert!(matches!(
        client.poll_recv(&mut s2c, now).unwrap(),
        Some(ProtoEvent::PrefaceComplete)
    ));
    // Drain SendWindowAvailable if server's initial window > 65535
    while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    while server.poll_recv(&mut c2s, now).unwrap().is_some() {}

    // Exchange SETTINGS ACKs
    pump_control(&mut server, &mut s2c);
    pump_control(&mut client, &mut c2s);
    while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    while server.poll_recv(&mut c2s, now).unwrap().is_some() {}
    assert!(client.is_handshake_complete());

    (client, server, c2s, s2c)
}

fn assert_last_goaway_reason(control_wire: &[u8], expected: Reason) {
    let mut pos = 0usize;
    let mut found = None;
    while pos + 9 <= control_wire.len() {
        let hdr = FrameHeader::decode(control_wire[pos..pos + 9].try_into().unwrap());
        pos += 9;
        let end = pos + hdr.length as usize;
        if end > control_wire.len() {
            break;
        }
        if hdr.kind == kind::GOAWAY && hdr.length >= 8 {
            let code = u32::from_be_bytes(control_wire[pos + 4..pos + 8].try_into().unwrap());
            found = Some(Reason::from_code(code));
        }
        pos = end;
    }
    assert_eq!(found, Some(expected), "expected GOAWAY({expected}) on wire");
}

#[test]
fn multiplexed_cjk_post_trailers_head_and_informational_responses() {
    let now = Instant::now();
    let (mut client, mut server, mut c2s, mut s2c) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);

    // Stream 1: POST with CJK headers, CJK body, and trailers.
    let cjk_body = "中文请求体 / 日本語リクエストボディ / 한국어 요청 본문".repeat(32);
    let req1 = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/upload?lang=cjk")
        .header(
            "x-cjk-meta",
            HeaderValue::from_bytes("你好・こんにちは・안녕하세요".as_bytes()).unwrap(),
        )
        .header("te", "trailers")
        .header("cookie", "a=1")
        .header("cookie", "b=2")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let s1 = client
        .open_request(&req1, Some(cjk_body.len() as u64), false)
        .unwrap();
    assert_eq!(s1.get(), 1);

    // Stream 3: HEAD request whose response carries `Content-Length: 99999` + `END_STREAM`.
    let req3 = http::Request::builder()
        .method(Method::HEAD)
        .uri("https://example.com/resource")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let s3 = client.open_request(&req3, None, true).unwrap();
    assert_eq!(s3.get(), 3);

    let mut out_vecs = Vec::new();
    let mut body_bytes = Bytes::from(cjk_body.clone().into_bytes());
    assert!(
        client
            .encode_data(s1, &mut body_bytes, false, &mut out_vecs)
            .unwrap()
    );
    let mut req_trailers = HeaderMap::new();
    req_trailers.insert("x-checksum", HeaderValue::from_static("sha256-ok"));
    client.send_trailers(s1, &req_trailers).unwrap();
    client.drain_control(&mut out_vecs);
    for v in out_vecs.drain(..) {
        c2s.extend_from_slice(&v);
    }

    // Server receives Stream 1 Request, Stream 3 HEAD Request, Stream 1 Data, Stream 1 Trailers.
    let mut seen_req1 = false;
    let mut seen_req3 = false;
    let mut recv_body1 = Vec::new();
    let mut seen_trailers1 = None;

    while let Some(ev) = server.poll_recv(&mut c2s, now).unwrap() {
        match ev {
            ProtoEvent::Request {
                stream_id,
                parts,
                end_stream,
                content_length,
            } if stream_id == s1 => {
                seen_req1 = true;
                assert!(!end_stream);
                assert_eq!(content_length, Some(cjk_body.len() as u64));
                assert_eq!(parts.version, Version::HTTP_2);
                assert_eq!(parts.headers["cookie"], "a=1; b=2");
                assert_eq!(
                    parts.headers["x-cjk-meta"].as_bytes(),
                    "你好・こんにちは・안녕하세요".as_bytes()
                );
            }
            ProtoEvent::Request {
                stream_id,
                end_stream,
                ..
            } if stream_id == s3 => {
                seen_req3 = true;
                assert!(end_stream);
            }
            ProtoEvent::Data {
                stream_id,
                data,
                end_stream,
            } if stream_id == s1 => {
                assert!(!end_stream);
                server.release_recv_capacity(s1, data.len());
                recv_body1.extend_from_slice(&data);
            }
            ProtoEvent::Trailers {
                stream_id,
                trailers,
            } if stream_id == s1 => {
                seen_trailers1 = Some(trailers);
            }
            other => panic!("unexpected server event: {other:?}"),
        }
    }
    assert!(seen_req1 && seen_req3);
    assert_eq!(recv_body1, cjk_body.as_bytes());
    assert_eq!(seen_trailers1.unwrap()["x-checksum"], "sha256-ok");

    // Server sends 103 Early Hints + 200 OK + body + trailers on Stream 1, and
    // 200 OK with Content-Length: 99999 + END_STREAM on Stream 3 (`HEAD`).
    let early = http::Response::builder()
        .status(StatusCode::EARLY_HINTS)
        .header("link", "</app.css>; rel=preload")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    server.send_informational(s1, &early).unwrap();

    let resp3 = http::Response::builder()
        .status(StatusCode::OK)
        .header("content-length", "99999")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    server.send_response(s3, &resp3, None, true, None).unwrap();

    let resp1 = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let date = HeaderValue::from_static("Wed, 18 Nov 2026 05:00:00 GMT");
    server
        .send_response(s1, &resp1, Some(cjk_body.len() as u64), false, Some(&date))
        .unwrap();

    let mut resp_body = Bytes::from(cjk_body.clone().into_bytes());
    assert!(
        server
            .encode_data(s1, &mut resp_body, false, &mut out_vecs)
            .unwrap()
    );
    let mut resp_trailers = HeaderMap::new();
    resp_trailers.insert("x-server-done", HeaderValue::from_static("1"));
    server.send_trailers(s1, &resp_trailers).unwrap();
    server.drain_control(&mut out_vecs);
    for v in out_vecs.drain(..) {
        s2c.extend_from_slice(&v);
    }
    assert_eq!(server.active_stream_count(), 0);

    let mut got_103 = false;
    let mut got_resp3 = false;
    let mut got_resp1 = false;
    let mut client_body1 = Vec::new();
    let mut got_resp_trailers = false;

    while let Some(ev) = client.poll_recv(&mut s2c, now).unwrap() {
        match ev {
            ProtoEvent::InformationalResponse { stream_id, parts } if stream_id == s1 => {
                assert_eq!(parts.status, StatusCode::EARLY_HINTS);
                got_103 = true;
            }
            ProtoEvent::Response {
                stream_id,
                parts,
                end_stream,
                content_length,
            } if stream_id == s3 => {
                assert_eq!(parts.status, StatusCode::OK);
                assert!(end_stream);
                assert_eq!(content_length, None);
                got_resp3 = true;
            }
            ProtoEvent::Response {
                stream_id,
                parts,
                end_stream,
                content_length,
            } if stream_id == s1 => {
                assert_eq!(parts.status, StatusCode::OK);
                assert_eq!(parts.headers["date"], date);
                assert!(!end_stream);
                assert_eq!(content_length, Some(cjk_body.len() as u64));
                got_resp1 = true;
            }
            ProtoEvent::Data {
                stream_id,
                data,
                end_stream,
            } if stream_id == s1 => {
                assert!(!end_stream);
                client.release_recv_capacity(s1, data.len());
                client_body1.extend_from_slice(&data);
            }
            ProtoEvent::Trailers {
                stream_id,
                trailers,
            } if stream_id == s1 => {
                assert_eq!(trailers["x-server-done"], "1");
                got_resp_trailers = true;
            }
            ProtoEvent::SendWindowAvailable { .. } => {}
            other => panic!("unexpected client event: {other:?}"),
        }
    }

    assert!(got_103 && got_resp3 && got_resp1 && got_resp_trailers);
    assert_eq!(client_body1, cjk_body.as_bytes());
    assert_eq!(client.active_stream_count(), 0);
}

#[test]
fn rejects_invalid_preface_and_oversized_frames_immediately() {
    let now = Instant::now();
    let mut server = ProtoConn::new_server(&ServerConfig::default(), now);
    let mut bad = BytesMut::from(&b"GET / HTTP/1.1\r\n\r\n"[..]);
    let err = server.poll_recv(&mut bad, now).unwrap_err();
    assert!(matches!(
        err,
        Error::Protocol {
            reason: Reason::PROTOCOL_ERROR,
            ..
        }
    ));
    let mut out = BytesMut::new();
    pump_control(&mut server, &mut out);
    assert_last_goaway_reason(&out, Reason::PROTOCOL_ERROR);

    // Valid 24-byte magic followed by PING instead of SETTINGS -> PROTOCOL_ERROR
    let mut server2 = ProtoConn::new_server(&ServerConfig::default(), now);
    let mut non_settings = BytesMut::from(&frame::CLIENT_PREFACE[..]);
    frame::encode_ping(false, [0; 8], &mut non_settings);
    let err2 = server2.poll_recv(&mut non_settings, now).unwrap_err();
    assert!(matches!(
        err2,
        Error::Protocol {
            reason: Reason::PROTOCOL_ERROR,
            ..
        }
    ));

    // Oversized frame header (`16_385 > 16_384`) rejected immediately with just 9 bytes!
    let (_, mut server3, _, _) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);
    let mut oversize = BytesMut::from(
        &FrameHeader {
            length: 16_385,
            kind: kind::DATA,
            flags: 0,
            stream_id: StreamId::new(1).unwrap(),
        }
        .encode()[..],
    );
    let err3 = server3.poll_recv(&mut oversize, now).unwrap_err();
    assert!(matches!(
        err3,
        Error::Protocol {
            reason: Reason::FRAME_SIZE_ERROR,
            ..
        }
    ));
    out.clear();
    pump_control(&mut server3, &mut out);
    assert_last_goaway_reason(&out, Reason::FRAME_SIZE_ERROR);
}

#[test]
fn stream_states_priority_idle_monotonicity_and_self_dependency() {
    let now = Instant::now();
    let mut srv_cfg = ServerConfig::default();
    srv_cfg.limits.max_concurrent_streams = Some(1);
    let (_, mut server, _, _) = handshake_pair(&ClientConfig::default(), &srv_cfg, now);

    // 1. PRIORITY on idle stream 9 MUST NOT advance `max_peer_stream_id`, so
    //    subsequent HEADERS on stream 5 still succeeds (h2spec Generic 3.3.5)!
    let mut wire = BytesMut::new();
    wire.extend_from_slice(
        &FrameHeader {
            length: 5,
            kind: kind::PRIORITY,
            flags: 0,
            stream_id: StreamId::new(9).unwrap(),
        }
        .encode(),
    );
    wire.extend_from_slice(&[0, 0, 0, 0, 16]);

    let mut enc = Encoder::default();
    let mut block = BytesMut::new();
    enc.encode(
        [
            EncodeField::new(b":method", b"GET"),
            EncodeField::new(b":scheme", b"https"),
            EncodeField::new(b":authority", b"example.com"),
            EncodeField::new(b":path", b"/"),
        ],
        &mut block,
    );
    let valid_get = block.split().freeze();
    frame::encode_header_block(
        StreamId::new(5).unwrap(),
        valid_get,
        false,
        16_384,
        &mut wire,
    );

    let ev = server.poll_recv(&mut wire, now).unwrap();
    assert!(matches!(
        ev,
        Some(ProtoEvent::Request { stream_id, .. }) if stream_id.get() == 5
    ));

    // Self-dependent PRIORITY on implicitly closed stream 3 (`< 5`) -> stream error
    // `RST_STREAM(PROTOCOL_ERROR)` without terminating the connection; whereas on an
    // idle stream RFC 9113 §6.4 forbids `RST_STREAM` and escalates to `GOAWAY(PROTOCOL_ERROR)`.
    wire.extend_from_slice(
        &FrameHeader {
            length: 5,
            kind: kind::PRIORITY,
            flags: 0,
            stream_id: StreamId::new(3).unwrap(),
        }
        .encode(),
    );
    wire.extend_from_slice(&[0x80, 0, 0, 3, 16]);
    assert!(server.poll_recv(&mut wire, now).unwrap().is_none());

    // 2. MAX_CONCURRENT_STREAMS = 1: opening stream 7 while stream 5 is open
    //    rejects stream 7 with `RST_STREAM(REFUSED_STREAM)` while preserving
    //    the HPACK dynamic table entry inserted on stream 7!
    enc.encode(
        [
            EncodeField::new(b":method", b"GET"),
            EncodeField::new(b":scheme", b"https"),
            EncodeField::new(b":authority", b"example.com"),
            EncodeField::new(b":path", b"/"),
            EncodeField::new(b"x-indexed-on-refused", b"preserved"),
        ],
        &mut block,
    );
    frame::encode_header_block(
        StreamId::new(7).unwrap(),
        block.split().freeze(),
        true,
        16_384,
        &mut wire,
    );
    assert!(server.poll_recv(&mut wire, now).unwrap().is_none());

    // Finish stream 5 (`END_STREAM` from client + 200 OK from server), then open
    // stream 9 referencing `x-indexed-on-refused` from the dynamic table!
    wire.extend_from_slice(&frame::encode_data_header(
        StreamId::new(5).unwrap(),
        0,
        true,
    ));
    assert!(matches!(
        server.poll_recv(&mut wire, now).unwrap(),
        Some(ProtoEvent::Data {
            end_stream: true,
            ..
        })
    ));
    let resp = http::Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    server
        .send_response(StreamId::new(5).unwrap(), &resp, None, true, None)
        .unwrap();

    enc.encode(
        [
            EncodeField::new(b":method", b"GET"),
            EncodeField::new(b":scheme", b"https"),
            EncodeField::new(b":authority", b"example.com"),
            EncodeField::new(b":path", b"/"),
            EncodeField::new(b"x-indexed-on-refused", b"preserved"),
        ],
        &mut block,
    );
    frame::encode_header_block(
        StreamId::new(9).unwrap(),
        block.split().freeze(),
        true,
        16_384,
        &mut wire,
    );
    let Some(ProtoEvent::Request { parts, .. }) = server.poll_recv(&mut wire, now).unwrap() else {
        panic!("expected Request on stream 9");
    };
    assert_eq!(parts.headers["x-indexed-on-refused"], "preserved");

    // 3. Sending HEADERS on already-closed stream 5 -> connection error `STREAM_CLOSED` (5.1.12)!
    enc.encode(
        [
            EncodeField::new(b":method", b"GET"),
            EncodeField::new(b":scheme", b"https"),
            EncodeField::new(b":path", b"/"),
        ],
        &mut block,
    );
    frame::encode_header_block(
        StreamId::new(5).unwrap(),
        block.split().freeze(),
        true,
        16_384,
        &mut wire,
    );
    let err = server.poll_recv(&mut wire, now).unwrap_err();
    assert!(matches!(
        err,
        Error::Protocol {
            reason: Reason::STREAM_CLOSED,
            ..
        }
    ));
}

#[test]
fn flow_control_negative_window_overflow_and_external_splice_data() {
    let now = Instant::now();
    let (mut client, mut server, mut c2s, mut s2c) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);

    // Client opens a streaming POST on stream 1.
    let req = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/stream")
        .header("content-length", "10")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let s1 = client.open_request(&req, Some(10), false).unwrap();
    pump_control(&mut client, &mut c2s);

    // Server shrinks `SETTINGS_INITIAL_WINDOW_SIZE` to `4` -> stream 1 send window becomes `4`!
    let mut shrink = BytesMut::new();
    frame::encode_settings(&[(frame::setting_id::INITIAL_WINDOW_SIZE, 4)], &mut shrink);
    s2c.extend_from_slice(&shrink);
    while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    client.drain_control(&mut Vec::new());
    assert_eq!(client.send_window(s1), 4);

    // Client tries to encode 10 bytes: only 4 bytes are emitted, 6 remain!
    let mut data = Bytes::from_static(b"0123456789");
    let mut out = Vec::new();
    assert!(!client.encode_data(s1, &mut data, true, &mut out).unwrap());
    assert_eq!(data.len(), 6);
    assert_eq!(client.send_window(s1), 0);

    // Server shrinks `SETTINGS_INITIAL_WINDOW_SIZE` to `0` -> stream 1 send window becomes `-4`!
    shrink.clear();
    frame::encode_settings(&[(frame::setting_id::INITIAL_WINDOW_SIZE, 0)], &mut shrink);
    s2c.extend_from_slice(&shrink);
    while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    client.drain_control(&mut Vec::new());
    assert_eq!(client.send_window(s1), 0);

    // Granting `WINDOW_UPDATE(s1, 3)` raises `-4` to `-1` (still blocked);
    // another `WINDOW_UPDATE(s1, 7)` raises `-1` to `+6` -> unblocks!
    shrink.clear();
    frame::encode_window_update(s1, 3, &mut shrink);
    s2c.extend_from_slice(&shrink);
    while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    assert_eq!(client.send_window(s1), 0);

    shrink.clear();
    frame::encode_window_update(s1, 7, &mut shrink);
    s2c.extend_from_slice(&shrink);
    while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    assert_eq!(client.send_window(s1), 6);

    // Send remaining 6 bytes via `prepare_raw_data` (simulating `SendFile` / `SpliceWrite`).
    let reserved = client.prepare_raw_data(s1, 6, true, &mut out).unwrap();
    assert_eq!(reserved, 6);
    out.push(data.split_to(6));
    for chunk in out.drain(..) {
        c2s.extend_from_slice(&chunk);
    }

    // Feed ONLY up to the second `DATA` frame's 9-byte header so we test
    // `pending_data_run()` + `consume_external_data()`!
    let tail_payload = c2s.split_off(c2s.len() - 6);
    assert_eq!(&tail_payload[..], b"456789");
    let mut first_part = Vec::new();
    while let Some(ev) = server.poll_recv(&mut c2s, now).unwrap() {
        if let ProtoEvent::Data { data, .. } = ev {
            first_part.extend_from_slice(&data);
        }
    }
    assert_eq!(first_part, b"0123");
    assert_eq!(
        server.pending_data_run(),
        Some(PendingData {
            stream_id: s1,
            remaining: 6
        })
    );
    assert!(!server.consume_external_data(2).unwrap());
    assert_eq!(server.pending_data_run().unwrap().remaining, 4);
    assert!(server.consume_external_data(4).unwrap());
    assert!(server.pending_data_run().is_none());

    // Overflowing connection `WINDOW_UPDATE` past 2^31 - 1 -> `FLOW_CONTROL_ERROR`!
    let mut bad_wu = BytesMut::new();
    frame::encode_window_update(StreamId::CONNECTION, 0x7FFF_FFFF, &mut bad_wu);
    let err = server.poll_recv(&mut bad_wu, now).unwrap_err();
    assert!(matches!(
        err,
        Error::Protocol {
            reason: Reason::FLOW_CONTROL_ERROR,
            ..
        }
    ));
}

#[test]
fn extended_connect_continuation_cap_rapid_reset_and_graceful_goaway() {
    let now = Instant::now();
    let mut srv_cfg = ServerConfig::default();
    srv_cfg.limits.max_continuation_frames = 3;
    srv_cfg.limits.max_rst_streams_per_window = 3;
    let (mut client, mut server, mut c2s, mut s2c) =
        handshake_pair(&ClientConfig::default(), &srv_cfg, now);

    assert!(client.can_send_extended_connect());

    // 1. Extended CONNECT (`:protocol = websocket`)
    let mut ws_req = http::Request::builder()
        .method(Method::CONNECT)
        .uri("https://example.com/ws")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    ws_req.extensions.insert(Protocol::from_static("websocket"));
    let ws_id = client.open_request(&ws_req, None, false).unwrap();

    // Open a second request (stream 3) BEFORE server's graceful shutdown lands!
    let req3 = http::Request::builder()
        .method(Method::GET)
        .uri("https://example.com/later")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let s3 = client.open_request(&req3, None, true).unwrap();

    // Deliver ONLY stream 1 to server first, then initiate two-phase graceful shutdown!
    pump_control(&mut client, &mut c2s);
    // Split out stream 3's HEADERS frame from the back of `c2s` so server only sees stream 1 before shutdown.
    let mut pos = 0usize;
    let mut s3_offset = None;
    while pos + 9 <= c2s.len() {
        let hdr = FrameHeader::decode(c2s[pos..pos + 9].try_into().unwrap());
        if hdr.kind == kind::HEADERS && hdr.stream_id == s3 {
            s3_offset = Some(pos);
            break;
        }
        pos += 9 + hdr.length as usize;
    }
    let delayed_s3 = c2s.split_off(s3_offset.unwrap());

    let Some(ProtoEvent::Request {
        stream_id, parts, ..
    }) = server.poll_recv(&mut c2s, now).unwrap()
    else {
        panic!("expected Extended CONNECT request");
    };
    assert_eq!(stream_id, ws_id);
    assert_eq!(
        parts.extensions.get::<Protocol>(),
        Some(&Protocol::from_static("websocket"))
    );

    // Server starts graceful shutdown -> sends `GOAWAY(2^31 - 1)` + `PING`.
    server.initiate_graceful_shutdown(now);
    assert!(!server.is_gracefully_drained());
    pump_control(&mut server, &mut s2c);

    // Client receives `GOAWAY(2^31 - 1)` + `PING` and queues `PING ACK`.
    while let Some(ev) = client.poll_recv(&mut s2c, now).unwrap() {
        if let ProtoEvent::GoAway {
            last_stream_id,
            rejected_streams,
            ..
        } = ev
        {
            assert_eq!(last_stream_id, StreamId::MAX);
            assert!(rejected_streams.is_empty());
        }
    }
    pump_control(&mut client, &mut c2s);

    // Server receives `PING ACK` BEFORE `delayed_s3` -> enters Phase 2 `GOAWAY(last_stream_id = 1)`!
    while server.poll_recv(&mut c2s, now).unwrap().is_some() {}
    // Now `delayed_s3` arrives after Phase 2 -> server refuses stream 3 with `REFUSED_STREAM`,
    // and client receives Phase 2 `GOAWAY(last_stream_id = 1)` listing `s3` in `rejected_streams`!
    c2s.extend_from_slice(&delayed_s3);
    while server.poll_recv(&mut c2s, now).unwrap().is_some() {}
    pump_control(&mut server, &mut s2c);

    let mut saw_rejected_s3 = false;
    while let Some(ev) = client.poll_recv(&mut s2c, now).unwrap() {
        match ev {
            ProtoEvent::GoAway {
                last_stream_id,
                rejected_streams,
                ..
            } if last_stream_id == ws_id => {
                if rejected_streams.contains(&s3) {
                    saw_rejected_s3 = true;
                }
            }
            ProtoEvent::StreamReset {
                stream_id,
                reason: Reason::REFUSED_STREAM,
            } if stream_id == s3 => {
                saw_rejected_s3 = true;
            }
            _ => {}
        }
    }
    assert!(saw_rejected_s3);

    // Finish stream 1 on both sides -> server `is_gracefully_drained()` becomes true!
    let mut empty = Bytes::new();
    let mut v = Vec::new();
    client.encode_data(ws_id, &mut empty, true, &mut v).unwrap();
    for b in v.drain(..) {
        c2s.extend_from_slice(&b);
    }
    while server.poll_recv(&mut c2s, now).unwrap().is_some() {}
    let ok_resp = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    server
        .send_response(ws_id, &ok_resp, None, true, None)
        .unwrap();
    assert!(server.is_gracefully_drained());

    // 2. CONTINUATION flood (`> 3` CONTINUATION frames) -> `ENHANCE_YOUR_CALM`!
    let (_, mut cont_srv, _, _) = handshake_pair(&ClientConfig::default(), &srv_cfg, now);
    let mut flood = BytesMut::new();
    flood.extend_from_slice(
        &FrameHeader {
            length: 1,
            kind: kind::HEADERS,
            flags: 0,
            stream_id: StreamId::new(1).unwrap(),
        }
        .encode(),
    );
    flood.extend_from_slice(&[0x82]);
    for _ in 0..4 {
        flood.extend_from_slice(
            &FrameHeader {
                length: 1,
                kind: kind::CONTINUATION,
                flags: 0,
                stream_id: StreamId::new(1).unwrap(),
            }
            .encode(),
        );
        flood.extend_from_slice(&[0x86]);
    }
    let err = cont_srv.poll_recv(&mut flood, now).unwrap_err();
    assert!(matches!(
        err,
        Error::Protocol {
            reason: Reason::ENHANCE_YOUR_CALM,
            ..
        }
    ));

    // 3. Rapid Reset (`> 3` RST_STREAMs on incomplete streams in window) -> `ENHANCE_YOUR_CALM`!
    let (_, mut rst_srv, _, _) = handshake_pair(&ClientConfig::default(), &srv_cfg, now);
    let mut rst_wire = BytesMut::new();
    let mut enc = Encoder::default();
    let mut blk = BytesMut::new();
    for i in 0..4u32 {
        let sid = StreamId::new(1 + i * 2).unwrap();
        enc.encode(
            [
                EncodeField::new(b":method", b"GET"),
                EncodeField::new(b":scheme", b"https"),
                EncodeField::new(b":authority", b"example.com"),
                EncodeField::new(b":path", b"/"),
            ],
            &mut blk,
        );
        frame::encode_header_block(sid, blk.split().freeze(), true, 16_384, &mut rst_wire);
        frame::encode_rst_stream(sid, Reason::CANCEL, &mut rst_wire);
    }
    let mut rapid_err = None;
    loop {
        match rst_srv.poll_recv(&mut rst_wire, now) {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                rapid_err = Some(e);
                break;
            }
        }
    }
    assert!(matches!(
        rapid_err,
        Some(Error::Protocol {
            reason: Reason::ENHANCE_YOUR_CALM,
            ..
        })
    ));
}

#[test]
fn smuggling_defenses_and_timeouts() {
    let now = Instant::now();

    // Handshake timeout before initial SETTINGS arrives -> `Timeout::Handshake`
    let mut srv_cfg = ServerConfig::default();
    srv_cfg.handshake_timeout = Some(Duration::from_secs(5));
    let mut srv = ProtoConn::new_server(&srv_cfg, now);
    assert_eq!(srv.next_deadline(), Some(now + Duration::from_secs(5)));
    let err = srv.poll_timeout(now + Duration::from_secs(5)).unwrap_err();
    assert!(matches!(err, Error::Timeout(Timeout::Handshake)));

    // Smuggling cases on an open connection: each rejected with `RST_STREAM(PROTOCOL_ERROR)`
    // while keeping the connection alive!
    let (_, mut server, _, _) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);
    let bad_requests: &[&[(&[u8], &[u8])]] = &[
        // Uppercase header name
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b"X-Upper", b"1"),
        ],
        // Transfer-Encoding forbidden
        &[
            (b":method", b"POST"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b"transfer-encoding", b"chunked"),
        ],
        // TE other than "trailers"
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b"te", b"trailers, deflate"),
        ],
        // Conflicting `:authority` and `host`
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"good.example.com"),
            (b":path", b"/"),
            (b"host", b"evil.example.com"),
        ],
        // Deprecated userinfo `@` in `:authority`
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"user@example.com"),
            (b":path", b"/"),
        ],
        // CRLF injection in header value
        &[
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.com"),
            (b":path", b"/"),
            (b"x-injected", b"ok\r\nevil: 1"),
        ],
    ];

    let mut enc = Encoder::default();
    let mut blk = BytesMut::new();
    let mut wire = BytesMut::new();
    for (i, fields) in bad_requests.iter().enumerate() {
        let sid = StreamId::new(1 + (i as u32) * 2).unwrap();
        enc.encode(
            fields.iter().map(|&(k, v)| EncodeField::new(k, v)),
            &mut blk,
        );
        frame::encode_header_block(sid, blk.split().freeze(), true, 16_384, &mut wire);
        assert!(
            server.poll_recv(&mut wire, now).unwrap().is_none(),
            "bad request #{i} must not emit ProtoEvent::Request"
        );
    }

    // Connection is STILL healthy and accepts the next valid request!
    let next_sid = StreamId::new(1 + (bad_requests.len() as u32) * 2).unwrap();
    enc.encode(
        [
            EncodeField::new(b":method", b"GET"),
            EncodeField::new(b":scheme", b"https"),
            EncodeField::new(b":authority", b"example.com"),
            EncodeField::new(b":path", b"/healthy"),
        ],
        &mut blk,
    );
    frame::encode_header_block(next_sid, blk.split().freeze(), true, 16_384, &mut wire);
    let Some(ProtoEvent::Request { parts, .. }) = server.poll_recv(&mut wire, now).unwrap() else {
        panic!("expected healthy request after stream-level rejections");
    };
    assert_eq!(parts.uri.path(), "/healthy");
}

#[test]
fn consume_external_data_content_length_mismatch_emits_stream_error() {
    let now = Instant::now();
    let (mut client, mut server, mut c2s, _) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);

    let req = http::Request::builder()
        .method(Method::POST)
        .uri("https://example.com/mismatch")
        .header("content-length", "10")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let s1 = client.open_request(&req, Some(10), false).unwrap();
    pump_control(&mut client, &mut c2s);
    assert!(matches!(
        server.poll_recv(&mut c2s, now).unwrap(),
        Some(ProtoEvent::Request { .. })
    ));

    // Peer sends a 4-byte `DATA(END_STREAM)` when `Content-Length: 10` was declared!
    c2s.extend_from_slice(&frame::encode_data_header(s1, 4, true));
    c2s.extend_from_slice(b"short".split_at(4).0);
    let Some(ProtoEvent::StreamError { stream_id, error }) =
        server.poll_recv(&mut c2s, now).unwrap()
    else {
        panic!("expected StreamError on Content-Length mismatch");
    };
    assert_eq!(stream_id, s1);
    assert!(matches!(
        error,
        Error::Malformed(Malformed::ContentLengthMismatch)
    ));

    // Releasing capacity for `s1` after it was reset still replenishes the
    // connection receive window cleanly without panicking or emitting stream WU!
    server.release_recv_capacity(s1, 6 * 1024 * 1024);
    assert!(server.has_pending_send());
}

#[test]
fn idle_zero_window_update_sends_goaway_without_rst_and_evicted_closed_streams_ignore_late_frames()
{
    let now = Instant::now();

    // 1. `WINDOW_UPDATE(increment = 0)` on an idle stream MUST fail the connection
    // with `GOAWAY(PROTOCOL_ERROR)` and MUST NOT emit `RST_STREAM` (RFC 9113 §5.1, §6.4).
    let (_, mut server, _, _) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);
    let mut bad_wu = BytesMut::new();
    bad_wu.extend_from_slice(
        &FrameHeader {
            length: 4,
            kind: kind::WINDOW_UPDATE,
            flags: 0,
            stream_id: StreamId::new(9).unwrap(),
        }
        .encode(),
    );
    bad_wu.extend_from_slice(&0u32.to_be_bytes());
    let err = server.poll_recv(&mut bad_wu, now).unwrap_err();
    assert!(matches!(
        err,
        Error::Protocol {
            reason: Reason::PROTOCOL_ERROR,
            ..
        }
    ));
    let mut out = Vec::new();
    server.drain_control(&mut out);
    let mut out_bytes = BytesMut::new();
    for chunk in out {
        out_bytes.extend_from_slice(&chunk);
    }
    let mut saw_goaway = false;
    while out_bytes.len() >= 9 {
        let hdr = FrameHeader::decode(out_bytes[..9].try_into().unwrap());
        let _ = out_bytes.split_to(9 + hdr.length as usize);
        assert_ne!(
            hdr.kind,
            kind::RST_STREAM,
            "idle stream error must never emit RST_STREAM"
        );
        if hdr.kind == kind::GOAWAY {
            saw_goaway = true;
        }
    }
    assert!(saw_goaway, "expected GOAWAY(PROTOCOL_ERROR)");

    // 2. Open and close 300 streams (`> STREAM_HISTORY_CAP = 256`), then send
    // late `WINDOW_UPDATE` and `RST_STREAM` on stream 1 (evicted from ring);
    // both must be ignored cleanly per RFC 9113 §5.1.1.
    let (mut client, mut srv, mut c2s, mut s2c) =
        handshake_pair(&ClientConfig::default(), &ServerConfig::default(), now);
    let get_parts = http::Request::builder()
        .method(Method::GET)
        .uri("https://example.com/")
        .body(())
        .unwrap()
        .into_parts()
        .0;
    let ok_parts = http::Response::builder()
        .status(StatusCode::OK)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    for _ in 0..300 {
        let sid = client.open_request(&get_parts, None, true).unwrap();
        pump_control(&mut client, &mut c2s);
        while srv.poll_recv(&mut c2s, now).unwrap().is_some() {}
        srv.send_response(sid, &ok_parts, None, true, None).unwrap();
        pump_control(&mut srv, &mut s2c);
        while client.poll_recv(&mut s2c, now).unwrap().is_some() {}
    }

    let s1 = StreamId::new(1).unwrap();
    let mut late = BytesMut::new();
    frame::encode_window_update(s1, 1024, &mut late);
    frame::encode_rst_stream(s1, Reason::NO_ERROR, &mut late);
    let mut late_for_client = late.clone();
    assert!(srv.poll_recv(&mut late, now).unwrap().is_none());
    assert!(
        client
            .poll_recv(&mut late_for_client, now)
            .unwrap()
            .is_none()
    );
}
