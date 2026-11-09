//! The client driver over an in-memory socket, against this crate's server
//! and against scripted peers.

mod support;

use std::cell::Cell;

use bytes::Bytes;
use futures_lite::{StreamExt as _, future::block_on, future::zip, stream};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use http_kit::{Body, BodyFrame, Request, Response};
use http_kit_h1::{
    ClientConfig, ClientOutcome, Error, SendRequest, ServerConfig, ServerConnection, handshake,
};
use support::{CJK, connection, within_reads};

fn request(method: Method, uri: &str, body: Body) -> Request {
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = uri.parse().unwrap();
    request
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn send_request_is_send_and_sync() {
    fn assert<T: Send + Sync + Clone>() {}
    assert::<SendRequest>();
}

#[test]
fn streaming_round_trip_with_trailers_and_keep_alive() {
    block_on(async {
        let ends = connection();
        let (server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let calls = Cell::new(0);
        // Echoes the request body and trailers back, chunked.
        let service = |request: Request| {
            calls.set(calls.get() + 1);
            async move {
                let mut body = request.into_body();
                let mut frames = Vec::new();
                while let Some(frame) = body.next().await {
                    frames.push(Ok::<_, std::io::Error>(frame.unwrap()));
                }
                Response::new(Body::from_frames(stream::iter(frames)))
            }
        };
        let server =
            ServerConnection::new(server_in, server_out, ServerConfig::default()).serve(&service);
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());

        let client = async move {
            for round in 0..2 {
                let mut trailers = HeaderMap::new();
                trailers.insert(
                    "x-round",
                    HeaderValue::from_str(&round.to_string()).unwrap(),
                );
                let body = Body::from_frames(stream::iter([
                    Ok::<_, std::io::Error>(BodyFrame::Data(Bytes::from_static("你好".as_bytes()))),
                    Ok(BodyFrame::Data(Bytes::from_static("こんにちは".as_bytes()))),
                    Ok(BodyFrame::Data(Bytes::from_static("안녕하세요".as_bytes()))),
                    Ok(BodyFrame::Trailers(trailers.clone())),
                ]));
                let mut request = request(Method::POST, "http://example.com/echo", body);
                request
                    .headers_mut()
                    .insert(header::TE, HeaderValue::from_static("trailers"));
                let response = send.send(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(response.headers()[header::TRANSFER_ENCODING], "chunked");
                let mut body = response.into_body();
                let mut data = Vec::new();
                let mut received = None;
                while let Some(frame) = body.next().await {
                    match frame.unwrap() {
                        BodyFrame::Data(chunk) => data.extend_from_slice(&chunk),
                        BodyFrame::Trailers(fields) => received = Some(fields),
                        other => panic!("unexpected frame {other:?}"),
                    }
                }
                assert_eq!(text(&data), "你好こんにちは안녕하세요");
                assert_eq!(received.unwrap(), trailers);
            }
            // Dropping the handle ends the connection.
        };
        let ((served, ran), ()) = zip(zip(server, conn.run()), client).await;
        assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
        served.unwrap();
        // Both requests went over the one connection.
        assert_eq!(calls.get(), 2);
    });
}

#[test]
fn expect_continue_waits_for_the_server() {
    block_on(async {
        let ends = connection();
        let (mut server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let peer = async move {
            let head = server_in.until(b"\r\n\r\n").await;
            assert!(text(&head).contains("expect: 100-continue\r\n"));
            // Nothing of the body has been sent before the interim response.
            futures_lite::future::yield_now().await;
            assert!(
                server_in.try_chunk().is_none(),
                "the body was sent before 100 Continue"
            );
            server_out.send(b"HTTP/1.1 100 Continue\r\n\r\n");
            let body = server_in.until(CJK.as_bytes()).await;
            assert_eq!(body, CJK.as_bytes());
            server_out.send(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
            server_in.read_to_end().await;
        };
        let client = async move {
            let mut request = request(
                Method::PUT,
                "http://example.com/upload",
                Body::from_bytes(CJK),
            );
            request
                .headers_mut()
                .insert(header::EXPECT, HeaderValue::from_static("100-continue"));
            let response = send.send(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        };
        let ((), (ran, ())) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
    });
}

#[test]
fn a_final_response_before_continue_withholds_the_body() {
    block_on(async {
        let ends = connection();
        let (mut server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let peer = async move {
            server_in.until(b"\r\n\r\n").await;
            server_out.send(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n");
            // The client sends no body and closes.
            assert!(server_in.read_to_end().await.is_empty());
        };
        let client = async move {
            let mut request = request(
                Method::PUT,
                "http://example.com/upload",
                Body::from_bytes(CJK),
            );
            request
                .headers_mut()
                .insert(header::EXPECT, HeaderValue::from_static("100-continue"));
            let response = send.send(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
            // The connection cannot be reused without the body it announced.
            send
        };
        let ((), (ran, send)) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
        assert!(send.is_closed());
    });
}

#[test]
fn upgrade_hands_back_the_socket_and_early_bytes() {
    block_on(async {
        let ends = connection();
        let (mut server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let early = "早上好 おはよう 좋은 아침";
        let peer = async move {
            let head = text(&server_in.until(b"\r\n\r\n").await);
            assert!(head.starts_with("GET /chat HTTP/1.1\r\nhost: example.com\r\n"));
            server_out.send(
                format!("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n{early}")
                    .as_bytes(),
            );
            (server_in, server_out)
        };
        let client = async move {
            let mut request = request(Method::GET, "http://example.com/chat", Body::empty());
            request
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            request
                .headers_mut()
                .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            let response = send.send(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        };
        let (_peer, (ran, ())) = zip(peer, zip(conn.run(), client)).await;
        let ClientOutcome::Upgraded(upgraded) = ran.unwrap() else {
            panic!("the connection must switch protocols");
        };
        assert_eq!(upgraded.read_buf, early.as_bytes());
    });
}

#[test]
fn an_unrequested_upgrade_fails() {
    block_on(async {
        let ends = connection();
        let (mut server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let peer = async move {
            server_in.until(b"\r\n\r\n").await;
            server_out.send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n");
            (server_in, server_out)
        };
        let client = async move {
            send.send(request(Method::GET, "http://example.com/", Body::empty()))
                .await
        };
        let (_peer, (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(ran, Err(Error::UnrequestedUpgrade)));
        assert!(matches!(sent, Err(Error::UnrequestedUpgrade)));
    });
}

#[test]
fn close_delimited_responses_are_zero_copy() {
    block_on(async {
        let ends = connection();
        let (mut server_in, mut server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let reads = client_in.reads();
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let body = CJK.repeat(30);
        let peer = async {
            server_in.until(b"\r\n\r\n").await;
            server_out.send(b"HTTP/1.1 200 OK\r\n\r\n");
            for piece in body.as_bytes().chunks(500) {
                server_out.send(piece);
            }
            server_out.close();
        };
        let client = async {
            let response = send
                .send(request(Method::GET, "http://example.com/", Body::empty()))
                .await
                .unwrap();
            let mut stream = response.into_body();
            let mut data = Vec::new();
            while let Some(frame) = stream.next().await {
                let BodyFrame::Data(chunk) = frame.unwrap() else {
                    panic!("a close-delimited body has only data");
                };
                assert!(
                    within_reads(&chunk, &reads),
                    "response data was copied out of the receive buffer"
                );
                data.extend_from_slice(&chunk);
            }
            assert_eq!(text(&data), body);
        };
        let ((), (ran, ())) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
    });
}

#[test]
fn interim_responses_are_skipped() {
    block_on(async {
        let ends = connection();
        let (mut server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let peer = async move {
            server_in.until(b"\r\n\r\n").await;
            server_out.send(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            server_in.read_to_end().await;
        };
        let client = async move {
            let response = send
                .send(request(Method::GET, "http://example.com/", Body::empty()))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.into_body().into_bytes().await.unwrap(), "ok");
        };
        let ((), (ran, ())) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
    });
}

#[test]
fn a_closed_connection_fails_the_request() {
    block_on(async {
        let ends = connection();
        let (mut server_in, mut server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let peer = async {
            server_in.until(b"\r\n\r\n").await;
            server_out.close();
        };
        let client = async {
            send.send(request(Method::GET, "http://example.com/", Body::empty()))
                .await
        };
        let ((), (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(ran, Err(Error::ConnectionClosed)));
        assert!(matches!(sent, Err(Error::ConnectionClosed)));
    });
}

#[test]
fn invalid_responses_fail_the_request() {
    block_on(async {
        let ends = connection();
        let (mut server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let peer = async move {
            server_in.until(b"\r\n\r\n").await;
            server_out
                .send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc");
            (server_in, server_out)
        };
        let client = async move {
            send.send(request(Method::GET, "http://example.com/", Body::empty()))
                .await
        };
        let (_peer, (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
        assert!(matches!(
            ran,
            Err(Error::Parse(
                http_kit_h1::ParseError::ConflictingContentLength
            ))
        ));
        assert!(matches!(
            sent,
            Err(Error::Parse(
                http_kit_h1::ParseError::ConflictingContentLength
            ))
        ));
    });
}

#[test]
fn an_unsendable_request_leaves_the_connection_usable() {
    block_on(async {
        let ends = connection();
        let (server_in, server_out) = ends.server;
        let (client_in, client_out) = ends.client;
        let service = |_: Request| async { Response::new(Body::from_bytes("ok")) };
        let server =
            ServerConnection::new(server_in, server_out, ServerConfig::default()).serve(&service);
        let (send, conn) = handshake(client_in, client_out, ClientConfig::default());
        let client = async move {
            // No authority and no Host field.
            let error = send
                .send(request(Method::GET, "/relative", Body::empty()))
                .await
                .unwrap_err();
            assert!(matches!(error, Error::MissingHost));
            let response = send
                .send(request(Method::GET, "http://example.com/", Body::empty()))
                .await
                .unwrap();
            assert_eq!(response.into_body().into_bytes().await.unwrap(), "ok");
        };
        let ((served, ran), ()) = zip(zip(server, conn.run()), client).await;
        served.unwrap();
        ran.unwrap();
    });
}
