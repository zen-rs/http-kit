//! The server driver over an in-memory socket.

mod support;

use std::{cell::RefCell, rc::Rc};

use bytes::Bytes;
use futures_lite::{StreamExt as _, future::block_on, future::zip, stream};
use http::{HeaderMap, HeaderValue, StatusCode, header};
use http_kit::{Body, BodyFrame, Request, Response};
use http_kit_h1::{Error, ParseError, ServerConfig, ServerConnection, ServerOutcome};
use http_kit_io::{BufResult, Read as _, Write as _};
use support::{CJK, NeverTimer, PipeReader, PipeWriter, connection, within_reads};

fn config() -> ServerConfig {
    ServerConfig {
        date_header: false,
        ..ServerConfig::default()
    }
}

fn text(response: &[u8]) -> String {
    String::from_utf8(response.to_vec()).expect("responses here are UTF-8")
}

fn server(
    reader: PipeReader,
    writer: PipeWriter,
) -> ServerConnection<PipeReader, PipeWriter, NeverTimer> {
    ServerConnection::new(reader, writer, NeverTimer, config())
}

/// The body's data and trailers.
async fn frames(mut body: Body) -> (Vec<u8>, Option<HeaderMap>) {
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.next().await {
        match frame.expect("body frame") {
            BodyFrame::Data(chunk) => data.extend_from_slice(&chunk),
            BodyFrame::Trailers(fields) => trailers = Some(fields),
            other => panic!("unexpected frame {other:?}"),
        }
    }
    (data, trailers)
}

#[test]
fn pipelined_requests_are_answered_in_order() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, mut client_out) = ends.client;
        let service = |request: Request| async move {
            let reply = format!("{} {CJK}", request.uri().path());
            Response::new(Body::from_bytes(reply))
        };
        client_out
            .send(b"GET /first HTTP/1.1\r\nHost: a\r\n\r\nGET /second HTTP/1.1\r\nHost: a\r\n\r\n");
        client_out.close();
        let (outcome, wire) = zip(
            server(reader, writer).serve(&service),
            client_in.read_to_end(),
        )
        .await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        let first = format!("/first {CJK}");
        let second = format!("/second {CJK}");
        let expected = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{first}HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{second}",
            first.len(),
            second.len()
        );
        assert_eq!(text(&wire), expected);
    });
}

#[test]
fn continue_is_sent_when_the_body_is_first_read() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, mut client_out) = ends.client;
        let service = |request: Request| async move {
            let body = request
                .into_body()
                .into_bytes()
                .await
                .expect("request body");
            Response::new(Body::from_bytes(body))
        };
        let client = async {
            client_out.send(
                format!("PUT /upload HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n", CJK.len())
                    .as_bytes(),
            );
            let interim = client_in.until(b"\r\n\r\n").await;
            assert_eq!(text(&interim), "HTTP/1.1 100 Continue\r\n\r\n");
            client_out.send(CJK.as_bytes());
            client_out.close();
            client_in.read_to_end().await
        };
        let (outcome, wire) = zip(server(reader, writer).serve(&service), client).await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        assert_eq!(
            text(&wire),
            format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{CJK}",
                CJK.len()
            )
        );
    });
}

#[test]
fn no_continue_and_close_when_the_body_is_never_read() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, client_out) = ends.client;
        let service = |_: Request| async { Response::new(Body::from_bytes("rejected")) };
        client_out.send(b"PUT /upload HTTP/1.1\r\nHost: a\r\nExpect: 100-continue\r\nContent-Length: 1000\r\n\r\n");
        let (outcome, wire) = zip(
            server(reader, writer).serve(&service),
            client_in.read_to_end(),
        )
        .await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        assert_eq!(
            text(&wire),
            "HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nrejected"
        );
        drop(client_out);
    });
}

#[test]
fn an_unread_body_closes_the_connection() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, client_out) = ends.client;
        let service = |_: Request| async { Response::new(Body::empty()) };
        client_out.send(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabcGET / HTTP/1.1\r\nHost: a\r\n\r\n");
        let (outcome, wire) = zip(
            server(reader, writer).serve(&service),
            client_in.read_to_end(),
        )
        .await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        assert_eq!(
            text(&wire),
            "HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        );
        drop(client_out);
    });
}

#[test]
fn upgrade_hands_back_the_socket_and_early_bytes() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, client_out) = ends.client;
        let early = "早上好 おはよう 좋은 아침";
        #[derive(Clone)]
        struct Protocol(&'static str);
        let service = |request: Request| async move {
            assert_eq!(request.headers()[header::UPGRADE], "websocket");
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
            response
                .headers_mut()
                .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            response.extensions_mut().insert(Protocol("chat"));
            response
        };
        client_out.send(
            format!("GET /chat HTTP/1.1\r\nHost: a\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n{early}").as_bytes(),
        );
        let (outcome, head) = zip(
            server(reader, writer).serve(&service),
            client_in.until(b"\r\n\r\n"),
        )
        .await;
        assert_eq!(
            text(&head),
            "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n"
        );
        let ServerOutcome::Upgraded { upgraded, response } = outcome.unwrap() else {
            panic!("the connection must switch protocols");
        };
        assert_eq!(response.extensions.get::<Protocol>().unwrap().0, "chat");
        assert_eq!(upgraded.read_buf, early.as_bytes());

        // Both halves of the socket carry the new protocol.
        let mut write = upgraded.write;
        let BufResult(result, _) = write.write_all(Bytes::from_static("안녕".as_bytes())).await;
        result.unwrap();
        assert_eq!(client_in.next_chunk().await, "안녕".as_bytes());
        client_out.send("さようなら".as_bytes());
        let mut read = upgraded.read;
        let BufResult(result, buf) = read.read(Vec::with_capacity(64)).await;
        assert_eq!(result.unwrap(), "さようなら".len());
        assert_eq!(buf, "さようなら".as_bytes());
    });
}

#[test]
fn connect_tunnels_after_a_success() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, client_out) = ends.client;
        let service = |_: Request| async { Response::new(Body::empty()) };
        client_out
            .send(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16\x03\x01");
        let (outcome, head) = zip(
            server(reader, writer).serve(&service),
            client_in.until(b"\r\n\r\n"),
        )
        .await;
        assert_eq!(text(&head), "HTTP/1.1 200 OK\r\n\r\n");
        let ServerOutcome::Upgraded { upgraded, .. } = outcome.unwrap() else {
            panic!("CONNECT must tunnel");
        };
        assert_eq!(upgraded.read_buf, &b"\x16\x03\x01"[..]);
    });
}

#[test]
fn chunked_bodies_with_trailers_in_both_directions() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, mut client_out) = ends.client;
        let service = |request: Request| async move {
            let (data, trailers) = frames(request.into_body()).await;
            assert_eq!(data, CJK.as_bytes());
            let trailers = trailers.expect("request trailers");
            assert_eq!(trailers["x-checksum"], "42");
            let mut echoed = HeaderMap::new();
            echoed.insert(
                "x-received",
                HeaderValue::from_str(&data.len().to_string()).unwrap(),
            );
            Response::new(Body::from_frames(stream::iter([
                Ok::<_, std::io::Error>(BodyFrame::Data(Bytes::from(data))),
                Ok(BodyFrame::Trailers(echoed)),
            ])))
        };
        let (first, second) = CJK.as_bytes().split_at(15);
        let mut request =
            b"POST /echo HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        request.extend(format!("{:x}\r\n", first.len()).as_bytes());
        request.extend(first);
        request.extend(format!("\r\n{:x}\r\n", second.len()).as_bytes());
        request.extend(second);
        request.extend(b"\r\n0\r\nX-Checksum: 42\r\n\r\n");
        client_out.send(&request);
        client_out.close();
        let (outcome, wire) = zip(
            server(reader, writer).serve(&service),
            client_in.read_to_end(),
        )
        .await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        let expected = format!(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{CJK}\r\n0\r\nx-received: {}\r\n\r\n",
            CJK.len(),
            CJK.len()
        );
        assert_eq!(text(&wire), expected);
    });
}

#[test]
fn received_bodies_are_not_copied() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, mut client_out) = ends.client;
        let reads = reader.reads();
        let body = CJK.repeat(40);
        let service = |request: Request| {
            let reads = reads.clone();
            async move {
                let mut body = request.into_body();
                let mut total = 0;
                while let Some(frame) = body.next().await {
                    let BodyFrame::Data(data) = frame.unwrap() else {
                        continue;
                    };
                    assert!(
                        within_reads(&data, &reads),
                        "body data was copied out of the receive buffer"
                    );
                    total += data.len();
                }
                Response::new(Body::from_bytes(total.to_string()))
            }
        };
        // Small reads, so the body arrives across many of them.
        let config = ServerConfig {
            read_buffer_size: 100,
            ..config()
        };
        let mut request = format!(
            "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend(body.as_bytes());
        request.extend(format!("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n", body.len()).as_bytes());
        for piece in request.chunks(333) {
            client_out.send(piece);
        }
        client_out.close();
        let connection = ServerConnection::new(reader, writer, NeverTimer, config);
        let (outcome, wire) = zip(connection.serve(&service), client_in.read_to_end()).await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        let total = body.len().to_string();
        let one = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{total}",
            total.len()
        );
        assert_eq!(text(&wire), one.repeat(2));
    });
}

async fn never(_: Request) -> Response {
    unreachable!("an invalid request never reaches the service")
}

#[test]
fn smuggling_attempts_are_answered_and_end_the_connection() {
    for (raw, status, error) in [
        (
            &b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"[..],
            "400 Bad Request",
            ParseError::ContentLengthWithTransferEncoding,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 30\r\n\r\nabc",
            "400 Bad Request",
            ParseError::ConflictingContentLength,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
            "400 Bad Request",
            ParseError::ChunkedNotFinal,
        ),
        (
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            "501 Not Implemented",
            ParseError::UnsupportedTransferCoding,
        ),
    ] {
        block_on(async {
            let ends = connection();
            let (reader, writer) = ends.server;
            let (mut client_in, client_out) = ends.client;
            client_out.send(raw);
            let (outcome, wire) = zip(server(reader, writer).serve(&never), client_in.read_to_end()).await;
            match outcome {
                Err(Error::Parse(actual)) => assert_eq!(actual, error),
                other => panic!("expected {error:?}, got {other:?}"),
            }
            assert_eq!(
                text(&wire),
                format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            );
            drop(client_out);
        });
    }
}

#[test]
fn malformed_chunked_body_reaches_the_service_as_an_error() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, mut client_out) = ends.client;
        let seen = Rc::new(RefCell::new(None));
        let service = |request: Request| {
            let seen = seen.clone();
            async move {
                let result = request.into_body().into_bytes().await;
                *seen.borrow_mut() = Some(result.is_err());
                let mut response = Response::new(Body::empty());
                *response.status_mut() = StatusCode::BAD_REQUEST;
                response
            }
        };
        client_out.send(
            b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n3\nabc\r\n0\r\n\r\n",
        );
        client_out.close();
        let (outcome, wire) = zip(
            server(reader, writer).serve(&service),
            client_in.read_to_end(),
        )
        .await;
        assert!(matches!(
            outcome,
            Err(Error::Parse(ParseError::MissingChunkCrlf))
        ));
        assert_eq!(*seen.borrow(), Some(true));
        assert!(text(&wire).starts_with("HTTP/1.1 400 Bad Request\r\n"));
    });
}

#[test]
fn http10_streams_close_delimited() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, client_out) = ends.client;
        let service = |_: Request| async {
            Response::new(Body::from_frames(stream::iter([
                Ok::<_, std::io::Error>(BodyFrame::Data(Bytes::from_static("你好".as_bytes()))),
                Ok(BodyFrame::Data(Bytes::from_static("こんにちは".as_bytes()))),
                Ok(BodyFrame::Data(Bytes::from_static("안녕하세요".as_bytes()))),
            ])))
        };
        client_out.send(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
        let (outcome, wire) = zip(
            server(reader, writer).serve(&service),
            client_in.read_to_end(),
        )
        .await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        assert_eq!(
            text(&wire),
            "HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n你好こんにちは안녕하세요"
        );
        drop(client_out);
    });
}

#[test]
fn shutdown_closes_an_idle_connection() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, client_out) = ends.client;
        let service = |_: Request| async { Response::new(Body::empty()) };
        let served = server(reader, writer).serve_until(&service, std::future::ready(()));
        let (outcome, wire) = zip(served, client_in.read_to_end()).await;
        assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
        assert!(wire.is_empty());
        drop(client_out);
    });
}

#[test]
fn date_is_added_when_absent() {
    block_on(async {
        let ends = connection();
        let (reader, writer) = ends.server;
        let (mut client_in, mut client_out) = ends.client;
        let service = |_: Request| async { Response::new(Body::empty()) };
        client_out.send(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
        client_out.close();
        let connection = ServerConnection::new(reader, writer, NeverTimer, ServerConfig::default());
        let (_, wire) = zip(connection.serve(&service), client_in.read_to_end()).await;
        let wire = text(&wire);
        let date = wire
            .lines()
            .find_map(|line| line.strip_prefix("date: "))
            .expect("a Date field");
        httpdate::parse_http_date(date).expect("an IMF-fixdate");
    });
}

#[cfg(feature = "fs")]
mod files {
    use std::fs::File;

    use super::*;
    use http_kit::FileRegion;

    fn source() -> (File, Vec<u8>) {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/server.rs");
        (File::open(path).unwrap(), std::fs::read(path).unwrap())
    }

    #[test]
    fn a_file_region_goes_through_send_file() {
        block_on(async {
            let ends = connection();
            let (reader, writer) = ends.server;
            let calls = writer.send_file_calls();
            let (mut client_in, mut client_out) = ends.client;
            let (_, contents) = source();
            let (offset, len) = (100, contents.len() - 200);
            let service = |_: Request| async move {
                let (file, _) = source();
                Response::new(Body::from_file_region(FileRegion::new(
                    file,
                    offset as u64,
                    len as u64,
                )))
            };
            client_out.send(b"GET /source HTTP/1.1\r\nHost: a\r\n\r\n");
            client_out.close();
            let (outcome, wire) = zip(
                server(reader, writer).serve(&service),
                client_in.read_to_end(),
            )
            .await;
            assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
            let mut expected =
                format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n").into_bytes();
            expected.extend(&contents[offset..offset + len]);
            assert!(wire == expected, "the region arrived intact");
            assert_eq!(calls.get(), 1, "the region went through send_file");
        });
    }

    #[test]
    fn file_regions_are_chunked_between_data_and_trailers() {
        block_on(async {
            let ends = connection();
            let (reader, writer) = ends.server;
            let calls = writer.send_file_calls();
            let (mut client_in, mut client_out) = ends.client;
            let (_, contents) = source();
            let service = |_: Request| async move {
                let (file, _) = source();
                let mut trailers = HeaderMap::new();
                trailers.insert("x-note", HeaderValue::from_static("done"));
                Response::new(Body::from_frames(stream::iter([
                    Ok::<_, std::io::Error>(BodyFrame::Data(Bytes::from_static(CJK.as_bytes()))),
                    Ok(BodyFrame::File(FileRegion::new(file, 0, 64))),
                    Ok(BodyFrame::Trailers(trailers)),
                ])))
            };
            client_out.send(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
            client_out.close();
            let (_, wire) = zip(
                server(reader, writer).serve(&service),
                client_in.read_to_end(),
            )
            .await;
            let mut expected = format!(
                "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{:x}\r\n{CJK}\r\n40\r\n",
                CJK.len()
            )
            .into_bytes();
            expected.extend(&contents[..64]);
            expected.extend(b"\r\n0\r\nx-note: done\r\n\r\n");
            assert_eq!(text(&wire), text(&expected));
            assert_eq!(calls.get(), 1);
        });
    }
}
