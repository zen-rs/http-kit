//! A server and a client exchanging requests over loopback UDP: streaming
//! bodies in both directions with trailers, many requests past the stream
//! limit, bodies larger than the flow-control windows, and a graceful
//! GOAWAY drain. Each runs on compio and on tokio.
#![cfg(feature = "quiche")]

mod support;

use std::{io, time::Duration};

use bytes::Bytes;
use futures_lite::{StreamExt as _, future::zip};
use futures_util::future::join_all;
use http_kit::{
    Body, BodyFrame, Method, Request, Response, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use http_kit_h3::{Client, ConnectionInfo, Error, Server};
use http_kit_io::{DatagramSocket as _, Io};
use support::{CJK, client_config, loopback, on_compio, on_tokio, pki, server_config, within};

const LIMIT: Duration = Duration::from_secs(30);

fn post(port: u16, path: &str, body: Body) -> Request {
    let mut request = Request::new(body);
    *request.method_mut() = Method::POST;
    *request.uri_mut() = format!("https://localhost:{port}{path}").parse().unwrap();
    request
}

fn cjk_value() -> HeaderValue {
    HeaderValue::from_bytes(CJK.concat().as_bytes()).unwrap()
}

/// Echoes the request body back frame by frame as it arrives, and answers
/// its trailers with trailers of its own.
async fn echo(request: Request) -> Response {
    let info = request.extensions().get::<ConnectionInfo>().unwrap();
    assert!(info.peer_addr().ip().is_loopback() && info.peer_addr().port() != 0);
    assert_ne!(info.peer_addr().port(), info.local_addr().port());
    let frames = request.into_body().map(|frame| {
        frame.map(|frame| match frame {
            BodyFrame::Trailers(mut trailers) => {
                trailers.insert(
                    HeaderName::from_static("x-echoed"),
                    HeaderValue::from_static("yes"),
                );
                BodyFrame::Trailers(trailers)
            }
            frame => frame,
        })
    });
    let mut response = Response::new(Body::from_frames(frames));
    response
        .headers_mut()
        .insert(HeaderName::from_static("x-greeting"), cjk_value());
    response
}

/// Reads data frames until `len` bytes arrived.
async fn read_exactly(body: &mut Body, len: usize) -> Vec<u8> {
    let mut read = Vec::new();
    while read.len() < len {
        match body.next().await {
            Some(Ok(BodyFrame::Data(data))) => read.extend_from_slice(&data),
            other => panic!("expected data, got {other:?}"),
        }
    }
    read
}

/// Each chunk of the request is echoed back before the next is sent, so both
/// bodies stream at once; the trailers cross in both directions.
async fn streaming_round_trip<I: Io>(io: I) {
    let pki = pki();
    let socket = io.bind_udp(loopback()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(&pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let served = server.serve_until(&echo, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let exchange = async move {
        let (chunks, frames) = async_channel::bounded::<Result<BodyFrame, io::Error>>(1);
        let response = send
            .send(post(port, "/echo", Body::from_frames(frames)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-greeting"], cjk_value());
        let mut body = response.into_body();
        for chunk in CJK {
            chunks
                .send(Ok(BodyFrame::Data(Bytes::from_static(chunk.as_bytes()))))
                .await
                .unwrap();
            assert_eq!(read_exactly(&mut body, chunk.len()).await, chunk.as_bytes());
        }
        let mut trailers = HeaderMap::new();
        trailers.insert(HeaderName::from_static("x-checksum"), cjk_value());
        chunks
            .send(Ok(BodyFrame::Trailers(trailers)))
            .await
            .unwrap();
        drop(chunks);
        let Some(Ok(BodyFrame::Trailers(echoed))) = body.next().await else {
            panic!("expected trailers");
        };
        assert_eq!(echoed["x-checksum"], cjk_value());
        assert_eq!(echoed["x-echoed"], "yes");
        assert!(body.next().await.is_none());
        drop(send);
    };
    let client = async {
        let ((), ran) = zip(exchange, connection.run()).await;
        ran.unwrap();
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

#[test]
fn streaming_round_trip_on_compio() {
    on_compio(streaming_round_trip);
}

#[test]
fn streaming_round_trip_on_tokio() {
    on_tokio(streaming_round_trip);
}

/// More concurrent requests than the server allows streams, and bodies
/// larger than the flow-control windows.
async fn many_and_large<I: Io>(io: I) {
    let pki = pki();
    let socket = io.bind_udp(loopback()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut config = server_config(&pki);
    config.transport.initial_max_streams_bidi = 4;
    let server = Server::new(socket, io.clone(), &config).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let served = server.serve_until(&echo, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    // Real text, four times the initial stream window.
    let source = include_bytes!("exchange.rs");
    let window = usize::try_from(config.transport.initial_max_stream_data_bidi).unwrap();
    let large = Bytes::from(source.repeat(4 * window / source.len() + 1));
    let exchanges = async move {
        let small = (0..32).map(|i| {
            let send = send.clone();
            async move {
                let text = format!("{i}: {}", CJK[i % CJK.len()]);
                let response = send
                    .send(post(port, "/small", Body::from_bytes(text.clone())))
                    .await
                    .unwrap();
                let body = response.into_body().into_bytes().await.unwrap();
                assert_eq!(body, text.as_bytes());
            }
        });
        let big = async {
            let response = send
                .send(post(port, "/large", Body::from_bytes(large.clone())))
                .await
                .unwrap();
            let body = response.into_body().into_bytes().await.unwrap();
            assert!(body == large, "large body differs");
        };
        zip(join_all(small), big).await;
        drop(send);
    };
    let client = async {
        let ((), ran) = zip(exchanges, connection.run()).await;
        ran.unwrap();
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

#[test]
fn many_and_large_on_compio() {
    on_compio(many_and_large);
}

#[test]
fn many_and_large_on_tokio() {
    on_tokio(many_and_large);
}

/// A file-region frame is read out and sent as the file's bytes.
#[cfg(feature = "fs")]
async fn file_regions<I: Io>(io: I) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/exchange.rs");
    let source = std::fs::read(path).unwrap();
    let (offset, len) = (100, source.len() - 200);
    let pki = pki();
    let socket = io.bind_udp(loopback()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(&pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let service = move |_request: Request| async move {
        let file = std::fs::File::open(path).unwrap();
        let region = http_kit::FileRegion::new(file, offset as u64, len as u64);
        Response::new(Body::from_file_region(region))
    };
    let served = server.serve_until(&service, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let exchange = async move {
        let response = send.send(post(port, "/file", Body::empty())).await.unwrap();
        assert_eq!(
            response.headers()["content-length"],
            len.to_string().as_str()
        );
        let body = response.into_body().into_bytes().await.unwrap();
        assert!(body == source[offset..offset + len], "region differs");
    };
    let client = async {
        let ((), ran) = zip(exchange, connection.run()).await;
        ran.unwrap();
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

#[cfg(feature = "fs")]
#[test]
fn file_regions_on_compio() {
    on_compio(file_regions);
}

#[cfg(feature = "fs")]
#[test]
fn file_regions_on_tokio() {
    on_tokio(file_regions);
}

/// A pipe frame is read out and sent as data: QUIC encrypts in user space, so
/// its bytes cannot go from the kernel to the socket.
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
async fn pipe_frames<I: Io>(io: I) {
    let payload = CJK.concat();
    let pki = pki();
    let socket = io.bind_udp(loopback()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(&pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let service = {
        let payload = payload.clone();
        move |_request: Request| {
            let pipe = http_kit_io::splice::Pipe::new()
                .unwrap()
                .fill(payload.as_bytes())
                .unwrap_or_else(|(error, _)| panic!("fill: {error}"));
            async move {
                Response::new(Body::from_frames(futures_lite::stream::iter([
                    Ok::<_, io::Error>(BodyFrame::Data(Bytes::from_static(b"head:"))),
                    Ok(BodyFrame::Pipe(pipe)),
                    Ok(BodyFrame::Data(Bytes::from_static(b":tail"))),
                ])))
            }
        }
    };
    let served = server.serve_until(&service, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let exchange = async move {
        let response = send.send(post(port, "/pipe", Body::empty())).await.unwrap();
        let body = response.into_body().into_bytes().await.unwrap();
        assert_eq!(body, format!("head:{payload}:tail").as_bytes());
    };
    let client = async {
        let ((), ran) = zip(exchange, connection.run()).await;
        ran.unwrap();
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
#[test]
fn pipe_frames_on_compio() {
    on_compio(pipe_frames);
}

#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
#[test]
fn pipe_frames_on_tokio() {
    on_tokio(pipe_frames);
}

/// A request in flight when shutdown begins is answered in full, its
/// response streaming after the GOAWAY; one sent after it is refused as safe
/// to retry; then the server closes the connection and returns.
async fn goaway_drains<I: Io>(io: I) {
    let pki = pki();
    let socket = io.bind_udp(loopback()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(&pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let (arrived_tx, arrived) = async_channel::bounded::<()>(1);
    let (release, released) = async_channel::bounded::<()>(1);
    let service = move |request: Request| {
        let arrived = arrived_tx.clone();
        let released = released.clone();
        async move {
            assert_eq!(request.uri().path(), "/slow");
            arrived.send(()).await.unwrap();
            // The response body is produced only after shutdown began.
            let body = futures_lite::stream::once_future(async move {
                released.recv().await.unwrap();
                Ok::<_, io::Error>(BodyFrame::Data(Bytes::from_static(CJK[1].as_bytes())))
            });
            Response::new(Body::from_frames(body))
        }
    };
    let served = server.serve_until(&service, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let exchange = async move {
        let slow = async {
            let response = send.send(post(port, "/slow", Body::empty())).await.unwrap();
            response.into_body().into_bytes().await.unwrap()
        };
        let drive = async {
            arrived.recv().await.unwrap();
            stop.send(()).await.unwrap();
            // Sent after shutdown began: never processed.
            let late = send.send(post(port, "/late", Body::empty())).await;
            assert!(
                matches!(late, Err(Error::RequestRejected | Error::ConnectionClosed)),
                "late request: {late:?}"
            );
            release.send(()).await.unwrap();
        };
        let (body, ()) = zip(slow, drive).await;
        assert_eq!(body, CJK[1].as_bytes());
    };
    // The client keeps its handle; the server's close ends the connection.
    let client = async {
        let ((), ran) = zip(exchange, connection.run()).await;
        ran.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

#[test]
fn goaway_drains_on_compio() {
    on_compio(goaway_drains);
}

#[test]
fn goaway_drains_on_tokio() {
    on_tokio(goaway_drains);
}

/// The drain again, on threads with a quarter of the default test stack.
/// The drivers' futures are boxed, so the futures wrapping them, and every
/// unoptimized frame that moves one, stay small; with the driver state
/// inline, this needed more than the default 2 MiB. An overflow aborts the
/// test binary.
#[test]
fn goaway_drains_on_a_small_stack() {
    const STACK: usize = 512 * 1024;
    let on_small_stack = |test: fn()| {
        std::thread::Builder::new()
            .stack_size(STACK)
            .spawn(test)
            .unwrap()
            .join()
            .unwrap();
    };
    on_small_stack(|| on_compio(goaway_drains));
    on_small_stack(|| on_tokio(goaway_drains));
}
