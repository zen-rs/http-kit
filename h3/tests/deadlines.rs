//! A client request's `Deadlines` over loopback: a response head that never
//! comes fails with `Timeout::ResponseHead`, a body that stalls after one
//! chunk fails with `BodyError::Receive(Stalled)`, and a response that
//! arrives in time is left alone. Each runs on compio and on tokio.
#![cfg(feature = "quiche")]

mod support;

use std::{
    future::{Future, pending},
    io,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_lite::{StreamExt as _, future::zip, stream};
use http_kit::{
    Body, BodyError, BodyFrame, Deadlines, Method, ReceiveError, Request, Response, StatusCode,
};
use http_kit_h3::{Client, Error, SendRequest, Server, Timeout};
use http_kit_io::{Datagram, DatagramSocket as _, Timer};
use support::{CJK, client_config, loopback, on_compio, on_tokio, pki, server_config, within};

const LIMIT: Duration = Duration::from_secs(30);
/// Short enough to keep the suite quick, long enough to tell a deadline from
/// scheduling noise.
const DEADLINE: Duration = Duration::from_millis(300);

fn get(port: u16, path: &str, deadlines: Deadlines) -> Request {
    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = format!("https://localhost:{port}{path}").parse().unwrap();
    request.extensions_mut().insert(deadlines);
    request
}

/// `/silent` never answers, `/stalls` sends one chunk and no more, and
/// `/prompt` answers at once.
async fn service(request: Request) -> Response {
    match request.uri().path() {
        "/silent" => pending().await,
        "/stalls" => {
            let chunk = Ok::<_, io::Error>(BodyFrame::Data(Bytes::from_static(CJK[0].as_bytes())));
            Response::new(Body::from_frames(
                stream::once(chunk).chain(stream::pending()),
            ))
        }
        _ => Response::new(Body::from_bytes(CJK.concat())),
    }
}

/// Runs `run` as a client of a server answering with [`service`].
async fn exchange<I: Datagram + Timer + Clone, F: Future<Output = ()>>(
    io: I,
    run: impl FnOnce(u16, SendRequest) -> F,
) {
    let pki = pki();
    let socket = io.bind_udp(loopback()).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(&pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let served = server.serve_until(&service, async move {
        stopped.recv().await.ok();
    });
    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).await.unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let client = async {
        let ((), ran) = zip(run(port, send), connection.run()).await;
        ran.unwrap();
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

/// The head never arrives: the request fails at its deadline, and the
/// connection still answers the next request.
async fn silent_head_times_out<I: Datagram + Timer + Clone>(io: I) {
    exchange(io, |port, send| async move {
        let deadlines = Deadlines::default().with_response_head(DEADLINE);
        let started = Instant::now();
        let error = send
            .send(get(port, "/silent", deadlines))
            .await
            .unwrap_err();
        assert!(
            matches!(error, Error::Timeout(Timeout::ResponseHead)),
            "{error:?}"
        );
        assert!(started.elapsed() >= DEADLINE, "{:?}", started.elapsed());
        let response = send.send(get(port, "/prompt", deadlines)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().into_bytes().await.unwrap();
        assert_eq!(body, CJK.concat().as_bytes());
        drop(send);
    })
    .await;
}

/// The body stops after one chunk: the read fails as stalled.
async fn stalled_body_fails<I: Datagram + Timer + Clone>(io: I) {
    exchange(io, |port, send| async move {
        let deadlines = Deadlines::default().with_body_idle(DEADLINE);
        let response = send.send(get(port, "/stalls", deadlines)).await.unwrap();
        let mut body = response.into_body();
        let Some(Ok(BodyFrame::Data(first))) = body.next().await else {
            panic!("expected the first chunk");
        };
        assert_eq!(first, CJK[0].as_bytes());
        let started = Instant::now();
        let Some(Err(error)) = body.next().await else {
            panic!("expected the stall to fail the body");
        };
        assert!(
            matches!(error, BodyError::Receive(ReceiveError::Stalled)),
            "{error:?}"
        );
        assert!(started.elapsed() >= DEADLINE, "{:?}", started.elapsed());
        drop(send);
    })
    .await;
}

/// A response that arrives within its deadlines is untouched by them.
async fn prompt_response_is_unaffected<I: Datagram + Timer + Clone>(io: I) {
    exchange(io, |port, send| async move {
        let deadlines = Deadlines::default()
            .with_response_head(DEADLINE * 10)
            .with_body_idle(DEADLINE * 10);
        let response = send.send(get(port, "/prompt", deadlines)).await.unwrap();
        let body = response.into_body().into_bytes().await.unwrap();
        assert_eq!(body, CJK.concat().as_bytes());
        drop(send);
    })
    .await;
}

#[test]
fn silent_head_times_out_on_compio() {
    on_compio(silent_head_times_out);
}

#[test]
fn silent_head_times_out_on_tokio() {
    on_tokio(silent_head_times_out);
}

#[test]
fn stalled_body_fails_on_compio() {
    on_compio(stalled_body_fails);
}

#[test]
fn stalled_body_fails_on_tokio() {
    on_tokio(stalled_body_fails);
}

#[test]
fn prompt_response_is_unaffected_on_compio() {
    on_compio(prompt_response_is_unaffected);
}

#[test]
fn prompt_response_is_unaffected_on_tokio() {
    on_tokio(prompt_response_is_unaffected);
}
