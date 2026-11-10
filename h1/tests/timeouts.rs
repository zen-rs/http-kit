//! Header-read, keep-alive idle, body-read and 100-continue deadlines, driven
//! by each I/O implementation's own timer.

mod support;

use std::time::{Duration, Instant};

use futures_lite::future::zip;
use http::{HeaderValue, Method, StatusCode, header};
use http_kit::{Body, Request, Response};
use http_kit_h1::{
    ClientConfig, ClientOutcome, Error, ServerConfig, ServerConnection, ServerOutcome, Timeout,
    handshake,
};
use http_kit_io::{BufResult, Read as _, Timer};
use support::{CJK, connection};

/// Short enough to keep the suite quick, long enough to tell a deadline from
/// scheduling noise.
const DEADLINE: Duration = Duration::from_millis(150);
/// The most a deadline may overshoot before something else is wrong.
const SLACK: Duration = Duration::from_secs(5);

fn server_config() -> ServerConfig {
    let mut config = ServerConfig::default();
    config.date_header = false;
    config.header_read_timeout = Some(Duration::from_secs(600));
    config.keep_alive_timeout = Some(Duration::from_secs(600));
    config.body_read_timeout = Some(Duration::from_secs(600));
    config
}

#[track_caller]
fn assert_at_deadline(started: Instant) {
    let elapsed = started.elapsed();
    assert!(
        (DEADLINE..DEADLINE + SLACK).contains(&elapsed),
        "resolved after {elapsed:?}, deadline {DEADLINE:?}"
    );
}

async fn ok(_request: Request) -> Response {
    Response::new(Body::empty())
}

/// A head that starts and never finishes gets a `408` at the deadline.
async fn stalled_head<T: Timer>(timer: T) {
    let ends = connection();
    let (reader, writer) = ends.server;
    let (mut client_in, client_out) = ends.client;
    let mut config = server_config();
    config.header_read_timeout = Some(DEADLINE);
    client_out.send(b"GET / HTTP/1.1\r\nHost: a\r\n");
    let started = Instant::now();
    let (outcome, wire) = zip(
        ServerConnection::new(reader, writer, timer, config).serve(&ok),
        client_in.read_to_end(),
    )
    .await;
    assert!(matches!(
        outcome.unwrap_err(),
        Error::Timeout(Timeout::HeadRead)
    ));
    assert_at_deadline(started);
    let wire = String::from_utf8(wire).unwrap();
    assert!(
        wire.starts_with("HTTP/1.1 408 Request Timeout\r\n"),
        "{wire}"
    );
    assert!(wire.contains("connection: close\r\n"), "{wire}");
    drop(client_out);
}

/// A connection that never sends a byte is closed at the head deadline
/// without a response: there is no request to answer.
async fn silent_connection<T: Timer>(timer: T) {
    let ends = connection();
    let (reader, writer) = ends.server;
    let (mut client_in, client_out) = ends.client;
    let mut config = server_config();
    config.header_read_timeout = Some(DEADLINE);
    let started = Instant::now();
    let (outcome, wire) = zip(
        ServerConnection::new(reader, writer, timer, config).serve(&ok),
        client_in.read_to_end(),
    )
    .await;
    assert!(matches!(
        outcome.unwrap_err(),
        Error::Timeout(Timeout::HeadRead)
    ));
    assert_at_deadline(started);
    assert!(wire.is_empty(), "no response to a request never made");
    drop(client_out);
}

/// After a served request, an idle connection ends at the keep-alive
/// deadline, counted from the end of the response and answered with nothing.
async fn idle_keep_alive<T: Timer>(timer: T) {
    let ends = connection();
    let (reader, writer) = ends.server;
    let (mut client_in, client_out) = ends.client;
    let mut config = server_config();
    config.keep_alive_timeout = Some(DEADLINE);
    client_out.send(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    let started = Instant::now();
    let (outcome, wire) = zip(
        ServerConnection::new(reader, writer, timer, config).serve(&ok),
        client_in.read_to_end(),
    )
    .await;
    assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
    assert_at_deadline(started);
    let wire = String::from_utf8(wire).unwrap();
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{wire}");
    assert!(!wire.contains("408"), "{wire}");
    drop(client_out);
}

/// The head deadline restarts for each request: a slow second head on a
/// keep-alive connection is a stalled head, not an idle connection.
async fn stalled_second_head<T: Timer>(timer: T) {
    let ends = connection();
    let (reader, writer) = ends.server;
    let (mut client_in, client_out) = ends.client;
    let mut config = server_config();
    config.header_read_timeout = Some(DEADLINE);
    client_out.send(b"GET / HTTP/1.1\r\nHost: a\r\n\r\nGET /two HTTP/1.1\r\nHo");
    let (outcome, wire) = zip(
        ServerConnection::new(reader, writer, timer, config).serve(&ok),
        client_in.read_to_end(),
    )
    .await;
    assert!(matches!(
        outcome.unwrap_err(),
        Error::Timeout(Timeout::HeadRead)
    ));
    let wire = String::from_utf8(wire).unwrap();
    assert!(wire.starts_with("HTTP/1.1 200 OK\r\n"), "{wire}");
    assert!(wire.contains("HTTP/1.1 408 Request Timeout\r\n"), "{wire}");
    drop(client_out);
}

/// A request body that stops arriving fails its reader and ends the
/// connection at the per-read deadline.
async fn stalled_body<T: Timer>(timer: T) {
    let ends = connection();
    let (reader, writer) = ends.server;
    let (_client_in, client_out) = ends.client;
    let mut config = server_config();
    config.body_read_timeout = Some(DEADLINE);
    client_out.send(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nabc");
    let service = |request: Request| async move {
        let body = request.into_body().into_bytes().await;
        assert!(body.is_err(), "the stalled body must fail, not end");
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
    };
    let started = Instant::now();
    let outcome = ServerConnection::new(reader, writer, timer, config)
        .serve(&service)
        .await;
    assert!(matches!(
        outcome.unwrap_err(),
        Error::Timeout(Timeout::BodyRead)
    ));
    assert_at_deadline(started);
    drop(client_out);
}

/// With no `100 Continue` coming, the client sends its body at the deadline.
async fn unanswered_continue<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let mut config = ClientConfig::default();
    config.expect_continue_timeout = Some(DEADLINE);
    let (send, conn) = handshake(client_in, client_out, timer, config);
    let started = Instant::now();
    let peer = async move {
        let head = server_in.until(b"\r\n\r\n").await;
        assert!(
            String::from_utf8(head)
                .unwrap()
                .contains("expect: 100-continue\r\n")
        );
        // Never answered with `100 Continue`: the body must still arrive.
        let body = server_in.until(CJK.as_bytes()).await;
        assert_eq!(body, CJK.as_bytes());
        assert_at_deadline(started);
        server_out.send(b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n");
        server_in.read_to_end().await;
    };
    let client = async move {
        let mut request = Request::new(Body::from_bytes(CJK));
        *request.method_mut() = Method::PUT;
        *request.uri_mut() = "http://example.com/upload".parse().unwrap();
        request
            .headers_mut()
            .insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        let response = send.send(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    };
    let ((), (ran, ())) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
}

fn client_config() -> ClientConfig {
    let mut config = ClientConfig::default();
    config.read_timeout = Some(DEADLINE);
    config
}

fn get(uri: &str) -> Request {
    let mut request = Request::new(Body::empty());
    *request.uri_mut() = uri.parse().unwrap();
    request
}

/// The response head never arrives: the exchange fails at the read deadline.
async fn client_stalled_head<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer, client_config());
    let started = Instant::now();
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        (server_in, server_out)
    };
    let client = async move { send.send(get("http://example.com/")).await };
    let (_peer, (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(matches!(sent, Err(Error::Timeout(Timeout::HeadRead))));
    assert_at_deadline(started);
}

/// An interim response restarts the wait; the final head then never comes.
async fn client_stalled_head_after_interim<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer.clone(), client_config());
    let started = Instant::now();
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        timer.sleep(DEADLINE / 2).await;
        server_out.send(b"HTTP/1.1 100 Continue\r\n\r\n");
        // The body is sent once the interim response arrived.
        server_in.until(CJK.as_bytes()).await;
        (server_in, server_out)
    };
    let client = async move {
        let mut request = Request::new(Body::from_bytes(CJK));
        *request.method_mut() = Method::PUT;
        *request.uri_mut() = "http://example.com/upload".parse().unwrap();
        request
            .headers_mut()
            .insert(header::EXPECT, HeaderValue::from_static("100-continue"));
        send.send(request).await
    };
    let (_peer, (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(matches!(sent, Err(Error::Timeout(Timeout::HeadRead))));
    let elapsed = started.elapsed();
    assert!(
        (DEADLINE + DEADLINE / 2..DEADLINE * 2 + SLACK).contains(&elapsed),
        "the interim response must restart the wait; failed after {elapsed:?}"
    );
}

/// A body that stops mid-stream fails through the response body.
async fn client_stalled_body<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer, client_config());
    let started = Instant::now();
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        server_out.send(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                CJK.len() * 2
            )
            .as_bytes(),
        );
        server_out.send(CJK.as_bytes());
        (server_in, server_out)
    };
    let client = async move {
        let response = send.send(get("http://example.com/")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let error = response.into_body().into_bytes().await.unwrap_err();
        assert!(error.to_string().contains("stalled"), "{error}");
    };
    let (_peer, (ran, ())) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran, Err(Error::Timeout(Timeout::BodyRead))));
    assert_at_deadline(started);
}

/// Each read that yields data restarts the wait, so a body slower in total
/// than the deadline still arrives.
async fn client_slow_body_progresses<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer.clone(), client_config());
    let started = Instant::now();
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        server_out
            .send(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", CJK.len()).as_bytes());
        let step = DEADLINE * 2 / 3;
        for part in CJK.as_bytes().chunks(CJK.len().div_ceil(5)) {
            timer.sleep(step).await;
            server_out.send(part);
        }
        (server_in, server_out)
    };
    let client = async move {
        let response = send.send(get("http://example.com/")).await.unwrap();
        let body = response.into_body().into_bytes().await.unwrap();
        assert_eq!(body.as_ref(), CJK.as_bytes());
    };
    let (_peer, (ran, ())) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
    assert!(
        started.elapsed() > DEADLINE,
        "the body must outlast the deadline"
    );
}

/// With no request in flight the deadline does not run: an idle connection
/// outlives it and serves the next request.
async fn client_idle_connection_is_reused<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer.clone(), client_config());
    let peer = async move {
        for _ in 0..2 {
            server_in.until(b"\r\n\r\n").await;
            server_out.send(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{CJK}",
                    CJK.len()
                )
                .as_bytes(),
            );
        }
        server_in.read_to_end().await;
    };
    let client = async move {
        for round in 0..2 {
            if round == 1 {
                timer.sleep(DEADLINE * 3).await;
            }
            let response = send.send(get("http://example.com/")).await.unwrap();
            let body = response.into_body().into_bytes().await.unwrap();
            assert_eq!(body.as_ref(), CJK.as_bytes());
        }
    };
    let ((), (ran, ())) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran.unwrap(), ClientOutcome::Closed));
}

/// Once the protocol switched the connection is the caller's: the deadline
/// no longer applies to it.
async fn client_switched_stream_is_not_bounded<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer.clone(), client_config());
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        server_out
            .send(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
        (server_in, server_out)
    };
    let client = async move {
        let mut request = get("http://example.com/chat");
        request
            .headers_mut()
            .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        request
            .headers_mut()
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        let response = send.send(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    };
    let ((_server_in, server_out), (ran, ())) = zip(peer, zip(conn.run(), client)).await;
    let ClientOutcome::Upgraded(mut upgraded) = ran.unwrap() else {
        panic!("the connection must switch protocols");
    };
    timer.sleep(DEADLINE * 3).await;
    server_out.send(CJK.as_bytes());
    let BufResult(read, buf) = upgraded.read.read(Vec::with_capacity(256)).await;
    assert_eq!(read.unwrap(), CJK.len());
    assert_eq!(buf, CJK.as_bytes());
}

macro_rules! suite {
    ($timer:expr, $run:expr) => {
        #[test]
        fn client_stalled_head() {
            $run(super::client_stalled_head($timer));
        }

        #[test]
        fn client_stalled_head_after_interim() {
            $run(super::client_stalled_head_after_interim($timer));
        }

        #[test]
        fn client_stalled_body() {
            $run(super::client_stalled_body($timer));
        }

        #[test]
        fn client_slow_body_progresses() {
            $run(super::client_slow_body_progresses($timer));
        }

        #[test]
        fn client_idle_connection_is_reused() {
            $run(super::client_idle_connection_is_reused($timer));
        }

        #[test]
        fn client_switched_stream_is_not_bounded() {
            $run(super::client_switched_stream_is_not_bounded($timer));
        }

        #[test]
        fn stalled_head() {
            $run(super::stalled_head($timer));
        }

        #[test]
        fn silent_connection() {
            $run(super::silent_connection($timer));
        }

        #[test]
        fn idle_keep_alive() {
            $run(super::idle_keep_alive($timer));
        }

        #[test]
        fn stalled_second_head() {
            $run(super::stalled_second_head($timer));
        }

        #[test]
        fn stalled_body() {
            $run(super::stalled_body($timer));
        }

        #[test]
        fn unanswered_continue() {
            $run(super::unanswered_continue($timer));
        }
    };
}

mod compio {
    fn run<F: std::future::Future>(future: F) -> F::Output {
        ::compio::runtime::Runtime::new()
            .expect("compio runtime")
            .block_on(future)
    }

    suite!(http_kit_io::compio::Compio, run);
}

mod tokio {
    fn run<F: std::future::Future>(future: F) -> F::Output {
        ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    suite!(http_kit_io::tokio::Tokio, run);
}
