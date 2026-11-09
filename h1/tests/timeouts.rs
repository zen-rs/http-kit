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
use http_kit_io::Timer;
use support::{CJK, connection};

/// Short enough to keep the suite quick, long enough to tell a deadline from
/// scheduling noise.
const DEADLINE: Duration = Duration::from_millis(150);
/// The most a deadline may overshoot before something else is wrong.
const SLACK: Duration = Duration::from_secs(5);

fn server_config() -> ServerConfig {
    ServerConfig {
        date_header: false,
        header_read_timeout: Some(Duration::from_secs(600)),
        keep_alive_timeout: Some(Duration::from_secs(600)),
        body_read_timeout: Some(Duration::from_secs(600)),
        ..ServerConfig::default()
    }
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
    let config = ServerConfig {
        header_read_timeout: Some(DEADLINE),
        ..server_config()
    };
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
    let config = ServerConfig {
        header_read_timeout: Some(DEADLINE),
        ..server_config()
    };
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
    let config = ServerConfig {
        keep_alive_timeout: Some(DEADLINE),
        ..server_config()
    };
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
    let config = ServerConfig {
        header_read_timeout: Some(DEADLINE),
        ..server_config()
    };
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
    let config = ServerConfig {
        body_read_timeout: Some(DEADLINE),
        ..server_config()
    };
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
    let config = ClientConfig {
        expect_continue_timeout: Some(DEADLINE),
        ..ClientConfig::default()
    };
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

macro_rules! suite {
    ($timer:expr, $run:expr) => {
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
