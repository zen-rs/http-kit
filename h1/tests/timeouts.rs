//! Header-read, keep-alive idle, body-read and 100-continue deadlines, driven
//! by each I/O implementation's own timer.

mod support;

use std::time::{Duration, Instant};

use futures_lite::future::zip;
use http::{HeaderValue, Method, StatusCode, header};
use http_kit::{Body, BodyError, Deadlines, ReceiveError, Request, Response};
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

/// Both receive deadlines at `DEADLINE`.
fn deadlines() -> Deadlines {
    Deadlines::default()
        .with_response_head(DEADLINE)
        .with_body_idle(DEADLINE)
}

/// A request that carries `deadlines` the way a client states them.
fn with(mut request: Request, deadlines: Deadlines) -> Request {
    request.extensions_mut().insert(deadlines);
    request
}

fn get_with(uri: &str, deadlines: Deadlines) -> Request {
    let mut request = Request::new(Body::empty());
    *request.uri_mut() = uri.parse().unwrap();
    with(request, deadlines)
}

fn get(uri: &str) -> Request {
    get_with(uri, deadlines())
}

fn put_expecting_continue() -> Request {
    let mut request = Request::new(Body::from_bytes(CJK));
    *request.method_mut() = Method::PUT;
    *request.uri_mut() = "http://example.com/upload".parse().unwrap();
    request
        .headers_mut()
        .insert(header::EXPECT, HeaderValue::from_static("100-continue"));
    with(request, deadlines())
}

/// The response head never arrives: the exchange fails at the read deadline.
async fn client_stalled_head<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer, ClientConfig::default());
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

/// An interim response does not restart the head deadline: the final head,
/// which would still be in time had the interim response restarted the wait,
/// finds the exchange already failed.
async fn client_interim_does_not_extend_head<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(
        client_in,
        client_out,
        timer.clone(),
        ClientConfig::default(),
    );
    let started = Instant::now();
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        timer.sleep(DEADLINE * 2 / 5).await;
        server_out.send(b"HTTP/1.1 100 Continue\r\n\r\n");
        // The body is sent once the interim response arrived.
        server_in.until(CJK.as_bytes()).await;
        timer
            .sleep((DEADLINE * 13 / 10).saturating_sub(started.elapsed()))
            .await;
        let delivered = server_out.send_if_open(b"HTTP/1.1 204 No Content\r\n\r\n");
        (server_in, server_out, delivered)
    };
    let client = async move { send.send(put_expecting_continue()).await };
    let ((_in, _out, delivered), (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(matches!(sent, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(
        !delivered,
        "the connection must be gone before the final head"
    );
    assert_at_deadline(started);
}

/// A head that dribbles in, each piece well inside the deadline, still
/// expires with the deadline: it bounds the whole head, not each read.
async fn client_dribbled_head_expires<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(
        client_in,
        client_out,
        timer.clone(),
        ClientConfig::default(),
    );
    let started = Instant::now();
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        let pieces: [&[u8]; 4] = [
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Length: 0\r\n",
            b"X-Greeting: \xe4\xbd\xa0\xe5\xa5\xbd\r\n",
            b"\r\n",
        ];
        let mut delivered = 0;
        for piece in pieces {
            timer.sleep(DEADLINE * 2 / 5).await;
            delivered += usize::from(server_out.send_if_open(piece));
        }
        (server_in, server_out, delivered)
    };
    let client = async move { send.send(get("http://example.com/")).await };
    let ((_in, _out, delivered), (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(matches!(sent, Err(Error::Timeout(Timeout::HeadRead))));
    // Every wait was shorter than the deadline, so only a bound on the whole
    // head can have fired; the head was still incomplete when it did.
    assert!(
        delivered < 4,
        "the last piece must find the connection gone"
    );
    assert_at_deadline(started);
}

/// A request whose upload stalls is bounded by the head deadline too.
async fn client_stalled_upload_exhausts_head<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer, ClientConfig::default());
    let started = Instant::now();
    let peer = async move {
        // The head arrives; the body never does, and no response follows.
        server_in.until(b"\r\n\r\n").await;
        (server_in, server_out)
    };
    let client = async move {
        let upload = futures_lite::stream::pending::<Result<bytes::Bytes, std::io::Error>>();
        let mut request = Request::new(Body::from_stream(upload));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = "http://example.com/upload".parse().unwrap();
        send.send(with(request, deadlines())).await
    };
    let (_peer, (ran, sent)) = zip(peer, zip(conn.run(), client)).await;
    assert!(matches!(ran, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(matches!(sent, Err(Error::Timeout(Timeout::HeadRead))));
    assert_at_deadline(started);
}

/// Two exchanges on one connection each keep their own deadlines: the first
/// waits longer than the second's head deadline and succeeds, the second
/// expires at its own.
async fn client_deadlines_are_per_exchange<T: Timer + Clone>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(
        client_in,
        client_out,
        timer.clone(),
        ClientConfig::default(),
    );
    let patient = Deadlines::default().with_response_head(DEADLINE * 20);
    let impatient = Deadlines::default().with_response_head(DEADLINE);
    let peer = async move {
        server_in.until(b"\r\n\r\n").await;
        timer.sleep(DEADLINE * 2).await;
        server_out.send(b"HTTP/1.1 204 No Content\r\n\r\n");
        // The second request is never answered.
        server_in.until(b"\r\n\r\n").await;
        (server_in, server_out)
    };
    let client = async move {
        let first_started = Instant::now();
        let first = send.send(get_with("http://example.com/", patient)).await;
        let first_elapsed = first_started.elapsed();
        let second_started = Instant::now();
        let second = send.send(get_with("http://example.com/", impatient)).await;
        (first, first_elapsed, second, second_started)
    };
    let (_peer, (ran, (first, first_elapsed, second, second_started))) =
        zip(peer, zip(conn.run(), client)).await;
    assert_eq!(first.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(
        first_elapsed >= DEADLINE * 2,
        "the first exchange answered after {first_elapsed:?}"
    );
    assert!(matches!(second, Err(Error::Timeout(Timeout::HeadRead))));
    assert!(matches!(ran, Err(Error::Timeout(Timeout::HeadRead))));
    assert_at_deadline(second_started);
}

/// A body that ends before its length fails with `Receive(Incomplete)`.
async fn client_truncated_body_is_incomplete<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer, ClientConfig::default());
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
        // Dropping the writer ends the stream mid-body.
        drop(server_out);
        server_in
    };
    let client = async move {
        let response = send.send(get("http://example.com/")).await.unwrap();
        response.into_body().into_bytes().await.unwrap_err()
    };
    let (_peer, (_ran, error)) = zip(peer, zip(conn.run(), client)).await;
    assert!(
        matches!(error, BodyError::Receive(ReceiveError::Incomplete)),
        "{error:?}"
    );
}

/// A body that stops mid-stream fails through the response body.
async fn client_stalled_body<T: Timer>(timer: T) {
    let ends = connection();
    let (mut server_in, server_out) = ends.server;
    let (client_in, client_out) = ends.client;
    let (send, conn) = handshake(client_in, client_out, timer, ClientConfig::default());
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
        assert!(
            matches!(error, BodyError::Receive(ReceiveError::Stalled)),
            "{error:?}"
        );
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
    let (send, conn) = handshake(
        client_in,
        client_out,
        timer.clone(),
        ClientConfig::default(),
    );
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
    let (send, conn) = handshake(
        client_in,
        client_out,
        timer.clone(),
        ClientConfig::default(),
    );
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
    let (send, conn) = handshake(
        client_in,
        client_out,
        timer.clone(),
        ClientConfig::default(),
    );
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
        fn client_interim_does_not_extend_head() {
            $run(super::client_interim_does_not_extend_head($timer));
        }

        #[test]
        fn client_dribbled_head_expires() {
            $run(super::client_dribbled_head_expires($timer));
        }

        #[test]
        fn client_stalled_upload_exhausts_head() {
            $run(super::client_stalled_upload_exhausts_head($timer));
        }

        #[test]
        fn client_deadlines_are_per_exchange() {
            $run(super::client_deadlines_are_per_exchange($timer));
        }

        #[test]
        fn client_truncated_body_is_incomplete() {
            $run(super::client_truncated_body_is_incomplete($timer));
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

    suite!(http_kit_io::compio::Compio::default(), run);
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
