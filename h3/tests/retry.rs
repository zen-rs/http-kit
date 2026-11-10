//! Address validation with a stateless Retry: a server requiring it opens a
//! connection only for an Initial that echoes a token it minted for that
//! client, and a forged, replayed or stale token opens none. Each runs on
//! compio and on tokio.
#![cfg(feature = "quiche")]

mod support;

use std::{net::SocketAddr, num::NonZeroU32, time::Duration};

use futures_lite::future::zip;
use http_kit::{Body, Request, Response, StatusCode};
use http_kit_h3::{Client, ClientConfig, Error, RetryWhen, Server, ServerConfig, ServerStats};
use http_kit_io::{BufResult, DatagramSocket, Io, datagram::MAX_COALESCED_BYTES};
use support::{CJK, client_config, loopback, on_compio, on_tokio, pki, server_config, within};

const LIMIT: Duration = Duration::from_secs(30);

async fn greet(_request: Request) -> Response {
    Response::new(Body::from_bytes(CJK.concat()))
}

fn get(port: u16) -> Request {
    let mut request = Request::new(Body::empty());
    *request.uri_mut() = format!("https://localhost:{port}/").parse().unwrap();
    request
}

/// Serves `config` while `client` runs against its address, then drains.
async fn serving<I: Io, F: Future<Output = ()>>(
    io: I,
    config: &ServerConfig,
    client: impl FnOnce(SocketAddr, ServerStats) -> F,
) {
    let io = &io;
    let socket = io.bind_udp(loopback()).unwrap();
    let addr = SocketAddr::from(([127, 0, 0, 1], socket.local_addr().unwrap().port()));
    let server = Server::new(socket, io.clone(), config).unwrap();
    let stats = server.stats();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let served = server.serve_until(&greet, async move {
        stopped.recv().await.ok();
    });
    let client = async {
        client(addr, stats).await;
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

/// One request on a fresh connection from the HTTP/3 client.
async fn fetch<I: Io>(io: &I, config: &ClientConfig, server: SocketAddr) -> Result<(), Error> {
    let mut client = Client::new(config).unwrap();
    let socket = io.bind_udp(loopback()).unwrap();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", server)
        .unwrap();
    let exchange = async move {
        let response = send.send(get(server.port())).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().into_bytes().await.unwrap();
        assert_eq!(body, CJK.concat().as_bytes());
        Ok(())
    };
    let (exchanged, ran) = zip(exchange, connection.run()).await;
    exchanged.and(ran)
}

/// The default configuration retries: the client answers the Retry on its
/// own, and its handshake checks the transport parameters naming it.
async fn handshake_via_retry<I: Io>(io: I) {
    let pki = pki();
    serving(
        io.clone(),
        &server_config(&pki),
        |server, stats| async move {
            fetch(&io, &client_config(&pki), server).await.unwrap();
            assert!(stats.retries_sent() >= 1);
            assert_eq!(stats.connections_accepted(), 1);
            assert_eq!(stats.invalid_tokens() + stats.expired_tokens(), 0);
        },
    )
    .await;
}

#[test]
fn handshake_via_retry_on_compio() {
    on_compio(handshake_via_retry);
}

#[test]
fn handshake_via_retry_on_tokio() {
    on_tokio(handshake_via_retry);
}

/// Without Retry, the first Initial opens the connection.
async fn never_retries<I: Io>(io: I) {
    let pki = pki();
    let mut config = server_config(&pki);
    config.retry = None;
    serving(io.clone(), &config, |server, stats| async move {
        fetch(&io, &client_config(&pki), server).await.unwrap();
        assert_eq!(stats.retries_sent(), 0);
        assert_eq!(stats.connections_accepted(), 1);
    })
    .await;
}

#[test]
fn never_retries_on_compio() {
    on_compio(never_retries);
}

#[test]
fn never_retries_on_tokio() {
    on_tokio(never_retries);
}

/// Above the rate, a connection is retried; below it, it is not.
async fn retries_above_rate<I: Io>(io: I) {
    let pki = pki();
    let mut config = server_config(&pki);
    config.retry.as_mut().unwrap().when = RetryWhen::AboveRate {
        connections: NonZeroU32::new(1).unwrap(),
        window: Duration::from_secs(3600),
    };
    serving(io.clone(), &config, |server, stats| async move {
        fetch(&io, &client_config(&pki), server).await.unwrap();
        assert_eq!(stats.retries_sent(), 0);
        fetch(&io, &client_config(&pki), server).await.unwrap();
        assert!(stats.retries_sent() >= 1);
        assert_eq!(stats.connections_accepted(), 2);
    })
    .await;
}

#[test]
fn retries_above_rate_on_compio() {
    on_compio(retries_above_rate);
}

#[test]
fn retries_above_rate_on_tokio() {
    on_tokio(retries_above_rate);
}

/// A token older than its validity is dropped, so the client's handshake
/// never completes and times out.
async fn stale_token<I: Io>(io: I) {
    let pki = pki();
    let mut config = server_config(&pki);
    config.retry.as_mut().unwrap().validity = Duration::ZERO;
    let mut client = client_config(&pki);
    client.transport.idle_timeout = Some(Duration::from_secs(1));
    serving(io.clone(), &config, |server, stats| async move {
        assert!(fetch(&io, &client, server).await.is_err());
        assert!(stats.retries_sent() >= 1);
        assert!(stats.expired_tokens() >= 1);
        assert_eq!(stats.invalid_tokens(), 0);
        assert_eq!(stats.connections_accepted(), 0);
    })
    .await;
}

#[test]
fn stale_token_opens_no_connection_on_compio() {
    on_compio(stale_token);
}

#[test]
fn stale_token_opens_no_connection_on_tokio() {
    on_tokio(stale_token);
}

/// Sends `packet` and returns the first datagram received back.
async fn round_trip<S: DatagramSocket>(socket: &S, to: SocketAddr, packet: Vec<u8>) -> Vec<u8> {
    let BufResult(sent, _) = socket.send_to(packet, to).await;
    sent.unwrap();
    let BufResult(received, buf) = socket
        .recv_from(Vec::with_capacity(MAX_COALESCED_BYTES))
        .await;
    let range = received.unwrap().segments().next().unwrap();
    buf[range].to_vec()
}

async fn send<S: DatagramSocket>(socket: &S, to: SocketAddr, packet: Vec<u8>) {
    let BufResult(sent, _) = socket.send_to(packet, to).await;
    sent.unwrap();
}

/// Starts a quiche client on `socket`, sends its first Initial without a
/// token, takes the server's Retry, and returns the Initial the client sends
/// next, carrying the Retry's token after `tamper`.
///
/// The Retry is rebuilt around the tampered token with a correct integrity
/// tag, so the client accepts it and echoes the token as given.
async fn retried_initial<S: DatagramSocket>(
    socket: &S,
    server: SocketAddr,
    tamper: impl FnOnce(&mut Vec<u8>),
) -> Vec<u8> {
    let local = socket.local_addr().unwrap();
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.verify_peer(false);
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    boring::rand::rand_bytes(&mut scid).unwrap();
    let scid = quiche::ConnectionId::from_ref(&scid);
    let mut conn = quiche::connect(Some("localhost"), &scid, local, server, &mut config).unwrap();
    let mut initial = vec![0; quiche::MIN_CLIENT_INITIAL_LEN];
    let (len, _) = conn.send(&mut initial).unwrap();
    initial.truncate(len);
    let mut first = initial.clone();
    let first = quiche::Header::from_slice(&mut first, quiche::MAX_CONN_ID_LEN).unwrap();

    let mut retry = round_trip(socket, server, initial).await;
    let retry = quiche::Header::from_slice(&mut retry, quiche::MAX_CONN_ID_LEN).unwrap();
    assert_eq!(retry.ty, quiche::Type::Retry);
    let mut token = retry.token.clone().unwrap();
    tamper(&mut token);
    let mut rebuilt = vec![0; quiche::MIN_CLIENT_INITIAL_LEN];
    let len = quiche::retry(
        &first.scid,
        &first.dcid,
        &retry.scid,
        &token,
        first.version,
        &mut rebuilt,
    )
    .unwrap();
    rebuilt.truncate(len);
    conn.recv(
        &mut rebuilt,
        quiche::RecvInfo {
            from: server,
            to: local,
        },
    )
    .unwrap();

    let mut next = vec![0; quiche::MIN_CLIENT_INITIAL_LEN];
    let (len, _) = conn.send(&mut next).unwrap();
    next.truncate(len);
    let header = quiche::Header::from_slice(&mut next.clone(), quiche::MAX_CONN_ID_LEN)
        .map(|header| (header.dcid.into_owned(), header.token))
        .unwrap();
    assert_eq!(header, (retry.scid.into_owned(), Some(token)));
    next
}

/// A forged token, and a genuine one sent from another address, are dropped
/// without a connection; the same genuine token from its own address opens
/// one.
async fn refused_tokens<I: Io>(io: I) {
    let pki = pki();
    serving(
        io.clone(),
        &server_config(&pki),
        |server, stats| async move {
            let first = io.bind_udp(loopback()).unwrap();
            let forged = retried_initial(&first, server, |token| {
                let last = token.len() - 1;
                token[last] ^= 1;
            })
            .await;
            send(&first, server, forged).await;

            let replayed = retried_initial(&first, server, |_| {}).await;
            let elsewhere = io.bind_udp(loopback()).unwrap();
            send(&elsewhere, server, replayed).await;

            // The server handles datagrams in order: once this Retry is back,
            // both Initials above have been handled.
            let own = io.bind_udp(loopback()).unwrap();
            let genuine = retried_initial(&own, server, |_| {}).await;
            assert_eq!(stats.retries_sent(), 3);
            assert_eq!(stats.invalid_tokens(), 2);
            assert_eq!(stats.connections_accepted(), 0);

            let answer = round_trip(&own, server, genuine).await;
            let answer = quiche::Header::from_slice(&mut answer.clone(), quiche::MAX_CONN_ID_LEN)
                .unwrap()
                .ty;
            assert_eq!(answer, quiche::Type::Initial);
            assert_eq!(stats.connections_accepted(), 1);
            assert_eq!(stats.invalid_tokens(), 2);
        },
    )
    .await;
}

#[test]
fn refused_tokens_open_no_connection_on_compio() {
    on_compio(refused_tokens);
}

#[test]
fn refused_tokens_open_no_connection_on_tokio() {
    on_tokio(refused_tokens);
}
