//! A request that left nothing on the wire comes back from `try_send`, its
//! body unread: on a closed handle, when a GOAWAY is read before a stream
//! opened for it, and when the server rejects it unprocessed
//! (`H3_REQUEST_REJECTED`). Each runs on compio and on tokio.
#![cfg(feature = "quiche")]

mod support;

use std::{
    net::UdpSocket,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use boring::{
    pkey::PKey,
    ssl::{SslContextBuilder, SslMethod},
    x509::X509,
};
use futures_lite::future::zip;
use http_kit::{Body, Method, Request, Response};
use http_kit_h3::{Client, Error, Server};
use http_kit_io::{Datagram, DatagramSocket as _, Timer};
use quiche::h3::{self, NameValue as _};
use support::{CJK, Pki, client_config, loopback, on_compio, on_tokio, pki, server_config, within};

const LIMIT: Duration = Duration::from_secs(30);

/// `H3_REQUEST_REJECTED` (RFC 9114 §8.1).
const REQUEST_REJECTED: u64 = 0x10b;

fn post(port: u16, path: &str) -> Request {
    let mut request = Request::new(Body::from_bytes(CJK.concat()));
    *request.method_mut() = Method::POST;
    *request.uri_mut() = format!("https://localhost:{port}{path}").parse().unwrap();
    request
}

fn get(port: u16, path: &str) -> Request {
    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = format!("https://localhost:{port}{path}").parse().unwrap();
    request
}

/// What `try_send` gave back must be the request as it was handed in: same
/// method and target, and a body nobody read.
async fn assert_returned(
    result: Result<Response, http_kit_h3::TrySendError>,
    expected: &Error,
    method: &Method,
    path: &str,
    body: &[u8],
) {
    let mut failure = result.unwrap_err();
    assert_eq!(
        std::mem::discriminant(failure.error()),
        std::mem::discriminant(expected),
        "{failure:?}"
    );
    let request = failure.take_request().expect("the request comes back");
    assert!(failure.take_request().is_none(), "returned once");
    assert_eq!(request.method(), method);
    assert_eq!(request.uri().path(), path);
    assert_eq!(request.into_body().into_bytes().await.unwrap(), body);
}

/// Waits until `send` reports the connection closed to new requests.
async fn closed<I: Datagram + Timer + Clone>(io: &I, send: &http_kit_h3::SendRequest) {
    while !send.is_closed() {
        io.sleep(Duration::from_millis(5)).await;
    }
}

/// Starts a server whose service holds `/slow` until released, and a client
/// connected to it; `test` gets the handle, the port, the server's stop and
/// its release switches.
async fn drained_server<I: Datagram + Timer + Clone, F: Future<Output = ()>>(
    io: I,
    max_streams: u64,
    test: impl FnOnce(
        http_kit_h3::SendRequest,
        u16,
        async_channel::Receiver<()>,
        async_channel::Sender<()>,
        async_channel::Sender<()>,
    ) -> F,
) {
    let pki = pki();
    let socket = io.bind_udp(loopback()).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let mut config = server_config(&pki);
    config.transport.initial_max_streams_bidi = max_streams;
    let server = Server::new(socket, io.clone(), &config).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let (arrived_tx, arrived) = async_channel::bounded::<()>(1);
    let (release, released) = async_channel::bounded::<()>(1);
    let service = move |_request: Request| {
        let arrived = arrived_tx.clone();
        let released = released.clone();
        async move {
            arrived.send(()).await.unwrap();
            released.recv().await.unwrap();
            Response::new(Body::from_bytes(CJK.concat()))
        }
    };
    let served = server.serve_until(&service, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).await.unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let exchange = test(send, port, arrived, stop, release);
    let client = async {
        let ((), ran) = zip(exchange, connection.run()).await;
        ran.unwrap();
    };
    let (served, ()) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

/// After the GOAWAY was read the handle is closed, and a request sent on it
/// comes back whole.
async fn closed_handle<I: Datagram + Timer + Clone>(io: I) {
    let io2 = io.clone();
    drained_server(io, 100, |send, port, arrived, stop, release| async move {
        let slow = async {
            let response = send.send(get(port, "/slow")).await.unwrap();
            response.into_body().into_bytes().await.unwrap()
        };
        let drive = async {
            arrived.recv().await.unwrap();
            stop.send(()).await.unwrap();
            closed(&io2, &send).await;
            let result = send.try_send(post(port, "/late")).await;
            assert_returned(
                result,
                &Error::ConnectionClosed,
                &Method::POST,
                "/late",
                CJK.concat().as_bytes(),
            )
            .await;
            release.send(()).await.unwrap();
        };
        let (body, ()) = zip(slow, drive).await;
        assert_eq!(body, CJK.concat().as_bytes());
    })
    .await;
}

#[test]
fn closed_handle_on_compio() {
    on_compio(closed_handle);
}

#[test]
fn closed_handle_on_tokio() {
    on_tokio(closed_handle);
}

/// A request waiting for a stream (the server allows one at a time, and
/// `/slow` holds it) when the GOAWAY is read never opens one: it comes back
/// as rejected, with its body unread.
async fn goaway_before_stream<I: Datagram + Timer + Clone>(io: I) {
    let io2 = io.clone();
    drained_server(io, 1, |send, port, arrived, stop, release| async move {
        let slow = async {
            let response = send.send(get(port, "/slow")).await.unwrap();
            response.into_body().into_bytes().await.unwrap()
        };
        let queued = async {
            arrived.recv().await.unwrap();
            let result = zip(send.try_send(post(port, "/queued")), async {
                // The stream limit holds the request back while the server
                // is told to drain.
                io2.sleep(Duration::from_millis(200)).await;
                stop.send(()).await.unwrap();
            })
            .await
            .0;
            assert_returned(
                result,
                &Error::RequestRejected,
                &Method::POST,
                "/queued",
                CJK.concat().as_bytes(),
            )
            .await;
            release.send(()).await.unwrap();
        };
        let (body, ()) = zip(slow, queued).await;
        assert_eq!(body, CJK.concat().as_bytes());
    })
    .await;
}

#[test]
fn goaway_before_stream_on_compio() {
    on_compio(goaway_before_stream);
}

#[test]
fn goaway_before_stream_on_tokio() {
    on_tokio(goaway_before_stream);
}

/// A QUIC and HTTP/3 server on its own thread that resets every request
/// stream with `H3_REQUEST_REJECTED` and answers nothing. Returns its port
/// and the switch that stops it.
fn rejecting_server(pki: &Pki) -> (u16, mpsc::Sender<()>, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind(loopback()).unwrap();
    let local = socket.local_addr().unwrap();
    let port = local.port();
    let mut tls = SslContextBuilder::new(SslMethod::tls()).unwrap();
    let mut chain = X509::stack_from_pem(&pki.chain_pem).unwrap().into_iter();
    tls.set_certificate(&chain.next().unwrap()).unwrap();
    for intermediate in chain {
        tls.add_extra_chain_cert(intermediate).unwrap();
    }
    tls.set_private_key(&PKey::private_key_from_pem(&pki.key_pem).unwrap())
        .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, tls).unwrap();
    config
        .set_application_protos(h3::APPLICATION_PROTOCOL)
        .unwrap();
    config.set_initial_max_data(1 << 20);
    config.set_initial_max_stream_data_bidi_local(1 << 20);
    config.set_initial_max_stream_data_bidi_remote(1 << 20);
    config.set_initial_max_stream_data_uni(1 << 20);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.verify_peer(false);
    socket
        .set_read_timeout(Some(Duration::from_millis(10)))
        .unwrap();
    let (stop, stopped) = mpsc::channel::<()>();
    let thread = thread::spawn(move || {
        let mut conn: Option<quiche::Connection> = None;
        let mut h3: Option<h3::Connection> = None;
        let mut buf = vec![0; 65_535];
        let mut out = vec![0; 1350];
        while stopped.try_recv().is_err() {
            match socket.recv_from(&mut buf) {
                Ok((len, from)) => {
                    let info = quiche::RecvInfo { from, to: local };
                    if conn.is_none() {
                        let header =
                            quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
                                .unwrap();
                        let scid = quiche::ConnectionId::from_ref(&header.dcid);
                        conn = Some(quiche::accept(&scid, None, local, from, &mut config).unwrap());
                    }
                    conn.as_mut().unwrap().recv(&mut buf[..len], info).ok();
                }
                Err(_) => {
                    if let Some(conn) = conn.as_mut() {
                        conn.on_timeout();
                    }
                }
            }
            let Some(conn) = conn.as_mut() else { continue };
            if h3.is_none() && conn.is_established() {
                h3 = Some(
                    h3::Connection::with_transport(conn, &h3::Config::new().unwrap()).unwrap(),
                );
            }
            while let Some(h3) = h3.as_mut() {
                match h3.poll(conn) {
                    Ok((id, h3::Event::Headers { list, .. })) => {
                        assert!(list.iter().any(|header| header.name() == b":method"));
                        conn.stream_shutdown(id, quiche::Shutdown::Read, REQUEST_REJECTED)
                            .ok();
                        conn.stream_shutdown(id, quiche::Shutdown::Write, REQUEST_REJECTED)
                            .ok();
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            while let Ok((len, info)) = conn.send(&mut out) {
                socket.send_to(&out[..len], info.to).ok();
            }
            if conn.is_closed() {
                break;
            }
        }
    });
    (port, stop, thread)
}

/// A server that rejects the stream unprocessed: a request without a body
/// comes back whole.
async fn rejected<I: Datagram + Timer + Clone>(io: I) {
    let pki = pki();
    let (port, stop, server) = rejecting_server(&pki);
    let mut client = Client::new(&client_config(&pki)).unwrap();
    let socket = io.bind_udp(loopback()).await.unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let exchange = async {
        let result = send.try_send(get(port, "/rejected")).await;
        assert_returned(
            result,
            &Error::RequestRejected,
            &Method::GET,
            "/rejected",
            b"",
        )
        .await;
        drop(send);
    };
    let started = Instant::now();
    let ((), ran) = within(&io, LIMIT, zip(exchange, connection.run())).await;
    // The server thread never answers the close, so the client's end is
    // whatever it is; the exchange above is what is under test.
    drop(ran);
    // The thread has already ended when the client's close reached it.
    stop.send(()).ok();
    server.join().unwrap();
    assert!(started.elapsed() < LIMIT);
}

#[test]
fn rejected_on_compio() {
    on_compio(rejected);
}

#[test]
fn rejected_on_tokio() {
    on_tokio(rejected);
}
