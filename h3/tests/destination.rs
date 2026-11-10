//! A server on a wildcard socket answers clients that reached it on
//! different local addresses: quiche sees the address each reached as the
//! path's local address, and every reply leaves from it (quiche drops
//! packets from an unexpected source, so an exchange that completes proves
//! it). Each runs on compio and on tokio.
#![cfg(all(
    feature = "quiche",
    any(
        target_os = "linux",
        target_os = "android",
        target_vendor = "apple",
        windows
    )
))]

mod support;

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use futures_lite::future::zip;
use http_kit::{Body, Request, Response, StatusCode};
use http_kit_h3::{Client, ConnectionInfo, Server};
use http_kit_io::{DatagramSocket as _, Io};
use support::{CJK, client_config, on_compio, on_tokio, pki, server_config, within};

const LIMIT: Duration = Duration::from_secs(30);

/// Answers with the local address the request's connection reached, and
/// the greeting, so a client checks both.
async fn report(request: Request) -> Response {
    let info = request.extensions().get::<ConnectionInfo>().unwrap();
    Response::new(Body::from_bytes(format!(
        "{} {}",
        info.local_addr(),
        CJK.concat()
    )))
}

/// An IPv6 wildcard socket that sees both families.
fn dual_stack() -> std::net::UdpSocket {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("create IPv6 socket");
    socket.set_only_v6(false).expect("make it dual-stack");
    socket
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
        .expect("bind wildcard server");
    socket.into()
}

async fn wildcard_server<I: Io>(io: I) {
    let pki = pki();
    let io = &io;
    let socket = io.udp_socket(dual_stack()).unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(&pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let served = server.serve_until(&report, async move {
        stopped.recv().await.ok();
    });
    let client = async {
        for reached in [
            SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        ] {
            let mut client = Client::new(&client_config(&pki)).unwrap();
            let socket = io
                .bind_udp(SocketAddr::new(reached.ip(), 0))
                .expect("bind client");
            let (send, connection) = client
                .connect(socket, io.clone(), "localhost", reached)
                .unwrap();
            let exchange = async move {
                let mut request = Request::new(Body::empty());
                *request.uri_mut() = format!("https://localhost:{port}/").parse().unwrap();
                let response = send.send(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                response.into_body().into_string().await.unwrap()
            };
            let (body, ran) = zip(exchange, connection.run()).await;
            ran.unwrap();
            assert_eq!(&*body, format!("{reached} {}", CJK.concat()));
        }
        stop.send(()).await.unwrap();
    };
    let (served, ()) = within(io, LIMIT, zip(served, client)).await;
    served.unwrap();
}

#[test]
fn wildcard_server_answers_each_address_on_compio() {
    on_compio(wildcard_server);
}

#[test]
fn wildcard_server_answers_each_address_on_tokio() {
    on_tokio(wildcard_server);
}
