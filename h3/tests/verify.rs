//! A client's own verification of the server's chain, and the handshake's
//! completion as the connection's caller sees it. Each runs on compio and on
//! tokio.
#![cfg(feature = "quiche")]

mod support;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_lite::future::zip;
use http_kit::{Body, Method, Request, Response, StatusCode};
use http_kit_h3::{Client, ClientConfig, Error, Rejection, Server, Verifier};
use http_kit_io::{Datagram, DatagramSocket as _, Timer};
use support::{
    CJK, MAX_FIELD_SECTION, Pki, loopback, on_compio, on_tokio, pki, server_config, within,
};

const LIMIT: Duration = Duration::from_secs(30);

/// QUIC's code for a TLS alert: `CRYPTO_ERROR` plus the alert (RFC 9001
/// §4.8).
const fn crypto_error(alert: u64) -> u64 {
    0x100 + alert
}

const UNKNOWN_CA: u64 = 48;
const BAD_CERTIFICATE: u64 = 42;

/// What the verifier was shown.
type Seen = Arc<Mutex<Vec<(Vec<Vec<u8>>, String, Vec<u8>)>>>;

/// A verifier that records what it is shown and returns `verdict`.
fn recording(seen: &Seen, verdict: Result<(), Rejection>) -> Verifier {
    let seen = seen.clone();
    Verifier::new(move |presented| {
        seen.lock().unwrap().push((
            presented.chain.to_vec(),
            presented.server_name.to_owned(),
            presented.ocsp_response.to_vec(),
        ));
        verdict
    })
}

fn get(port: u16) -> Request {
    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = format!("https://localhost:{port}/").parse().unwrap();
    request
}

/// Starts a server counting the requests it answers, and a client with
/// `config`, and hands both ends to `test`.
async fn exchange<I: Datagram + Timer + Clone, F: Future>(
    io: I,
    pki: &Pki,
    config: ClientConfig,
    test: impl FnOnce(http_kit_h3::SendRequest, u16, Arc<AtomicUsize>) -> F,
) -> (F::Output, Result<(), Error>) {
    let socket = io.bind_udp(loopback()).await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let server = Server::new(socket, io.clone(), &server_config(pki)).unwrap();
    let (stop, stopped) = async_channel::bounded::<()>(1);
    let answered = Arc::new(AtomicUsize::new(0));
    let service = {
        let answered = answered.clone();
        move |_request: Request| {
            answered.fetch_add(1, Ordering::SeqCst);
            async { Response::new(Body::from_bytes(CJK.concat())) }
        }
    };
    let served = server.serve_until(&service, async move {
        stopped.recv().await.ok();
    });

    let mut client = Client::new(&config).unwrap();
    let socket = io.bind_udp(loopback()).await.unwrap();
    let peer = ([127, 0, 0, 1], port).into();
    let (send, connection) = client
        .connect(socket, io.clone(), "localhost", peer)
        .unwrap();
    let client = async {
        let (output, ran) = zip(test(send, port, answered), connection.run()).await;
        stop.send(()).await.unwrap();
        (output, ran)
    };
    let (served, client) = within(&io, LIMIT, zip(served, client)).await;
    served.unwrap();
    client
}

/// A verifier that allows the chain decides the handshake: the client sees
/// it complete before it sends anything, from every clone of the handle,
/// and then a request is answered.
async fn allowed_chain<I: Datagram + Timer + Clone>(io: I) {
    let pki = pki();
    let seen = Seen::default();
    let config = ClientConfig::with_verifier(recording(&seen, Ok(())), MAX_FIELD_SECTION);
    let ((), ran) = exchange(io, &pki, config, |send, port, answered| async move {
        send.ready().await.unwrap();
        send.clone().ready().await.unwrap();
        assert_eq!(
            answered.load(Ordering::SeqCst),
            0,
            "ready before any request"
        );

        let response = send.send(get(port)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().into_bytes().await.unwrap();
        assert_eq!(body, CJK.concat().as_bytes());
        assert_eq!(answered.load(Ordering::SeqCst), 1);
        drop(send);
    })
    .await;
    ran.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "the verifier ran once");
    let (chain, name, ocsp) = &seen[0];
    assert_eq!(chain, &[pki.leaf.clone(), pki.ca.clone()], "leaf first");
    assert_eq!(name, "localhost");
    assert!(ocsp.is_empty(), "nothing was stapled");
}

#[test]
fn allowed_chain_on_compio() {
    on_compio(allowed_chain);
}

#[test]
fn allowed_chain_on_tokio() {
    on_tokio(allowed_chain);
}

/// A chain the verifier refuses fails the handshake with the alert it chose:
/// readiness and the request both report it, and the server answers nothing.
async fn refused_chain<I: Datagram + Timer + Clone>(io: I) {
    let pki = pki();
    let seen = Seen::default();
    let config = ClientConfig::with_verifier(
        recording(&seen, Err(Rejection::UnknownCa)),
        MAX_FIELD_SECTION,
    );
    let ((ready, sent, answered), ran) =
        exchange(io, &pki, config, |send, port, answered| async move {
            let ready = send.ready().await;
            let sent = send.send(get(port)).await.map(|response| response.status());
            // Asked again after the fact, the answer is the same.
            assert!(send.ready().await.is_err());
            (ready, sent, answered.load(Ordering::SeqCst))
        })
        .await;
    let alert = Error::LocallyClosed {
        application: false,
        code: crypto_error(UNKNOWN_CA),
    }
    .to_string();
    assert_eq!(ready.unwrap_err().to_string(), alert);
    assert!(
        sent.is_err(),
        "no request is sent on a refused connection: {sent:?}"
    );
    assert_eq!(answered, 0);
    assert_eq!(ran.unwrap_err().to_string(), alert);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[test]
fn refused_chain_on_compio() {
    on_compio(refused_chain);
}

#[test]
fn refused_chain_on_tokio() {
    on_tokio(refused_chain);
}

/// A pinned certificate: the verifier compares the leaf the server sent with
/// the one it expects, as a real verifier compares what it is shown.
async fn pinned_leaf<I: Datagram + Timer + Clone>(io: I) {
    let pki = pki();
    let other = support::pki();
    for (pinned, accepted) in [(pki.leaf.clone(), true), (other.leaf, false)] {
        let verifier = Verifier::new(move |presented| {
            assert_eq!(presented.server_name, "localhost");
            if presented.chain.first() == Some(&pinned) {
                Ok(())
            } else {
                Err(Rejection::BadCertificate)
            }
        });
        let config = ClientConfig::with_verifier(verifier, MAX_FIELD_SECTION);
        let (ready, ran) = exchange(io.clone(), &pki, config, |send, _, _| async move {
            send.ready().await
        })
        .await;
        if accepted {
            ready.unwrap();
            ran.unwrap();
        } else {
            let alert = Error::LocallyClosed {
                application: false,
                code: crypto_error(BAD_CERTIFICATE),
            }
            .to_string();
            assert_eq!(ready.unwrap_err().to_string(), alert);
            assert_eq!(ran.unwrap_err().to_string(), alert);
        }
    }
}

#[test]
fn pinned_leaf_on_compio() {
    on_compio(pinned_leaf);
}

#[test]
fn pinned_leaf_on_tokio() {
    on_tokio(pinned_leaf);
}

const CERTIFICATE_REVOKED: u64 = 44;

/// The stapled bytes: the verifier is shown them exactly as the server sent
/// them, whatever they hold.
fn stapled() -> Vec<u8> {
    CJK.concat().into_bytes()
}

/// A response the server staples reaches the verifier byte for byte, and the
/// handshake goes on when the verifier accepts it.
async fn stapled_response<I: Datagram + Timer + Clone>(io: I) {
    let mut pki = pki();
    pki.identity = pki.identity.clone().with_ocsp_response(stapled());
    let seen = Seen::default();
    let config = ClientConfig::with_verifier(recording(&seen, Ok(())), MAX_FIELD_SECTION);
    let ((), ran) = exchange(io, &pki, config, |send, port, _| async move {
        let response = send.send(get(port)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        drop(send);
    })
    .await;
    ran.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].2, stapled());
}

#[test]
fn stapled_response_on_compio() {
    on_compio(stapled_response);
}

#[test]
fn stapled_response_on_tokio() {
    on_tokio(stapled_response);
}

/// A verifier that reads a revoked status out of the stapled response fails
/// the handshake with `certificate_revoked`, and nothing is sent.
async fn revoked_status<I: Datagram + Timer + Clone>(io: I) {
    let mut pki = pki();
    let revoked = stapled();
    pki.identity = pki.identity.clone().with_ocsp_response(revoked.clone());
    let verifier = Verifier::new(move |presented| {
        if presented.ocsp_response == revoked {
            Err(Rejection::Revoked)
        } else {
            Ok(())
        }
    });
    let config = ClientConfig::with_verifier(verifier, MAX_FIELD_SECTION);
    let ((ready, answered), ran) = exchange(io, &pki, config, |send, _, answered| async move {
        (send.ready().await, answered.load(Ordering::SeqCst))
    })
    .await;
    let alert = Error::LocallyClosed {
        application: false,
        code: crypto_error(CERTIFICATE_REVOKED),
    }
    .to_string();
    assert_eq!(ready.unwrap_err().to_string(), alert);
    assert_eq!(answered, 0);
    assert_eq!(ran.unwrap_err().to_string(), alert);
}

#[test]
fn revoked_status_on_compio() {
    on_compio(revoked_status);
}

#[test]
fn revoked_status_on_tokio() {
    on_tokio(revoked_status);
}
