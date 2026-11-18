//! RFC 9113 & RFC 7541 conformance suite via `h2spec` (`generic`, `http2`, and
//! `hpack` in `--strict` mode) over both cleartext h2c and `http-kit-tls` ALPN
//! `h2` on `compio`.

mod support;

use std::{path::PathBuf, process::Command, time::Duration};

use futures_lite::future::{or, zip};
use http_kit::{Body, Request, Response};
use http_kit_h2::{ServerConfig, ServerConnection};
use http_kit_io::{Listen as _, Listener as _};
use support::{CJK, loopback, on_compio, pki, tls_acceptor, within};

fn find_h2spec() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("HTTP_KIT_H2_H2SPEC") {
        let path = PathBuf::from(explicit);
        assert!(
            path.exists(),
            "HTTP_KIT_H2_H2SPEC points to non-existent binary: {}",
            path.display()
        );
        return Some(path);
    }
    for candidate in ["/opt/homebrew/bin/h2spec", "/usr/local/bin/h2spec"] {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(output) = Command::new("h2spec").arg("--version").output()
        && output.status.success()
    {
        return Some(PathBuf::from("h2spec"));
    }
    assert!(
        !(cfg!(target_os = "linux") && std::env::var_os("CI").is_some()),
        "Linux CI requires HTTP_KIT_H2_H2SPEC or h2spec on PATH"
    );
    None
}

async fn h2spec_service(request: Request) -> Response {
    let body = request.into_body().into_bytes().await.unwrap_or_default();
    let payload = if body.is_empty() {
        CJK.concat().into_bytes()
    } else {
        body.to_vec()
    };
    Response::new(Body::from_bytes(payload))
}

#[test]
fn passes_h2spec_strict_cleartext_and_tls() {
    let Some(h2spec) = find_h2spec() else {
        return;
    };

    let pki = pki();
    let acceptor = tls_acceptor(&pki);

    on_compio(|io| async move {
        let h2c_listener = io.bind_tcp(loopback()).expect("bind h2c");
        let h2c_port = h2c_listener.local_addr().expect("h2c addr").port();

        let tls_listener = io.bind_tcp(loopback()).expect("bind tls");
        let tls_port = tls_listener.local_addr().expect("tls addr").port();

        let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);

        let io_h2c = io.clone();
        let stop_h2c = stop_rx.clone();
        let serve_h2c = async move {
            loop {
                let accept = async { Some(h2c_listener.accept().await) };
                let stop = async {
                    let _ = stop_h2c.recv().await;
                    None
                };
                let Some(accepted) = or(accept, stop).await else {
                    break;
                };
                let (stream, _) = accepted.expect("accept h2c");
                let conn_io = io_h2c.clone();
                compio::runtime::spawn(async move {
                    let mut config = ServerConfig::default();
                    config.limits.max_concurrent_streams = Some(100);
                    let _ = ServerConnection::from_stream(stream, conn_io, config)
                        .serve(&h2spec_service)
                        .await;
                })
                .detach();
            }
        };

        let io_tls = io.clone();
        let stop_tls = stop_rx;
        let serve_tls = async move {
            loop {
                let accept = async { Some(tls_listener.accept().await) };
                let stop = async {
                    let _ = stop_tls.recv().await;
                    None
                };
                let Some(accepted) = or(accept, stop).await else {
                    break;
                };
                let (stream, _) = accepted.expect("accept tls");
                let conn_io = io_tls.clone();
                let conn_acceptor = acceptor.clone();
                compio::runtime::spawn(async move {
                    let Ok(tls_stream) = conn_acceptor.accept(stream, &conn_io).await else {
                        return;
                    };
                    let mut config = ServerConfig::default();
                    config.limits.max_concurrent_streams = Some(100);
                    let _ = ServerConnection::from_stream(tls_stream, conn_io, config)
                        .serve(&h2spec_service)
                        .await;
                })
                .detach();
            }
        };

        let (done_tx, done_rx) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let cleartext = Command::new(&h2spec)
                .args([
                    "--strict",
                    "-h",
                    "127.0.0.1",
                    "-p",
                    &h2c_port.to_string(),
                    "-o",
                    "3",
                ])
                .output()
                .expect("run h2spec cleartext");

            let tls = Command::new(&h2spec)
                .args([
                    "--strict",
                    "-t",
                    "-k",
                    "-h",
                    "127.0.0.1",
                    "-p",
                    &tls_port.to_string(),
                    "-o",
                    "3",
                ])
                .output()
                .expect("run h2spec tls");

            done_tx
                .send_blocking((cleartext, tls))
                .expect("send h2spec output");
        });

        let runner = async {
            let result = done_rx.recv().await.expect("receive h2spec output");
            stop_tx.close();
            result
        };

        let (((), ()), (cleartext, tls)) = within(
            &io,
            Duration::from_secs(90),
            zip(zip(serve_h2c, serve_tls), runner),
        )
        .await;

        assert!(
            cleartext.status.success(),
            "h2spec --strict (cleartext) failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&cleartext.stdout),
            String::from_utf8_lossy(&cleartext.stderr),
        );
        assert!(
            tls.status.success(),
            "h2spec --strict (TLS ALPN h2) failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&tls.stdout),
            String::from_utf8_lossy(&tls.stderr),
        );
    });
}
