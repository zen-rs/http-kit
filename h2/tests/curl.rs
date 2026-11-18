//! Interop tests running `curl` (`nghttp2`) against `http-kit-h2::ServerConnection`
//! over both `http-kit-tls` ALPN `h2` (`--http2`) and cleartext prior knowledge
//! (`--http2-prior-knowledge`) on `compio`.

mod support;

use std::{path::PathBuf, process::Command, time::Duration};

use futures_lite::future::{or, zip};
use http_kit::{Method, Request, Response};
use http_kit_h2::{ServerConfig, ServerConnection};
use http_kit_io::{Listen as _, Listener as _};
use support::{CJK, cjk_payload, loopback, on_compio, pki, tls_acceptor, within};

fn find_http2_curl() -> Option<PathBuf> {
    for var in ["HTTP_KIT_H2_CURL", "HTTP_KIT_H3_CURL"] {
        if let Some(val) = std::env::var_os(var) {
            let path = PathBuf::from(val);
            if supports_http2(&path) {
                return Some(path);
            }
        }
    }
    let default = PathBuf::from("curl");
    if supports_http2(&default) {
        return Some(default);
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI requires an HTTP/2-capable curl binary"
    );
    None
}

fn supports_http2(bin: &PathBuf) -> bool {
    let Ok(out) = Command::new(bin).arg("-V").output() else {
        return false;
    };
    out.status.success() && String::from_utf8_lossy(&out.stdout).contains("HTTP2")
}

async fn echo_service(request: Request) -> Response {
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), "/echo");
    let greeting = request.headers()["x-greeting"].clone();
    let mut response = Response::new(request.into_body());
    response.headers_mut().insert("x-greeting", greeting);
    response
}

#[test]
fn answers_curl_http2_tls_and_prior_knowledge() {
    let Some(curl) = find_http2_curl() else {
        return;
    };

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("curl-http2");
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let pki = pki();
    let root_pem = dir.join("root.pem");
    std::fs::write(&root_pem, &pki.ca_pem).expect("write root PEM");

    // ~2.4 MiB multi-frame CJK payload so HTTP/2 stream & connection windows cycle repeatedly.
    let body = cjk_payload(16 * 1024);
    let upload = dir.join("upload.bin");
    std::fs::write(&upload, &body).expect("write upload payload");
    let dl_tls = dir.join("download-tls.bin");
    let dl_h2c = dir.join("download-h2c.bin");

    let acceptor = tls_acceptor(&pki);
    let dl_tls_out = dl_tls.clone();
    let dl_h2c_out = dl_h2c.clone();

    on_compio(|io| async move {
        let tls_listener = io.bind_tcp(loopback()).expect("bind tls");
        let tls_port = tls_listener.local_addr().expect("tls addr").port();

        let h2c_listener = io.bind_tcp(loopback()).expect("bind h2c");
        let h2c_port = h2c_listener.local_addr().expect("h2c addr").port();

        let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);

        let io_tls = io.clone();
        let stop_tls = stop_rx.clone();
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
                    let tls_stream = conn_acceptor
                        .accept(stream, &conn_io)
                        .await
                        .expect("TLS accept");
                    assert_eq!(tls_stream.alpn_protocol(), Some(&b"h2"[..]));
                    ServerConnection::from_stream(tls_stream, conn_io, ServerConfig::default())
                        .serve(&echo_service)
                        .await
                        .expect("serve curl TLS");
                })
                .detach();
            }
        };

        let io_h2c = io.clone();
        let stop_h2c = stop_rx;
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
                    ServerConnection::from_stream(stream, conn_io, ServerConfig::default())
                        .serve(&echo_service)
                        .await
                        .expect("serve curl h2c");
                })
                .detach();
            }
        };

        let (done_tx, done_rx) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let out_tls = Command::new(&curl)
                .args(["--http2", "--silent", "--show-error", "--fail"])
                .arg("--cacert")
                .arg(&root_pem)
                .args(["--resolve", &format!("localhost:{tls_port}:127.0.0.1")])
                .args(["--header", &format!("x-greeting: {}", CJK[2])])
                .arg("--data-binary")
                .arg(format!("@{}", upload.display()))
                .arg("--output")
                .arg(&dl_tls_out)
                .args([
                    "--write-out",
                    "%{http_version} %{response_code} %header{x-greeting}",
                ])
                .arg(format!("https://localhost:{tls_port}/echo"))
                .output()
                .expect("spawn curl --http2");

            let out_h2c = Command::new(&curl)
                .args([
                    "--http2-prior-knowledge",
                    "--silent",
                    "--show-error",
                    "--fail",
                ])
                .args(["--header", &format!("x-greeting: {}", CJK[0])])
                .arg("--data-binary")
                .arg(format!("@{}", upload.display()))
                .arg("--output")
                .arg(&dl_h2c_out)
                .args([
                    "--write-out",
                    "%{http_version} %{response_code} %header{x-greeting}",
                ])
                .arg(format!("http://127.0.0.1:{h2c_port}/echo"))
                .output()
                .expect("spawn curl --http2-prior-knowledge");

            done_tx
                .send_blocking((out_tls, out_h2c))
                .expect("send curl outputs");
        });

        let client = async {
            let res = done_rx.recv().await.expect("recv curl outputs");
            stop_tx.close();
            res
        };

        let (_, (out_tls, out_h2c)) = within(
            &io,
            Duration::from_secs(60),
            zip(zip(serve_tls, serve_h2c), client),
        )
        .await;

        assert!(
            out_tls.status.success(),
            "curl --http2 failed: {}",
            String::from_utf8_lossy(&out_tls.stderr)
        );
        assert_eq!(
            String::from_utf8(out_tls.stdout).expect("utf8"),
            format!("2 200 {}", CJK[2])
        );

        assert!(
            out_h2c.status.success(),
            "curl --http2-prior-knowledge failed: {}",
            String::from_utf8_lossy(&out_h2c.stderr)
        );
        assert_eq!(
            String::from_utf8(out_h2c.stdout).expect("utf8"),
            format!("2 200 {}", CJK[0])
        );
    });

    assert_eq!(std::fs::read(&dl_tls).expect("read tls download"), body);
    assert_eq!(std::fs::read(&dl_h2c).expect("read h2c download"), body);
}
