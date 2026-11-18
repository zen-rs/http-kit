//! Interop tests running `curl` (`nghttp2`) against `http-kit-h2::ServerConnection`
//! over both `http-kit-tls` ALPN `h2` (`--http2`) and cleartext prior knowledge
//! (`--http2-prior-knowledge`) on `compio`.

mod support;

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use futures_lite::future::{or, zip};
use http_kit::{Method, Request, Response};
use http_kit_h2::{ServerConfig, ServerConnection};
use http_kit_io::{Listen as _, Listener as _};
use support::{CJK, cjk_payload, loopback, on_compio, pki, tls_acceptor, within};

fn find_http2_curl() -> Option<(PathBuf, bool)> {
    for var in ["HTTP_KIT_H2_CURL", "HTTP_KIT_H3_CURL"] {
        if let Some(val) = std::env::var_os(var) {
            let path = PathBuf::from(val);
            if let Some(schannel) = probe_http2_curl(&path) {
                return Some((path, schannel));
            }
        }
    }
    let default = PathBuf::from("curl");
    if let Some(schannel) = probe_http2_curl(&default) {
        return Some((default, schannel));
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "CI requires an HTTP/2-capable curl binary"
    );
    None
}

/// Returns `Some(uses_schannel)` if `bin -V` reports HTTP/2 support.
fn probe_http2_curl(bin: &Path) -> Option<bool> {
    let out = Command::new(bin).arg("-V").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let info = String::from_utf8_lossy(&out.stdout);
    info.contains("HTTP2").then(|| info.contains("Schannel"))
}

fn extract_header<'a>(dumped: &'a str, name: &str) -> Option<&'a str> {
    dumped.lines().find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim_matches([' ', '\t', '\r']))
    })
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
    let Some((curl, schannel)) = find_http2_curl() else {
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

    // Pass UTF-8 headers via `@file` and `--dump-header` so Windows `CP1252`
    // process argv / stdout encoding never mangles CJK octets.
    let req_hdr_tls = dir.join("req-hdr-tls.txt");
    let req_hdr_h2c = dir.join("req-hdr-h2c.txt");
    std::fs::write(&req_hdr_tls, format!("x-greeting: {}\r\n", CJK[2])).expect("write tls hdr");
    std::fs::write(&req_hdr_h2c, format!("x-greeting: {}\r\n", CJK[0])).expect("write h2c hdr");
    let resp_hdr_tls = dir.join("resp-hdr-tls.txt");
    let resp_hdr_h2c = dir.join("resp-hdr-h2c.txt");

    let acceptor = tls_acceptor(&pki);
    let dl_tls_out = dl_tls.clone();
    let dl_h2c_out = dl_h2c.clone();
    let resp_hdr_tls_out = resp_hdr_tls.clone();
    let resp_hdr_h2c_out = resp_hdr_h2c.clone();

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
            let mut cmd_tls = Command::new(&curl);
            cmd_tls.args(["--http2", "--silent", "--show-error", "--fail"]);
            if schannel {
                // Windows `System32\curl.exe` uses Schannel, which requires
                // `--ssl-no-revoke` for ephemeral self-signed test CAs with no CRL/OCSP.
                cmd_tls.arg("--ssl-no-revoke");
            }
            let out_tls = cmd_tls
                .arg("--cacert")
                .arg(&root_pem)
                .args(["--resolve", &format!("localhost:{tls_port}:127.0.0.1")])
                .arg("--header")
                .arg(format!("@{}", req_hdr_tls.display()))
                .arg("--dump-header")
                .arg(&resp_hdr_tls_out)
                .arg("--data-binary")
                .arg(format!("@{}", upload.display()))
                .arg("--output")
                .arg(&dl_tls_out)
                .args(["--write-out", "%{http_version} %{response_code}"])
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
                .arg("--header")
                .arg(format!("@{}", req_hdr_h2c.display()))
                .arg("--dump-header")
                .arg(&resp_hdr_h2c_out)
                .arg("--data-binary")
                .arg(format!("@{}", upload.display()))
                .arg("--output")
                .arg(&dl_h2c_out)
                .args(["--write-out", "%{http_version} %{response_code}"])
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
        assert_eq!(String::from_utf8(out_tls.stdout).expect("utf8"), "2 200");

        assert!(
            out_h2c.status.success(),
            "curl --http2-prior-knowledge failed: {}",
            String::from_utf8_lossy(&out_h2c.stderr)
        );
        assert_eq!(String::from_utf8(out_h2c.stdout).expect("utf8"), "2 200");
    });

    let dumped_tls = std::fs::read_to_string(&resp_hdr_tls).expect("read tls response headers");
    assert_eq!(extract_header(&dumped_tls, "x-greeting"), Some(CJK[2]));
    let dumped_h2c = std::fs::read_to_string(&resp_hdr_h2c).expect("read h2c response headers");
    assert_eq!(extract_header(&dumped_h2c, "x-greeting"), Some(CJK[0]));

    assert_eq!(std::fs::read(&dl_tls).expect("read tls download"), body);
    assert_eq!(std::fs::read(&dl_h2c).expect("read h2c download"), body);
}
