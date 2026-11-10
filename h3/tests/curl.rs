//! The server answers curl's HTTP/3 client.
//!
//! `HTTP_KIT_H3_CURL` names an HTTP/3-capable curl (`curl -V` lists
//! `HTTP3`). Without it the test has nothing to run against and passes
//! vacuously, except in CI on Linux, where it is required.
#![cfg(feature = "quiche")]

mod support;

use std::{path::PathBuf, process::Command, time::Duration};

use futures_lite::future::zip;
use http_kit::{Body, Method, Request, Response};
use http_kit_h3::Server;
use http_kit_io::{DatagramSocket as _, Io as _};
use support::{CJK, loopback, on_compio, pki, server_config, within};

fn curl() -> Option<PathBuf> {
    let curl = std::env::var_os("HTTP_KIT_H3_CURL").map(PathBuf::from);
    assert!(
        curl.is_some() || !(cfg!(target_os = "linux") && std::env::var_os("CI").is_some()),
        "CI requires HTTP_KIT_H3_CURL, the path of an HTTP/3-capable curl"
    );
    curl
}

/// Streams the request body back, with the request's greeting as a header.
async fn echo(request: Request) -> Response {
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), "/echo");
    let greeting = request.headers()["x-greeting"].clone();
    let mut response = Response::new(Body::from_frames(request.into_body()));
    response.headers_mut().insert("x-greeting", greeting);
    response
}

#[test]
fn answers_curl_http3() {
    let Some(curl) = curl() else {
        return;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("curl-http3");
    std::fs::create_dir_all(&dir).unwrap();
    let pki = pki();
    let root = dir.join("root.pem");
    std::fs::write(&root, &pki.root).unwrap();
    // Several times curl's upload buffer, so the body streams in pieces.
    let body: Vec<u8> = CJK.concat().into_bytes().repeat(8 * 1024);
    let upload = dir.join("upload.txt");
    std::fs::write(&upload, &body).unwrap();
    let download = dir.join("download.txt");
    let output = download.clone();

    on_compio(|io| async move {
        let socket = io.bind_udp(loopback()).unwrap();
        let port = socket.local_addr().unwrap().port();
        let server = Server::new(socket, io, &server_config(&pki)).unwrap();
        let (stop, stopped) = async_channel::bounded::<()>(1);
        let served = server.serve_until(&echo, async move {
            stopped.recv().await.ok();
        });

        let (done, finished) = async_channel::bounded(1);
        let mut command = Command::new(&curl);
        command
            .arg("--http3-only")
            .args(["--silent", "--show-error", "--fail"])
            .arg("--cacert")
            .arg(&root)
            .args(["--resolve", &format!("localhost:{port}:127.0.0.1")])
            .args(["--header", &format!("x-greeting: {}", CJK[2])])
            .arg("--data-binary")
            .arg(format!("@{}", upload.display()))
            .arg("--output")
            .arg(&output)
            .args([
                "--write-out",
                "%{http_version} %{response_code} %header{x-greeting}",
            ])
            .arg(format!("https://localhost:{port}/echo"));
        // curl blocks; it runs on its own thread while the server runs here.
        std::thread::spawn(move || done.send_blocking(command.output()).unwrap());
        let client = async {
            let output = finished.recv().await.unwrap().unwrap();
            stop.send(()).await.unwrap();
            output
        };
        let (served, output) = within(&io, Duration::from_secs(60), zip(served, client)).await;
        served.unwrap();
        assert!(
            output.status.success(),
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let summary = String::from_utf8(output.stdout).unwrap();
        assert_eq!(summary, format!("3 200 {}", CJK[2]));
    });
    assert!(
        std::fs::read(&download).unwrap() == body,
        "echoed body differs"
    );
}
