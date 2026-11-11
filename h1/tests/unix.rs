//! A server over a Unix-domain socket, on every I/O implementation that
//! offers one. The driver has no Unix `connect`, so the client is a blocking
//! `std` socket on its own thread, speaking HTTP/1.1 by hand.
#![cfg(unix)]

use std::{
    io::{Read as _, Write as _},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    thread::JoinHandle,
};

use http_kit::{Body, Request, Response};
use http_kit_h1::{ServerConfig, ServerConnection, ServerOutcome};
use http_kit_io::{FromStdUnix, Listener as _, Split, Timer};

const CJK: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// A directory of its own, short enough for `sun_path`, with the socket's
/// path inside it.
fn socket_dir(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("hk1-{}-{}", std::process::id(), name));
    std::fs::create_dir_all(&dir).expect("create the socket directory");
    let path = dir.join("s");
    (dir, path)
}

/// Requests `target` and reads the whole response, the server closing the
/// connection after it.
fn request(path: &Path, target: &str) -> JoinHandle<Vec<u8>> {
    let path = path.to_owned();
    let request = format!("GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    std::thread::spawn(move || {
        let mut stream = UnixStream::connect(path).expect("connect");
        stream
            .write_all(request.as_bytes())
            .expect("write the request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .expect("read the response");
        response
    })
}

/// Splits a response into its head and body.
fn split_response(response: &[u8]) -> (String, &[u8]) {
    let end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("the response has a head");
    (
        String::from_utf8(response[..end].to_vec()).expect("the head is text"),
        &response[end + 4..],
    )
}

/// Serves one connection with `service`.
async fn serve<I, S>(io: I, name: &str, target: &str, service: S) -> Vec<u8>
where
    I: FromStdUnix + Timer + Clone,
    S: http_kit_h1::Service,
{
    let (dir, path) = socket_dir(name);
    let listener = io
        .unix_listener(UnixListener::bind(&path).expect("bind"))
        .expect("adopt the listener");
    let client = request(&path, target);

    let (stream, _) = listener.accept().await.expect("accept");
    let (reader, writer) = stream.split();
    let outcome = ServerConnection::new(reader, writer, io.clone(), ServerConfig::default())
        .serve(&service)
        .await;
    assert!(matches!(
        outcome.expect("server connection"),
        ServerOutcome::Closed
    ));
    let response = client.join().expect("client");
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    response
}

async fn text_response<I: FromStdUnix + Timer + Clone>(io: I, name: &str) {
    let service = |_: Request| async { Response::new(Body::from_bytes(CJK)) };
    let response = serve(io, name, "/hello", service).await;
    let (head, body) = split_response(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(body, CJK.as_bytes());
}

#[cfg(feature = "fs")]
async fn file_region_response<I: FromStdUnix + Timer + Clone>(io: I, name: &str) {
    let file_path = std::env::temp_dir().join(format!("hk1-{}-{}.bin", std::process::id(), name));
    let mut contents = include_bytes!("unix.rs").repeat(48);
    contents.extend(CJK.as_bytes());
    std::fs::write(&file_path, &contents).expect("write the file to serve");
    let (offset, len) = (11, contents.len() - 11 - 5);
    let service = |_: Request| {
        let file = std::fs::File::open(&file_path).expect("open the file to serve");
        async move {
            Response::new(Body::from_file_region(http_kit::FileRegion::new(
                file,
                offset as u64,
                len as u64,
            )))
        }
    };
    let response = serve(io, name, "/file", service).await;
    std::fs::remove_file(&file_path).expect("remove the served file");
    let (head, body) = split_response(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        body == &contents[offset..offset + len],
        "the region arrived intact"
    );
}

macro_rules! suite {
    ($io:expr, $run:expr) => {
        #[test]
        fn text_response() {
            $run(super::text_response($io, concat!(module_path!(), "-text")));
        }

        #[cfg(feature = "fs")]
        #[test]
        fn file_region_response() {
            $run(super::file_region_response(
                $io,
                concat!(module_path!(), "-file"),
            ));
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
