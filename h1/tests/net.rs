//! Server and client over real TCP sockets, on every I/O implementation.
//!
//! File regions go to the socket's own `send_file`: `splice(2)` through a
//! pipe with compio on Linux, `sendfile(2)` with tokio on Linux and with both
//! on Apple platforms. The wrapper below counts the bytes that leave through
//! `send_file` and through `write`, so a region this crate read into memory
//! and wrote instead fails the test. Where the platform has neither call
//! (Windows), the I/O layer itself copies inside `send_file`.

use std::{borrow::Borrow, cell::Cell, fs::File, future::Future, io, net::SocketAddr, rc::Rc};

use bytes::Bytes;
use futures_lite::{future::zip, stream};
use http::Method;
use http_kit::{Body, BodyFrame, Request, Response};
use http_kit_h1::{
    ClientConfig, ClientOutcome, ServerConfig, ServerConnection, ServerOutcome, handshake_stream,
};
use http_kit_io::{
    BufResult, Dial, IoBuf, IoVectoredBuf, Listen, Listener as _, SendFile, SpliceWrite, Split,
    Timer, Write,
};
#[cfg(feature = "fs")]
use {
    futures_lite::StreamExt as _,
    http::{HeaderMap, HeaderValue},
    std::path::PathBuf,
};

#[cfg(feature = "fs")]
const CJK: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// Bytes that left through each path of a socket's write half.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Sent {
    written: usize,
    sent_from_file: usize,
}

/// Counts the bytes that went through `write` and through `send_file`.
struct Counting<W> {
    inner: W,
    sent: Rc<Cell<Sent>>,
}

impl<W> Counting<W> {
    fn add(&self, result: &io::Result<usize>, from_file: bool) {
        if let Ok(n) = result {
            let mut sent = self.sent.get();
            if from_file {
                sent.sent_from_file += n;
            } else {
                sent.written += n;
            }
            self.sent.set(sent);
        }
    }
}

impl<W: Write> Write for Counting<W> {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = self.inner.write(buf).await;
        self.add(&result.0, false);
        result
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = self.inner.write_vectored(buf).await;
        self.add(&result.0, false);
        result
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        self.inner.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.inner.shutdown()
    }
}

impl<W: SendFile> SendFile for Counting<W> {
    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        let result = self.inner.send_file(file, offset, len).await;
        self.add(&result.0, true);
        result
    }
}

impl<W: SpliceWrite> SpliceWrite for Counting<W> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        SpliceWrite::can_splice(&self.inner)
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn splice_from_pipe(
        &mut self,
        filled: http_kit_io::splice::FilledPipe,
    ) -> impl Future<Output = io::Result<http_kit_io::splice::Pipe>> {
        self.inner.splice_from_pipe(filled)
    }
}

/// A file larger than a socket buffer, so the region takes several sends.
#[cfg(feature = "fs")]
fn payload_file(name: &str) -> (PathBuf, Vec<u8>) {
    // `name` comes from `module_path!`, and Windows forbids `:` in file names.
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name.replace("::", "-"));
    let mut contents = include_bytes!("net.rs").repeat(48);
    contents.extend(CJK.as_bytes());
    std::fs::write(&path, &contents).expect("write the file to serve");
    (path, contents)
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Serves one connection with `service`, and runs `client` against it.
async fn exchange<I, S, C, Fut>(io: I, service: S, client: C) -> (Sent, Fut::Output)
where
    I: Dial + Listen + Timer + Clone,
    S: http_kit_h1::Service,
    C: FnOnce(http_kit_h1::SendRequest) -> Fut,
    Fut: Future,
{
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let sent = Rc::new(Cell::new(Sent::default()));
    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, writer) = stream.split();
        let writer = Counting {
            inner: writer,
            sent: sent.clone(),
        };
        ServerConnection::new(reader, writer, io.clone(), ServerConfig::default())
            .serve(&service)
            .await
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        let (send, conn) = handshake_stream(stream, io.clone(), ClientConfig::default());
        let (ran, output) = zip(conn.run(), client(send)).await;
        assert!(matches!(
            ran.expect("client connection"),
            ClientOutcome::Closed
        ));
        output
    };
    let (served, output) = zip(server, client).await;
    assert!(matches!(
        served.expect("server connection"),
        ServerOutcome::Closed
    ));
    (sent.get(), output)
}

/// Every byte of a `region`-byte file region went through `send_file`, and
/// `write` carried no more than heads and framing (`overhead` bytes at most).
#[cfg(feature = "fs")]
#[track_caller]
fn assert_sent_from_file(sent: Sent, region: usize, overhead: usize) {
    assert_eq!(
        sent.sent_from_file, region,
        "the region went to the socket's send_file"
    );
    assert!(
        sent.written <= overhead,
        "{} bytes went through write; the region was copied",
        sent.written
    );
}

fn get(uri: &str) -> Request {
    let mut request = Request::new(Body::empty());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = uri.parse().unwrap();
    request
}

async fn keep_alive_round_trips<I: Dial + Listen + Timer + Clone>(io: I) {
    let service = |request: Request| async move {
        let body = request
            .into_body()
            .into_bytes()
            .await
            .expect("request body");
        Response::new(Body::from_bytes(body))
    };
    let (_, ()) = exchange(io, service, |send| async move {
        for _ in 0..3 {
            let mut request = get("http://localhost/echo");
            *request.method_mut() = Method::POST;
            *request.body_mut() = Body::from_frames(stream::iter([
                Ok::<_, io::Error>(BodyFrame::Data(Bytes::from_static("你好".as_bytes()))),
                Ok(BodyFrame::Data(Bytes::from_static("こんにちは".as_bytes()))),
                Ok(BodyFrame::Data(Bytes::from_static("안녕하세요".as_bytes()))),
            ]));
            let response = send.send(request).await.expect("response");
            let body = response
                .into_body()
                .into_bytes()
                .await
                .expect("response body");
            assert_eq!(body, "你好こんにちは안녕하세요".as_bytes());
        }
    })
    .await;
}

#[cfg(feature = "fs")]
async fn file_region_response<I: Dial + Listen + Timer + Clone>(io: I, name: &str) {
    let (path, contents) = payload_file(name);
    let (offset, len) = (11, contents.len() - 11 - 5);
    let service = |_: Request| {
        let file = File::open(&path).expect("open the file to serve");
        async move {
            Response::new(Body::from_file_region(http_kit::FileRegion::new(
                file,
                offset as u64,
                len as u64,
            )))
        }
    };
    let (sent, body) = exchange(io, service, |send| async move {
        let response = send
            .send(get("http://localhost/file"))
            .await
            .expect("response");
        assert_eq!(
            response.headers()["content-length"],
            len.to_string().as_str()
        );
        response
            .into_body()
            .into_bytes()
            .await
            .expect("response body")
    })
    .await;
    std::fs::remove_file(&path).expect("remove the served file");
    assert!(
        body == contents[offset..offset + len],
        "the region arrived intact"
    );
    assert_sent_from_file(sent, len, 256);
}

#[cfg(feature = "fs")]
async fn chunked_file_region_with_trailers<I: Dial + Listen + Timer + Clone>(io: I, name: &str) {
    let (path, contents) = payload_file(name);
    let service = |_: Request| {
        let file = File::open(&path).expect("open the file to serve");
        let len = contents.len() as u64;
        async move {
            let mut trailers = HeaderMap::new();
            trailers.insert("x-length", HeaderValue::from_str(&len.to_string()).unwrap());
            Response::new(Body::from_frames(stream::iter([
                Ok::<_, io::Error>(BodyFrame::File(http_kit::FileRegion::new(file, 0, len))),
                Ok(BodyFrame::Data(Bytes::from_static(CJK.as_bytes()))),
                Ok(BodyFrame::Trailers(trailers)),
            ])))
        }
    };
    let (sent, (data, trailers)) = exchange(io, service, |send| async move {
        let response = send
            .send(get("http://localhost/file"))
            .await
            .expect("response");
        assert_eq!(response.headers()["transfer-encoding"], "chunked");
        let mut body = response.into_body();
        let mut data = Vec::new();
        let mut trailers = None;
        while let Some(frame) = body.next().await {
            match frame.expect("body frame") {
                BodyFrame::Data(chunk) => data.extend_from_slice(&chunk),
                BodyFrame::Trailers(fields) => trailers = Some(fields),
                other => panic!("unexpected frame {other:?}"),
            }
        }
        (data, trailers)
    })
    .await;
    std::fs::remove_file(&path).expect("remove the served file");
    let mut expected = contents.clone();
    expected.extend(CJK.as_bytes());
    assert!(data == expected, "the body arrived intact");
    assert_eq!(
        trailers.expect("trailers")["x-length"],
        contents.len().to_string().as_str()
    );
    assert_sent_from_file(sent, contents.len(), 256 + CJK.len());
}

macro_rules! suite {
    ($io:expr, $run:expr) => {
        #[test]
        fn keep_alive_round_trips() {
            $run(super::keep_alive_round_trips($io));
        }

        #[cfg(feature = "fs")]
        #[test]
        fn file_region_response() {
            $run(super::file_region_response(
                $io,
                concat!(module_path!(), "-file_region"),
            ));
        }

        #[cfg(feature = "fs")]
        #[test]
        fn chunked_file_region_with_trailers() {
            $run(super::chunked_file_region_with_trailers(
                $io,
                concat!(module_path!(), "-chunked_region"),
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
