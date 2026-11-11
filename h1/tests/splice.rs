//! Pipe frames through both drivers, on real sockets (Linux and Android).
//!
//! The peer of each test is a plain blocking socket on its own thread, so it
//! chooses exactly which bytes arrive when: a body is held back until the head
//! was read (`Expect: 100-continue` for a request, a pause for a response), so
//! nothing of it is buffered past the head and the raw bytes are still in the
//! socket. The wrappers below count what went through `splice(2)` on each
//! side, so a body that was read into memory and written instead fails the
//! test.
#![cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]

mod support;

use std::{
    cell::{Cell, RefCell},
    fs::File,
    future::{Future, poll_fn},
    io::{self, Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    pin::Pin,
    rc::Rc,
    thread::{self, JoinHandle},
    time::Duration,
};

use bytes::Bytes;
use futures_lite::{StreamExt as _, future::zip, stream};
use http::{HeaderMap, HeaderValue, Method};
use http_kit::{Body, BodyFrame, PipeOffer, Request, Response};
use http_kit_h1::{
    ClientConfig, ClientOutcome, ServerConfig, ServerConnection, ServerOutcome, Service, handshake,
};
use http_kit_io::{
    BufResult, Dial, IoBuf, IoBufMut, IoVectoredBuf, Listen, Listener as _, Read, ReadOwned,
    Received, SendFile, SpliceRead, SpliceWrite, Split, Timer, Write,
    splice::{FilledPipe, Pipe, Spliced},
};

/// Greetings in Chinese, Japanese and Korean.
const CJK: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// How long a peer waits between two writes it wants to arrive separately.
const PAUSE: Duration = Duration::from_millis(150);

/// The most a peer waits for the other side before the test fails.
const PEER_TIMEOUT: Duration = Duration::from_secs(20);

/// The most bytes one pipe frame may hold in these tests.
const OFFER: usize = 64 * 1024;

/// Bytes that went through each path of a socket, per side.
#[derive(Debug, Default)]
struct Counts {
    spliced_in: Cell<usize>,
    spliced_out: Cell<usize>,
    written: Cell<usize>,
}

type Spy = Rc<Counts>;

/// A read half that counts the bytes spliced out of it.
struct SpyRead<R> {
    inner: R,
    counts: Spy,
}

impl<R: Read> Read for SpyRead<R> {
    fn read<B: IoBufMut>(&mut self, buf: B) -> impl Future<Output = BufResult<usize, B>> {
        self.inner.read(buf)
    }
}

impl<R: ReadOwned> ReadOwned for SpyRead<R> {
    type Buf = R::Buf;

    fn read_owned(&mut self) -> impl Future<Output = io::Result<Received<R::Buf>>> {
        self.inner.read_owned()
    }
}

impl<R: SpliceRead> SpliceRead for SpyRead<R> {
    fn can_splice(&self) -> bool {
        self.inner.can_splice()
    }

    async fn splice_to_pipe(
        &mut self,
        pipe: Pipe,
        max: usize,
    ) -> Result<Spliced, (io::Error, Pipe)> {
        let spliced = self.inner.splice_to_pipe(pipe, max).await?;
        if let Spliced::Filled(filled) = &spliced {
            self.counts
                .spliced_in
                .set(self.counts.spliced_in.get() + filled.len());
        }
        Ok(spliced)
    }
}

/// A write half that counts the bytes written and the bytes spliced into it.
struct SpyWrite<W> {
    inner: W,
    counts: Spy,
}

impl<W> SpyWrite<W> {
    fn add_written(&self, result: &io::Result<usize>) {
        if let Ok(n) = result {
            self.counts.written.set(self.counts.written.get() + n);
        }
    }
}

impl<W: Write> Write for SpyWrite<W> {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = self.inner.write(buf).await;
        self.add_written(&result.0);
        result
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let result = self.inner.write_vectored(buf).await;
        self.add_written(&result.0);
        result
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        self.inner.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.inner.shutdown()
    }
}

impl<W: SendFile> SendFile for SpyWrite<W> {
    // `Borrow` stays unimported: its `borrow` would shadow `RefCell::borrow`.
    fn send_file<F: std::borrow::Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> impl Future<Output = BufResult<usize, F>> {
        self.inner.send_file(file, offset, len)
    }
}

impl<W: SpliceWrite> SpliceWrite for SpyWrite<W> {
    fn can_splice(&self) -> bool {
        self.inner.can_splice()
    }

    async fn splice_from_pipe(&mut self, filled: FilledPipe) -> io::Result<Pipe> {
        let len = filled.len();
        let pipe = self.inner.splice_from_pipe(filled).await?;
        self.counts
            .spliced_out
            .set(self.counts.spliced_out.get() + len);
        Ok(pipe)
    }
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// A body of `repeats` greetings: more than a pipe holds when it is large.
fn payload(repeats: usize) -> Vec<u8> {
    CJK.repeat(repeats).into_bytes()
}

// ----- the blocking peer -----------------------------------------------------

fn connect(addr: SocketAddr) -> TcpStream {
    let stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(PEER_TIMEOUT))
        .expect("read timeout");
    stream
}

/// Reads one byte at a time until what was read ends with `needle`.
fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut read = Vec::new();
    let mut byte = [0];
    while !read.ends_with(needle) {
        stream
            .read_exact(&mut byte)
            .unwrap_or_else(|error| panic!("waiting for {needle:?}: {error}"));
        read.push(byte[0]);
    }
    read
}

/// A response with a `Content-Length`: its head and its body.
fn read_response(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let head = String::from_utf8(read_until(stream, b"\r\n\r\n")).expect("a UTF-8 head");
    let len = head
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length: ")
                .map(|len| len.trim().parse::<usize>().expect("a length"))
        })
        .expect("a Content-Length");
    let mut body = vec![0; len];
    stream.read_exact(&mut body).expect("the response body");
    (head, body)
}

/// Reads until the other side closes. A reset ends it too: a side that hangs
/// up with part of a body unread may reset the connection, and what this
/// returns is only what arrived before.
fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).ok();
    rest
}

fn send_continued_head(stream: &mut TcpStream, framing: &str) {
    write!(
        stream,
        "POST /up HTTP/1.1\r\nHost: localhost\r\n{framing}\r\nExpect: 100-continue\r\n\r\n"
    )
    .expect("send the head");
    read_until(stream, b"100 Continue\r\n\r\n");
}

// ----- server side -----------------------------------------------------------

/// Everything a consumer that offers a pipe saw of a body.
#[derive(Debug, Default)]
struct Seen {
    pipes: usize,
    data: usize,
    bytes: Vec<u8>,
    trailers: Option<HeaderMap>,
}

/// Reads `body` offering a pipe with every poll, and reusing it.
async fn collect_offering(mut body: Body, max: usize) -> Seen {
    let mut seen = Seen::default();
    let mut offer = PipeOffer::with_pipe(max, Pipe::new().expect("pipe"));
    while let Some(frame) =
        poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer)).await
    {
        match frame.expect("body frame") {
            BodyFrame::Pipe(filled) => {
                seen.pipes += 1;
                let (bytes, pipe) = filled.read_out().expect("read the pipe out");
                seen.bytes.extend_from_slice(&bytes);
                offer = PipeOffer::with_pipe(max, pipe);
            }
            BodyFrame::Data(data) => {
                seen.data += 1;
                seen.bytes.extend_from_slice(&data);
            }
            BodyFrame::Trailers(trailers) => seen.trailers = Some(trailers),
            other => panic!("unexpected frame {other:?}"),
        }
    }
    seen
}

/// Reads `body` offering nothing.
async fn collect_plain(mut body: Body) -> Seen {
    let mut seen = Seen::default();
    while let Some(frame) = body.next().await {
        match frame.expect("body frame") {
            BodyFrame::Data(data) => {
                seen.data += 1;
                seen.bytes.extend_from_slice(&data);
            }
            BodyFrame::Trailers(trailers) => seen.trailers = Some(trailers),
            other => panic!("unexpected frame {other:?}"),
        }
    }
    seen
}

fn peer<T: Send + 'static>(
    addr: SocketAddr,
    run: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> JoinHandle<T> {
    thread::spawn(move || run(connect(addr)))
}

/// Serves the one connection `run` makes with `service`, until it closes.
async fn serve_peer<I, S, T>(
    io: I,
    service: S,
    run: impl FnOnce(TcpStream) -> T + Send + 'static,
) -> (Spy, T)
where
    I: Listen + Timer + Clone,
    S: Service,
    T: Send + 'static,
{
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let peer = peer(addr, run);
    let (stream, _) = listener.accept().await.expect("accept");
    let (reader, writer) = stream.split();
    let counts = Spy::default();
    let connection = ServerConnection::new(
        SpyRead {
            inner: reader,
            counts: counts.clone(),
        },
        SpyWrite {
            inner: writer,
            counts: counts.clone(),
        },
        io.clone(),
        ServerConfig::default(),
    );
    let outcome = connection.serve(&service).await;
    assert!(matches!(
        outcome.expect("server connection"),
        ServerOutcome::Closed
    ));
    (counts, peer.join().expect("the peer"))
}

/// A service that records what each request body looked like to a consumer
/// that offers a pipe (`offering`) or nothing, and answers with the path.
fn recording_service(
    seen: &Rc<RefCell<Vec<Seen>>>,
    offering: bool,
) -> impl Fn(Request) -> Pin<Box<dyn Future<Output = Response>>> {
    let seen = seen.clone();
    move |request: Request| {
        let seen = seen.clone();
        Box::pin(async move {
            let path = request.uri().path().to_owned();
            let body = request.into_body();
            let collected = if offering {
                collect_offering(body, OFFER).await
            } else {
                collect_plain(body).await
            };
            seen.borrow_mut().push(collected);
            Response::new(Body::from_bytes(path))
        })
    }
}

async fn content_length_request<I: Listen + Timer + Clone>(io: I) {
    // Larger than one pipe holds, so the body takes several frames.
    let body = payload(4000);
    let sent = body.clone();
    let seen = Rc::default();
    let (counts, (head, reply)) =
        serve_peer(io, recording_service(&seen, true), move |mut stream| {
            send_continued_head(&mut stream, &format!("Content-Length: {}", sent.len()));
            stream.write_all(&sent).expect("send the body");
            read_response(&mut stream)
        })
        .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(reply, b"/up");
    let seen = seen.borrow();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].data, 0, "no byte of the body was read into memory");
    assert!(seen[0].pipes > 1, "the body took several pipe frames");
    assert!(seen[0].bytes == body, "the body arrived intact");
    assert_eq!(counts.spliced_in.get(), body.len());
}

async fn chunked_request_with_trailers<I: Listen + Timer + Clone>(io: I) {
    let body = payload(300);
    let sent = body.clone();
    let seen = Rc::default();
    let (counts, (head, reply)) =
        serve_peer(io, recording_service(&seen, true), move |mut stream| {
            send_continued_head(&mut stream, "Transfer-Encoding: chunked");
            let (first, second) = sent.split_at(sent.len() / 2);
            // The size line, then the chunk's data in two runs, each arriving
            // with nothing buffered ahead of it.
            write!(stream, "{:x}\r\n", sent.len()).expect("send the chunk size");
            thread::sleep(PAUSE);
            stream.write_all(first).expect("send the first half");
            thread::sleep(PAUSE);
            stream
                .write_all(second)
                .expect("send the rest of the chunk");
            thread::sleep(PAUSE);
            stream
                .write_all(b"\r\n0\r\nx-checksum: abc123\r\n\r\n")
                .expect("send the end of the body");
            read_response(&mut stream)
        })
        .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(reply, b"/up");
    let seen = seen.borrow();
    assert_eq!(seen[0].data, 0, "no byte of the chunk was read into memory");
    assert!(seen[0].pipes >= 2, "the chunk's two runs were two frames");
    assert!(seen[0].bytes == body, "the chunk arrived intact");
    assert_eq!(
        seen[0].trailers.as_ref().expect("trailers")["x-checksum"],
        "abc123"
    );
    assert_eq!(counts.spliced_in.get(), body.len());
}

async fn pipelined_request_stays_in_the_socket<I: Listen + Timer + Clone>(io: I) {
    let body = payload(200);
    let sent = body.clone();
    let seen = Rc::default();
    let (counts, replies) = serve_peer(io, recording_service(&seen, true), move |mut stream| {
        send_continued_head(&mut stream, &format!("Content-Length: {}", sent.len()));
        // The body and the next request arrive together: the splice must stop
        // at the end of the body and leave the request in the socket.
        let mut both = sent.clone();
        both.extend_from_slice(b"GET /second HTTP/1.1\r\nHost: localhost\r\n\r\n");
        stream
            .write_all(&both)
            .expect("send the body and a request");
        let first = read_response(&mut stream).1;
        let second = read_response(&mut stream).1;
        (first, second)
    })
    .await;
    assert_eq!(replies.0, b"/up");
    assert_eq!(replies.1, b"/second");
    let seen = seen.borrow();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].bytes == body, "the first body arrived intact");
    assert_eq!(seen[0].data, 0);
    assert_eq!(counts.spliced_in.get(), body.len(), "nothing past the body");
}

async fn pipelined_requests_in_one_write_are_read_as_data<I: Listen + Timer + Clone>(io: I) {
    // The whole of both requests is buffered with the head, so there is
    // nothing to splice: the bodies come as data, offer or not.
    let seen = Rc::default();
    let (counts, replies) = serve_peer(io, recording_service(&seen, true), |mut stream| {
        stream
            .write_all(
                b"POST /one HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhelloPOST /two HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nworld",
            )
            .expect("send both requests");
        let first = read_response(&mut stream).1;
        let second = read_response(&mut stream).1;
        (first, second)
    })
    .await;
    assert_eq!(replies.0, b"/one");
    assert_eq!(replies.1, b"/two");
    let seen = seen.borrow();
    assert_eq!(seen[0].bytes, b"hello");
    assert_eq!(seen[1].bytes, b"world");
    assert_eq!(seen[0].pipes + seen[1].pipes, 0);
    assert_eq!(counts.spliced_in.get(), 0);
}

async fn a_consumer_that_offers_nothing_gets_data<I: Listen + Timer + Clone>(io: I) {
    let body = payload(300);
    let sent = body.clone();
    let seen = Rc::default();
    let (counts, (_, reply)) =
        serve_peer(io, recording_service(&seen, false), move |mut stream| {
            send_continued_head(&mut stream, &format!("Content-Length: {}", sent.len()));
            stream.write_all(&sent).expect("send the body");
            read_response(&mut stream)
        })
        .await;
    assert_eq!(reply, b"/up");
    let seen = seen.borrow();
    assert!(seen[0].data > 0);
    assert_eq!(seen[0].pipes, 0);
    assert!(seen[0].bytes == body, "the body arrived intact");
    assert_eq!(counts.spliced_in.get(), 0, "the socket was never spliced");
}

async fn a_dropped_request_body_closes_the_connection<I: Listen + Timer + Clone>(io: I) {
    let first = payload(100);
    let announced = first.len() + 50_000;
    let sent = first.clone();
    let taken = Rc::new(Cell::new(0));
    let service = {
        let taken = taken.clone();
        move |request: Request| {
            let taken = taken.clone();
            async move {
                let mut body = request.into_body();
                let mut offer = PipeOffer::with_pipe(OFFER, Pipe::new().expect("pipe"));
                let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer))
                    .await
                    .expect("a frame")
                    .expect("body frame");
                let BodyFrame::Pipe(filled) = frame else {
                    panic!("expected a pipe frame, got {frame:?}");
                };
                taken.set(filled.len());
                // The rest of the body is never read.
                drop(body);
                Response::new(Body::from_bytes("dropped"))
            }
        }
    };
    let (counts, (reply, rest)) = serve_peer(io, service, move |mut stream| {
        send_continued_head(&mut stream, &format!("Content-Length: {announced}"));
        stream.write_all(&sent).expect("send the first part");
        // The peer holds the rest back, so the server has nothing to reset.
        let reply = read_response(&mut stream).1;
        (reply, read_to_end(&mut stream))
    })
    .await;
    assert_eq!(reply, b"dropped");
    assert!(rest.is_empty(), "the connection closed after the response");
    assert!(taken.get() > 0 && taken.get() <= first.len());
    assert_eq!(counts.spliced_in.get(), taken.get());
}

/// What a response body looked like to the client that read it.
async fn fetch<I: Dial + Timer + Clone, F, Fut>(
    io: I,
    serve: impl FnOnce(TcpStream) + Send + 'static,
    read: F,
) -> (Spy, Fut::Output)
where
    F: FnOnce(Response) -> Fut,
    Fut: Future,
{
    let listener = TcpListener::bind(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(PEER_TIMEOUT))
            .expect("read timeout");
        serve(stream);
    });
    let counts = Spy::default();
    let stream = io.connect(addr).await.expect("connect");
    let (reader, writer) = stream.split();
    let (send, connection) = handshake(
        SpyRead {
            inner: reader,
            counts: counts.clone(),
        },
        SpyWrite {
            inner: writer,
            counts: counts.clone(),
        },
        io.clone(),
        ClientConfig::default(),
    );
    let request = async move {
        let mut request = Request::new(Body::empty());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = format!("http://{addr}/down").parse().unwrap();
        let response = send.send(request).await.expect("response");
        // The handle is dropped with this future, which ends the connection
        // once the response was read.
        read(response).await
    };
    let (ran, output) = zip(connection.run(), request).await;
    assert!(matches!(
        ran.expect("client connection"),
        ClientOutcome::Closed
    ));
    server.join().expect("the server thread");
    (counts, output)
}

/// Reads a request head off `stream`.
fn read_request(stream: &mut TcpStream) {
    read_until(stream, b"\r\n\r\n");
}

async fn close_delimited_response<I: Dial + Timer + Clone>(io: I) {
    let body = payload(300);
    let sent = body.clone();
    let (counts, seen) = fetch(
        io,
        move |mut stream| {
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
                .expect("send the head");
            let (first, second) = sent.split_at(sent.len() / 3);
            thread::sleep(PAUSE);
            stream.write_all(first).expect("send the first run");
            thread::sleep(PAUSE);
            stream.write_all(second).expect("send the rest");
            // Dropping the stream ends the body.
        },
        |response| collect_offering(response.into_body(), OFFER),
    )
    .await;
    assert_eq!(seen.data, 0, "no byte of the body was read into memory");
    assert!(seen.pipes >= 2);
    assert!(seen.bytes == body, "the body arrived intact");
    assert_eq!(counts.spliced_in.get(), body.len());
}

async fn content_length_response<I: Dial + Timer + Clone>(io: I) {
    let body = payload(300);
    let sent = body.clone();
    let (counts, seen) = fetch(
        io,
        move |mut stream| {
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                sent.len()
            )
            .expect("send the head");
            thread::sleep(PAUSE);
            stream.write_all(&sent).expect("send the body");
            // Wait for the client to hang up.
            read_to_end(&mut stream);
        },
        |response| collect_offering(response.into_body(), OFFER),
    )
    .await;
    assert_eq!(seen.data, 0);
    assert!(seen.bytes == body, "the body arrived intact");
    assert_eq!(counts.spliced_in.get(), body.len());
}

async fn chunked_response_with_trailers<I: Dial + Timer + Clone>(io: I) {
    let body = payload(300);
    let sent = body.clone();
    let (counts, seen) = fetch(
        io,
        move |mut stream| {
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .expect("send the head");
            thread::sleep(PAUSE);
            write!(stream, "{:x}\r\n", sent.len()).expect("send the chunk size");
            thread::sleep(PAUSE);
            stream.write_all(&sent).expect("send the chunk");
            thread::sleep(PAUSE);
            stream
                .write_all(b"\r\n0\r\nx-checksum: abc123\r\n\r\n")
                .expect("send the end of the body");
            read_to_end(&mut stream);
        },
        |response| collect_offering(response.into_body(), OFFER),
    )
    .await;
    assert_eq!(seen.data, 0);
    assert!(seen.bytes == body, "the chunk arrived intact");
    assert_eq!(seen.trailers.expect("trailers")["x-checksum"], "abc123");
    assert_eq!(counts.spliced_in.get(), body.len());
}

async fn a_response_that_is_read_without_an_offer_is_data<I: Dial + Timer + Clone>(io: I) {
    let body = payload(300);
    let sent = body.clone();
    let (counts, seen) = fetch(
        io,
        move |mut stream| {
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                sent.len()
            )
            .expect("send the head");
            thread::sleep(PAUSE);
            stream.write_all(&sent).expect("send the body");
            read_to_end(&mut stream);
        },
        |response| collect_plain(response.into_body()),
    )
    .await;
    assert_eq!(seen.pipes, 0);
    assert!(seen.bytes == body, "the body arrived intact");
    assert_eq!(counts.spliced_in.get(), 0, "the socket was never spliced");
}

async fn a_dropped_response_body_closes_the_connection<I: Dial + Timer + Clone>(io: I) {
    let first = payload(100);
    let announced = first.len() + 50_000;
    let sent = first.clone();
    let (counts, taken) = fetch(
        io,
        move |mut stream| {
            read_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {announced}\r\n\r\n"
            )
            .expect("send the head");
            thread::sleep(PAUSE);
            stream.write_all(&sent).expect("send the first part");
            // The client hangs up without the rest.
            read_to_end(&mut stream);
        },
        |response| async move {
            let mut body = response.into_body();
            let mut offer = PipeOffer::with_pipe(OFFER, Pipe::new().expect("pipe"));
            let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer))
                .await
                .expect("a frame")
                .expect("body frame");
            let BodyFrame::Pipe(filled) = frame else {
                panic!("expected a pipe frame, got {frame:?}");
            };
            filled.len()
        },
    )
    .await;
    assert!(taken > 0 && taken <= first.len());
    assert_eq!(counts.spliced_in.get(), taken);
}

// ----- the writing side ------------------------------------------------------

/// A response whose body holds a pipe frame between data, with the bytes
/// `payload` in the pipe; `declared` is its `Content-Length`, or `None` for
/// chunked framing with trailers.
fn response_with_pipe(payload: &[u8], declared: Option<usize>) -> Response {
    let pipe = Pipe::new()
        .expect("pipe")
        .fill(payload)
        .unwrap_or_else(|(error, _)| panic!("fill: {error}"));
    assert_eq!(pipe.len(), payload.len(), "the payload fits one pipe");
    let mut frames = vec![
        Ok::<_, io::Error>(BodyFrame::Data(Bytes::from_static(b"head:"))),
        Ok(BodyFrame::Pipe(pipe)),
        Ok(BodyFrame::Data(Bytes::from_static(b":tail"))),
    ];
    if declared.is_none() {
        let mut trailers = HeaderMap::new();
        trailers.insert("x-checksum", HeaderValue::from_static("abc123"));
        frames.push(Ok(BodyFrame::Trailers(trailers)));
    }
    let mut response = Response::new(Body::from_frames(stream::iter(frames)));
    if let Some(declared) = declared {
        response
            .headers_mut()
            .insert("content-length", HeaderValue::from(declared));
    }
    response
}

async fn pipe_frames_are_sent_with_splice<I: Dial + Listen + Timer + Clone>(io: I, chunked: bool) {
    // Small enough for one pipe, large enough to tell from the framing.
    let payload = payload(200);
    let declared = (!chunked).then(|| "head:".len() + payload.len() + ":tail".len());
    let service = {
        let payload = payload.clone();
        move |_: Request| {
            let response = response_with_pipe(&payload, declared);
            async move { response }
        }
    };
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let counts = Spy::default();
    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        let (reader, writer) = stream.split();
        let connection = ServerConnection::new(
            SpyRead {
                inner: reader,
                counts: counts.clone(),
            },
            SpyWrite {
                inner: writer,
                counts: counts.clone(),
            },
            io.clone(),
            ServerConfig::default(),
        );
        connection.serve(&service).await
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        let (reader, writer) = stream.split();
        let (send, connection) = handshake(reader, writer, io.clone(), ClientConfig::default());
        let request = async move {
            let mut request = Request::new(Body::empty());
            *request.uri_mut() = format!("http://{addr}/pipe").parse().unwrap();
            let response = send.send(request).await.expect("response");
            assert_eq!(
                response.headers().contains_key("transfer-encoding"),
                chunked,
                "{:?}",
                response.headers()
            );
            collect_plain(response.into_body()).await
        };
        let (ran, seen) = zip(connection.run(), request).await;
        assert!(matches!(
            ran.expect("client connection"),
            ClientOutcome::Closed
        ));
        seen
    };
    let (served, seen) = zip(server, client).await;
    assert!(matches!(
        served.expect("server connection"),
        ServerOutcome::Closed
    ));
    let mut expected = b"head:".to_vec();
    expected.extend_from_slice(&payload);
    expected.extend_from_slice(b":tail");
    assert!(seen.bytes == expected, "the body arrived intact");
    assert_eq!(
        seen.trailers.is_some(),
        chunked,
        "trailers follow chunked framing only"
    );
    assert_eq!(
        counts.spliced_out.get(),
        payload.len(),
        "the pipe went to the socket through splice"
    );
    // Heads and framing only: the payload itself never went through `write`.
    assert!(
        counts.written.get() < 512,
        "{} bytes went through write; the pipe was copied",
        counts.written.get()
    );
}

/// What a proxy does: the request body's pipes become the response body.
async fn pipes_forward_from_request_to_response<I: Listen + Timer + Clone>(io: I) {
    let body = payload(200);
    let sent = body.clone();
    let service = |request: Request| async move {
        let length = request.headers()["content-length"].clone();
        let mut body = request.into_body();
        let mut offer = PipeOffer::with_pipe(OFFER, Pipe::new().expect("pipe"));
        let mut frames = Vec::new();
        while let Some(frame) =
            poll_fn(|cx| Pin::new(&mut body).poll_frame_offering(cx, &mut offer)).await
        {
            frames.push(Ok::<_, io::Error>(frame.expect("body frame")));
        }
        assert!(
            frames
                .iter()
                .all(|frame| matches!(frame, Ok(BodyFrame::Pipe(_)))),
            "{frames:?}"
        );
        let mut response = Response::new(Body::from_frames(stream::iter(frames)));
        response.headers_mut().insert("content-length", length);
        response
    };
    let (counts, (head, reply)) = serve_peer(io, service, move |mut stream| {
        send_continued_head(&mut stream, &format!("Content-Length: {}", sent.len()));
        stream.write_all(&sent).expect("send the body");
        read_response(&mut stream)
    })
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(reply == body, "the body arrived intact");
    assert_eq!(counts.spliced_in.get(), body.len());
    assert_eq!(counts.spliced_out.get(), body.len());
    assert!(
        counts.written.get() < 512,
        "{} bytes went through write",
        counts.written.get()
    );
}

macro_rules! suite {
    ($io:expr, $run:expr) => {
        #[test]
        fn content_length_request() {
            $run(super::content_length_request($io));
        }

        #[test]
        fn chunked_request_with_trailers() {
            $run(super::chunked_request_with_trailers($io));
        }

        #[test]
        fn pipelined_request_stays_in_the_socket() {
            $run(super::pipelined_request_stays_in_the_socket($io));
        }

        #[test]
        fn pipelined_requests_in_one_write_are_read_as_data() {
            $run(super::pipelined_requests_in_one_write_are_read_as_data($io));
        }

        #[test]
        fn a_consumer_that_offers_nothing_gets_data() {
            $run(super::a_consumer_that_offers_nothing_gets_data($io));
        }

        #[test]
        fn a_dropped_request_body_closes_the_connection() {
            $run(super::a_dropped_request_body_closes_the_connection($io));
        }

        #[test]
        fn close_delimited_response() {
            $run(super::close_delimited_response($io));
        }

        #[test]
        fn content_length_response() {
            $run(super::content_length_response($io));
        }

        #[test]
        fn chunked_response_with_trailers() {
            $run(super::chunked_response_with_trailers($io));
        }

        #[test]
        fn a_response_that_is_read_without_an_offer_is_data() {
            $run(super::a_response_that_is_read_without_an_offer_is_data($io));
        }

        #[test]
        fn a_dropped_response_body_closes_the_connection() {
            $run(super::a_dropped_response_body_closes_the_connection($io));
        }

        #[test]
        fn a_pipe_is_sent_chunked() {
            $run(super::pipe_frames_are_sent_with_splice($io, true));
        }

        #[test]
        fn a_pipe_is_sent_with_a_content_length() {
            $run(super::pipe_frames_are_sent_with_splice($io, false));
        }

        #[test]
        fn pipes_forward_from_request_to_response() {
            $run(super::pipes_forward_from_request_to_response($io));
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

// ----- sockets that cannot splice --------------------------------------------

mod in_memory {
    use super::*;
    use futures_lite::future::block_on;
    use support::{NeverTimer, connection};

    /// An in-memory read half cannot splice: a body offered a pipe is data.
    #[test]
    fn a_socket_that_cannot_splice_gets_data_for_an_offer() {
        block_on(async {
            let ends = connection();
            let (reader, writer) = ends.server;
            let (mut client_in, mut client_out) = ends.client;
            let seen = Rc::default();
            let service = recording_service(&seen, true);
            client_out.send(
                format!(
                    "POST /up HTTP/1.1\r\nHost: a\r\nContent-Length: {}\r\n\r\n{CJK}",
                    CJK.len()
                )
                .as_bytes(),
            );
            client_out.close();
            let (outcome, _) = zip(
                ServerConnection::new(reader, writer, NeverTimer, ServerConfig::default())
                    .serve(&service),
                client_in.read_to_end(),
            )
            .await;
            assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
            let seen = seen.borrow();
            assert_eq!(seen[0].pipes, 0);
            assert_eq!(seen[0].bytes, CJK.as_bytes());
        });
    }

    /// A writer that cannot splice takes a pipe frame as data, framed like
    /// any other.
    #[test]
    fn a_writer_that_cannot_splice_gets_a_pipe_as_data() {
        block_on(async {
            let ends = connection();
            let (reader, writer) = ends.server;
            let (mut client_in, client_out) = ends.client;
            let service = |_: Request| async { response_with_pipe(CJK.as_bytes(), None) };
            client_out.send(b"GET /pipe HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
            let mut config = ServerConfig::default();
            config.date_header = false;
            let (outcome, wire) = zip(
                ServerConnection::new(reader, writer, NeverTimer, config).serve(&service),
                client_in.read_to_end(),
            )
            .await;
            assert!(matches!(outcome.unwrap(), ServerOutcome::Closed));
            let wire = String::from_utf8(wire).expect("UTF-8");
            let (head, body) = wire.split_once("\r\n\r\n").expect("a head");
            assert!(head.contains("transfer-encoding: chunked"), "{head}");
            let chunk = |data: &str| format!("{:x}\r\n{data}\r\n", data.len());
            let expected = format!(
                "{}{}{}0\r\nx-checksum: abc123\r\n\r\n",
                chunk("head:"),
                chunk(CJK),
                chunk(":tail")
            );
            assert_eq!(body, expected);
        });
    }
}
