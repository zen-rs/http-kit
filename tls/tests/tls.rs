//! TLS over real TCP sockets, on every I/O implementation: handshakes with
//! ALPN, raw full-duplex streams, and HTTP/1.1 over TLS.
//!
//! On Linux with the `kernel` feature every connection must end up in kernel
//! TLS (the CI runner loads the `tls` module), and a file region must reach
//! the socket through its own `send_file` — `splice` with compio,
//! `sendfile` with tokio — encrypted by the kernel. Everywhere else the same
//! tests run in user space, where a file region is read and encrypted.

use std::{
    borrow::Borrow, cell::Cell, fs::File, future::Future, io, net::SocketAddr, path::PathBuf,
    rc::Rc, sync::Arc, time::Duration,
};

use futures_lite::future::zip;
use http::Method;
use http_kit::{Body, BodyFrame, Request, Response};
use http_kit_h1::{ClientConfig, ServerConfig, ServerConnection, handshake_stream};
use http_kit_io::{
    BufResult, Io, IoBuf, IoVectoredBuf, Listener as _, Read, SendFile, Split, Write,
};
use http_kit_tls::{
    Client, Mode, Server, TlsAcceptor, TlsConnector, TlsStream, Transport,
    rustls::{
        self, SupportedCipherSuite, SupportedProtocolVersion,
        crypto::{CryptoProvider, ring},
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _},
    },
};

/// Greetings in Chinese, Japanese and Korean.
const CJK: &str = "你好，世界。こんにちは、世界。안녕하세요, 세계.";

/// The mode every connection here must end up in.
const EXPECTED: Mode = if cfg!(all(target_os = "linux", feature = "kernel")) {
    Mode::Kernel
} else {
    Mode::User
};

/// CJK text repeated well past a socket buffer and many 16 KiB records,
/// with a line number per line so a misplaced record shows.
fn cjk_body(lines: usize) -> Vec<u8> {
    (0..lines)
        .flat_map(|line| format!("{line:06} {CJK}\n").into_bytes())
        .collect()
}

#[track_caller]
fn assert_bytes(actual: &[u8], expected: &[u8]) {
    let mismatch = actual.iter().zip(expected).position(|(a, e)| a != e);
    assert!(
        actual.len() == expected.len() && mismatch.is_none(),
        "got {} bytes, expected {}; first difference at {mismatch:?}",
        actual.len(),
        expected.len(),
    );
}

/// A certificate for `localhost`, issued as PEM the way it is read from
/// files.
struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl Identity {
    fn new() -> Self {
        let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("issue a certificate");
        let (cert_pem, key_pem) = (issued.cert.pem(), issued.signing_key.serialize_pem());
        Self {
            chain: CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                .collect::<Result<_, _>>()
                .expect("certificate PEM"),
            key: PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("key PEM"),
        }
    }
}

/// One suite and version to run a connection on.
#[derive(Clone, Copy)]
struct Params {
    suite: SupportedCipherSuite,
    version: &'static SupportedProtocolVersion,
}

const TLS13_AES_128: Params = Params {
    suite: ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    version: &rustls::version::TLS13,
};

fn provider(params: Params) -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        cipher_suites: vec![params.suite],
        ..ring::default_provider()
    })
}

fn server_config(identity: &Identity, params: Params, alpn: &[&[u8]]) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder_with_provider(provider(params))
        .with_protocol_versions(&[params.version])
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(identity.chain.clone(), identity.key.clone_key())
        .expect("server certificate");
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

fn acceptor(identity: &Identity, params: Params, alpn: &[&[u8]]) -> TlsAcceptor {
    acceptor_for(server_config(identity, params, alpn))
}

fn acceptor_for(config: rustls::ServerConfig) -> TlsAcceptor {
    let acceptor = TlsAcceptor::new(Arc::new(config));
    #[cfg(feature = "kernel")]
    let acceptor = acceptor.with_kernel_tls(http_kit_tls::KernelTls::probe().expect("probe"));
    acceptor
}

fn connector(identity: &Identity, params: Params, alpn: &[&[u8]]) -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(identity.chain[0].clone()).expect("trust root");
    let mut config = rustls::ClientConfig::builder_with_provider(provider(params))
        .with_protocol_versions(&[params.version])
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let connector = TlsConnector::new(Arc::new(config));
    #[cfg(feature = "kernel")]
    let connector = connector.with_kernel_tls(http_kit_tls::KernelTls::probe().expect("probe"));
    connector
}

fn localhost() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("a DNS name")
}

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Accepts one TLS connection and dials it, handing each end to its task.
async fn tls_pair<I, S, C, SF, CF>(
    io: I,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    server: S,
    client: C,
) -> (SF::Output, CF::Output)
where
    I: Io,
    I::TcpStream: Transport,
    S: FnOnce(TlsStream<I::TcpStream, Server>) -> SF,
    C: FnOnce(TlsStream<I::TcpStream, Client>) -> CF,
    SF: Future,
    CF: Future,
{
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        let stream = acceptor
            .accept(stream, &io)
            .await
            .expect("server handshake");
        server(stream).await
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        let stream = connector
            .connect(localhost(), stream, &io)
            .await
            .expect("client handshake");
        client(stream).await
    };
    zip(server, client).await
}

async fn read_to_end(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = Vec::with_capacity(8192);
    loop {
        let BufResult(res, filled) = reader.read(buf).await;
        if res? == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&filled);
        buf = filled;
    }
}

/// ALPN picks the server's preference among what the client offers, and a
/// large body crosses in both directions at once: the server echoes from
/// its reading half to its writing half while the client is still writing.
async fn alpn_and_full_duplex_echo<I: Io>(io: I)
where
    I::TcpStream: Transport,
{
    let identity = Identity::new();
    let body = cjk_body(40_000);
    let (served, echoed) = tls_pair(
        io,
        acceptor(&identity, TLS13_AES_128, &[b"h2", b"http/1.1"]),
        connector(&identity, TLS13_AES_128, &[b"http/1.1", b"h2"]),
        |stream| async move {
            assert_eq!(stream.alpn_protocol(), Some(&b"h2"[..]));
            assert_eq!(stream.mode(), EXPECTED);
            let (mut read, mut write) = stream.split();
            let mut buf = Vec::with_capacity(20_000);
            let mut echoed = 0;
            loop {
                let BufResult(res, filled) = read.read(buf).await;
                if res.expect("server read") == 0 {
                    break;
                }
                let BufResult(res, filled) = write.write_all(filled).await;
                res.expect("server write");
                echoed += filled.len();
                buf = filled;
            }
            write.shutdown().await.expect("server shutdown");
            echoed
        },
        |stream| async {
            assert_eq!(stream.negotiated().alpn_protocol(), Some(&b"h2"[..]));
            assert_eq!(stream.mode(), EXPECTED);
            let (mut read, mut write) = stream.split();
            let send = async {
                // Unequal pieces, so records do not line up with writes.
                for piece in body.chunks(30_011) {
                    let BufResult(res, _) = write.write_all(piece.to_vec()).await;
                    res.expect("client write");
                }
                write.shutdown().await.expect("client shutdown");
            };
            let ((), echoed) = zip(send, read_to_end(&mut read)).await;
            echoed.expect("client read")
        },
    )
    .await;
    assert_eq!(served, body.len());
    assert_bytes(&echoed, &body);
}

/// Every suite kernel TLS can take, on TLS 1.3 and TLS 1.2: the handshake
/// settles on it, and data crosses both ways.
async fn every_kernel_suite<I: Io>(io: I)
where
    I::TcpStream: Transport,
{
    let identity = Identity::new();
    let tls12 = &rustls::version::TLS12;
    let tls13 = &rustls::version::TLS13;
    let cases = [
        (ring::cipher_suite::TLS13_AES_128_GCM_SHA256, tls13),
        (ring::cipher_suite::TLS13_AES_256_GCM_SHA384, tls13),
        (ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256, tls13),
        (
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            tls12,
        ),
        (
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls12,
        ),
        (
            ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            tls12,
        ),
    ];
    let request = &cjk_body(3_000);
    for (suite, version) in cases {
        let params = Params { suite, version };
        let (served, answer) = tls_pair(
            io.clone(),
            acceptor(&identity, params, &[]),
            connector(&identity, params, &[]),
            |mut stream| async move {
                let negotiated = stream.negotiated().clone();
                let received = read_to_end(&mut stream).await.expect("server read");
                let BufResult(res, _) = stream.write_all(received.clone()).await;
                res.expect("server write");
                stream.shutdown().await.expect("server shutdown");
                (negotiated, received)
            },
            |mut stream| async move {
                let BufResult(res, _) = stream.write_all(request.clone()).await;
                res.expect("client write");
                stream.shutdown().await.expect("client shutdown");
                (
                    stream.mode(),
                    read_to_end(&mut stream).await.expect("client read"),
                )
            },
        )
        .await;
        let (negotiated, received) = served;
        let name = suite.suite();
        assert_eq!(negotiated.cipher_suite().suite(), name);
        assert_eq!(negotiated.protocol_version(), version.version, "{name:?}");
        assert_eq!(negotiated.mode(), EXPECTED, "server on {name:?}");
        assert_eq!(answer.0, EXPECTED, "client on {name:?}");
        assert_bytes(&received, request);
        assert_bytes(&answer.1, request);
    }
}

/// Bytes that left a socket's write half through `write` and through
/// `send_file`.
#[derive(Debug, Default, Clone, Copy)]
struct Sent {
    written: usize,
    sent_from_file: usize,
}

/// A stream whose write half counts what goes through each path, beneath
/// TLS: in kernel mode a file region must take `send_file` all the way down.
struct Counted<S> {
    inner: S,
    sent: Rc<Cell<Sent>>,
}

struct CountingWrite<W> {
    inner: W,
    sent: Rc<Cell<Sent>>,
}

impl<W> CountingWrite<W> {
    fn add(&self, res: &io::Result<usize>, from_file: bool) {
        if let Ok(n) = res {
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

impl<S: Split> Split for Counted<S>
where
    S::WriteHalf: SendFile,
{
    type ReadHalf = S::ReadHalf;
    type WriteHalf = CountingWrite<S::WriteHalf>;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        let (read, write) = self.inner.split();
        (
            read,
            CountingWrite {
                inner: write,
                sent: self.sent,
            },
        )
    }
}

impl<W: Write> Write for CountingWrite<W> {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let res = self.inner.write(buf).await;
        self.add(&res.0, false);
        res
    }

    async fn write_vectored<B: IoVectoredBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        let res = self.inner.write_vectored(buf).await;
        self.add(&res.0, false);
        res
    }

    fn flush(&mut self) -> impl Future<Output = io::Result<()>> {
        self.inner.flush()
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.inner.shutdown()
    }
}

impl<W: SendFile> SendFile for CountingWrite<W> {
    async fn send_file<F: Borrow<File> + 'static>(
        &mut self,
        file: F,
        offset: u64,
        len: usize,
    ) -> BufResult<usize, F> {
        let res = self.inner.send_file(file, offset, len).await;
        self.add(&res.0, true);
        res
    }
}

#[cfg(unix)]
impl<W: http_kit_io::WriteControl> http_kit_io::WriteControl for CountingWrite<W> {
    fn write_control<B: IoBuf, C: IoBuf>(
        &mut self,
        buf: B,
        control: C,
    ) -> impl Future<Output = BufResult<usize, (B, C)>> {
        self.inner.write_control(buf, control)
    }
}

#[cfg(unix)]
impl<W: std::os::fd::AsFd> std::os::fd::AsFd for CountingWrite<W> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// A file larger than many records, with CJK text throughout.
fn payload_file(name: &str) -> (PathBuf, Vec<u8>) {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name.replace("::", "-"));
    let contents = cjk_body(20_000);
    std::fs::write(&path, &contents).expect("write the file to serve");
    (path, contents)
}

fn request(method: Method, path: &str, body: Body) -> Request {
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = format!("https://localhost{path}").parse().unwrap();
    request
}

/// HTTP/1.1 over TLS: a large CJK request body echoed back on a kept-alive
/// connection, then a file region, which in kernel mode leaves through the
/// socket's `send_file` and in user mode is read and encrypted.
async fn http1_over_tls<I: Io>(io: I, name: &str)
where
    I::TcpStream: Transport,
{
    let identity = Identity::new();
    let (path, contents) = payload_file(name);
    let (offset, len) = (7, contents.len() - 7 - 3);
    let echo = cjk_body(30_000);
    let sent = Rc::new(Cell::new(Sent::default()));

    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let acceptor = acceptor(&identity, TLS13_AES_128, &[b"http/1.1"]);
    let connector = connector(&identity, TLS13_AES_128, &[b"http/1.1"]);
    let service = |request: Request| {
        let path = path.clone();
        async move {
            if request.uri().path() == "/file" {
                let file = File::open(&path).expect("open the file to serve");
                return Response::new(Body::from_file_region(http_kit::FileRegion::new(
                    file,
                    offset as u64,
                    len as u64,
                )));
            }
            let body = request
                .into_body()
                .into_bytes()
                .await
                .expect("request body");
            Response::new(Body::from_bytes(body))
        }
    };
    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        let stream = Counted {
            inner: stream,
            sent: sent.clone(),
        };
        let stream = acceptor
            .accept(stream, &io)
            .await
            .expect("server handshake");
        assert_eq!(stream.mode(), EXPECTED);
        ServerConnection::from_stream(stream, io.clone(), ServerConfig::default())
            .serve(&service)
            .await
            .expect("server connection");
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        let stream = connector
            .connect(localhost(), stream, &io)
            .await
            .expect("client handshake");
        let (send, conn) = handshake_stream(stream, io.clone(), ClientConfig::default());
        let sent = sent.clone();
        let requests = async move {
            for round in 0..2 {
                let body = Body::from_frames(futures_lite::stream::iter(
                    echo.chunks(50_000)
                        .map(|chunk| Ok::<_, io::Error>(BodyFrame::Data(chunk.to_vec().into())))
                        .collect::<Vec<_>>(),
                ));
                let response = send
                    .send(request(Method::POST, "/echo", body))
                    .await
                    .expect("echo response");
                let body = response.into_body().into_bytes().await.expect("echo body");
                assert_bytes(&body, &echo);
                assert!(!send.is_closed(), "round {round} kept the connection");
            }
            let before = sent.get();
            let response = send
                .send(request(Method::GET, "/file", Body::empty()))
                .await
                .expect("file response");
            assert_eq!(
                response.headers()["content-length"],
                len.to_string().as_str()
            );
            let body = response.into_body().into_bytes().await.expect("file body");
            let after = sent.get();
            (body, before, after)
        };
        let (ran, out) = zip(conn.run(), requests).await;
        ran.expect("client connection");
        out
    };
    let ((), (body, before, after)) = zip(server, client).await;
    std::fs::remove_file(&path).expect("remove the served file");
    assert_bytes(&body, &contents[offset..offset + len]);
    let from_file = after.sent_from_file - before.sent_from_file;
    let written = after.written - before.written;
    match EXPECTED {
        Mode::Kernel => {
            assert_eq!(from_file, len, "the region went to the socket's send_file");
            assert!(
                written <= 512,
                "{written} bytes went through write: the region was copied"
            );
        }
        Mode::User => {
            assert_eq!(
                from_file, 0,
                "user-space TLS cannot send a file unencrypted"
            );
            assert!(written > len, "the region went out encrypted");
        }
    }
}

/// A peer that connects and never speaks is refused at the deadline.
async fn handshake_deadline<I: Io>(io: I)
where
    I::TcpStream: Transport,
{
    let identity = Identity::new();
    let acceptor = acceptor(&identity, TLS13_AES_128, &[])
        .with_handshake_timeout(Some(Duration::from_millis(100)));
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        acceptor.accept(stream, &io).await
    };
    let (accepted, silent) = zip(server, io.connect(addr)).await;
    let error = accepted.expect_err("a silent peer is refused");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    drop(silent);
}

/// A connection closed without `close_notify` is cut short, not ended.
async fn truncation_is_an_error<I: Io>(io: I)
where
    I::TcpStream: Transport,
{
    let identity = Identity::new();
    // No session tickets: a client that closes with tickets still unread in
    // its receive buffer makes the kernel answer with a reset, so the server
    // would see `ConnectionReset` from TCP rather than the missing
    // `close_notify` this test is about.
    let mut config = server_config(&identity, TLS13_AES_128, &[]);
    config.send_tls13_tickets = 0;
    let (read, ()) = tls_pair(
        io,
        acceptor_for(config),
        connector(&identity, TLS13_AES_128, &[]),
        |mut stream| async move {
            let mut buf = Vec::with_capacity(64);
            loop {
                let BufResult(res, filled) = stream.read(buf).await;
                match res {
                    Ok(0) => return Ok(()),
                    Ok(_) => buf = filled,
                    Err(error) => return Err(error),
                }
            }
        },
        |mut stream| async move {
            let BufResult(res, _) = stream.write_all(CJK.as_bytes().to_vec()).await;
            res.expect("client write");
            // Dropped without a shutdown: TCP closes, no close_notify.
        },
    )
    .await;
    assert_eq!(
        read.expect_err("a truncated stream fails").kind(),
        io::ErrorKind::UnexpectedEof
    );
}

macro_rules! suite {
    ($io:expr, $run:expr) => {
        #[test]
        fn alpn_and_full_duplex_echo() {
            $run(super::alpn_and_full_duplex_echo($io));
        }

        #[test]
        fn every_kernel_suite() {
            $run(super::every_kernel_suite($io));
        }

        #[test]
        fn http1_over_tls() {
            $run(super::http1_over_tls(
                $io,
                concat!(module_path!(), "-http1"),
            ));
        }

        #[test]
        fn handshake_deadline() {
            $run(super::handshake_deadline($io));
        }

        #[test]
        fn truncation_is_an_error() {
            $run(super::truncation_is_an_error($io));
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
