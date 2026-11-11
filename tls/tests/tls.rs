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
    BufResult, Dial, IoBuf, IoVectoredBuf, Listen, Listener, Read, SendFile, SpliceRead,
    SpliceWrite, Split, Timer, Write,
};
use http_kit_tls::{
    Client, HandshakeError, Mode, Server, TlsAcceptor, TlsConnector, TlsStream, Transport,
    rustls::{
        self, AlertDescription, SupportedCipherSuite, SupportedProtocolVersion,
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

fn client_config(identity: &Identity, params: Params, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(identity.chain[0].clone()).expect("trust root");
    let mut config = rustls::ClientConfig::builder_with_provider(provider(params))
        .with_protocol_versions(&[params.version])
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config
}

fn connector(identity: &Identity, params: Params, alpn: &[&[u8]]) -> TlsConnector {
    let connector = TlsConnector::new(Arc::new(client_config(identity, params, alpn)));
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

/// The stream a listener of `I` accepts.
type Accepted<I> = <<I as Listen>::Listener as Listener>::Stream;

/// Accepts one TLS connection and dials it, handing each end to its task.
async fn tls_pair<I, S, C, SF, CF>(
    io: I,
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    server: S,
    client: C,
) -> (SF::Output, CF::Output)
where
    I: Dial + Listen + Timer,
    I::Connection: Transport,
    Accepted<I>: Transport,
    S: FnOnce(TlsStream<Accepted<I>, Server>) -> SF,
    C: FnOnce(TlsStream<I::Connection, Client>) -> CF,
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
async fn alpn_and_full_duplex_echo<I: Dial + Listen + Timer>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
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
async fn every_kernel_suite<I: Dial + Listen + Timer + Clone>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
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

impl<W: http_kit_io::SpliceWrite> http_kit_io::SpliceWrite for CountingWrite<W> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn can_splice(&self) -> bool {
        self.inner.can_splice()
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    async fn splice_from_pipe(
        &mut self,
        filled: http_kit_io::splice::FilledPipe,
    ) -> io::Result<http_kit_io::splice::Pipe> {
        let len = filled.len();
        let pipe = self.inner.splice_from_pipe(filled).await?;
        self.add(&Ok(len), false);
        Ok(pipe)
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
async fn http1_over_tls<I: Dial + Listen + Timer + Clone>(io: I, name: &str)
where
    I::Connection: Transport,
    // The counting wrapper is a socket only where its halves are: kernel TLS
    // needs the descriptor, which `Transport` alone no longer implies.
    Counted<Accepted<I>>: Transport,
{
    let identity = Identity::new();
    let (path, contents) = payload_file(name);
    let (offset, len) = (7, contents.len() - 7 - 3);
    let echo = cjk_body(30_000);
    let sent = Rc::new(Cell::new(Sent::default()));
    // The counts when the file request reaches the server: every earlier
    // response has been written by then. A client-side reading would race the
    // server's write completions, which may land after the peer has the bytes.
    let before_file = Rc::new(Cell::new(None::<Sent>));

    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let acceptor = acceptor(&identity, TLS13_AES_128, &[b"http/1.1"]);
    let connector = connector(&identity, TLS13_AES_128, &[b"http/1.1"]);
    let service = |request: Request| {
        let path = path.clone();
        let sent = sent.clone();
        let before_file = before_file.clone();
        async move {
            if request.uri().path() == "/file" {
                before_file.set(Some(sent.get()));
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
            let response = send
                .send(request(Method::GET, "/file", Body::empty()))
                .await
                .expect("file response");
            assert_eq!(
                response.headers()["content-length"],
                len.to_string().as_str()
            );
            response.into_body().into_bytes().await.expect("file body")
        };
        let (ran, out) = zip(conn.run(), requests).await;
        ran.expect("client connection");
        out
    };
    let ((), body) = zip(server, client).await;
    // The server has returned, so all its write completions are counted.
    let after = sent.get();
    let before = before_file
        .get()
        .expect("the file request reached the server");
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
async fn handshake_deadline<I: Dial + Listen + Timer>(io: I)
where
    Accepted<I>: Transport,
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
    match accepted.expect_err("a silent peer is refused") {
        HandshakeError::TimedOut(deadline) => assert_eq!(deadline, Duration::from_millis(100)),
        other => panic!("expected a handshake timeout, got {other:?}"),
    }
    drop(silent);
}

/// A server whose certificate the client does not trust is a certificate
/// failure, not a timeout, an alert or a transport error.
async fn bad_certificate<I: Dial + Listen + Timer>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
{
    let served = Identity::new();
    let trusted = Identity::new();
    let acceptor = acceptor(&served, TLS13_AES_128, &[]);
    let connector = connector(&trusted, TLS13_AES_128, &[]);
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        // The client hangs up on rejecting the certificate.
        acceptor.accept(stream, &io).await.map(drop)
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        connector.connect(localhost(), stream, &io).await.map(drop)
    };
    let (_, client) = zip(server, client).await;
    match client.expect_err("an untrusted certificate is refused") {
        HandshakeError::Tls(rustls::Error::InvalidCertificate(_)) => {}
        other => panic!("expected a certificate failure, got {other:?}"),
    }
}

/// A fatal alert from the peer is rustls's `AlertReceived`, not a transport
/// error.
async fn received_alert<I: Dial + Listen + Timer>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
{
    /// A fatal `handshake_failure` alert record (RFC 8446 §6, `AlertLevel`
    /// 2, `AlertDescription` 40) in TLS 1.2's record framing.
    const HANDSHAKE_FAILURE: [u8; 7] = [21, 3, 3, 0, 2, 2, 40];

    let identity = Identity::new();
    let connector = connector(&identity, TLS13_AES_128, &[]);
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let peer = async {
        let (stream, _) = listener.accept().await.expect("accept");
        let (read, mut write) = stream.split();
        let BufResult(res, _) = write.write_all(HANDSHAKE_FAILURE.to_vec()).await;
        res.expect("peer write");
        // Held open until the client has read the alert: closing with the
        // ClientHello unread would reset the connection instead.
        (read, write)
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        connector.connect(localhost(), stream, &io).await.map(drop)
    };
    let (_peer, client) = zip(peer, client).await;
    match client.expect_err("an alert refuses the handshake") {
        HandshakeError::Tls(rustls::Error::AlertReceived(AlertDescription::HandshakeFailure)) => {}
        other => panic!("expected a received alert, got {other:?}"),
    }
}

/// A connection closed without `close_notify` is cut short, not ended.
async fn truncation_is_an_error<I: Dial + Listen + Timer>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
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

/// A TLS session inside another, as a client tunnelling through an HTTPS
/// proxy runs: the outer session over the socket (in the kernel where it
/// can be), the inner one over the outer stream, which only user space can
/// serve. Data crosses both ways through both layers.
async fn tls_in_tls<I: Dial + Listen + Timer + Clone>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
{
    let proxy = Identity::new();
    let origin = Identity::new();
    let body = cjk_body(20_000);
    let sent = body.clone();
    let inner_acceptor = acceptor(&origin, TLS13_AES_128, &[b"http/1.1"]);
    let inner_connector = connector(&origin, TLS13_AES_128, &[b"http/1.1"]);
    let server_io = io.clone();
    let client_io = io.clone();
    let (served, echoed) = tls_pair(
        io,
        acceptor(&proxy, TLS13_AES_128, &[]),
        connector(&proxy, TLS13_AES_128, &[]),
        |outer| async move {
            assert_eq!(outer.mode(), EXPECTED);
            let inner = inner_acceptor
                .accept(outer, &server_io)
                .await
                .expect("inner server handshake");
            assert_eq!(inner.mode(), Mode::User);
            assert_eq!(inner.alpn_protocol(), Some(&b"http/1.1"[..]));
            let (mut read, mut write) = inner.split();
            let mut buf = Vec::with_capacity(20_000);
            let mut echoed = 0;
            loop {
                let BufResult(res, filled) = read.read(buf).await;
                if res.expect("inner server read") == 0 {
                    break;
                }
                let BufResult(res, filled) = write.write_all(filled).await;
                res.expect("inner server write");
                echoed += filled.len();
                buf = filled;
            }
            write.shutdown().await.expect("inner server shutdown");
            echoed
        },
        |outer| async move {
            assert_eq!(outer.mode(), EXPECTED);
            let inner = inner_connector
                .connect(localhost(), outer, &client_io)
                .await
                .expect("inner client handshake");
            assert_eq!(inner.mode(), Mode::User);
            let (mut read, mut write) = inner.split();
            let send = async {
                for piece in sent.chunks(30_011) {
                    let BufResult(res, _) = write.write_all(piece.to_vec()).await;
                    res.expect("inner client write");
                }
                write.shutdown().await.expect("inner client shutdown");
            };
            let ((), echoed) = zip(send, read_to_end(&mut read)).await;
            echoed.expect("inner client read")
        },
    )
    .await;
    assert_eq!(served, body.len());
    assert_bytes(&echoed, &body);
}

/// A stream a caller joins from two halves it holds, as an HTTP client does
/// after CONNECT through an HTTPS proxy.
struct Joined<R, W>(R, W);

impl<R: Read + 'static, W: Write + 'static> Split for Joined<R, W> {
    type ReadHalf = R;
    type WriteHalf = W;

    fn split(self) -> (R, W) {
        (self.0, self.1)
    }
}

/// A TLS session over a stream joined from a TLS connection's two halves is a
/// [`Transport`] whatever the features, and stays in user space.
async fn tls_over_joined_halves<I: Dial + Listen + Timer + Clone>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
{
    let proxy = Identity::new();
    let origin = Identity::new();
    let body = cjk_body(2_000);
    let sent = body.clone();
    let inner_acceptor = acceptor(&origin, TLS13_AES_128, &[]);
    let inner_connector = connector(&origin, TLS13_AES_128, &[]);
    let server_io = io.clone();
    let client_io = io.clone();
    let (served, echoed) = tls_pair(
        io,
        acceptor(&proxy, TLS13_AES_128, &[]),
        connector(&proxy, TLS13_AES_128, &[]),
        |outer| async move {
            let (read, write) = outer.split();
            let inner = inner_acceptor
                .accept(Joined(read, write), &server_io)
                .await
                .expect("inner server handshake");
            assert_eq!(inner.mode(), Mode::User);
            let (mut read, mut write) = inner.split();
            let mut buf = Vec::with_capacity(20_000);
            let mut echoed = 0;
            loop {
                let BufResult(res, filled) = read.read(buf).await;
                if res.expect("inner server read") == 0 {
                    break;
                }
                let BufResult(res, filled) = write.write_all(filled).await;
                res.expect("inner server write");
                echoed += filled.len();
                buf = filled;
            }
            write.shutdown().await.expect("inner server shutdown");
            echoed
        },
        |outer| async move {
            let (read, write) = outer.split();
            let inner = inner_connector
                .connect(localhost(), Joined(read, write), &client_io)
                .await
                .expect("inner client handshake");
            assert_eq!(inner.mode(), Mode::User);
            let (mut read, mut write) = inner.split();
            let send = async {
                for piece in sent.chunks(30_011) {
                    let BufResult(res, _) = write.write_all(piece.to_vec()).await;
                    res.expect("inner client write");
                }
                write.shutdown().await.expect("inner client shutdown");
            };
            let ((), echoed) = zip(send, read_to_end(&mut read)).await;
            echoed.expect("inner client read")
        },
    )
    .await;
    assert_eq!(served, body.len());
    assert_bytes(&echoed, &body);
}

fn assert_read_splice<T: SpliceRead>() {}

fn assert_write_splice<T: SpliceWrite>() {}

/// A TLS stream and its halves implement the splice traits on every
/// platform, whichever transport they run over.
#[test]
fn tls_stream_and_halves_implement_the_splice_traits() {
    fn check<S: Transport>() {
        assert_read_splice::<TlsStream<S, Server>>();
        assert_write_splice::<TlsStream<S, Client>>();
        assert_read_splice::<<TlsStream<S, Server> as Split>::ReadHalf>();
        assert_write_splice::<<TlsStream<S, Client> as Split>::WriteHalf>();
    }
    check::<<http_kit_io::tokio::Tokio as Dial>::Connection>();
    check::<<http_kit_io::compio::Compio as Dial>::Connection>();
}

/// A connection encrypted in user space reports that it cannot splice, on
/// the stream and on both halves, and refuses a splice with the pipe back.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn user_mode_cannot_splice<I: Dial + Listen + Timer>(io: I)
where
    I::Connection: Transport,
    Accepted<I>: Transport,
{
    use http_kit_io::splice::Pipe;

    async fn check<T>(mut stream: T)
    where
        T: SpliceRead + SpliceWrite + Split,
        T::ReadHalf: SpliceRead,
        T::WriteHalf: SpliceWrite,
    {
        assert!(!SpliceRead::can_splice(&stream));
        assert!(!SpliceWrite::can_splice(&stream));
        let (error, _) = SpliceRead::splice_to_pipe(&mut stream, Pipe::new().expect("pipe"), 1)
            .await
            .expect_err("a user-space connection cannot splice in");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);

        let (mut read, mut write) = stream.split();
        assert!(!SpliceRead::can_splice(&read));
        assert!(!SpliceWrite::can_splice(&write));
        let (error, _) = SpliceRead::splice_to_pipe(&mut read, Pipe::new().expect("pipe"), 1)
            .await
            .expect_err("a user-space half cannot splice in");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        let filled = Pipe::new()
            .expect("pipe")
            .fill(CJK.as_bytes())
            .unwrap_or_else(|(error, _)| panic!("fill: {error}"));
        let error = SpliceWrite::splice_from_pipe(&mut write, filled)
            .await
            .expect_err("a user-space half cannot splice out");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    let identity = Identity::new();
    // No kernel probe is given, so the records stay in user space.
    let acceptor = TlsAcceptor::new(Arc::new(server_config(&identity, TLS13_AES_128, &[])));
    let connector = TlsConnector::new(Arc::new(client_config(&identity, TLS13_AES_128, &[])));
    tls_pair(
        io,
        acceptor,
        connector,
        |stream| async move {
            assert_eq!(stream.mode(), Mode::User);
            check(stream).await;
        },
        |stream| async move {
            assert_eq!(stream.mode(), Mode::User);
            check(stream).await;
        },
    )
    .await;
}

/// Forwarding through TLS against an independent TLS implementation
/// (rustls's buffered API on a thread of its own), so the key changes and
/// session tickets come from a peer that is not this crate.
///
/// Where the connection is in kernel mode the subject forwards by
/// splicing; everywhere else it reads and writes, and the same peers check
/// the exchange itself.
mod forward {
    use std::{
        io::{Read as _, Write as _},
        net::{SocketAddr, TcpListener, TcpStream},
        ops::DerefMut,
        sync::Arc,
        thread::{self, JoinHandle},
    };

    use http_kit_io::{
        BufResult, Dial, Listen, Listener as _, SpliceRead, SpliceWrite, Split, Timer, Write,
    };
    use http_kit_tls::{Transport, rustls};

    use super::{
        Accepted, CJK, EXPECTED, Identity, Mode, TLS13_AES_128, acceptor, assert_bytes, cjk_body,
        client_config, connector, localhost, loopback, server_config,
    };

    /// Whether the subject's connections forward by splicing.
    const SPLICES: bool = cfg!(all(target_os = "linux", feature = "kernel"));

    /// How many bytes the peer sends before it reads the echo of them.
    const ROUND: usize = 40_000;

    /// Whether the running kernel takes a new key for a direction it
    /// already has one for (a TLS 1.3 `KeyUpdate`), which Linux 6.13 added
    /// for receiving. Connections in user space always do.
    fn takes_key_updates() -> bool {
        #[cfg(all(target_os = "linux", feature = "kernel"))]
        {
            let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
                .expect("the running kernel's release");
            let mut numbers = release
                .trim()
                .split(['.', '-'])
                .map(|part| part.parse::<u32>().expect("a number in the kernel release"));
            let version = (numbers.next().unwrap_or(0), numbers.next().unwrap_or(0));
            let takes = version >= (6, 13);
            if !takes {
                eprintln!(
                    "kernel {} cannot take a new receive key: the KeyUpdate step is skipped",
                    release.trim()
                );
            }
            takes
        }
        #[cfg(not(all(target_os = "linux", feature = "kernel")))]
        {
            true
        }
    }

    /// The round before which the peer asks for new keys, if the connection
    /// can take them: half the rounds cross the change.
    fn rekey_before(payload: &[u8]) -> Option<usize> {
        takes_key_updates().then(|| payload.chunks(ROUND).count() / 2)
    }

    /// The peer's side of a lockstep exchange: it sends a round, reads the
    /// same bytes back, and repeats, so neither side's socket buffers fill
    /// while the other is not reading. Keys are refreshed once, before the
    /// round `rekey_before`; the connection ends with a `close_notify`.
    fn lockstep<C, T>(
        mut tls: rustls::StreamOwned<C, TcpStream>,
        payload: &[u8],
        rekey_before: Option<usize>,
    ) -> Vec<u8>
    where
        C: DerefMut + std::ops::Deref<Target = rustls::ConnectionCommon<T>>,
        T: rustls::SideData,
    {
        let mut echoed = Vec::new();
        for (round, chunk) in payload.chunks(ROUND).enumerate() {
            if rekey_before == Some(round) {
                tls.conn
                    .refresh_traffic_keys()
                    .expect("ask for a key update");
            }
            tls.write_all(chunk).expect("peer write");
            tls.flush().expect("peer flush");
            let mut back = vec![0; chunk.len()];
            tls.read_exact(&mut back).expect("peer read");
            echoed.extend_from_slice(&back);
        }
        tls.conn.send_close_notify();
        tls.flush().expect("peer close_notify");
        let mut rest = Vec::new();
        tls.read_to_end(&mut rest)
            .expect("peer reads up to the close_notify");
        assert!(
            rest.is_empty(),
            "the echo ended with {} extra bytes",
            rest.len()
        );
        echoed
    }

    fn client_peer(
        addr: SocketAddr,
        config: rustls::ClientConfig,
        payload: Vec<u8>,
        rekey_before: Option<usize>,
    ) -> JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let socket = TcpStream::connect(addr).expect("peer connect");
            let conn = rustls::ClientConnection::new(Arc::new(config), localhost())
                .expect("peer client connection");
            lockstep(
                rustls::StreamOwned::new(conn, socket),
                &payload,
                rekey_before,
            )
        })
    }

    fn server_peer(
        listener: TcpListener,
        config: rustls::ServerConfig,
        payload: Vec<u8>,
        rekey_before: Option<usize>,
    ) -> JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let (socket, _) = listener.accept().expect("peer accept");
            let conn =
                rustls::ServerConnection::new(Arc::new(config)).expect("peer server connection");
            lockstep(
                rustls::StreamOwned::new(conn, socket),
                &payload,
                rekey_before,
            )
        })
    }

    /// Everything `read` yields goes into `write`, until the stream ends and
    /// `write` is shut down. Returns how many bytes.
    ///
    /// In kernel mode the bytes go through a pipe, never into memory.
    async fn echo(read: &mut impl SpliceRead, write: &mut impl SpliceWrite) -> usize {
        let mut echoed = 0;
        #[cfg(all(target_os = "linux", feature = "kernel"))]
        {
            use http_kit_io::splice::{Pipe, Spliced};

            let mut pipe = Pipe::new().expect("pipe");
            loop {
                match read.splice_to_pipe(pipe, usize::MAX).await {
                    Ok(Spliced::Filled(filled)) => {
                        echoed += filled.len();
                        pipe = write.splice_from_pipe(filled).await.expect("splice out");
                    }
                    Ok(Spliced::End(_)) => break,
                    Err((error, _)) => panic!("splice in: {error}"),
                }
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "kernel")))]
        {
            let mut buf = Vec::with_capacity(20_000);
            loop {
                let BufResult(res, filled) = read.read(buf).await;
                if res.expect("subject read") == 0 {
                    break;
                }
                let BufResult(res, filled) = write.write_all(filled).await;
                res.expect("subject write");
                echoed += filled.len();
                buf = filled;
            }
        }
        write.shutdown().await.expect("subject shutdown");
        echoed
    }

    #[cfg(all(target_os = "linux", feature = "kernel"))]
    fn assert_can_splice(read: &impl SpliceRead, write: &impl SpliceWrite) {
        assert!(SpliceRead::can_splice(read) && SpliceWrite::can_splice(write));
    }

    #[cfg(not(all(target_os = "linux", feature = "kernel")))]
    fn assert_can_splice(_read: &impl SpliceRead, _write: &impl SpliceWrite) {}

    /// A TLS server forwards what a peer sends back to it, across the
    /// peer's key update. In kernel mode its receiving half takes the
    /// `KeyUpdate` out of the splice, and its writing half, asked for a key
    /// in return, sends its own before splicing the next round out.
    pub(super) async fn echo_as_server<I: Listen + Timer>(io: I)
    where
        Accepted<I>: Transport,
    {
        let identity = Identity::new();
        let payload = cjk_body(4_000);
        let rekey = rekey_before(&payload);
        let listener = io.bind_tcp(loopback()).expect("bind");
        let peer = client_peer(
            listener.local_addr().expect("local address"),
            client_config(&identity, TLS13_AES_128, &[]),
            payload.clone(),
            rekey,
        );
        let (stream, _) = listener.accept().await.expect("accept");
        let stream = acceptor(&identity, TLS13_AES_128, &[])
            .accept(stream, &io)
            .await
            .expect("server handshake");
        assert_eq!(stream.mode(), EXPECTED);
        assert_eq!(
            SPLICES,
            matches!(stream.mode(), Mode::Kernel),
            "kernel mode and splicing go together"
        );
        let (mut read, mut write) = stream.split();
        assert_can_splice(&read, &write);
        let forwarded = echo(&mut read, &mut write).await;
        let echoed = peer.join().expect("the peer's thread");
        assert_eq!(forwarded, payload.len());
        assert_bytes(&echoed, &payload);
    }

    /// A TLS client forwards what the peer sends back to it. The server
    /// peer sends session tickets after the handshake, which in kernel mode
    /// the client's kernel hands back from the splice, and then changes
    /// keys.
    pub(super) async fn echo_as_client<I: Dial + Timer>(io: I)
    where
        I::Connection: Transport,
    {
        let identity = Identity::new();
        let payload = cjk_body(4_000);
        let rekey = rekey_before(&payload);
        let listener = TcpListener::bind(loopback()).expect("bind");
        let addr = listener.local_addr().expect("local address");
        let peer = server_peer(
            listener,
            server_config(&identity, TLS13_AES_128, &[]),
            payload.clone(),
            rekey,
        );
        let stream = io.connect(addr).await.expect("connect");
        let stream = connector(&identity, TLS13_AES_128, &[])
            .connect(localhost(), stream, &io)
            .await
            .expect("client handshake");
        assert_eq!(stream.mode(), EXPECTED);
        let (mut read, mut write) = stream.split();
        assert_can_splice(&read, &write);
        let forwarded = echo(&mut read, &mut write).await;
        let echoed = peer.join().expect("the peer's thread");
        assert_eq!(forwarded, payload.len());
        assert_bytes(&echoed, &payload);
    }

    /// Bytes the peer sends right after its handshake are forwarded first,
    /// whether rustls decrypted them before the kernel took the connection
    /// (they come out of memory) or the kernel did (out of the socket).
    pub(super) async fn early_bytes_come_first<I: Listen + Timer>(io: I)
    where
        Accepted<I>: Transport,
    {
        let identity = Identity::new();
        let later = cjk_body(3_000);
        let listener = io.bind_tcp(loopback()).expect("bind");
        let addr = listener.local_addr().expect("local address");
        let peer = thread::spawn({
            let config = client_config(&identity, TLS13_AES_128, &[]);
            move || {
                let socket = TcpStream::connect(addr).expect("peer connect");
                let conn = rustls::ClientConnection::new(Arc::new(config), localhost())
                    .expect("peer client connection");
                let mut tls = rustls::StreamOwned::new(conn, socket);
                tls.write_all(CJK.as_bytes()).expect("peer early write");
                tls.flush().expect("peer flush");
                let mut received = Vec::new();
                tls.read_to_end(&mut received).expect("peer read");
                received
            }
        });
        let (stream, _) = listener.accept().await.expect("accept");
        let stream = acceptor(&identity, TLS13_AES_128, &[])
            .accept(stream, &io)
            .await
            .expect("server handshake");
        let (mut read, mut write) = stream.split();
        let seen = take(&mut read, CJK.len()).await;
        assert_bytes(&seen, CJK.as_bytes());
        let BufResult(res, _) = write.write_all(later.clone()).await;
        res.expect("server write");
        write.shutdown().await.expect("server shutdown");
        let received = peer.join().expect("the peer's thread");
        assert_bytes(&received, &later);
    }

    /// The first `len` bytes of the stream, spliced into a pipe and read out
    /// of it in kernel mode, read in user space.
    async fn take(read: &mut impl SpliceRead, len: usize) -> Vec<u8> {
        let mut seen = Vec::new();
        #[cfg(all(target_os = "linux", feature = "kernel"))]
        {
            use http_kit_io::splice::{Pipe, Spliced};

            let mut pipe = Pipe::new().expect("pipe");
            while seen.len() < len {
                match read.splice_to_pipe(pipe, usize::MAX).await {
                    Ok(Spliced::Filled(filled)) => {
                        let (bytes, emptied) = filled.read_out().expect("read out");
                        seen.extend_from_slice(&bytes);
                        pipe = emptied;
                    }
                    Ok(Spliced::End(_)) => panic!("the stream ended early"),
                    Err((error, _)) => panic!("splice in: {error}"),
                }
            }
        }
        #[cfg(not(all(target_os = "linux", feature = "kernel")))]
        {
            let mut buf = Vec::with_capacity(len);
            while seen.len() < len {
                let BufResult(res, filled) = read.read(buf).await;
                assert_ne!(res.expect("subject read"), 0, "the stream ended early");
                seen.extend_from_slice(&filled);
                buf = filled;
                buf.clear();
            }
        }
        seen
    }
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
        fn tls_in_tls() {
            $run(super::tls_in_tls($io));
        }

        #[test]
        fn tls_over_joined_halves() {
            $run(super::tls_over_joined_halves($io));
        }

        #[test]
        fn forward_as_server() {
            $run(super::forward::echo_as_server($io));
        }

        #[test]
        fn forward_as_client() {
            $run(super::forward::echo_as_client($io));
        }

        #[test]
        fn early_bytes_come_first() {
            $run(super::forward::early_bytes_come_first($io));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn user_mode_cannot_splice() {
            $run(super::user_mode_cannot_splice($io));
        }

        #[test]
        fn handshake_deadline() {
            $run(super::handshake_deadline($io));
        }

        #[test]
        fn bad_certificate() {
            $run(super::bad_certificate($io));
        }

        #[test]
        fn received_alert() {
            $run(super::received_alert($io));
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
