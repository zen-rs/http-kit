//! TCP and UDP echo, file-to-socket transfer, the poll-style capability and
//! timers, run against every implementation.
#![cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]

use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU16,
    rc::Rc,
    time::{Duration, Instant},
};

use futures_lite::{AsyncReadExt as _, AsyncWriteExt as _, future::zip};
use http_kit_io::{
    BufResult, DatagramSocket, IntoPoll, Io, Listener, Read, SendFile, Split, TcpOptions, Write,
    datagram::MAX_COALESCED_BYTES,
};

/// Compares two byte strings without printing kilobytes of them.
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

fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

/// Real text to move around: this file's own source, repeated until it is
/// larger than a socket buffer, so writes and reads come back short.
fn payload() -> Vec<u8> {
    include_bytes!("io.rs").repeat(32)
}

async fn read_to_end(reader: &mut impl Read) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = Vec::with_capacity(4096);
    loop {
        let BufResult(res, filled) = reader.read(buf).await;
        if res.expect("read") == 0 {
            return out;
        }
        out.extend_from_slice(&filled);
        buf = filled;
    }
}

async fn tcp_echo<I: Io>(io: I) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let data = payload();

    let server = async {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::with_capacity(8192);
        loop {
            let BufResult(res, filled) = stream.read(buf).await;
            if res.expect("server read") == 0 {
                break;
            }
            let BufResult(res, filled) = stream.write_all(filled).await;
            res.expect("server write");
            buf = filled;
        }
        stream.shutdown().await.expect("server shutdown");
    };
    let client = async {
        let stream = io.connect(addr).await.expect("connect");
        let (mut reader, mut writer) = stream.split();
        let send = async {
            let BufResult(res, _) = writer.write_all(data.clone()).await;
            res.expect("client write");
            writer.shutdown().await.expect("client shutdown");
        };
        zip(send, read_to_end(&mut reader)).await.1
    };
    let ((), echoed) = zip(server, client).await;
    assert_bytes(&echoed, &data);
}

async fn tcp_vectored<I: Io>(io: I) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let head = b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\n".to_vec();
    let body = b"hello".to_vec();

    let server = async {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let BufResult(res, _) = stream
            .write_vectored(vec![head.clone(), body.clone()])
            .await;
        assert_eq!(res.expect("vectored write"), head.len() + body.len());
        stream.shutdown().await.expect("shutdown");
    };
    let client = async {
        let mut stream = io.connect(addr).await.expect("connect");
        read_to_end(&mut stream).await
    };
    let ((), received) = zip(server, client).await;
    assert_bytes(&received, &[head, body].concat());
}

async fn udp_echo<I: Io>(io: I) {
    let server = io.bind_udp(loopback()).expect("bind server");
    let client = io.bind_udp(loopback()).expect("bind client");
    let server_addr = server.local_addr().expect("server address");
    let client_addr = client.local_addr().expect("client address");
    let message = include_bytes!("io.rs")[..1200].to_vec();

    let serve = async {
        let BufResult(res, buf) = server
            .recv_from(Vec::with_capacity(MAX_COALESCED_BYTES))
            .await;
        let meta = res.expect("server receive");
        assert_eq!(meta.from(), client_addr);
        let BufResult(res, _) = server.send_to(buf, meta.from()).await;
        assert_eq!(res.expect("server send"), meta.len());
    };
    let ask = async {
        let BufResult(res, _) = client.send_to(message.clone(), server_addr).await;
        assert_eq!(res.expect("client send"), message.len());
        let BufResult(res, buf) = client
            .recv_from(Vec::with_capacity(MAX_COALESCED_BYTES))
            .await;
        let meta = res.expect("client receive");
        assert_eq!(meta.from(), server_addr);
        buf
    };
    let ((), echoed) = zip(serve, ask).await;
    assert_bytes(&echoed, &message);
}

async fn udp_segments<I: Io>(io: I) {
    let receiver = io.bind_udp(loopback()).expect("bind receiver");
    let sender = io.bind_udp(loopback()).expect("bind sender");
    let target = receiver.local_addr().expect("receiver address");
    if cfg!(target_os = "linux") {
        assert_eq!(sender.max_send_segments(), 64, "Linux offers UDP GSO");
    } else {
        assert_eq!(sender.max_send_segments(), 1);
    }
    let segment = NonZeroU16::new(1200).unwrap();
    let data = include_bytes!("io.rs")[..2900].to_vec();

    let send = async {
        let BufResult(res, _) = sender.send_segments(data.clone(), segment, target).await;
        assert_eq!(res.expect("segmented send"), data.len());
    };
    let receive = async {
        let mut datagrams = Vec::new();
        let mut buf = Vec::with_capacity(MAX_COALESCED_BYTES);
        while datagrams.iter().map(Vec::len).sum::<usize>() < data.len() {
            let BufResult(res, filled) = receiver.recv_from(buf).await;
            let meta = res.expect("receive");
            assert_eq!(
                filled.len(),
                meta.len(),
                "the buffer holds exactly the receive"
            );
            datagrams.extend(meta.segments().map(|range| filled[range].to_vec()));
            buf = filled;
        }
        datagrams
    };
    let ((), datagrams) = zip(send, receive).await;
    assert_eq!(
        datagrams.iter().map(Vec::len).collect::<Vec<_>>(),
        [1200, 1200, 500]
    );
    assert_bytes(&datagrams.concat(), &data);
}

/// The socket `server`, bound to a wildcard address, receives datagrams sent
/// to each of `destinations`, reports each one's destination, and a reply sent
/// from that address reaches the client from it.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
))]
async fn udp_destination<I: Io>(io: &I, server: std::net::UdpSocket, destinations: &[IpAddr]) {
    let server = io.udp_socket(server).expect("adopt wildcard server");
    let port = server.local_addr().expect("server address").port();
    let question = include_bytes!("io.rs")[..300].to_vec();

    for &destination in destinations {
        let client = io
            .bind_udp(SocketAddr::new(loopback_for(destination), 0))
            .expect("bind client");
        let target = SocketAddr::new(destination, port);

        let serve = async {
            let BufResult(res, buf) = server
                .recv_from(Vec::with_capacity(MAX_COALESCED_BYTES))
                .await;
            let meta = res.expect("server receive");
            assert_eq!(
                meta.destination(),
                Some(destination),
                "datagram to {target}"
            );
            let BufResult(res, _) = server.send_from(buf, meta.from(), meta.destination()).await;
            assert_eq!(res.expect("reply from the destination"), meta.len());
        };
        let ask = async {
            let BufResult(res, _) = client.send_to(question.clone(), target).await;
            assert_eq!(res.expect("client send"), question.len());
            let BufResult(res, buf) = client
                .recv_from(Vec::with_capacity(MAX_COALESCED_BYTES))
                .await;
            let meta = res.expect("client receive");
            assert_eq!(meta.from(), target, "the reply comes from {destination}");
            buf
        };
        let ((), reply) = zip(serve, ask).await;
        assert_bytes(&reply, &question);
    }
}

/// The loopback address of the family of `ip`.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
))]
fn loopback_for(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => Ipv4Addr::LOCALHOST.into(),
        IpAddr::V6(_) => Ipv6Addr::LOCALHOST.into(),
    }
}

/// An IPv6 wildcard socket that sees both families. Whether a new one does
/// depends on the platform (Windows makes it IPv6-only), so the test asks.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
))]
async fn udp_destination_dual_stack<I: Io>(io: I) {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .expect("create IPv6 socket");
    socket.set_only_v6(false).expect("make it dual-stack");
    socket
        .bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())
        .expect("bind wildcard server");
    udp_destination(
        &io,
        socket.into(),
        &[Ipv6Addr::LOCALHOST.into(), Ipv4Addr::LOCALHOST.into()],
    )
    .await;
}

/// Linux answers for all of 127/8; other platforms have only 127.0.0.1.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn udp_destination_v4<I: Io>(io: I) {
    udp_destination(
        &io,
        std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind wildcard server"),
        &[
            Ipv4Addr::LOCALHOST.into(),
            Ipv4Addr::new(127, 0, 0, 2).into(),
        ],
    )
    .await;
}

/// A file larger than a pipe, so a splice-based transfer takes several
/// rounds, sent from an offset that is not page-aligned.
async fn send_file<I: Io>(io: I, name: &str) {
    // `name` comes from `module_path!`, and Windows forbids `:` in file names.
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(name.replace("::", "-"));
    let contents = payload();
    std::fs::write(&path, &contents).expect("write the file to send");
    let file = Rc::new(File::open(&path).expect("open the file to send"));
    let (offset, len) = (7, contents.len() - 7 - 3);

    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let server = async {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let BufResult(res, file) = stream.send_file_all(file.clone(), offset, len).await;
        res.expect("send file region");
        let BufResult(res, _) = stream.send_file(file, contents.len() as u64, 16).await;
        assert_eq!(res.expect("send past the end"), 0);
        stream.shutdown().await.expect("shutdown");
    };
    let client = async {
        let mut stream = io.connect(addr).await.expect("connect");
        read_to_end(&mut stream).await
    };
    let ((), received) = zip(server, client).await;
    std::fs::remove_file(&path).expect("remove the sent file");
    assert_bytes(&received, &contents[offset as usize..offset as usize + len]);
}

async fn poll_echo<I: Io>(io: I) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let data = payload();

    let server = async {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut stream = stream.into_poll();
        let mut received = Vec::new();
        stream
            .read_to_end(&mut received)
            .await
            .expect("server read");
        stream.write_all(&received).await.expect("server write");
        stream.close().await.expect("server close");
    };
    let client = async {
        let mut stream = io.connect(addr).await.expect("connect").into_poll();
        stream.write_all(&data).await.expect("client write");
        stream.close().await.expect("client close");
        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.expect("client read");
        echoed
    };
    let ((), echoed) = zip(server, client).await;
    assert_bytes(&echoed, &data);
}

/// A directory of its own for a Unix socket, short enough for `sun_path`
/// (104 bytes on Apple platforms), and the socket's path inside it.
#[cfg(unix)]
fn unix_socket_dir(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "hk-{}-{}",
        std::process::id(),
        name.replace("::", "-")
    ));
    std::fs::create_dir_all(&dir).expect("create the socket directory");
    let path = dir.join("s");
    (dir, path)
}

/// A client on its own threads, since the driver has no Unix `connect`: it
/// sends `data` and shuts down its write direction while reading whatever
/// the server sends until the server shuts down too.
#[cfg(unix)]
fn unix_client(path: std::path::PathBuf, data: Vec<u8>) -> std::thread::JoinHandle<Vec<u8>> {
    use std::{io::Write as _, net::Shutdown, os::unix::net::UnixStream};

    std::thread::spawn(move || {
        let stream = UnixStream::connect(&path).expect("connect");
        let mut writer = stream.try_clone().expect("clone the stream");
        let sending = std::thread::spawn(move || {
            writer.write_all(&data).expect("client write");
            writer.shutdown(Shutdown::Write).expect("client shutdown");
        });
        let mut received = Vec::new();
        std::io::Read::read_to_end(&mut &stream, &mut received).expect("client read");
        sending.join().expect("client writer");
        received
    })
}

#[cfg(unix)]
async fn unix_echo<I: Io>(io: I, name: &str) {
    let (dir, path) = unix_socket_dir(name);
    let listener = io
        .unix_listener(std::os::unix::net::UnixListener::bind(&path).expect("bind"))
        .expect("adopt the listener");
    let bound = listener.local_addr().expect("local address");
    assert_eq!(bound.as_pathname(), Some(path.as_path()));
    let data = payload();
    let client = unix_client(path, data.clone());

    let (mut stream, peer) = listener.accept().await.expect("accept");
    assert!(peer.is_unnamed(), "the client never bound an address");
    let mut buf = Vec::with_capacity(8192);
    loop {
        let BufResult(res, filled) = stream.read(buf).await;
        if res.expect("server read") == 0 {
            break;
        }
        let BufResult(res, filled) = stream.write_all(filled).await;
        res.expect("server write");
        buf = filled;
    }
    stream.shutdown().await.expect("server shutdown");
    let echoed = client.join().expect("client");
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    assert_bytes(&echoed, &data);
}

/// Both halves of a split stream at once: the server reads the whole request
/// while it writes the whole reply.
#[cfg(unix)]
async fn unix_split<I: Io>(io: I, name: &str) {
    let (dir, path) = unix_socket_dir(name);
    let listener = io
        .unix_listener(std::os::unix::net::UnixListener::bind(&path).expect("bind"))
        .expect("adopt the listener");
    let data = payload();
    let mut reply = data.clone();
    reply.reverse();
    let client = unix_client(path, data.clone());

    let (stream, _) = listener.accept().await.expect("accept");
    let (mut reader, mut writer) = stream.split();
    let (received, ()) = zip(read_to_end(&mut reader), async {
        let BufResult(res, _) = writer.write_all(reply.clone()).await;
        res.expect("server write");
        writer.shutdown().await.expect("server shutdown");
    })
    .await;
    let answered = client.join().expect("client");
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    assert_bytes(&received, &data);
    assert_bytes(&answered, &reply);
}

#[cfg(unix)]
async fn unix_send_file<I: Io>(io: I, name: &str) {
    let (dir, path) = unix_socket_dir(name);
    let contents = payload();
    let file_path = dir.join("f");
    std::fs::write(&file_path, &contents).expect("write the file to send");
    let file = Rc::new(File::open(&file_path).expect("open the file to send"));
    let (offset, len) = (7, contents.len() - 7 - 3);

    let listener = io
        .unix_listener(std::os::unix::net::UnixListener::bind(&path).expect("bind"))
        .expect("adopt the listener");
    let client = unix_client(path, Vec::new());

    let (mut stream, _) = listener.accept().await.expect("accept");
    let BufResult(res, file) = stream.send_file_all(file.clone(), offset, len).await;
    res.expect("send file region");
    let BufResult(res, _) = stream.send_file(file, contents.len() as u64, 16).await;
    assert_eq!(res.expect("send past the end"), 0);
    stream.shutdown().await.expect("shutdown");
    let received = client.join().expect("client");
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    assert_bytes(&received, &contents[offset as usize..offset as usize + len]);
}

#[cfg(unix)]
async fn unix_poll_echo<I: Io>(io: I, name: &str) {
    let (dir, path) = unix_socket_dir(name);
    let listener = io
        .unix_listener(std::os::unix::net::UnixListener::bind(&path).expect("bind"))
        .expect("adopt the listener");
    let data = payload();
    let client = unix_client(path, data.clone());

    let (stream, _) = listener.accept().await.expect("accept");
    let mut stream = stream.into_poll();
    let mut received = Vec::new();
    stream
        .read_to_end(&mut received)
        .await
        .expect("server read");
    stream.write_all(&received).await.expect("server write");
    stream.close().await.expect("server close");
    let echoed = client.join().expect("client");
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    assert_bytes(&echoed, &data);
}

/// `connect_unix` reaches a listener of the same implementation, and bytes
/// round-trip.
#[cfg(unix)]
async fn unix_connect<I: Io>(io: I, name: &str) {
    let (dir, path) = unix_socket_dir(name);
    let listener = io
        .unix_listener(std::os::unix::net::UnixListener::bind(&path).expect("bind"))
        .expect("adopt the listener");
    let data = payload();

    let server = async {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buf = Vec::with_capacity(8192);
        loop {
            let BufResult(res, filled) = stream.read(buf).await;
            if res.expect("server read") == 0 {
                break;
            }
            let BufResult(res, filled) = stream.write_all(filled).await;
            res.expect("server write");
            buf = filled;
        }
        stream.shutdown().await.expect("server shutdown");
    };
    let client = async {
        let stream = io.connect_unix(&path).await.expect("connect");
        let (mut reader, mut writer) = stream.split();
        let send = async {
            let BufResult(res, _) = writer
                .write_all("世界 せかい 세계\n".as_bytes().to_vec())
                .await;
            res.expect("client write");
            let BufResult(res, _) = writer.write_all(data.clone()).await;
            res.expect("client write");
            writer.shutdown().await.expect("client shutdown");
        };
        zip(send, read_to_end(&mut reader)).await.1
    };
    let ((), echoed) = zip(server, client).await;
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    let mut expected = "世界 せかい 세계\n".as_bytes().to_vec();
    expected.extend_from_slice(&data);
    assert_bytes(&echoed, &expected);
}

/// A path with nothing listening is refused, not hung.
#[cfg(unix)]
async fn unix_connect_refused<I: Io>(io: I, name: &str) {
    let (dir, path) = unix_socket_dir(name);
    let Err(err) = io.connect_unix(&path).await else {
        panic!("nothing listens");
    };
    std::fs::remove_dir_all(dir).expect("remove the socket directory");
    assert!(
        matches!(
            err.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ),
        "{err:?}"
    );
}

async fn tcp_nodelay<I: Io>(io: I) {
    let listener = io.bind_tcp(loopback()).expect("bind");
    let addr = listener.local_addr().expect("local address");
    let (accepted, stream) = zip(listener.accept(), io.connect(addr)).await;
    let _accepted = accepted.expect("accept");
    let stream = stream.expect("connect");
    stream.set_nodelay(true).expect("set TCP_NODELAY");
    assert!(stream.nodelay().expect("read TCP_NODELAY"));
    stream.set_nodelay(false).expect("clear TCP_NODELAY");
    assert!(!stream.nodelay().expect("read TCP_NODELAY"));
}

async fn timer<I: Io>(io: I) {
    let start = Instant::now();
    io.sleep(Duration::from_millis(20)).await;
    assert!(start.elapsed() >= Duration::from_millis(20));
    let past = Instant::now();
    io.sleep_until(past).await;
}

macro_rules! suite {
    ($io:expr, $run:path) => {
        #[test]
        fn tcp_echo() {
            $run(super::tcp_echo($io));
        }

        #[test]
        fn tcp_vectored() {
            $run(super::tcp_vectored($io));
        }

        #[test]
        fn udp_echo() {
            $run(super::udp_echo($io));
        }

        #[test]
        fn udp_segments() {
            $run(super::udp_segments($io));
        }

        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_vendor = "apple",
            windows
        ))]
        #[test]
        fn udp_destination_dual_stack() {
            $run(super::udp_destination_dual_stack($io));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn udp_destination_v4() {
            $run(super::udp_destination_v4($io));
        }

        #[test]
        fn send_file() {
            $run(super::send_file($io, concat!(module_path!(), "-send_file")));
        }

        #[test]
        fn poll_echo() {
            $run(super::poll_echo($io));
        }

        #[cfg(unix)]
        #[test]
        fn unix_echo() {
            $run(super::unix_echo($io, concat!(module_path!(), "-echo")));
        }

        #[cfg(unix)]
        #[test]
        fn unix_split() {
            $run(super::unix_split($io, concat!(module_path!(), "-split")));
        }

        #[cfg(unix)]
        #[test]
        fn unix_send_file() {
            $run(super::unix_send_file($io, concat!(module_path!(), "-file")));
        }

        #[cfg(unix)]
        #[test]
        fn unix_poll_echo() {
            $run(super::unix_poll_echo($io, concat!(module_path!(), "-poll")));
        }

        #[cfg(unix)]
        #[test]
        fn unix_connect() {
            $run(super::unix_connect(
                $io,
                concat!(module_path!(), "-connect"),
            ));
        }

        #[cfg(unix)]
        #[test]
        fn unix_connect_refused() {
            $run(super::unix_connect_refused(
                $io,
                concat!(module_path!(), "-refused"),
            ));
        }

        #[test]
        fn tcp_nodelay() {
            $run(super::tcp_nodelay($io));
        }

        #[test]
        fn timer() {
            $run(super::timer($io));
        }
    };
}

#[cfg(feature = "compio")]
mod compio {
    use std::future::Future;

    fn run<F: Future>(future: F) -> F::Output {
        ::compio::runtime::Runtime::new()
            .expect("compio runtime")
            .block_on(future)
    }

    suite!(http_kit_io::compio::Compio, run);

    /// A connection accepted by a plain std listener on one thread is adopted
    /// by a compio runtime on another and serves both directions there.
    #[test]
    fn a_std_stream_accepted_elsewhere_is_adopted() {
        use http_kit_io::{Read as _, Write as _, compio::TcpStream};
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind(super::loopback()).expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let accepted = std::thread::spawn(move || listener.accept().expect("accept").0);
        let mut client = std::net::TcpStream::connect(addr).expect("connect");
        let accepted = accepted.join().expect("accept thread");
        let server = std::thread::spawn(move || {
            run(async move {
                let mut stream =
                    TcpStream::from(::compio::net::TcpStream::from_std(accepted).expect("adopt"));
                let http_kit_io::BufResult(read, buf) = stream.read(Vec::with_capacity(64)).await;
                read.expect("read");
                let http_kit_io::BufResult(written, _) = stream.write(buf).await;
                written.expect("write back");
            });
        });
        client
            .write_all("世界 せかい 세계".as_bytes())
            .expect("send");
        let mut echoed = vec![0; "世界 せかい 세계".len()];
        client.read_exact(&mut echoed).expect("echo");
        assert_eq!(echoed, "世界 せかい 세계".as_bytes());
        server.join().expect("server thread");
    }
}

#[cfg(feature = "tokio")]
mod tokio {
    use std::future::Future;

    fn run<F: Future>(future: F) -> F::Output {
        ::tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime")
            .block_on(future)
    }

    suite!(http_kit_io::tokio::Tokio, run);
}

#[cfg(feature = "async-io")]
mod async_io {
    suite!(http_kit_io::async_io::AsyncIo, ::async_io::block_on);
}
