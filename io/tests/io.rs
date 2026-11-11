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
    BufResult, Datagram, DatagramSocket, Dial, FromStd, IntoPoll, Listen, Listener, Read, SendFile,
    SpliceRead, SpliceWrite, Split, TcpOptions, Timer, Write, datagram::MAX_COALESCED_BYTES,
};
#[cfg(unix)]
use http_kit_io::{DialUnix, FromStdUnix, ListenUnix};

/// The stream a TCP listener of `I` accepts.
type Accepted<I> = <<I as Listen>::Listener as Listener>::Stream;
/// The stream a Unix-domain listener of `I` accepts.
#[cfg(unix)]
type AcceptedUnix<I> = <<I as ListenUnix>::UnixListener as Listener>::Stream;

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

async fn tcp_echo<I: Dial + Listen>(io: I) {
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

async fn tcp_vectored<I: Dial + Listen>(io: I) {
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

async fn udp_echo<I: Datagram>(io: I) {
    let server = io.bind_udp(loopback()).await.expect("bind server");
    let client = io.bind_udp(loopback()).await.expect("bind client");
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

async fn udp_segments<I: Datagram>(io: I) {
    let receiver = io.bind_udp(loopback()).await.expect("bind receiver");
    let sender = io.bind_udp(loopback()).await.expect("bind sender");
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
async fn udp_destination<I: FromStd>(io: &I, server: std::net::UdpSocket, destinations: &[IpAddr]) {
    let server = io.udp_socket(server).expect("adopt wildcard server");
    let port = server.local_addr().expect("server address").port();
    let question = include_bytes!("io.rs")[..300].to_vec();

    for &destination in destinations {
        let client = io
            .bind_udp(SocketAddr::new(loopback_for(destination), 0))
            .await
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
async fn udp_destination_dual_stack<I: FromStd>(io: I) {
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
async fn udp_destination_v4<I: FromStd>(io: I) {
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
async fn send_file<I: Dial + Listen>(io: I, name: &str)
where
    Accepted<I>: SendFile,
{
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

/// Every stream and half implements the splice traits on every platform,
/// whether or not the platform has the methods.
#[test]
fn every_stream_and_half_is_spliceable() {
    fn stream<S: SpliceRead + SpliceWrite>() {}
    fn halves<S: Split>()
    where
        S::ReadHalf: SpliceRead,
        S::WriteHalf: SpliceWrite,
    {
    }

    #[cfg(feature = "compio")]
    {
        stream::<http_kit_io::compio::TcpStream>();
        halves::<http_kit_io::compio::TcpStream>();
        #[cfg(unix)]
        {
            stream::<http_kit_io::compio::UnixStream>();
            halves::<http_kit_io::compio::UnixStream>();
        }
    }
    #[cfg(feature = "tokio")]
    {
        stream::<http_kit_io::tokio::TcpStream>();
        halves::<http_kit_io::tokio::TcpStream>();
        #[cfg(unix)]
        {
            stream::<http_kit_io::tokio::UnixStream>();
            halves::<http_kit_io::tokio::UnixStream>();
        }
    }
    #[cfg(feature = "async-io")]
    {
        stream::<http_kit_io::async_io::TcpStream>();
        halves::<http_kit_io::async_io::TcpStream>();
        #[cfg(unix)]
        {
            stream::<http_kit_io::async_io::UnixStream>();
            halves::<http_kit_io::async_io::UnixStream>();
        }
    }
}

/// CJK text of exactly `len` bytes (the last character may be cut).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn cjk_payload(len: usize) -> Vec<u8> {
    let unit = "世界 せかい 세계 — 通过管道转发 パイプ経由 파이프 전달\n".as_bytes();
    unit.iter().copied().cycle().take(len).collect()
}

/// 16 MiB goes from one stream socket through a pipe into another.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn splice_socket_to_socket<I: Listen>(io: I)
where
    Accepted<I>: SpliceRead + SpliceWrite,
{
    use http_kit_io::splice::{Pipe, Spliced};
    use std::io::{Read as _, Write as _};

    const LEN: usize = 16 * 1024 * 1024;

    let source = io.bind_tcp(loopback()).expect("bind source");
    let sink = io.bind_tcp(loopback()).expect("bind sink");
    let (source_addr, sink_addr) = (
        source.local_addr().expect("source address"),
        sink.local_addr().expect("sink address"),
    );
    let data = cjk_payload(LEN);
    let sender = std::thread::spawn({
        let data = data.clone();
        move || {
            let mut stream = std::net::TcpStream::connect(source_addr).expect("sender connect");
            stream.write_all(&data).expect("send");
        }
    });
    let receiver = std::thread::spawn(move || {
        let mut stream = std::net::TcpStream::connect(sink_addr).expect("receiver connect");
        let mut received = Vec::with_capacity(LEN);
        stream.read_to_end(&mut received).expect("receive");
        received
    });

    let (mut from, _) = source.accept().await.expect("accept source");
    let (mut to, _) = sink.accept().await.expect("accept sink");
    let mut pipe = Pipe::new().expect("pipe");
    let mut spliced = 0;
    loop {
        match from.splice_to_pipe(pipe, usize::MAX).await {
            Ok(Spliced::Filled(filled)) => {
                spliced += filled.len();
                pipe = to.splice_from_pipe(filled).await.expect("splice out");
            }
            Ok(Spliced::End(_)) => break,
            Err((e, _)) => panic!("splice in: {e}"),
        }
    }
    Write::shutdown(&mut to).await.expect("shutdown");
    sender.join().expect("sender thread");
    let received = receiver.join().expect("receiver thread");
    assert_eq!(spliced, LEN);
    assert_bytes(&received, &data);
}

/// Two tunnel ends joined: replay bytes go first, data goes both ways, and a
/// half-close of one peer reaches the other while the reverse direction stays
/// open.
#[cfg(any(target_os = "linux", target_os = "android"))]
async fn splice_duplex_join<I: Listen>(io: I) {
    use http_kit_io::splice::SpliceDuplex;
    use std::io::{Read as _, Write as _};

    let left = io.bind_tcp(loopback()).expect("bind left");
    let right = io.bind_tcp(loopback()).expect("bind right");
    let (left_addr, right_addr) = (
        left.local_addr().expect("left address"),
        right.local_addr().expect("right address"),
    );
    let left_replay = "左 replay: 世界 せかい 세계\n";
    let right_replay = "右 replay: 你好 こんにちは 안녕\n";
    let from_left = cjk_payload(300_000);
    let from_right = cjk_payload(200_000);

    let left_peer = std::thread::spawn({
        let from_left = from_left.clone();
        move || {
            let mut stream = std::net::TcpStream::connect(left_addr).expect("left connect");
            stream.write_all(&from_left).expect("left send");
            stream
                .shutdown(std::net::Shutdown::Write)
                .expect("left half-close");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).expect("left receive");
            received
        }
    });
    // The right peer writes only after it has seen the left peer's half-close.
    let right_peer = std::thread::spawn({
        let from_right = from_right.clone();
        move || {
            let mut stream = std::net::TcpStream::connect(right_addr).expect("right connect");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).expect("right receive");
            stream.write_all(&from_right).expect("right send");
            received
        }
    });

    let (left_stream, _) = left.accept().await.expect("accept left");
    let (right_stream, _) = right.accept().await.expect("accept right");
    let (left_read, left_write) = left_stream.split();
    let (right_read, right_write) = right_stream.split();
    let left_end = SpliceDuplex::new(left_replay.into(), left_read, left_write);
    let right_end = SpliceDuplex::new(right_replay.into(), right_read, right_write);
    assert!(left_end.can_splice() && right_end.can_splice());

    let (to_right, to_left) = left_end.join(right_end).await.expect("join");
    let received_by_right = right_peer.join().expect("right thread");
    let received_by_left = left_peer.join().expect("left thread");

    assert_eq!(to_right, (left_replay.len() + from_left.len()) as u64);
    assert_eq!(to_left, (right_replay.len() + from_right.len()) as u64);
    let expected_right = [left_replay.as_bytes(), &from_left].concat();
    let expected_left = [right_replay.as_bytes(), &from_right].concat();
    assert_bytes(&received_by_right, &expected_right);
    assert_bytes(&received_by_left, &expected_left);
}

async fn poll_echo<I: Dial + Listen>(io: I)
where
    I::Connection: IntoPoll,
    Accepted<I>: IntoPoll,
{
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
async fn unix_echo<I: FromStdUnix>(io: I, name: &str) {
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
async fn unix_split<I: FromStdUnix>(io: I, name: &str) {
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
async fn unix_send_file<I: FromStdUnix>(io: I, name: &str)
where
    AcceptedUnix<I>: SendFile,
{
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
async fn unix_poll_echo<I: FromStdUnix>(io: I, name: &str)
where
    AcceptedUnix<I>: IntoPoll,
{
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
async fn unix_connect<I: DialUnix + FromStdUnix>(io: I, name: &str) {
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
async fn unix_connect_refused<I: DialUnix>(io: I, name: &str) {
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

async fn tcp_nodelay<I: Dial + Listen>(io: I) {
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

async fn timer<I: Timer>(io: I) {
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

        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn splice_socket_to_socket() {
            $run(super::splice_socket_to_socket($io));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        #[test]
        fn splice_duplex_join() {
            $run(super::splice_duplex_join($io));
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

    /// How many submission queue entries the current thread's io_uring has
    /// been handed: the tail the kernel reports in the ring's fdinfo.
    #[cfg(target_os = "linux")]
    fn submitted() -> u32 {
        use std::os::fd::AsRawFd as _;

        let ring = ::compio::runtime::Runtime::with_current(|runtime| runtime.as_raw_fd());
        let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{ring}"))
            .expect("read the ring's fdinfo");
        info.lines()
            .find_map(|line| line.strip_prefix("SqTail:"))
            .unwrap_or_else(|| panic!("the runtime is not on io_uring:\n{info}"))
            .trim()
            .parse()
            .expect("submission queue tail")
    }

    /// Connects `count` blocking clients to `addr`; each completes in the
    /// listener's backlog, through no operation of the runtime's ring.
    #[cfg(target_os = "linux")]
    fn backlog(addr: std::net::SocketAddr, count: usize) -> Vec<std::net::TcpStream> {
        (0..count)
            .map(|_| std::net::TcpStream::connect(addr).expect("connect"))
            .collect()
    }

    /// One multishot accept serves every connection waiting on a listener,
    /// and an accept abandoned while pending leaves it armed; compio's own
    /// accept, the control, takes a submission per connection.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_accept_submission_serves_many_connections() {
        use http_kit_io::{FromStd as _, Listen as _, Listener as _, Timer as _, compio::Compio};

        const CONNECTIONS: usize = 32;
        run(async {
            // The driver arms a poll on its own wake-up eventfd the first time
            // it parks; park it once so that submission is not counted.
            Compio.sleep(std::time::Duration::from_millis(1)).await;

            let listener = Compio.bind_tcp(super::loopback()).expect("bind");
            let addr = listener.local_addr().expect("local address");
            let before = submitted();
            // Submits the accept, then drops the call that submitted it.
            assert!(
                futures_lite::future::poll_once(listener.accept())
                    .await
                    .is_none()
            );
            let clients = backlog(addr, CONNECTIONS);
            let mut accepted = Vec::with_capacity(CONNECTIONS);
            for _ in 0..CONNECTIONS {
                let (_stream, peer) = listener.accept().await.expect("accept");
                accepted.push(peer);
            }
            assert_eq!(
                submitted() - before,
                1,
                "submissions for {CONNECTIONS} accepts"
            );
            let mut peers: Vec<_> = clients
                .iter()
                .map(|client| client.local_addr().expect("client address"))
                .collect();
            peers.sort_unstable();
            accepted.sort_unstable();
            assert_eq!(accepted, peers);

            let single = ::compio::net::TcpListener::from_std(
                std::net::TcpListener::bind(super::loopback()).expect("bind"),
            )
            .expect("register");
            let _clients = backlog(single.local_addr().expect("local address"), CONNECTIONS);
            let before = submitted();
            for _ in 0..CONNECTIONS {
                single.accept().await.expect("accept");
            }
            assert_eq!(
                submitted() - before,
                u32::try_from(CONNECTIONS).expect("connection count"),
                "submissions for {CONNECTIONS} single-shot accepts"
            );
        });
    }

    /// The io-wq workers of this process that are doing something other than
    /// waiting for work, each as its thread id and kernel wait channel.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn busy_kernel_workers() -> Vec<String> {
        let mut busy = Vec::new();
        for task in std::fs::read_dir("/proc/self/task").expect("list threads") {
            let task = task.expect("thread entry").path();
            let comm = std::fs::read_to_string(task.join("comm")).unwrap_or_default();
            if !comm.starts_with("iou-wrk") {
                continue;
            }
            let wchan = std::fs::read_to_string(task.join("wchan")).unwrap_or_default();
            if wchan.trim() != "io_wq_worker" {
                busy.push(format!("{}: {}", task.display(), wchan.trim()));
            }
        }
        busy
    }

    /// A splice waiting for a peer that sends nothing holds no io-wq worker,
    /// and moves the bytes once they come.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn an_idle_splice_holds_no_kernel_worker() {
        use std::{io::Write as _, sync::mpsc, time::Duration};

        use http_kit_io::{
            Listen as _, Listener as _, SpliceRead as _,
            splice::{Pipe, Spliced},
        };

        let (addr_tx, addr_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let mut stream = std::net::TcpStream::connect(addr).expect("connect");
            std::thread::sleep(Duration::from_millis(1000));
            stream
                .write_all("世界 せかい 세계".as_bytes())
                .expect("send");
        });

        let (busy, bytes) = run(async {
            let io = http_kit_io::compio::Compio;
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");
            let splice = async {
                match stream
                    .splice_to_pipe(Pipe::new().expect("pipe"), usize::MAX)
                    .await
                {
                    Ok(Spliced::Filled(filled)) => filled.read_out().expect("read out").0,
                    Ok(Spliced::End(_)) => panic!("the peer ended without sending"),
                    Err((e, _)) => panic!("splice: {e}"),
                }
            };
            let watch = async {
                ::compio::time::sleep(Duration::from_millis(500)).await;
                busy_kernel_workers()
            };
            let (bytes, busy) = futures_lite::future::zip(splice, watch).await;
            (busy, bytes)
        });
        peer.join().expect("peer thread");
        assert_eq!(&bytes[..], "世界 せかい 세계".as_bytes());
        assert!(
            busy.is_empty(),
            "kernel workers held by the idle splice: {busy:?}"
        );
    }

    /// A region larger than both socket buffers, sent to a peer that stops
    /// reading, leaves no io-wq worker waiting for the peer.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn send_file_to_a_stalled_peer_holds_no_kernel_worker() {
        use std::{io::Read as _, sync::mpsc, time::Duration};

        use http_kit_io::{BufResult, Listen as _, Listener as _, SendFile as _};

        const BUFFER: usize = 16 * 1024;

        let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("compio-stalled-peer");
        let contents = super::payload();
        std::fs::write(&path, &contents).expect("write the file to send");
        let file = std::rc::Rc::new(std::fs::File::open(&path).expect("open the file to send"));

        let (release, released) = mpsc::channel::<()>();
        let (addr_tx, addr_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                .expect("peer socket");
            socket
                .set_recv_buffer_size(BUFFER)
                .expect("peer receive buffer");
            socket
                .connect(&socket2::SockAddr::from(addr))
                .expect("connect");
            let mut stream = std::net::TcpStream::from(socket);
            released.recv().expect("release");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).expect("read");
            received
        });

        let busy = run(async {
            let io = http_kit_io::compio::Compio;
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(BUFFER)
                .expect("send buffer");
            let send = async {
                let BufResult(res, _) = stream.send_file_all(file, 0, contents.len()).await;
                res.expect("send file region");
                http_kit_io::Write::shutdown(&mut stream)
                    .await
                    .expect("shutdown");
            };
            let watch = async {
                ::compio::time::sleep(Duration::from_millis(500)).await;
                let busy = busy_kernel_workers();
                release.send(()).expect("release the peer");
                busy
            };
            futures_lite::future::zip(send, watch).await.1
        });
        let received = peer.join().expect("peer thread");
        std::fs::remove_file(&path).expect("remove the sent file");
        super::assert_bytes(&received, &contents);
        assert!(
            busy.is_empty(),
            "kernel workers held during the stall: {busy:?}"
        );
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

/// Bytes put into a pipe from memory come out of it in order, at most a
/// pipe's capacity at a time.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[test]
fn a_pipe_is_filled_from_memory() {
    use http_kit_io::splice::Pipe;

    let pipe = Pipe::new().expect("pipe");
    let capacity = pipe.capacity();
    let payload = cjk_payload(capacity + 1_000);

    let (pipe, error) = match Pipe::new().expect("pipe").fill(&[]) {
        Err((error, pipe)) => (pipe, error),
        Ok(_) => panic!("filling with nothing succeeded"),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let filled = pipe
        .fill(&payload)
        .unwrap_or_else(|(e, _)| panic!("fill: {e}"));
    assert_eq!(filled.len(), capacity);
    let (first, pipe) = filled.read_out().expect("read out");
    assert_eq!(&first[..], &payload[..capacity]);

    let filled = pipe
        .fill(&payload[capacity..])
        .unwrap_or_else(|(e, _)| panic!("fill the rest: {e}"));
    let (rest, _) = filled.read_out().expect("read out");
    assert_eq!(&rest[..], &payload[capacity..]);
}
