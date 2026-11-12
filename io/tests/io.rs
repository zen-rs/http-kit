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

    suite!(http_kit_io::compio::Compio::default(), run);

    /// A connection accepted by a plain std listener on one thread is adopted
    /// by a compio runtime on another and serves both directions there.
    #[test]
    fn a_std_stream_accepted_elsewhere_is_adopted() {
        use http_kit_io::{Read as _, Write as _, compio::Compio};
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind(super::loopback()).expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let accepted = std::thread::spawn(move || listener.accept().expect("accept").0);
        let mut client = std::net::TcpStream::connect(addr).expect("connect");
        let accepted = accepted.join().expect("accept thread");
        let server = std::thread::spawn(move || {
            run(async move {
                let mut stream = Compio::default()
                    .tcp_stream(::compio::net::TcpStream::from_std(accepted).expect("adopt"));
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

    /// A stream whose descriptor number is closed and reused behind its back
    /// (here by `dup2` of a regular file over it, which does both at once)
    /// fails its next use of the number in a debug build instead of moving
    /// bytes into the file now holding it (zen-rs/http-kit#159). On Linux the
    /// use is a file region's splice into the socket.
    #[cfg(all(unix, debug_assertions))]
    #[test]
    #[should_panic(expected = "no longer names the stream's socket")]
    fn a_reused_descriptor_number_fails_its_next_use() {
        use http_kit_io::compio::Compio;
        use std::os::fd::{AsFd as _, AsRawFd as _};

        let listener = std::net::TcpListener::bind(super::loopback()).expect("bind");
        let client = std::net::TcpStream::connect(listener.local_addr().expect("local addr"))
            .expect("connect");
        let (accepted, _) = listener.accept().expect("accept");
        let file = super::File::open(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/io.rs"))
            .expect("open this test's source");
        run(async move {
            let stream = Compio::default()
                .tcp_stream(::compio::net::TcpStream::from_std(accepted).expect("adopt"));
            let number = stream.as_fd().as_raw_fd();
            // SAFETY: both descriptors are open; `dup2` replaces the
            // stream's number with a duplicate of the file's.
            assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), number) }, number);
            #[cfg(target_os = "linux")]
            {
                use super::SendFile as _;

                let mut stream = stream;
                let _ = stream.send_file(super::Rc::new(file), 0, 64).await;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = stream.as_fd();
            }
        });
        drop(client);
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
        use http_kit_io::{
            Listen as _, Listener as _, Timer as _,
            compio::{Compio, FileTable},
        };

        const CONNECTIONS: usize = 32;
        run(async {
            // The driver arms a poll on its own wake-up eventfd the first time
            // it parks; park it once so that submission is not counted. Each
            // stream would take a slot in the file table with a submission
            // of its own; this counts accepts alone.
            let io = Compio::default().with_file_table(FileTable::new(0));
            io.sleep(std::time::Duration::from_millis(1)).await;

            let listener = io.bind_tcp(super::loopback()).expect("bind");
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

    /// Both ways a ring can consume its buffers: whole, and incrementally
    /// where the kernel accepts it (Linux 6.12; whole before).
    #[cfg(target_os = "linux")]
    const CONSUMPTIONS: [bool; 2] = [false, true];

    /// A runtime whose provided buffer ring has `buffers` buffers of `len`
    /// bytes each, registered for incremental consumption if `incremental`.
    #[cfg(target_os = "linux")]
    fn run_with_ring<F: Future>(
        buffers: u16,
        len: usize,
        incremental: bool,
        future: F,
    ) -> F::Output {
        let mut proactor = ::compio::driver::ProactorBuilder::new();
        proactor
            .buffer_pool_size(std::num::NonZeroU16::new(buffers).expect("a ring has buffers"))
            .buffer_pool_buffer_len(len);
        if incremental {
            proactor.buffer_pool_flag(
                u16::try_from(io_uring::types::IOU_PBUF_RING_INC).expect("a ring flag"),
            );
        }
        ::compio::runtime::RuntimeBuilder::new()
            .with_proactor(proactor)
            .build()
            .expect("compio runtime")
            .block_on(future)
    }

    /// One accepted connection, with the peer on a thread of its own.
    #[cfg(target_os = "linux")]
    async fn accept_one(
        peer: impl FnOnce(std::net::TcpStream) + Send + 'static,
    ) -> (http_kit_io::compio::TcpStream, std::thread::JoinHandle<()>) {
        use http_kit_io::{Listen as _, Listener as _, compio::Compio};

        let listener = Compio::default().bind_tcp(super::loopback()).expect("bind");
        let addr = listener.local_addr().expect("local address");
        let peer =
            std::thread::spawn(move || peer(std::net::TcpStream::connect(addr).expect("connect")));
        let (stream, _) = listener.accept().await.expect("accept");
        (stream, peer)
    }

    /// One multishot receive serves every read of a connection. The ring
    /// holds a quarter of what the connection carries, so each buffer must
    /// go back to it as soon as its bytes are read; a buffer kept would run
    /// the ring dry, end the receive and take a submission to arm it again.
    #[cfg(target_os = "linux")]
    #[test]
    fn one_receive_submission_serves_many_reads() {
        use std::io::{Read as _, Write as _};

        use http_kit_io::{ReadOwned as _, Received, Timer as _, compio::Compio};

        const BUFFERS: u16 = 4;
        const BUFFER_LEN: usize = 4096;
        const MESSAGE: usize = 1024;
        const MESSAGES: usize = 64;

        for incremental in CONSUMPTIONS {
            let data = super::payload()[..MESSAGE * MESSAGES].to_vec();
            let sent = data.clone();
            run_with_ring(BUFFERS, BUFFER_LEN, incremental, async move {
                // The driver arms a poll on its own wake-up eventfd the first time
                // it parks; park it once so that submission is not counted.
                Compio::default()
                    .sleep(std::time::Duration::from_millis(1))
                    .await;
                // Each message waits for the one before it to be read, so the
                // receive always finds a free buffer.
                let (mut stream, peer) = accept_one(move |mut client| {
                    for message in sent.chunks(MESSAGE) {
                        client.write_all(message).expect("send");
                        client.read_exact(&mut [0]).expect("wait for the read");
                    }
                })
                .await;
                // The stream takes its slot with a submission of its own; count
                // from once it holds it, so the receive is armed on the slot.
                until_held(&socket_name(&stream), 1).await;
                let before = submitted();
                let mut received = Vec::with_capacity(data.len());
                let mut reads = 0;
                while received.len() < data.len() {
                    let Received::Lent(buf) = stream.read_owned().await.expect("read") else {
                        panic!("the ring ran dry or the peer closed early");
                    };
                    reads += 1;
                    received.extend_from_slice(&buf);
                    drop(buf);
                    if received.len() % MESSAGE == 0 {
                        // The acknowledgement is a send, which is a submission;
                        // count it out.
                        let ack = submitted();
                        let http_kit_io::BufResult(res, _) =
                            http_kit_io::Write::write(&mut stream, vec![0]).await;
                        res.expect("acknowledge");
                        assert_eq!(submitted() - ack, 1, "an acknowledgement is one send");
                    }
                }
                let acks = u32::try_from(MESSAGES).expect("message count");
                assert_eq!(
                    submitted() - before - acks,
                    1,
                    "receive submissions for {reads} reads"
                );
                assert!(reads >= MESSAGES, "{reads} reads");
                super::assert_bytes(&received, &data);
                peer.join().expect("peer thread");
            });
        }
    }

    /// A connection that carries far more than the ring holds, sent as fast
    /// as the peer can, completes: buffers go back to the ring as they are
    /// read, and a read that finds the ring dry receives into the caller's
    /// buffer instead. Reads smaller than a ring buffer take it in parts.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_connection_reads_more_than_the_ring_holds() {
        use std::io::Write as _;

        for incremental in CONSUMPTIONS {
            let data = super::payload();
            let sent = data.clone();
            run_with_ring(2, 4096, incremental, async move {
                let (mut stream, peer) = accept_one(move |mut client| {
                    client.write_all(&sent).expect("send");
                })
                .await;
                let mut received = Vec::with_capacity(data.len());
                let mut buf = Vec::with_capacity(1500);
                loop {
                    let http_kit_io::BufResult(res, filled) =
                        http_kit_io::Read::read(&mut stream, buf).await;
                    if res.expect("read") == 0 {
                        break;
                    }
                    received.extend_from_slice(&filled);
                    buf = filled;
                }
                super::assert_bytes(&received, &data);
                peer.join().expect("peer thread");
            });
        }
    }

    /// A splice from a socket that has received ahead of its reader moves
    /// those bytes first, so it never passes them.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_splice_takes_the_bytes_received_ahead_first() {
        use std::io::Write as _;

        use http_kit_io::{
            SpliceRead as _,
            splice::{Pipe, Spliced},
        };

        for incremental in CONSUMPTIONS {
            let data = "世界 せかい 세계 ".repeat(512).into_bytes();
            let sent = data.clone();
            run_with_ring(8, 4096, incremental, async move {
                let (mut stream, peer) = accept_one(move |mut client| {
                    client.write_all(&sent).expect("send");
                })
                .await;
                // A small read leaves the rest of its ring buffer held.
                let http_kit_io::BufResult(res, head) =
                    http_kit_io::Read::read(&mut stream, Vec::with_capacity(10)).await;
                assert_eq!(res.expect("read"), 10);
                let mut received = head;
                let mut pipe = Pipe::new().expect("pipe");
                loop {
                    match stream.splice_to_pipe(pipe, usize::MAX).await {
                        Ok(Spliced::Filled(filled)) => {
                            let (bytes, empty) = filled.read_out().expect("read the pipe");
                            received.extend_from_slice(&bytes);
                            pipe = empty;
                        }
                        Ok(Spliced::End(_)) => break,
                        Err((error, _)) => panic!("splice: {error}"),
                    }
                }
                super::assert_bytes(&received, &data);
                peer.join().expect("peer thread");
            });
        }
    }

    /// Stopping the read-ahead hands back what was received and not read,
    /// and the reads after it continue from the socket where that ended.
    #[cfg(target_os = "linux")]
    #[test]
    fn stopping_read_ahead_hands_back_what_was_received() {
        use std::io::Write as _;

        use http_kit_io::ReadAhead as _;

        for incremental in CONSUMPTIONS {
            let data = "世界 せかい 세계 ".repeat(4096).into_bytes();
            let sent = data.clone();
            run_with_ring(8, 4096, incremental, async move {
                let (mut stream, peer) = accept_one(move |mut client| {
                    client.write_all(&sent).expect("send");
                })
                .await;
                let http_kit_io::BufResult(res, head) =
                    http_kit_io::Read::read(&mut stream, Vec::with_capacity(10)).await;
                assert_eq!(res.expect("read"), 10);
                let mut received = head;
                received.extend_from_slice(&stream.stop_read_ahead().await);
                received.extend_from_slice(&super::read_to_end(&mut stream).await);
                super::assert_bytes(&received, &data);
                peer.join().expect("peer thread");
            });
        }
    }

    /// On a ring the kernel consumes incrementally, consecutive small reads
    /// of a connection share a ring buffer, each continuing where the one
    /// before ended: a ring of two buffers lends eight reads at once, where
    /// consuming buffers whole would run it dry after two.
    #[cfg(target_os = "linux")]
    #[test]
    fn small_reads_share_a_ring_buffer() {
        use std::io::{Read as _, Write as _};

        use http_kit_io::{ReadOwned as _, Received};

        const MESSAGE: usize = 16;
        const MESSAGES: usize = 8;

        let data = super::payload()[..MESSAGE * MESSAGES].to_vec();
        let sent = data.clone();
        run_with_ring(2, 4096, true, async move {
            let incremental = ::compio::runtime::Runtime::with_current(|runtime| {
                runtime.buffer_pool()?.is_incremental()
            })
            .expect("the runtime's ring");
            if !incremental {
                eprintln!("the kernel consumes ring buffers whole (before Linux 6.12), skipping");
                return;
            }
            // Each message waits for the one before it to be read, so each
            // read is one message.
            let (mut stream, peer) = accept_one(move |mut client| {
                for message in sent.chunks(MESSAGE) {
                    client.write_all(message).expect("send");
                    client.read_exact(&mut [0]).expect("wait for the read");
                }
            })
            .await;
            let mut lent = Vec::with_capacity(MESSAGES);
            for message in data.chunks(MESSAGE) {
                let Received::Lent(buf) = stream.read_owned().await.expect("read") else {
                    panic!("the ring ran dry after {} reads", lent.len());
                };
                assert_eq!(&*buf, message);
                lent.push(buf);
                let http_kit_io::BufResult(res, _) =
                    http_kit_io::Write::write(&mut stream, vec![0]).await;
                res.expect("acknowledge");
            }
            for pair in lent.windows(2) {
                assert_eq!(
                    pair[1].as_ptr(),
                    pair[0].as_ptr().wrapping_add(pair[0].len()),
                    "a read continues in the buffer of the one before"
                );
            }
            peer.join().expect("peer thread");
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
            let io = http_kit_io::compio::Compio::default();
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
            let io = http_kit_io::compio::Compio::default();
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

    /// A round that fails after part of it reached the socket reports the
    /// part that did, as any write does, and leaves the error to the next
    /// call: reported as the round's result, a retried error (`Interrupted`,
    /// which `send_file_all` retries at the same offset) would send those
    /// bytes twice.
    ///
    /// The peer reads nothing and both socket buffers are at their minimum,
    /// so the round's pipe drains only partly before the socket is full;
    /// the peer then resets the connection, which fails the rest.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn send_file_reports_what_it_sent_before_failing() {
        use std::{sync::mpsc, time::Duration};

        use http_kit_io::{BufResult, Listen as _, Listener as _, SendFile as _};

        // Below the kernel's minimum, which each buffer is raised to
        // (`SOCK_MIN_SNDBUF`, `SOCK_MIN_RCVBUF`), far below a pipe's 64 KiB.
        const BUFFER: usize = 1;

        let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("compio-reset-peer");
        let contents = super::payload();
        std::fs::write(&path, &contents).expect("write the file to send");
        let file = std::rc::Rc::new(std::fs::File::open(&path).expect("open the file to send"));

        let (reset, resets) = mpsc::channel::<()>();
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
            resets.recv().expect("reset");
            // A zero linger closes with a reset.
            socket
                .set_linger(Some(Duration::ZERO))
                .expect("zero linger");
        });

        let (first, next) = run(async {
            let io = http_kit_io::compio::Compio::default();
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(BUFFER)
                .expect("send buffer");
            let send = stream.send_file(file.clone(), 0, contents.len());
            let watch = async {
                // The round fills its pipe and waits on the full socket.
                ::compio::time::sleep(Duration::from_millis(300)).await;
                reset.send(()).expect("reset the peer");
            };
            let (BufResult(first, _), ()) = futures_lite::future::zip(send, watch).await;
            let sent = *first.as_ref().expect("the round reports what it sent");
            let BufResult(next, _) = stream
                .send_file(file.clone(), sent as u64, contents.len() - sent)
                .await;
            (sent, next)
        });
        peer.join().expect("peer thread");
        std::fs::remove_file(&path).expect("remove the sent file");
        assert!(
            first > 0 && first < contents.len(),
            "part of the region was sent: {first} of {} bytes",
            contents.len()
        );
        assert!(
            next.is_err(),
            "the next call reports the reset connection: {next:?}"
        );
    }

    /// A buffer that records when it is dropped.
    #[cfg(target_os = "linux")]
    struct Tracked {
        bytes: Vec<u8>,
        dropped: std::rc::Rc<std::cell::Cell<bool>>,
    }

    #[cfg(target_os = "linux")]
    impl http_kit_io::IoBuf for Tracked {
        fn as_init(&self) -> &[u8] {
            &self.bytes
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    /// Runs `future`, failing the test if it takes longer than `limit`.
    #[cfg(target_os = "linux")]
    async fn within<F: Future>(limit: std::time::Duration, what: &str, future: F) -> F::Output {
        let expired = async {
            ::compio::time::sleep(limit).await;
            panic!("{what} took longer than {limit:?}");
        };
        futures_lite::future::or(future, expired).await
    }

    /// A zero-copy write returns while the kernel still reads the caller's
    /// buffer: a peer that reads nothing leaves most of it unsent. The stream
    /// keeps the buffer, and the kernel's notification, which comes once the
    /// peer has read every byte, drops it.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_notification_releases_a_zero_copy_buffer() {
        use std::{cell::Cell, io::Read as _, rc::Rc, sync::mpsc, time::Duration};

        use http_kit_io::{BufResult, Listen as _, Listener as _, Write as _, compio::Compio};

        /// What the peer's receive buffer is asked to hold: far less than
        /// the write, so the rest waits in the sender's queue.
        const PEER_BUFFER: usize = 16 * 1024;
        /// Above the default threshold, and within the sender's send buffer
        /// (which zero-copy pages count against) once raised.
        const LEN: usize = 256 * 1024;

        let data = super::payload()[..LEN].to_vec();
        let (release, released) = mpsc::channel::<()>();
        let (addr_tx, addr_rx) = mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
                .expect("peer socket");
            socket
                .set_recv_buffer_size(PEER_BUFFER)
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

        let sent = data.clone();
        run(async move {
            let io = Compio::default();
            assert!(LEN >= io.zero_copy().threshold());
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(4 * LEN)
                .expect("send buffer");

            let dropped = Rc::new(Cell::new(false));
            let buf = Tracked {
                bytes: sent,
                dropped: Rc::clone(&dropped),
            };
            let BufResult(res, kept) = within(
                Duration::from_secs(10),
                "the zero-copy write",
                stream.write_all_owned([buf]),
            )
            .await;
            res.expect("zero-copy write");
            assert!(
                kept.is_none(),
                "the stream handed back a buffer the kernel may still read"
            );
            assert!(
                !dropped.get(),
                "the buffer was dropped while the peer had read nothing"
            );

            release.send(()).expect("release the peer");
            within(Duration::from_secs(10), "the notification", async {
                while !dropped.get() {
                    ::compio::time::sleep(Duration::from_millis(1)).await;
                }
            })
            .await;
            http_kit_io::Write::shutdown(&mut stream)
                .await
                .expect("shutdown");
        });
        super::assert_bytes(&peer.join().expect("peer thread"), &data);
    }

    /// A write below the threshold copies and hands its buffer back, and so
    /// does any write once the threshold is raised on a clone of the setting
    /// the stream already holds.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_zero_copy_threshold_is_a_runtime_setting() {
        use std::io::Read as _;

        use http_kit_io::{
            BufResult, Listen as _, Listener as _, Write as _,
            compio::{Compio, ZeroCopySend},
        };

        let data = super::payload()[..64 * 1024].to_vec();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let mut stream = std::net::TcpStream::connect(addr).expect("connect");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).expect("read");
            received
        });

        let sent = data.clone();
        run(async move {
            let setting = ZeroCopySend::new(sent.len() + 1);
            let io = Compio::default().with_zero_copy(setting.clone());
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");

            let BufResult(res, kept) = stream.write_all_owned([sent]).await;
            res.expect("write below the threshold");
            let [sent] = kept.expect("a copying write hands the buffer back");

            setting.set_threshold(0);
            let BufResult(res, kept) = stream.write_all_owned([sent]).await;
            res.expect("zero-copy write");
            assert!(kept.is_none(), "the lowered threshold did not apply");

            setting.set_threshold(usize::MAX);
            let BufResult(res, kept) = stream.write_all_owned([vec![0; 64 * 1024]]).await;
            res.expect("write with zero-copy off");
            assert!(kept.is_some(), "the raised threshold did not apply");
            http_kit_io::Write::shutdown(&mut stream)
                .await
                .expect("shutdown");
        });
        let received = peer.join().expect("peer thread");
        let mut expected = data.clone();
        expected.extend_from_slice(&data);
        expected.extend_from_slice(&[0; 64 * 1024]);
        super::assert_bytes(&received, &expected);
    }

    /// A file read into the ring's region of registered buffers is sent from
    /// it, with a head from ordinary memory before it, byte for byte; a
    /// write with no bytes in the region goes out as before.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_write_from_the_registered_region_sends_its_bytes() {
        use std::io::Read as _;

        use http_kit_io::{
            BufResult, Listen as _, Listener as _, Write as _,
            compio::{Compio, FixedBuffers, ZeroCopySend},
        };

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/io.rs");
        let body = std::fs::read(path).expect("read the file");
        let head = b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n".to_vec();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let mut stream = std::net::TcpStream::connect(addr).expect("connect");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).expect("read");
            received
        });

        let (sent_head, len) = (head.clone(), body.len());
        run(async move {
            let io = Compio::default()
                .with_zero_copy(ZeroCopySend::new(0))
                .with_fixed_buffers(FixedBuffers::new(4 * 1024 * 1024))
                .register_fixed_region()
                .await
                .expect("register the region");
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");

            let body = match io.fixed_region() {
                Some(region) => {
                    let file = ::compio::driver::SharedFd::new(
                        std::fs::File::open(path).expect("open the file"),
                    );
                    region
                        .read_at(file, 0, len)
                        .await
                        .expect("read into the region")
                        .expect("the region has room")
                }
                // The kernel refused io_uring: nothing is registered.
                None => bytes::Bytes::from(std::fs::read(path).expect("read the file")),
            };
            let BufResult(res, _) = stream
                .write_all_owned([bytes::Bytes::from(sent_head), body])
                .await;
            res.expect("write from the region");
            let BufResult(res, _) = stream
                .write_all_owned([bytes::Bytes::from_static(b"ordinary memory")])
                .await;
            res.expect("write from ordinary memory");
            http_kit_io::Write::shutdown(&mut stream)
                .await
                .expect("shutdown");
        });
        let received = peer.join().expect("peer thread");
        let mut expected = head;
        expected.extend_from_slice(&body);
        expected.extend_from_slice(b"ordinary memory");
        super::assert_bytes(&received, &expected);
    }

    /// Bytes handed out of a region and dropped on another thread give their
    /// span back to it.
    #[cfg(target_os = "linux")]
    #[test]
    fn region_bytes_dropped_elsewhere_give_their_span_back() {
        use http_kit_io::compio::{Compio, FixedBuffers};

        run(async {
            let io = Compio::default()
                .with_fixed_buffers(FixedBuffers::new(1024 * 1024))
                .register_fixed_region()
                .await
                .expect("register the region");
            let Some(region) = io.fixed_region() else {
                // The kernel refused io_uring: nothing is registered.
                return;
            };
            // Most of the region, since the allocator rounds a request up to
            // its size class.
            let most = region.len() / 4 * 3;
            let held = region.alloc(most).expect("most of the region");
            assert!(region.alloc(most).is_none(), "the region has no room left");
            let bytes = held.freeze();
            std::thread::spawn(move || drop(bytes))
                .join()
                .expect("drop on another thread");
            assert!(region.alloc(most).is_some(), "the span came back");
        });
    }

    /// The name the kernel gives a socket's file, as `/proc` lists it.
    #[cfg(target_os = "linux")]
    fn socket_name(socket: &impl std::os::fd::AsFd) -> String {
        use std::os::fd::AsRawFd as _;

        let link = format!("/proc/self/fd/{}", socket.as_fd().as_raw_fd());
        std::fs::read_link(link)
            .expect("socket link")
            .into_os_string()
            .into_string()
            .expect("socket name")
    }

    /// How many slots of the current ring's file table hold the file named
    /// `name`, as the kernel lists them (`io_uring_show_fdinfo`).
    #[cfg(target_os = "linux")]
    fn slots_holding(name: &str) -> usize {
        use std::os::fd::AsRawFd as _;

        let ring = ::compio::runtime::Runtime::with_current(|runtime| runtime.as_raw_fd());
        let info =
            std::fs::read_to_string(format!("/proc/self/fdinfo/{ring}")).expect("ring fdinfo");
        info.lines()
            .skip_while(|line| !line.starts_with("UserFiles:"))
            .skip(1)
            .take_while(|line| {
                line.split(':')
                    .next()
                    .is_some_and(|slot| slot.trim().parse::<u32>().is_ok())
            })
            .filter(|line| line.trim_end().ends_with(name))
            .count()
    }

    /// Waits until `held` slots hold the file named `name`.
    #[cfg(target_os = "linux")]
    async fn until_held(name: &str, held: usize) {
        within(std::time::Duration::from_secs(5), "the file table", async {
            while slots_holding(name) != held {
                ::compio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await;
    }

    /// Once a stream holds its slot, its operations name the socket by it:
    /// with the descriptor pointed elsewhere, the multishot receive, copying
    /// and zero-copy sends and the shutdown still reach the socket. Dropping
    /// the stream gives the slot back.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_stream_operates_through_its_registered_slot() {
        use std::{
            io::{Read as _, Write as _},
            os::fd::{AsFd as _, AsRawFd as _},
        };

        use http_kit_io::{BufResult, Listen as _, Listener as _, Read as _, Write as _};

        let greeting = "你好 こんにちは 안녕하세요".as_bytes();
        let data = super::payload()[..256 * 1024].to_vec();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let mut stream = std::net::TcpStream::connect(addr).expect("connect");
            stream.write_all(greeting).expect("greet");
            let mut received = Vec::new();
            stream.read_to_end(&mut received).expect("read");
            received
        });

        let sent = data.clone();
        run(async move {
            let io = http_kit_io::compio::Compio::default();
            assert!(sent.len() >= io.zero_copy().threshold());
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");
            let name = socket_name(&stream);
            until_held(&name, 1).await;

            let null = std::fs::File::open("/dev/null").expect("/dev/null");
            // SAFETY: the stream's descriptor stays open, on /dev/null from
            // here on, and the stream closes it when dropped.
            let duped = unsafe { libc::dup2(null.as_raw_fd(), stream.as_fd().as_raw_fd()) };
            assert_ne!(duped, -1, "dup2: {}", std::io::Error::last_os_error());

            let mut echoed = Vec::new();
            while echoed.len() < greeting.len() {
                let BufResult(res, buf) = stream.read(Vec::with_capacity(64)).await;
                assert_ne!(res.expect("read through the slot"), 0, "early end");
                echoed.extend_from_slice(&buf);
            }
            let BufResult(res, _) = stream.write_all_owned([echoed]).await;
            res.expect("copying write through the slot");
            let BufResult(res, kept) = stream.write_all_owned([sent]).await;
            res.expect("zero-copy write through the slot");
            assert!(kept.is_none(), "the write was not zero-copy");
            http_kit_io::Write::shutdown(&mut stream)
                .await
                .expect("shutdown through the slot");
            drop(stream);
            until_held(&name, 0).await;
        });
        let mut expected = greeting.to_vec();
        expected.extend_from_slice(&data);
        super::assert_bytes(&peer.join().expect("peer thread"), &expected);
    }

    /// A runtime dropped while a task still holds a stream with a slot tears
    /// down cleanly: dropping the stream with the task hands the runtime no
    /// new task while it is clearing its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_runtime_drops_while_a_task_holds_a_stream_with_a_slot() {
        use std::io::Read as _;

        let peer = run(async {
            let (stream, peer) = accept_one(|mut client| {
                // The connection ends with the runtime, which drops the
                // stream with the task holding it.
                let _ = client.read_to_end(&mut Vec::new());
            })
            .await;
            until_held(&socket_name(&stream), 1).await;
            ::compio::runtime::spawn(async move {
                let _stream = stream;
                std::future::pending::<()>().await;
            })
            .detach();
            peer
        });
        peer.join().expect("peer thread");
    }

    /// A socket the ring's table has no room for stays on its descriptor and
    /// works as any other.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_socket_the_table_has_no_room_for_uses_its_descriptor() {
        use std::io::{Read as _, Write as _};

        use http_kit_io::{
            BufResult, Listen as _, Listener as _, Read as _, Write as _,
            compio::{Compio, FileTable},
        };

        let greeting = "世界 せかい 세계".as_bytes();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let peers = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let peers = [(); 2].map(|()| {
                let mut stream = std::net::TcpStream::connect(addr).expect("connect");
                stream.write_all(greeting).expect("greet");
                stream
            });
            peers.map(|mut stream| {
                let mut received = Vec::new();
                stream.read_to_end(&mut received).expect("read");
                received
            })
        });

        run(async move {
            let io = Compio::default().with_file_table(FileTable::new(1));
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (first, _) = listener.accept().await.expect("accept");
            let (second, _) = listener.accept().await.expect("accept");
            let names = [socket_name(&first), socket_name(&second)];
            within(
                std::time::Duration::from_secs(5),
                "a slot for one of the sockets",
                async {
                    while names.iter().map(|name| slots_holding(name)).sum::<usize>() == 0 {
                        ::compio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                },
            )
            .await;
            // Both keepers have asked for a slot by now; the one that came
            // second found the table full.
            ::compio::time::sleep(std::time::Duration::from_millis(20)).await;
            let held = names.each_ref().map(|name| slots_holding(name));
            assert_eq!(held.iter().sum::<usize>(), 1, "slots held: {held:?}");

            for mut stream in [first, second] {
                let mut echoed = Vec::new();
                while echoed.len() < greeting.len() {
                    let BufResult(res, buf) = stream.read(Vec::with_capacity(64)).await;
                    assert_ne!(res.expect("read"), 0, "early end");
                    echoed.extend_from_slice(&buf);
                }
                let BufResult(res, _) = stream.write_all_owned([echoed]).await;
                res.expect("write");
                http_kit_io::Write::shutdown(&mut stream)
                    .await
                    .expect("shutdown");
            }
        });
        for received in peers.join().expect("peer thread") {
            super::assert_bytes(&received, greeting);
        }
    }

    /// A table the kernel refuses to register is the stream's error, not a
    /// silent loss of the slot.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_table_the_kernel_refuses_fails_the_stream() {
        use std::io::Read as _;

        use http_kit_io::{
            BufResult, Listen as _, Listener as _, Write as _,
            compio::{Compio, FileTable},
        };

        /// One slot more than any ring may register (`IORING_MAX_FIXED_FILES`,
        /// `io_uring/rsrc.h`).
        const SLOTS: u32 = (1 << 20) + 1;

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let peer = std::thread::spawn(move || {
            let addr = addr_rx.recv().expect("listener address");
            let mut stream = std::net::TcpStream::connect(addr).expect("connect");
            let mut received = Vec::new();
            // The stream may end in a reset once it fails.
            let _ = stream.read_to_end(&mut received);
        });

        run(async move {
            let io = Compio::default().with_file_table(FileTable::new(SLOTS));
            let listener = io.bind_tcp(super::loopback()).expect("bind");
            addr_tx
                .send(listener.local_addr().expect("local address"))
                .expect("send address");
            let (mut stream, _) = listener.accept().await.expect("accept");
            let error = within(
                std::time::Duration::from_secs(5),
                "the refused table",
                async {
                    loop {
                        let BufResult(res, _) = stream.write(b"x".to_vec()).await;
                        if let Err(error) = res {
                            break error;
                        }
                        ::compio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                },
            )
            .await;
            assert!(
                error.to_string().contains("registering a file table"),
                "unexpected error: {error}"
            );
        });
        peer.join().expect("peer thread");
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
