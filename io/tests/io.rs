//! TCP and UDP echo, file-to-socket transfer, the poll-style capability and
//! timers, run against every implementation.
#![cfg(any(feature = "compio", feature = "tokio", feature = "async-io"))]

use std::{
    fs::File,
    net::SocketAddr,
    num::NonZeroU16,
    rc::Rc,
    time::{Duration, Instant},
};

use futures_lite::{AsyncReadExt as _, AsyncWriteExt as _, future::zip};
use http_kit_io::{
    BufResult, DatagramSocket, IntoPoll, Io, Listener, Read, SendFile, Split, Write,
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

        #[test]
        fn send_file() {
            $run(super::send_file($io, concat!(module_path!(), "-send_file")));
        }

        #[test]
        fn poll_echo() {
            $run(super::poll_echo($io));
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
