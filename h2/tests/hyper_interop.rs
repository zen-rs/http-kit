//! Bidirectional HTTP/2 interop tests between `http-kit-h2` and `hyper` / `h2`
//! across `compio` and `tokio`, cleartext h2c and `http-kit-tls` ALPN `h2`
//! (with Linux kernel TLS verification), covering concurrent multiplexing,
//! multi-MB flow-control backpressure, trailers, `GOAWAY` & `REFUSED_STREAM`
//! unprocessed `POST` recovery, `RST_STREAM`, `Deadlines`, `SendFile`, Linux
//! `Pipe` splicing, and RFC 9113 / RFC 8441 `CONNECT` & Extended `CONNECT`.

mod support;

use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_lite::{StreamExt as _, future::zip, stream};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body_util::BodyExt as _;
use http_kit::{Body, BodyError, BodyFrame, Deadlines, ReceiveError, Request, Response};
use http_kit_h2::{
    ClientConfig, Error, FlowControlConfig, Protocol, Reason, ServerConfig, ServerConnection,
    Timeout, handshake_stream,
};
use http_kit_io::{Dial, Listen, Listener as _, StreamSocket, Timer};
use hyper::{
    body::{Body as HttpBody, Frame},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use support::{
    CJK, TestPki, cjk_payload, loopback, on_compio, on_tokio, pki, tls_acceptor, tls_connector,
    within,
};

/// Tokio HTTP/2 server body supporting streaming chunks and trailers.
struct HyperStreamBody {
    chunks: Vec<Bytes>,
    idx: usize,
    trailers: Option<HeaderMap>,
}

impl HttpBody for HyperStreamBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.idx < self.chunks.len() {
            let chunk = self.chunks[self.idx].clone();
            self.idx += 1;
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        if let Some(trailers) = self.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }
}

/// Spawns a background `hyper` HTTP/2 server (cleartext or rustls ALPN `h2`) on
/// a dedicated Tokio thread and returns `(addr, connection_count, shutdown_tx)`.
fn spawn_hyper_server(
    tls: Option<Arc<rustls::ServerConfig>>,
) -> (SocketAddr, Arc<AtomicUsize>, async_channel::Sender<()>) {
    let std_listener = std::net::TcpListener::bind(loopback()).expect("bind std listener");
    std_listener.set_nonblocking(true).expect("nonblocking");
    let addr = std_listener.local_addr().expect("local addr");
    let accepted_conns = Arc::new(AtomicUsize::new(0));
    let conns_clone = Arc::clone(&accepted_conns);
    let (stop_tx, stop_rx) = async_channel::bounded::<()>(1);

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio server runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
            let tls_acceptor = tls.map(tokio_rustls::TlsAcceptor::from);
            loop {
                let accept = async { Some(listener.accept().await) };
                let stop = async {
                    let _ = stop_rx.recv().await;
                    None
                };
                let Some(Ok((tcp, _))) = futures_lite::future::or(accept, stop).await else {
                    break;
                };
                let _ = tcp.set_nodelay(true);
                conns_clone.fetch_add(1, Ordering::SeqCst);
                let tls_acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    let svc = service_fn(handle_hyper_request);
                    let mut builder =
                        hyper::server::conn::http2::Builder::new(TokioExecutor::new());
                    builder.initial_stream_window_size(64 * 1024);
                    builder.initial_connection_window_size(128 * 1024);
                    if let Some(acceptor) = tls_acceptor {
                        let Ok(tls_stream) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let _ = builder
                            .serve_connection(TokioIo::new(tls_stream), svc)
                            .await;
                    } else {
                        let _ = builder.serve_connection(TokioIo::new(tcp), svc).await;
                    }
                });
            }
        });
    });

    (addr, accepted_conns, stop_tx)
}

async fn handle_hyper_request(
    req: http::Request<hyper::body::Incoming>,
) -> Result<http::Response<HyperStreamBody>, Infallible> {
    let path = req.uri().path().to_owned();
    let method = req.method().clone();

    if path == "/slow-head" {
        tokio::time::sleep(Duration::from_millis(400)).await;
        return Ok(http::Response::new(HyperStreamBody {
            chunks: vec![Bytes::from_static(b"late")],
            idx: 0,
            trailers: None,
        }));
    }

    let greeting = req.headers().get("x-cjk").cloned();
    let collected = req.into_body().collect().await.expect("collect hyper req");
    let req_trailers = collected.trailers().cloned();
    let bytes = collected.to_bytes();

    if method == Method::HEAD {
        let mut resp = http::Response::new(HyperStreamBody {
            chunks: Vec::new(),
            idx: 0,
            trailers: None,
        });
        resp.headers_mut()
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("68"));
        return Ok(resp);
    }

    let trailers = if path == "/trailers" {
        let mut map = HeaderMap::new();
        map.insert("grpc-status", HeaderValue::from_static("0"));
        if let Some(in_tr) = req_trailers.and_then(|t| t.get("x-client-trailer").cloned()) {
            map.insert("x-echo-trailer", in_tr);
        }
        Some(map)
    } else {
        None
    };

    let chunks = if bytes.is_empty() {
        vec![Bytes::from(CJK.concat())]
    } else {
        bytes
            .chunks(16 * 1024)
            .map(Bytes::copy_from_slice)
            .collect()
    };

    let mut resp = http::Response::new(HyperStreamBody {
        chunks,
        idx: 0,
        trailers,
    });
    if let Some(g) = greeting {
        resp.headers_mut().insert("x-cjk", g);
    }
    Ok(resp)
}

async fn run_client_suite<I>(io: &I, pki: &TestPki, use_tls: bool)
where
    I: Dial + Timer + Clone + 'static,
    I::Connection: http_kit_tls::Transport + StreamSocket,
{
    let (addr, accepted_conns, _stop) =
        spawn_hyper_server(use_tls.then(|| pki.server_rustls.clone()));
    let scheme = if use_tls { "https" } else { "http" };

    let mut config = ClientConfig::default();
    // Exercise frequent WINDOW_UPDATE cycles on multi-MB transfers.
    config.flow_control = FlowControlConfig::default();
    config.flow_control.initial_stream_window_size = 64 * 1024;
    config.flow_control.initial_connection_window_size = 128 * 1024;

    let tcp = io.connect(addr).await.expect("dial hyper server");
    let (send, runner) = if use_tls {
        let connector = tls_connector(pki);
        let name = "localhost".try_into().expect("server name");
        let tls_stream = connector.connect(name, tcp, io).await.expect("TLS connect");
        assert_eq!(tls_stream.alpn_protocol(), Some(&b"h2"[..]));
        #[cfg(target_os = "linux")]
        if http_kit_tls::KernelTls::probe().is_ok() {
            assert_eq!(
                tls_stream.mode(),
                http_kit_tls::Mode::Kernel,
                "Linux TLS stream must offload records to kernel TLS"
            );
        }
        let (s, c) = handshake_stream(tls_stream, io.clone(), config);
        (
            s,
            Box::pin(c.run()) as Pin<Box<dyn std::future::Future<Output = Result<(), Error>>>>,
        )
    } else {
        let (s, c) = handshake_stream(tcp, io.clone(), config);
        (
            s,
            Box::pin(c.run()) as Pin<Box<dyn std::future::Future<Output = Result<(), Error>>>>,
        )
    };

    let client_work = async move {
        // 1. 24 concurrent CJK streams multiplexed over 1 TCP connection.
        let mut futs = Vec::new();
        for idx in 0..24usize {
            let s = send.clone();
            let payload = format!("{idx}:{}", CJK[idx % 3]);
            futs.push(async move {
                let mut req = Request::new(Body::from_bytes(payload.clone()));
                *req.method_mut() = Method::POST;
                *req.uri_mut() = format!("{scheme}://localhost:{}/mux/{idx}", addr.port())
                    .parse()
                    .expect("uri");
                req.headers_mut()
                    .insert("x-cjk", HeaderValue::from_str(CJK[idx % 3]).expect("hdr"));
                let resp = s.send(req).await.expect("mux send");
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(resp.headers()["x-cjk"], CJK[idx % 3]);
                let out = resp.into_body().into_bytes().await.expect("mux body");
                assert_eq!(out, payload.as_bytes());
            });
        }
        for fut in futs {
            fut.await;
        }
        assert_eq!(
            accepted_conns.load(Ordering::SeqCst),
            1,
            "all 24 concurrent streams multiplexed on one connection"
        );

        // 2. HEAD request with non-zero Content-Length and empty body.
        let mut head_req = Request::new(Body::empty());
        *head_req.method_mut() = Method::HEAD;
        *head_req.uri_mut() = format!("{scheme}://localhost:{}/head", addr.port())
            .parse()
            .expect("uri");
        let head_resp = send.send(head_req).await.expect("HEAD send");
        assert_eq!(head_resp.headers()["content-length"], "68");
        assert!(
            head_resp
                .into_body()
                .into_bytes()
                .await
                .expect("HEAD body")
                .is_empty()
        );

        // 3. Multi-MB (~2.1 MiB) CJK echo exercising bidirectional flow control.
        let big = cjk_payload(14 * 1024);
        let mut big_req = Request::new(Body::from_bytes(big.clone()));
        *big_req.method_mut() = Method::POST;
        *big_req.uri_mut() = format!("{scheme}://localhost:{}/big", addr.port())
            .parse()
            .expect("uri");
        let big_resp = send.send(big_req).await.expect("big send");
        let big_out = big_resp.into_body().into_bytes().await.expect("big body");
        assert_eq!(big_out.as_ref(), big.as_slice());

        // 4. Request & response trailers.
        let mut req_trailers = HeaderMap::new();
        req_trailers.insert("x-client-trailer", HeaderValue::from_static("ok-cjk"));
        let trailer_body = Body::from_frames(stream::iter([
            Ok::<_, BodyError>(BodyFrame::Data(Bytes::from(CJK[1]))),
            Ok(BodyFrame::Trailers(req_trailers)),
        ]));
        let mut tr_req = Request::new(trailer_body);
        *tr_req.method_mut() = Method::POST;
        *tr_req.uri_mut() = format!("{scheme}://localhost:{}/trailers", addr.port())
            .parse()
            .expect("uri");
        let tr_resp = send.send(tr_req).await.expect("trailers send");
        let frames: Vec<BodyFrame> = tr_resp
            .into_body()
            .try_collect()
            .await
            .expect("collect frames");
        let mut data_acc = Vec::new();
        let mut seen_trailers = None;
        for frame in frames {
            if let Some(d) = frame.as_data() {
                data_acc.extend_from_slice(d);
            } else if let Some(t) = frame.as_trailers() {
                seen_trailers = Some(t.clone());
            }
        }
        assert_eq!(data_acc, CJK[1].as_bytes());
        let seen_trailers = seen_trailers.expect("response trailers present");
        assert_eq!(seen_trailers["grpc-status"], "0");
        assert_eq!(seen_trailers["x-echo-trailer"], "ok-cjk");

        // 5. `SendFile` zero-copy file region (`fs` feature).
        #[cfg(feature = "fs")]
        {
            let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
            std::fs::create_dir_all(&dir).expect("tmpdir");
            let file_path = dir.join(format!("sendfile-{use_tls}-{}.bin", addr.port()));
            let file_bytes = cjk_payload(1024);
            std::fs::write(&file_path, &file_bytes).expect("write temp file");
            let file = std::fs::File::open(&file_path).expect("open temp file");
            let region = http_kit::FileRegion::new(file, 17, (file_bytes.len() - 29) as u64);
            let mut fs_req = Request::new(Body::from_file_region(region));
            *fs_req.method_mut() = Method::POST;
            *fs_req.uri_mut() = format!("{scheme}://localhost:{}/file", addr.port())
                .parse()
                .expect("uri");
            let fs_resp = send.send(fs_req).await.expect("sendfile request");
            let echoed = fs_resp
                .into_body()
                .into_bytes()
                .await
                .expect("sendfile echo");
            assert_eq!(echoed.as_ref(), &file_bytes[17..file_bytes.len() - 12]);
        }

        // 6. Per-request `response_head` deadline resets only the slow stream.
        let mut slow_req = Request::new(Body::empty());
        *slow_req.uri_mut() = format!("{scheme}://localhost:{}/slow-head", addr.port())
            .parse()
            .expect("uri");
        let mut deadlines = Deadlines::default();
        deadlines.response_head = Some(Duration::from_millis(60));
        slow_req.extensions_mut().insert(deadlines);
        let err = send
            .send(slow_req)
            .await
            .expect_err("response_head must time out");
        assert!(
            matches!(err, Error::Timeout(Timeout::ResponseHead)),
            "got {err:?}"
        );

        // Connection remains healthy after single-stream deadline reset.
        let mut after_req = Request::new(Body::from_bytes(CJK[2]));
        *after_req.method_mut() = Method::POST;
        *after_req.uri_mut() = format!("{scheme}://localhost:{}/after", addr.port())
            .parse()
            .expect("uri");
        let after_resp = send
            .send(after_req)
            .await
            .expect("healthy after stream timeout");
        assert_eq!(
            after_resp.into_body().into_bytes().await.expect("body"),
            CJK[2].as_bytes()
        );

        drop(send);
    };

    let (ran, ()) = within(io, Duration::from_secs(30), zip(runner, client_work)).await;
    ran.expect("client connection finished cleanly");
}

#[test]
fn client_interop_with_hyper_on_compio_h2c_and_tls() {
    let pki = pki();
    on_compio(|io| async move {
        run_client_suite(&io, &pki, false).await;
        run_client_suite(&io, &pki, true).await;
    });
}

#[test]
fn client_interop_with_hyper_on_tokio_h2c_and_tls() {
    let pki = pki();
    on_tokio(|io| async move {
        run_client_suite(&io, &pki, false).await;
        run_client_suite(&io, &pki, true).await;
    });
}

/// Drives `hyper::client::conn::http2` against `http-kit-h2::ServerConnection`
/// over both cleartext and TLS, including `SendFile`, trailers, and graceful `serve_until`.
async fn server_interop_service(request: Request) -> Response {
    let path = request.uri().path().to_owned();
    if path == "/trailers" {
        let body = request.into_body().into_bytes().await.expect("req body");
        let mut trailers = HeaderMap::new();
        trailers.insert("x-server-cjk", HeaderValue::from_static("ok"));
        return Response::new(Body::from_frames(stream::iter([
            Ok::<_, BodyError>(BodyFrame::Data(body)),
            Ok(BodyFrame::Trailers(trailers)),
        ])));
    }
    #[cfg(feature = "fs")]
    if path == "/sendfile" {
        let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let file_path = dir.join("server-sendfile.bin");
        let content = cjk_payload(512);
        std::fs::write(&file_path, &content).expect("write server file");
        let file = std::fs::File::open(&file_path).expect("open server file");
        return Response::new(Body::from_file_region(http_kit::FileRegion::new(
            file,
            0,
            content.len() as u64,
        )));
    }
    let greeting = request.headers().get("x-cjk").cloned();
    let mut resp = Response::new(request.into_body());
    if let Some(g) = greeting {
        resp.headers_mut().insert("x-cjk", g);
    }
    resp
}

async fn run_server_suite<I>(io: &I, pki: &TestPki, use_tls: bool)
where
    I: Listen + Timer + Clone + 'static,
    <I::Listener as http_kit_io::Listener>::Stream: http_kit_tls::Transport + StreamSocket,
{
    let listener = io.bind_tcp(loopback()).expect("bind server");
    let port = listener.local_addr().expect("local addr").port();
    let acceptor = tls_acceptor(pki);
    let client_tls = use_tls.then(|| pki.client_rustls.clone());
    let (shutdown_tx, shutdown_rx) = async_channel::bounded::<()>(1);

    let server_io = io.clone();
    let server = async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut config = ServerConfig::default();
        config.flow_control.initial_stream_window_size = 64 * 1024;
        config.flow_control.initial_connection_window_size = 128 * 1024;
        if use_tls {
            let tls_stream = acceptor
                .accept(stream, &server_io)
                .await
                .expect("TLS accept");
            assert_eq!(tls_stream.alpn_protocol(), Some(&b"h2"[..]));
            ServerConnection::from_stream(tls_stream, server_io, config)
                .serve_until(&server_interop_service, async move {
                    let _ = shutdown_rx.recv().await;
                })
                .await
                .expect("serve_until TLS");
        } else {
            ServerConnection::from_stream(stream, server_io, config)
                .serve_until(&server_interop_service, async move {
                    let _ = shutdown_rx.recv().await;
                })
                .await
                .expect("serve_until h2c");
        }
    };

    let (done_tx, done_rx) = async_channel::bounded(1);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("hyper client runtime");
        rt.block_on(async move {
            let tcp = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                .await
                .expect("hyper connect");
            let _ = tcp.set_nodelay(true);
            let mut sender = if let Some(tls_cfg) = client_tls {
                let connector = tokio_rustls::TlsConnector::from(tls_cfg);
                let name = "localhost".try_into().expect("sni");
                let tls = connector.connect(name, tcp).await.expect("tls connect");
                let (sender, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                        .await
                        .expect("hyper h2 handshake");
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sender
            } else {
                let (sender, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
                        .await
                        .expect("hyper h2 handshake");
                tokio::spawn(async move {
                    let _ = conn.await;
                });
                sender
            };

            // 16 concurrent streams + ~1.5 MiB body + trailers + SendFile.
            let mut handles = Vec::new();
            for i in 0..16usize {
                let mut s = sender.clone();
                handles.push(tokio::spawn(async move {
                    let payload = format!("{i}:{}", CJK[i % 3]);
                    let req = http::Request::builder()
                        .method(Method::POST)
                        .uri(format!("https://localhost:{port}/echo/{i}"))
                        .header("x-cjk", CJK[i % 3])
                        .body(http_body_util::Full::new(Bytes::from(payload.clone())))
                        .expect("build req");
                    let resp = s.send_request(req).await.expect("hyper send");
                    assert_eq!(resp.status(), StatusCode::OK);
                    assert_eq!(resp.headers()["x-cjk"], CJK[i % 3]);
                    let body = resp.into_body().collect().await.expect("body").to_bytes();
                    assert_eq!(body.as_ref(), payload.as_bytes());
                }));
            }
            for h in handles {
                h.await.expect("join stream");
            }

            let big = cjk_payload(10 * 1024);
            let big_req = http::Request::builder()
                .method(Method::POST)
                .uri(format!("https://localhost:{port}/echo-big"))
                .body(http_body_util::Full::new(Bytes::from(big.clone())))
                .expect("big req");
            let big_resp = sender.send_request(big_req).await.expect("big send");
            let big_out = big_resp
                .into_body()
                .collect()
                .await
                .expect("big collect")
                .to_bytes();
            assert_eq!(big_out.as_ref(), big.as_slice());

            let tr_req = http::Request::builder()
                .method(Method::POST)
                .uri(format!("https://localhost:{port}/trailers"))
                .body(http_body_util::Full::new(Bytes::from(CJK[0])))
                .expect("trailers req");
            let tr_resp = sender.send_request(tr_req).await.expect("trailers send");
            let collected = tr_resp.into_body().collect().await.expect("collect tr");
            let tr = collected.trailers().expect("server trailers").clone();
            assert_eq!(tr["x-server-cjk"], "ok");
            assert_eq!(collected.to_bytes().as_ref(), CJK[0].as_bytes());

            #[cfg(feature = "fs")]
            {
                let fs_req = http::Request::builder()
                    .method(Method::GET)
                    .uri(format!("https://localhost:{port}/sendfile"))
                    .body(http_body_util::Full::new(Bytes::new()))
                    .expect("sendfile req");
                let fs_resp = sender.send_request(fs_req).await.expect("sendfile send");
                let fs_bytes = fs_resp
                    .into_body()
                    .collect()
                    .await
                    .expect("collect fs")
                    .to_bytes();
                assert_eq!(fs_bytes.as_ref(), cjk_payload(512).as_slice());
            }

            // Trigger graceful two-phase GOAWAY on the server.
            shutdown_tx.close();
            done_tx.send_blocking(()).expect("signal done");
        });
    });

    let ((), ()) = within(
        io,
        Duration::from_secs(30),
        zip(server, async { done_rx.recv().await.expect("client done") }),
    )
    .await;
}

#[test]
fn server_interop_with_hyper_on_compio_and_tokio() {
    let pki = pki();
    let pki_compio = pki.clone();
    on_compio(|io| async move {
        run_server_suite(&io, &pki_compio, false).await;
        run_server_suite(&io, &pki_compio, true).await;
    });
    on_tokio(|io| async move {
        run_server_suite(&io, &pki, false).await;
        run_server_suite(&io, &pki, true).await;
    });
}

/// Tests `REFUSED_STREAM`, `GOAWAY` unprocessed `POST` recovery, `RST_STREAM(CANCEL)`,
/// `Deadlines::body_idle`, standard `CONNECT`, and RFC 8441 Extended `CONNECT` (`:protocol`)
/// against a peer `h2::server`.
#[test]
fn goaway_refused_reset_body_idle_and_extended_connect_interop() {
    let std_listener = std::net::TcpListener::bind(loopback()).expect("bind raw h2 server");
    std_listener.set_nonblocking(true).expect("nonblocking");
    let addr = std_listener.local_addr().expect("addr");

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("raw h2 runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).expect("listener");
            // Connection 1: REFUSED_STREAM on first POST, CANCEL on /cancel, stall on /stall,
            // CONNECT + Extended CONNECT, then GOAWAY(last_stream_id) on /trigger-goaway.
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut builder = h2::server::Builder::new();
                    builder.enable_connect_protocol();
                    let Ok(mut conn) = builder.handshake::<_, Bytes>(tcp).await else {
                        return;
                    };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        let path = req.uri().path().to_owned();
                        let method = req.method().clone();
                        let proto_ext = req.extensions().get::<h2::ext::Protocol>().cloned();

                        if path == "/refuse" {
                            respond.send_reset(h2::Reason::REFUSED_STREAM);
                            continue;
                        }
                        if path == "/cancel" {
                            respond.send_reset(h2::Reason::CANCEL);
                            continue;
                        }
                        if path == "/goaway-now" {
                            conn.graceful_shutdown();
                            let resp = http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            let mut send = respond.send_response(resp, false).unwrap();
                            send.send_data(Bytes::from_static(b"ok"), true).unwrap();
                            continue;
                        }
                        if path == "/stall-body" {
                            tokio::spawn(async move {
                                let resp = http::Response::builder()
                                    .status(StatusCode::OK)
                                    .body(())
                                    .unwrap();
                                let mut send = respond.send_response(resp, false).unwrap();
                                let _ = send.send_data(Bytes::from(CJK[0]), false);
                                tokio::time::sleep(Duration::from_secs(5)).await;
                                let _ = send.send_data(Bytes::from(CJK[1]), true);
                            });
                            continue;
                        }
                        if method == Method::CONNECT {
                            tokio::spawn(async move {
                                let mut recv = req.into_body();
                                let mut resp_builder =
                                    http::Response::builder().status(StatusCode::OK);
                                if let Some(p) = proto_ext {
                                    resp_builder =
                                        resp_builder.header("x-accepted-protocol", p.as_str());
                                }
                                let mut send = respond
                                    .send_response(resp_builder.body(()).unwrap(), false)
                                    .unwrap();
                                while let Some(Ok(chunk)) = recv.data().await {
                                    let _ = recv.flow_control().release_capacity(chunk.len());
                                    if send.send_data(chunk, false).is_err() {
                                        return;
                                    }
                                }
                                let _ = send.send_data(Bytes::new(), true);
                            });
                            continue;
                        }

                        tokio::spawn(async move {
                            let mut recv = req.into_body();
                            let mut buf = Vec::new();
                            while let Some(Ok(chunk)) = recv.data().await {
                                let _ = recv.flow_control().release_capacity(chunk.len());
                                buf.extend_from_slice(&chunk);
                            }
                            let resp = http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            let mut send = respond.send_response(resp, false).unwrap();
                            let _ = send.send_data(Bytes::from(buf), true);
                        });
                    }
                });
            }
        });
    });

    on_compio(|io| async move {
        let stream1 = io.connect(addr).await.expect("connect 1");
        let (send1, conn1) = handshake_stream(stream1, io.clone(), ClientConfig::default());

        let stream2 = io.connect(addr).await.expect("connect 2");
        let (send2, conn2) = handshake_stream(stream2, io.clone(), ClientConfig::default());

        let timer_io = io.clone();
        let test_logic = async move {
            // 1. POST rejected with REFUSED_STREAM recovers the full POST request & CJK body!
            let post_payload = CJK.concat();
            let mut post_req = Request::new(Body::from_text(post_payload.clone()));
            *post_req.method_mut() = Method::POST;
            *post_req.uri_mut() = format!("http://localhost:{}/refuse", addr.port())
                .parse()
                .unwrap();
            let mut refused = send1
                .try_send(post_req)
                .await
                .expect_err("REFUSED_STREAM must fail");
            assert!(matches!(refused.error(), Error::RequestRejected));
            let mut recovered = refused
                .take_request()
                .expect("REFUSED_STREAM must recover single-chunk POST request");
            assert_eq!(recovered.method(), Method::POST);
            // Retry recovered POST on `/ok` on `send2`!
            *recovered.uri_mut() = format!("http://localhost:{}/ok", addr.port())
                .parse()
                .unwrap();
            let retried = send2.send(recovered).await.expect("retry recovered POST");
            assert_eq!(
                retried.into_body().into_bytes().await.unwrap(),
                post_payload.as_bytes()
            );

            // 2. Peer RST_STREAM(CANCEL) -> Error::StreamReset(Reason::CANCEL).
            let mut cancel_req = Request::new(Body::empty());
            *cancel_req.uri_mut() = format!("http://localhost:{}/cancel", addr.port())
                .parse()
                .unwrap();
            let cancel_err = send1.send(cancel_req).await.expect_err("CANCEL must error");
            assert!(matches!(cancel_err, Error::StreamReset(r) if r == Reason::CANCEL));

            // 3. Body idle deadline -> ReceiveError::Stalled without killing sibling streams.
            let mut stall_req = Request::new(Body::empty());
            *stall_req.uri_mut() = format!("http://localhost:{}/stall-body", addr.port())
                .parse()
                .unwrap();
            let mut deadlines = Deadlines::default();
            deadlines.body_idle = Some(Duration::from_millis(80));
            stall_req.extensions_mut().insert(deadlines);
            let stall_resp = send1.send(stall_req).await.expect("head arrives");
            let body_err = stall_resp
                .into_body()
                .into_bytes()
                .await
                .expect_err("body must stall");
            assert!(
                matches!(body_err, BodyError::Receive(ReceiveError::Stalled)),
                "expected ReceiveError::Stalled, got {body_err:?}"
            );

            // 4. Full-duplex Extended CONNECT (`:protocol = websocket`) bidirectional streaming!
            let (tun_tx, tun_rx) = async_channel::bounded::<Result<Bytes, BodyError>>(4);
            let mut ext_connect = Request::new(Body::from_stream(tun_rx));
            *ext_connect.method_mut() = Method::CONNECT;
            *ext_connect.uri_mut() = format!("http://localhost:{}/chat", addr.port())
                .parse()
                .unwrap();
            ext_connect
                .extensions_mut()
                .insert(Protocol::from_static("websocket"));
            let tun_resp = send1.send(ext_connect).await.expect("Extended CONNECT");
            assert_eq!(tun_resp.status(), StatusCode::OK);
            assert_eq!(tun_resp.headers()["x-accepted-protocol"], "websocket");
            let mut tun_in = tun_resp.into_body().into_data_stream();
            for msg in CJK {
                tun_tx.send(Ok(Bytes::from(msg))).await.unwrap();
                let echoed = tun_in.next().await.expect("tunnel chunk").expect("ok");
                assert_eq!(echoed.as_ref(), msg.as_bytes());
            }
            tun_tx.close();
            assert!(tun_in.next().await.is_none());

            // 5. Standard RFC 9113 §8.5 CONNECT tunnel (authority only).
            let (std_tx, std_rx) = async_channel::bounded::<Result<Bytes, BodyError>>(2);
            let mut std_connect = Request::new(Body::from_stream(std_rx));
            *std_connect.method_mut() = Method::CONNECT;
            *std_connect.uri_mut() = format!("localhost:{}", addr.port()).parse().unwrap();
            let std_resp = send1.send(std_connect).await.expect("standard CONNECT");
            assert_eq!(std_resp.status(), StatusCode::OK);
            let mut std_in = std_resp.into_body().into_data_stream();
            std_tx.send(Ok(Bytes::from(CJK[0]))).await.unwrap();
            assert_eq!(
                std_in.next().await.unwrap().unwrap().as_ref(),
                CJK[0].as_bytes()
            );
            std_tx.close();
            assert!(std_in.next().await.is_none());

            // 6. Trigger peer GOAWAY -> SendRequest::is_closed() becomes true, and
            // subsequent POST is returned unsent via TrySendError::take_request()!
            let mut goaway_req = Request::new(Body::empty());
            *goaway_req.uri_mut() = format!("http://localhost:{}/goaway-now", addr.port())
                .parse()
                .unwrap();
            let goaway_resp = send1
                .send(goaway_req)
                .await
                .expect("in-flight before GOAWAY");
            assert_eq!(
                goaway_resp.into_body().into_bytes().await.unwrap().as_ref(),
                b"ok"
            );

            // Give the driver one turn to read the trailing GOAWAY frame if needed.
            while !send1.is_closed() {
                timer_io.sleep(Duration::from_millis(5)).await;
            }
            let mut after_goaway = Request::new(Body::from_bytes(CJK[2]));
            *after_goaway.method_mut() = Method::POST;
            *after_goaway.uri_mut() = format!("http://localhost:{}/ok", addr.port())
                .parse()
                .unwrap();
            let mut err = send1
                .try_send(after_goaway)
                .await
                .expect_err("closed handle refuses");
            let recovered_post = err.take_request().expect("closed handle returns POST");
            let ok_resp = send2.send(recovered_post).await.expect("succeeds on conn2");
            assert_eq!(
                ok_resp.into_body().into_bytes().await.unwrap().as_ref(),
                CJK[2].as_bytes()
            );

            drop(send1);
            drop(send2);
        };

        let ((r1, r2), ()) = within(
            &io,
            Duration::from_secs(30),
            zip(zip(conn1.run(), conn2.run()), test_logic),
        )
        .await;
        r1.expect("conn1 clean");
        r2.expect("conn2 clean");
    });
}

/// Verifies `ServerConnection` accepts RFC 8441 Extended `CONNECT` (`:protocol`)
/// from an `h2::client` peer and echoes full-duplex `DATA` frames.
#[test]
fn server_handles_extended_connect_from_h2_client() {
    on_compio(|io| async move {
        let listener = io.bind_tcp(loopback()).expect("bind");
        let port = listener.local_addr().expect("addr").port();

        let service = |request: Request| async move {
            assert_eq!(request.method(), Method::CONNECT);
            let proto = request
                .extensions()
                .get::<Protocol>()
                .expect("Extended CONNECT Protocol extension")
                .as_str()
                .to_owned();
            let mut resp = Response::new(request.into_body());
            resp.headers_mut()
                .insert("x-proto", HeaderValue::from_str(&proto).unwrap());
            resp
        };

        let server_io = io.clone();
        let server = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            ServerConnection::from_stream(stream, server_io, ServerConfig::default())
                .serve(&service)
                .await
                .expect("serve extended connect");
        };

        let (done_tx, done_rx) = async_channel::bounded(1);
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let tcp = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
                    .await
                    .unwrap();
                let (mut client, conn) = h2::client::handshake(tcp).await.unwrap();
                let conn_task = tokio::spawn(conn);
                client = client.ready().await.unwrap();

                let mut req = http::Request::builder()
                    .method(Method::CONNECT)
                    .uri(format!("http://localhost:{port}/tunnel"))
                    .body(())
                    .unwrap();
                req.extensions_mut()
                    .insert(h2::ext::Protocol::from_static("webtransport"));

                let (resp_fut, mut send_stream) = client.send_request(req, false).unwrap();
                let resp = resp_fut.await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(resp.headers()["x-proto"], "webtransport");
                let mut recv_stream = resp.into_body();

                for msg in CJK {
                    send_stream.send_data(Bytes::from(msg), false).unwrap();
                    let chunk = recv_stream.data().await.unwrap().unwrap();
                    let _ = recv_stream.flow_control().release_capacity(chunk.len());
                    assert_eq!(chunk.as_ref(), msg.as_bytes());
                }
                send_stream.send_data(Bytes::new(), true).unwrap();
                while let Some(chunk) = recv_stream.data().await {
                    assert!(chunk.unwrap().is_empty());
                }
                drop((send_stream, recv_stream, client));
                let _ = conn_task.await;
                done_tx.send_blocking(()).unwrap();
            });
        });

        let ((), ()) = within(
            &io,
            Duration::from_secs(20),
            zip(server, async { done_rx.recv().await.unwrap() }),
        )
        .await;
    });
}

/// Regression test covering:
/// 1. RFC 9113 §8.1: Server sends a complete multi-frame response (`END_STREAM`)
///    followed immediately by `RST_STREAM(NO_ERROR)` while the client's upload
///    stream is still open — client must still read the complete response body!
/// 2. Server sends `HEADERS` + `DATA(END_STREAM)` + `GOAWAY(NO_ERROR)` and closes
///    TCP (`EOF`) *before* the caller polls `Response::into_body()` — client must
///    still read the buffered complete response body and exit `Connection::run` cleanly!
#[test]
fn complete_response_with_rst_no_error_and_peer_eof_before_body_poll() {
    let std_listener = std::net::TcpListener::bind(loopback()).expect("bind");
    std_listener.set_nonblocking(true).expect("nonblocking");
    let addr = std_listener.local_addr().expect("addr");
    let expected = Bytes::from(cjk_payload(256));
    let expected_srv = expected.clone();

    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            let mut handles = Vec::new();
            for _ in 0..2 {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let payload = expected_srv.clone();
                handles.push(tokio::spawn(async move {
                    let Ok(mut conn) = h2::server::handshake(tcp).await else {
                        return;
                    };
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        let path = req.uri().path().to_owned();
                        if path == "/early-reply-rst" {
                            let payload = payload.clone();
                            tokio::spawn(async move {
                                let resp = http::Response::builder()
                                    .status(StatusCode::OK)
                                    .body(())
                                    .unwrap();
                                let mut send = respond.send_response(resp, false).unwrap();
                                let mid = payload.len() / 2;
                                send.send_data(payload.slice(..mid), false).unwrap();
                                send.send_data(payload.slice(mid..), true).unwrap();
                                // Let `conn` flush `HEADERS` + `DATA(END_STREAM)` onto TCP first,
                                // then drop `req` (with client upload still open), causing `h2`
                                // to transmit `RST_STREAM(NO_ERROR)` per RFC 9113 §8.1!
                                tokio::time::sleep(Duration::from_millis(10)).await;
                                drop(req);
                            });
                        } else if path == "/complete-then-eof" {
                            conn.graceful_shutdown();
                            let resp = http::Response::builder()
                                .status(StatusCode::OK)
                                .body(())
                                .unwrap();
                            let mut send = respond.send_response(resp, false).unwrap();
                            send.send_data(payload.clone(), true).unwrap();
                            // Drive `conn` to send HEADERS + DATA(END_STREAM) + GOAWAY(NO_ERROR) and close TCP!
                            break;
                        }
                    }
                    while conn.accept().await.is_some() {}
                }));
            }
            for handle in handles {
                let _ = handle.await;
            }
        });
    });

    on_compio(|io| async move {
        // Part 1: Complete response + `RST_STREAM(NO_ERROR)` while upload is still open.
        let stream1 = io.connect(addr).await.expect("connect 1");
        let (send1, conn1) = handshake_stream(stream1, io.clone(), ClientConfig::default());
        let timer1 = io.clone();
        let exp1 = expected.clone();
        let part1 = async move {
            let (_upload_tx, upload_rx) = async_channel::bounded::<Result<Bytes, BodyError>>(4);
            let mut req = Request::new(Body::from_stream(upload_rx));
            *req.method_mut() = Method::POST;
            *req.uri_mut() = format!("http://localhost:{}/early-reply-rst", addr.port())
                .parse()
                .unwrap();
            let resp = send1.send(req).await.expect("response head");
            // Wait slightly so `DATA(END_STREAM)` + `RST_STREAM(NO_ERROR)` both arrive in `recv_body`
            // before the consumer polls the body!
            timer1.sleep(Duration::from_millis(30)).await;
            let body_bytes = resp
                .into_body()
                .into_bytes()
                .await
                .expect("complete response must survive RST_STREAM(NO_ERROR)");
            assert_eq!(body_bytes.as_ref(), exp1.as_ref());
            drop(send1);
        };
        let (r1, ()) = within(&io, Duration::from_secs(15), zip(conn1.run(), part1)).await;
        r1.expect("conn1 clean");

        // Part 2: Complete response + `GOAWAY(NO_ERROR)` + peer TCP EOF before body is polled.
        let stream2 = io.connect(addr).await.expect("connect 2");
        let (send2, conn2) = handshake_stream(stream2, io.clone(), ClientConfig::default());
        let timer2 = io.clone();
        let exp2 = expected;
        let part2 = async move {
            let mut req = Request::new(Body::empty());
            *req.uri_mut() = format!("http://localhost:{}/complete-then-eof", addr.port())
                .parse()
                .unwrap();
            let resp = send2.send(req).await.expect("response head");
            // Wait until the server has sent GOAWAY + closed TCP (`send2.is_closed()` + EOF read)!
            timer2.sleep(Duration::from_millis(40)).await;
            assert!(send2.is_closed());
            let body_bytes = resp
                .into_body()
                .into_bytes()
                .await
                .expect("buffered END_STREAM body must survive peer EOF");
            assert_eq!(body_bytes.as_ref(), exp2.as_ref());
            drop(send2);
        };
        let (r2, ()) = within(&io, Duration::from_secs(15), zip(conn2.run(), part2)).await;
        r2.expect("conn2 clean after graceful GOAWAY + EOF");
    });
}

/// On Linux and Android (`pipe` feature), verifies that `ServerConnection`
/// echoing a streaming `POST` body from `hyper` splices unpadded `DATA` payloads
/// directly through kernel pipes (`SpliceRead` -> `Pipe` -> `SpliceWrite`).
#[cfg(all(feature = "pipe", any(target_os = "linux", target_os = "android")))]
#[test]
fn linux_pipe_splice_echoes_zero_copy() {
    use http_kit_io::{
        BufResult, IoBuf, IoBufMut, IoVectoredBuf, Read, ReadOwned, Received, SendFile, SpliceRead,
        SpliceWrite, Split, Write,
        splice::{FilledPipe, Pipe, Spliced},
    };
    use std::{cell::Cell, rc::Rc};

    #[derive(Default)]
    struct Counts {
        spliced_in: Cell<usize>,
        spliced_out: Cell<usize>,
    }

    struct SpyRead<R> {
        inner: R,
        counts: Rc<Counts>,
    }
    impl<R: Read> Read for SpyRead<R> {
        fn read<B: IoBufMut>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<usize, B>> {
            self.inner.read(buf)
        }
    }
    impl<R: ReadOwned> ReadOwned for SpyRead<R> {
        type Buf = R::Buf;
        fn read_owned(
            &mut self,
        ) -> impl std::future::Future<Output = std::io::Result<Received<Self::Buf>>> {
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
        ) -> Result<Spliced, (std::io::Error, Pipe)> {
            let res = self.inner.splice_to_pipe(pipe, max).await?;
            if let Spliced::Filled(f) = &res {
                self.counts
                    .spliced_in
                    .set(self.counts.spliced_in.get() + f.len());
            }
            Ok(res)
        }
    }

    struct SpyWrite<W> {
        inner: W,
        counts: Rc<Counts>,
    }
    impl<W: Write> Write for SpyWrite<W> {
        fn write<B: IoBuf>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<usize, B>> {
            self.inner.write(buf)
        }
        fn write_vectored<B: IoVectoredBuf>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<usize, B>> {
            self.inner.write_vectored(buf)
        }
        fn write_all_owned<B: IoVectoredBuf>(
            &mut self,
            buf: B,
        ) -> impl std::future::Future<Output = BufResult<(), Option<B>>> {
            self.inner.write_all_owned(buf)
        }
        fn flush(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> {
            self.inner.flush()
        }
        fn shutdown(&mut self) -> impl std::future::Future<Output = std::io::Result<()>> {
            self.inner.shutdown()
        }
    }
    impl<W: SendFile> SendFile for SpyWrite<W> {
        fn send_file<F: std::borrow::Borrow<std::fs::File> + 'static>(
            &mut self,
            file: F,
            offset: u64,
            len: usize,
        ) -> impl std::future::Future<Output = BufResult<usize, F>> {
            self.inner.send_file(file, offset, len)
        }
    }
    impl<W: SpliceWrite> SpliceWrite for SpyWrite<W> {
        fn can_splice(&self) -> bool {
            self.inner.can_splice()
        }
        async fn splice_from_pipe(&mut self, filled: FilledPipe) -> std::io::Result<Pipe> {
            let n = filled.len();
            let pipe = self.inner.splice_from_pipe(filled).await?;
            self.counts
                .spliced_out
                .set(self.counts.spliced_out.get() + n);
            Ok(pipe)
        }
    }

    on_compio(|io| async move {
        let listener = io.bind_tcp(loopback()).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let counts = Rc::new(Counts::default());
        let counts_srv = Rc::clone(&counts);

        let server_io = io.clone();
        let server = async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (r, w) = stream.split();
            let spy_r = SpyRead {
                inner: r,
                counts: Rc::clone(&counts_srv),
            };
            let spy_w = SpyWrite {
                inner: w,
                counts: counts_srv,
            };
            let echo = |req: Request| async move { Response::new(req.into_body()) };
            ServerConnection::new(spy_r, spy_w, server_io, ServerConfig::default())
                .serve(&echo)
                .await
                .expect("serve splice");
        };

        let chunk = Bytes::from(cjk_payload(128));
        let total_chunks = 16usize;
        let expected: Vec<u8> = chunk.as_ref().repeat(total_chunks);
        let client_io = io.clone();
        let client = async move {
            let stream = client_io.connect(addr).await.expect("connect");
            let (r, w) = stream.split();
            let timer_io = client_io.clone();
            let (send, conn) = http_kit_h2::handshake(r, w, client_io, ClientConfig::default());
            let ex = async move {
                let (tx, rx) = async_channel::bounded::<Result<Bytes, BodyError>>(1);
                let mut req = Request::new(Body::from_stream(rx));
                *req.method_mut() = Method::POST;
                *req.uri_mut() = format!("http://{addr}/splice").parse().unwrap();
                let feeder = async {
                    // Let HEADERS arrive and the echo service park its PipeOffer first.
                    timer_io.sleep(Duration::from_millis(20)).await;
                    for _ in 0..total_chunks {
                        tx.send(Ok(chunk.clone())).await.unwrap();
                    }
                    tx.close();
                };
                let requester = async {
                    let resp = send.send(req).await.expect("send");
                    drop(send);
                    let echoed = resp.into_body().into_bytes().await.expect("body");
                    assert_eq!(echoed.as_ref(), expected.as_slice());
                };
                zip(feeder, requester).await;
            };
            let (ran, _) = zip(conn.run(), ex).await;
            ran.expect("client run");
        };

        within(&io, Duration::from_secs(30), zip(server, client)).await;
        assert!(
            counts.spliced_in.get() > 0 && counts.spliced_out.get() > 0,
            "expected kernel pipe splice > 0 bytes, got in={} out={}",
            counts.spliced_in.get(),
            counts.spliced_out.get()
        );
    });
}
