//! TLS over owned-buffer streams: rustls driven straight over
//! [`http_kit_io`] sockets, with the record layer handed to the kernel on
//! Linux.
//!
//! # Entry points
//!
//! [`TlsAcceptor::accept`] runs the server handshake over an accepted
//! stream, [`TlsConnector::connect`] the client one over a connected stream;
//! both take a [`ServerConfig`](rustls::ServerConfig) or
//! [`ClientConfig`](rustls::ClientConfig) as rustls builds them (ALPN
//! included) and bound the handshake by a deadline. Either returns a
//! [`TlsStream`], which is a stream like the one under it — [`Read`],
//! [`Write`], [`SendFile`] and [`Split`] — so an HTTP/1.1 connection runs
//! over it unchanged, and [`TlsStream::alpn_protocol`] says which protocol
//! that should be.
//!
//! # No copy through a poll bridge
//!
//! rustls's unbuffered API decrypts records in place in a buffer the socket
//! read into by ownership, and encrypts straight into the buffer the socket
//! then writes from; nothing goes through `futures_io` or an intermediate
//! copy of the stream.
//!
//! # Kernel TLS
//!
//! With the `kernel` feature on Linux, an acceptor or connector given a
//! [`KernelTls`] probe moves each connection to kernel TLS when its
//! handshake completes and the kernel takes the negotiated suite
//! (AES-GCM-128/256 or ChaCha20-Poly1305, TLS 1.2 or 1.3). The socket then
//! reads and writes plaintext, and [`SendFile`] is the socket's own
//! `splice`/`sendfile`, encrypted in the kernel without the file entering
//! user space. A connection the kernel cannot take stays in user space;
//! which one it is, is [`TlsStream::mode`].
//!
//! A kernel TLS stream and its halves also forward without the bytes
//! entering user space: they implement [`SpliceRead`] and [`SpliceWrite`]
//! (Linux and Android), splicing the plaintext the kernel opens into a pipe
//! and from a pipe into records the kernel seals. Plaintext rustls decrypted
//! before the switch comes out first, and a record other than data (a
//! `KeyUpdate`, a `NewSessionTicket`, a `close_notify`) is handled in the
//! middle of a splice as it is in a read. A user-space connection reports
//! `can_splice() == false` and refuses a splice with
//! [`io::ErrorKind::Unsupported`](std::io::ErrorKind::Unsupported). On Linux
//! the kernel's socket halves must be splice-capable
//! ([`SpliceRead`]/[`SpliceWrite`]) to be handed to the kernel, which every
//! socket of `http-kit-io` is.
//!
//! # Closing
//!
//! Shutting the write side down sends `close_notify` first. A peer that
//! closes the connection without one is reported as
//! [`io::ErrorKind::UnexpectedEof`](std::io::ErrorKind::UnexpectedEof), not
//! as the end of the stream: the data may have been cut short.
//!
//! # Threads
//!
//! Nothing is `Send`: a connection, and both its halves, stay on the thread
//! that accepted or dialled it.
//!
//! # Example
//!
//! An HTTP/1.1 exchange over TLS on one compio thread:
//!
//! ```
//! use std::sync::Arc;
//!
//! use futures_lite::future::zip;
//! use http_kit::{Body, Request, Response};
//! use http_kit_h1::{ClientConfig, ServerConfig, ServerConnection, handshake_stream};
//! use http_kit_io::{Dial as _, Listen as _, Listener as _, compio::Compio};
//! use http_kit_tls::{TlsAcceptor, TlsConnector, rustls};
//!
//! # fn main() -> std::io::Result<()> {
//! let provider = Arc::new(rustls::crypto::ring::default_provider());
//! let issued = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
//! let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
//!     .with_safe_default_protocol_versions()
//!     .unwrap()
//!     .with_no_client_auth()
//!     .with_single_cert(
//!         vec![issued.cert.der().clone()],
//!         issued.signing_key.serialize_der().try_into().unwrap(),
//!     )
//!     .unwrap();
//! server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
//! let mut roots = rustls::RootCertStore::empty();
//! roots.add(issued.cert.der().clone()).unwrap();
//! let mut client = rustls::ClientConfig::builder_with_provider(provider)
//!     .with_safe_default_protocol_versions()
//!     .unwrap()
//!     .with_root_certificates(roots)
//!     .with_no_client_auth();
//! client.alpn_protocols = vec![b"http/1.1".to_vec()];
//! let acceptor = TlsAcceptor::new(Arc::new(server));
//! let connector = TlsConnector::new(Arc::new(client));
//!
//! compio::runtime::Runtime::new()?.block_on(async {
//!     let io = Compio::default();
//!     let listener = io.bind_tcp("127.0.0.1:0".parse().unwrap())?;
//!     let addr = listener.local_addr()?;
//!     let service = |request: Request| async move {
//!         Response::new(Body::from_bytes(request.uri().path().to_owned()))
//!     };
//!     let server = async {
//!         let (stream, _) = listener.accept().await?;
//!         let stream = acceptor.accept(stream, &io).await.map_err(std::io::Error::other)?;
//!         assert_eq!(stream.alpn_protocol(), Some(&b"http/1.1"[..]));
//!         let connection = ServerConnection::from_stream(stream, io.clone(), ServerConfig::default());
//!         connection.serve(&service).await.map_err(std::io::Error::other)
//!     };
//!     let client = async {
//!         let stream = io.connect(addr).await?;
//!         let name = "localhost".try_into().unwrap();
//!         let stream = connector.connect(name, stream, &io).await.map_err(std::io::Error::other)?;
//!         let (send, connection) = handshake_stream(stream, io.clone(), ClientConfig::default());
//!         let request = async move {
//!             let mut request = Request::new(Body::empty());
//!             *request.uri_mut() = format!("https://localhost:{}/hello", addr.port()).parse().unwrap();
//!             let response = send.send(request).await?;
//!             response.into_body().into_bytes().await.map_err(http_kit_h1::Error::from)
//!         };
//!         let (ran, body) = zip(connection.run(), request).await;
//!         ran.and(body).map_err(std::io::Error::other)
//!     };
//!     let (served, body) = zip(server, client).await;
//!     served?;
//!     assert_eq!(body?, "/hello");
//!     Ok(())
//! })
//! # }
//! ```

mod accept;
mod engine;
mod error;
#[cfg(feature = "kernel")]
mod kernel;
#[cfg(any(test, all(target_os = "linux", feature = "kernel")))]
mod record;
mod side;
mod stream;
mod user;

#[cfg(doc)]
use http_kit_io::{Read, SendFile, SpliceRead, SpliceWrite, Split, Write};
pub use rustls;

#[cfg(feature = "kernel")]
pub use crate::kernel::KernelTls;
pub use crate::{
    accept::{TlsAcceptor, TlsConnector},
    error::HandshakeError,
    side::{Client, Server, Side},
    stream::{
        Mode, Negotiated, TlsReadHalf, TlsStream, TlsWriteHalf, Transport, TransportRead,
        TransportWrite,
    },
};
