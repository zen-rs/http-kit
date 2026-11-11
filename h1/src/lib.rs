//! HTTP/1.1 server and client: a sans-IO protocol core, driven over
//! owned-buffer I/O.
//!
//! - [`proto`]: the protocol as pure functions and state machines over byte
//!   buffers. Heads are parsed with `httparse`; body framing
//!   (`Content-Length`, chunked with trailers in both directions) and the
//!   connection rules are this crate's own. Testable without a socket.
//! - [`server`]: [`ServerConnection`] runs the core over an
//!   [`http_kit_io`] socket and answers requests with a [`Service`].
//! - [`client`]: [`handshake`] runs it the other way, behind a
//!   [`SendRequest`] handle.
//!
//! # Zero copy
//!
//! Each read lands in the spare capacity of one receive buffer, and every
//! head field value and body data frame handed up is a [`Bytes`] slice of
//! that allocation: received bodies reach their consumer without a copy. On
//! the way out, a body's data frames go to a vectored write next to their
//! framing, and a file-region frame (feature `fs`) goes to
//! [`SendFile`](http_kit_io::SendFile), which is `sendfile`/`splice` where
//! the platform has them.
//!
//! With the `pipe` feature, on Linux and Android, a received body goes through
//! the kernel as well. A consumer that polls it with a
//! [`PipeOffer`](http_kit::PipeOffer) gets `BodyFrame::Pipe` frames for the
//! runs of raw body bytes (the rest of the `Content-Length`, the rest of a
//! chunk, a close-delimited body) that are still in a socket that can splice,
//! with nothing buffered ahead of them; framing, trailers and everything else
//! stay data and trailers frames, and a consumer that offers nothing receives
//! only those. A pipe frame in a body being sent is spliced into the socket
//! like a file region, with the chunk framing written around it.
//!
//! # Request smuggling
//!
//! Framing follows RFC 9112 §6.3 strictly: `Content-Length` together with
//! `Transfer-Encoding`, differing `Content-Length` values, a request whose
//! transfer coding is other than a lone final `chunked` (a response whose
//! final coding is not `chunked` is read until the connection closes, as
//! RFC 9112 §6.3 says), `Transfer-Encoding` in HTTP/1.0,
//! obs-fold and bare CR in a request, and chunk lines not ended by CRLF are
//! all rejected and end the connection. Head size, field count and chunk
//! line length are bounded by [`Limits`].
//!
//! # Timeouts
//!
//! Deadlines are driven by a [`Timer`](http_kit_io::Timer) handed to
//! [`ServerConnection`] and [`handshake`] (every
//! `http_kit_io` implementation is one). A server bounds the time to receive a request
//! head, the idle time between keep-alive requests and each read of a
//! request body; a client bounds its wait for `100 Continue`. Those durations
//! are fields of [`ServerConfig`] and [`ClientConfig`]. A client's receive
//! deadlines belong to the exchange, not the connection: each request carries
//! [`http_kit::Deadlines`] in its extensions, bounding the whole final
//! response head from the moment the connection takes the request and each
//! wait for body bytes.
//!
//! # Threads
//!
//! No future, body or service is required to be `Send`: a connection lives
//! on the thread that accepted or dialled it. Only the client's
//! [`SendRequest`] handle is `Send`, so a pool may hand it around.
//!
//! # Example
//!
//! A server and a client on one compio thread:
//!
//! ```
//! use futures_lite::future::zip;
//! use http_kit::{Body, Request, Response};
//! use http_kit_h1::{ClientConfig, ServerConfig, ServerConnection, handshake_stream};
//! use http_kit_io::{Dial as _, Listen as _, Listener as _, compio::Compio};
//!
//! # fn main() -> std::io::Result<()> {
//! compio::runtime::Runtime::new()?.block_on(async {
//!     let listener = Compio.bind_tcp("127.0.0.1:0".parse().unwrap())?;
//!     let addr = listener.local_addr()?;
//!     let service = |request: Request| async move {
//!         Response::new(Body::from_bytes(request.uri().path().to_owned()))
//!     };
//!     let server = async {
//!         let (stream, _) = listener.accept().await?;
//!         let connection = ServerConnection::from_stream(stream, Compio, ServerConfig::default());
//!         connection.serve(&service).await.map_err(std::io::Error::other)
//!     };
//!     let client = async {
//!         let stream = Compio.connect(addr).await?;
//!         let (send, connection) = handshake_stream(stream, Compio, ClientConfig::default());
//!         let request = async move {
//!             let mut request = Request::new(Body::empty());
//!             *request.uri_mut() = format!("http://{addr}/hello").parse().unwrap();
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

pub mod client;
pub mod proto;
pub mod server;

mod body;
mod config;
mod conn;
mod error;
mod splice;

use std::fmt;

use bytes::Bytes;

pub use crate::{
    client::{ClientOutcome, Connection, SendRequest, TrySendError, handshake, handshake_stream},
    config::{ClientConfig, Limits, ServerConfig},
    error::{Error, ParseError, Timeout},
    proto::RequestTarget,
    server::{ServerConnection, ServerOutcome, Service},
};

/// A connection handed over to another protocol after a switch.
pub struct Upgraded<R, W> {
    /// The read half of the socket.
    pub read: R,
    /// The write half of the socket.
    pub write: W,
    /// Bytes the peer sent after the head that switched protocols, already
    /// read off the socket: the new protocol's first bytes.
    pub read_buf: Bytes,
}

impl<R, W> fmt::Debug for Upgraded<R, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Upgraded")
            .field("read_buf", &self.read_buf.len())
            .finish_non_exhaustive()
    }
}
