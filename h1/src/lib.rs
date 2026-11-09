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
//! use http_kit_io::{Io as _, Listener as _, compio::Compio};
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
//!         let connection = ServerConnection::from_stream(stream, ServerConfig::default());
//!         connection.serve(&service).await.map_err(std::io::Error::other)
//!     };
//!     let client = async {
//!         let stream = Compio.connect(addr).await?;
//!         let (send, connection) = handshake_stream(stream, ClientConfig::default());
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

use std::fmt;

use bytes::Bytes;

pub use crate::{
    client::{ClientOutcome, Connection, SendRequest, handshake, handshake_stream},
    config::{ClientConfig, Limits, ServerConfig},
    error::{Error, ParseError},
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
