#![deny(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]
//! Sans-IO HTTP/2 (RFC 9113) server and client with HPACK (RFC 7541), SIMD
//! field validation, Extended `CONNECT` (RFC 8441), and zero-copy bodies over
//! [`http_kit_io`]'s owned-buffer sockets.
//!
//! - [`proto`], [`frame`], [`hpack`]: pure sans-IO HTTP/2 framing, stream and
//!   connection flow-control state machines, and HPACK header compression,
//!   testable without sockets or a runtime.
//! - [`client`]: [`handshake`] and [`handshake_stream`] multiplex concurrent
//!   requests through a thread-safe [`SendRequest`] handle onto a single-thread
//!   [`Connection`] driver.
//! - [`server`]: [`ServerConnection`] serves multiplexed requests with a
//!   `!Send` [`Service`] and drains connections via RFC 9113 §6.8 two-phase
//!   graceful `GOAWAY`.
//!
//! # Zero copy
//!
//! Socket reads go straight through [`ReadOwned`](http_kit_io::ReadOwned) into
//! owned buffers, slicing `DATA` payloads as [`Bytes`](bytes::Bytes) without
//! copying, and granting stream and connection `WINDOW_UPDATE` frames only as
//! the consumer drains [`Body`](http_kit::Body) frames so HTTP/2 flow control
//! carries real end-to-end backpressure.
//!
//! Outgoing control frames, `HEADERS`, and `DATA` headers + payloads batch into
//! vectored [`Write::write_all_owned`](http_kit_io::Write::write_all_owned)
//! calls bounded by peer `SETTINGS_MAX_FRAME_SIZE` and send windows. With `fs`,
//! `BodyFrame::File` regions go straight to [`SendFile`](http_kit_io::SendFile);
//! with `pipe` on Linux and Android, unpadded `DATA` payloads splice directly
//! between sockets and kernel pipes via [`SpliceRead`](http_kit_io::SpliceRead)
//! and [`SpliceWrite`](http_kit_io::SpliceWrite).
//!
//! # Example
//!
//! Multiplexing requests between [`ServerConnection`] and [`handshake_stream`]
//! on one `compio` thread:
//!
//! ```
//! use futures_lite::future::zip;
//! use http_kit::{Body, Request, Response};
//! use http_kit_h2::{ClientConfig, ServerConfig, ServerConnection, handshake_stream};
//! use http_kit_io::{Dial as _, Listen as _, Listener as _, compio::Compio};
//!
//! # fn main() -> std::io::Result<()> {
//! compio::runtime::Runtime::new()?.block_on(async {
//!     let io = Compio::default();
//!     let listener = io.bind_tcp("127.0.0.1:0".parse().unwrap())?;
//!     let addr = listener.local_addr()?;
//!     let service = |request: Request| async move {
//!         Response::new(Body::from_bytes(request.uri().path().to_owned()))
//!     };
//!     let server = async {
//!         let (stream, _) = listener.accept().await?;
//!         ServerConnection::from_stream(stream, io.clone(), ServerConfig::default())
//!             .serve(&service)
//!             .await
//!             .map_err(std::io::Error::other)
//!     };
//!     let client = async {
//!         let stream = io.connect(addr).await?;
//!         let (send, connection) = handshake_stream(stream, io.clone(), ClientConfig::default());
//!         let exchange = async move {
//!             let mut request = Request::new(Body::empty());
//!             *request.uri_mut() = format!("http://{addr}/hello").parse().unwrap();
//!             let response = send.send(request).await?;
//!             drop(send);
//!             response.into_body().into_bytes().await.map_err(http_kit_h2::Error::from)
//!         };
//!         let (ran, body) = zip(connection.run(), exchange).await;
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
pub mod frame;
pub mod hpack;
pub mod proto;
pub mod server;

mod body;
mod config;
mod conn;
mod error;
mod fields;
mod simd;
mod splice;

pub use crate::{
    client::{Connection, SendRequest, handshake, handshake_stream},
    config::{ClientConfig, FlowControlConfig, Limits, ServerConfig},
    error::{Error, Malformed, Reason, Timeout, TrySendError},
    fields::{InvalidProtocol, Protocol},
    frame::CLIENT_PREFACE,
    proto::StreamId,
    server::{ServerConnection, Service},
};
