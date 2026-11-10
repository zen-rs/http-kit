//! HTTP/3 server and client on [quiche], driven over owned-buffer datagram
//! I/O.
//!
//! Everything sits behind the `quiche` feature: quiche builds BoringSSL from
//! source with cmake, so a build pays for it only when it asks for HTTP/3.
//!
//! - [`Server`]: one UDP socket and every connection that reaches it,
//!   answering requests with a [`Service`].
//! - [`Client`]: [`Client::connect`] opens a connection behind a
//!   [`SendRequest`] handle and the [`Connection`] that drives it.
//!
//! Both mirror `http-kit-h1`: a socket, a [`Timer`](http_kit_io::Timer) and
//! a configuration go in; a future that owns the socket comes out, and no
//! future, body or service is required to be `Send`. Only [`SendRequest`]
//! is `Send`, so a pool may hand it around.
//!
//! # The driver
//!
//! An endpoint is one future on one thread. It receives into one buffer
//! sized for receive coalescing (GRO), splits it with
//! [`RecvMeta::segments`](http_kit_io::RecvMeta::segments), and routes each
//! datagram to its connection by destination connection ID; an Initial
//! packet for an unknown ID opens a connection, after a stateless Retry has
//! validated its source address unless
//! [`ServerConfig::retry`] says otherwise. quiche's timers are filed in
//! one queue, earliest first, so the endpoint sleeps on a single deadline.
//! After each wakeup it services the connections it touched and sends their
//! packets: consecutive equal-sized packets to one peer go out as one
//! segmented send (GSO), up to the socket's
//! [`max_send_segments`](http_kit_io::DatagramSocket::max_send_segments). A
//! packet quiche paces into the future is held until its release time.
//!
//! # Messages
//!
//! Requests and responses are http-kit messages; HTTP/3 field sections are
//! checked as RFC 9114 §4.2 and §4.3 require, and a malformed message resets
//! its stream with `H3_MESSAGE_ERROR`. Bodies stream in both directions as
//! [`BodyFrame`](http_kit::BodyFrame)s, trailers included. A received body
//! is read off its QUIC stream only as its consumer asks, so QUIC flow
//! control carries backpressure to the peer; an outgoing body is pulled
//! only as quiche takes it. With the `fs` feature, a file-region frame is
//! read out through [`FileRegion::into_stream`](http_kit::FileRegion::into_stream):
//! QUIC encrypts in user space, so there is no kernel zero-copy on this
//! path.
//!
//! # Limits
//!
//! [`ServerConfig::new`] and [`ClientConfig::new`] take
//! `max_field_section_size`, the largest header or trailer section the peer
//! may send: it bounds the memory one head can cost, so it has no default.
//! Every other setting is a public field with a default.
//!
//! # Example
//!
//! A server on a compio thread:
//!
//! ```no_run
//! use http_kit::{Body, Request, Response};
//! use http_kit_h3::{Identity, Server, ServerConfig};
//! use http_kit_io::{Io as _, compio::Compio};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let identity = Identity::from_pem(std::fs::read("cert.pem")?, std::fs::read("key.pem")?);
//! let config = ServerConfig::new(identity, 64 * 1024);
//! compio::runtime::Runtime::new()?.block_on(async {
//!     let socket = Compio.bind_udp("[::]:443".parse().unwrap())?;
//!     let server = Server::new(socket, Compio, &config)?;
//!     let service = |request: Request| async move {
//!         Response::new(Body::from_bytes(request.uri().path().to_owned()))
//!     };
//!     server.serve(&service).await?;
//!     Ok(())
//! })
//! # }
//! ```

#[cfg(feature = "quiche")]
pub mod client;
#[cfg(feature = "quiche")]
pub mod server;

#[cfg(feature = "quiche")]
mod body;
#[cfg(feature = "quiche")]
mod config;
#[cfg(feature = "quiche")]
mod conn;
#[cfg(feature = "quiche")]
mod driver;
#[cfg(feature = "quiche")]
mod error;
#[cfg(feature = "quiche")]
mod fields;
#[cfg(feature = "quiche")]
mod retry;

#[cfg(feature = "quiche")]
pub use crate::{
    client::{Client, Connection, SendRequest},
    config::{ClientConfig, CongestionControl, Identity, Roots, ServerConfig, TransportConfig},
    conn::ConnectionInfo,
    error::{Error, Malformed},
    retry::{RetryConfig, RetryWhen, TokenKey},
    server::{Server, ServerStats, Service},
};
