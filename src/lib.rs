#![deny(unsafe_code)]
#![no_std]
#![warn(missing_docs, missing_debug_implementations)]
//! A flexible and ergonomic HTTP toolkit for Rust.
//!
//! This crate provides high-level abstractions for HTTP operations while maintaining
//! performance and type safety. It's designed to be no-std compatible with optional
//! standard library features.
//!
//! # Features
//!
//! - **Type-safe HTTP primitives** - Request, Response, Headers, and Body types with strong type checking
//! - **Streaming support** - Efficient handling of large payloads through streaming interfaces
//! - **Body transformations** - Convert between different body formats (JSON, form data, files) with zero-copy when possible
//! - **Middleware system** - Extensible middleware architecture for request/response processing
//! - **Async/await ready** - Built on top of `futures-lite` for async I/O operations
//!
//! # Threads
//!
//! Nothing here has to be `Send`. An endpoint, a middleware or a future is
//! `Send` when its parts are, so a concrete endpoint built from `Send` parts
//! still goes to a work-stealing executor, and one holding an `Rc` serves a
//! thread-per-core runtime. A body erases its source, so it comes in two
//! [flavours](flavor): [`Body`] (`Send + Sync`) and [`LocalBody`].
//!
//! Generic code cannot see through a trait method's future, so code that must
//! move one across threads without knowing the concrete type bounds on
//! [`SendEndpoint`] and [`SendMiddleware`], whose futures are `Send` by
//! contract. The type-erased forms come in the same two flavours:
//! [`AnyEndpoint`](endpoint::AnyEndpoint) and
//! [`AnySendEndpoint`](endpoint::AnySendEndpoint),
//! [`AnyMiddleware`](middleware::AnyMiddleware) and
//! [`AnySendMiddleware`](middleware::AnySendMiddleware).
//!
//! # Optional Features
//!
//! - `json` - JSON serialization/deserialization via serde_json (enabled by default)
//! - `form` - Form data handling via serde_urlencoded (enabled by default)
//! - `fs` - File-region bodies (`FileRegion`, `Body::from_file`) with MIME type detection
//! - `pipe` - `BodyFrame::Pipe`, body bytes still in the kernel (Linux and Android)
//! - `mime` - MIME type parsing and manipulation
//! - `http_body` - Implementation of http_body traits
//! - `std` - Enable standard library support (enabled by default)
extern crate alloc;

#[macro_use]
mod macros;

pub mod sse;

pub mod error;
pub use error::{BoxHttpError, Error, HttpError, Result, ResultExt};
mod body;

mod deadlines;
pub use deadlines::Deadlines;

pub use body::Error as BodyError;
pub use body::ReceiveError;
pub use body::{Body, BodyFrame, DataStream, FrameSource, GenericBody, LocalBody, PipeOffer};
#[cfg(feature = "fs")]
pub use body::{FileRegion, FileRegionStream};

pub mod flavor;

pub mod middleware;
#[doc(inline)]
pub use middleware::{Middleware, SendMiddleware};

pub mod endpoint;
#[doc(inline)]
pub use endpoint::{Endpoint, SendEndpoint};

pub mod utils;
/// An HTTP request whose body has flavour `F`: [`Shared`](flavor::Shared)
/// unless stated, [`Local`](flavor::Local) for [`LocalRequest`].
pub type Request<F = flavor::Shared> = http::Request<GenericBody<F>>;
/// An HTTP response whose body has flavour `F`: [`Shared`](flavor::Shared)
/// unless stated, [`Local`](flavor::Local) for [`LocalResponse`].
pub type Response<F = flavor::Shared> = http::Response<GenericBody<F>>;
/// An HTTP request whose body may be bound to one thread.
pub type LocalRequest = Request<flavor::Local>;
/// An HTTP response whose body may be bound to one thread.
pub type LocalResponse = Response<flavor::Local>;

#[cfg(feature = "cookie")]
pub use cookie;

#[cfg(feature = "ws")]
pub mod ws;

pub use http::{header, method, uri, version, Extensions, Method, StatusCode, Uri, Version};
