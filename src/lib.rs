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
//! # Optional Features
//!
//! - `json` - JSON serialization/deserialization via serde_json (enabled by default)
//! - `form` - Form data handling via serde_urlencoded (enabled by default)
//! - `fs` - File upload support with MIME type detection
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

pub use body::Body;
pub use body::Error as BodyError;

pub mod middleware;
#[doc(inline)]
pub use middleware::Middleware;

pub mod endpoint;
#[doc(inline)]
pub use endpoint::Endpoint;

pub mod utils;
/// A type alias for HTTP requests with a custom `Body` type.
pub type Request = http::Request<Body>;
/// A type alias for HTTP responses with a custom `Body` type.
pub type Response = http::Response<Body>;

#[cfg(feature = "cookie")]
pub use cookie;

#[cfg(feature = "ws")]
pub mod ws;

pub use http::{header, method, uri, version, Extensions, Method, StatusCode, Uri, Version};
