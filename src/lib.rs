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
//!
//! # Examples
//!
//! ## Basic Request/Response Handling
//!
//! ```rust
//! use http_kit::{Request, Response, Result};
//!
//! async fn echo_handler(mut request: Request) -> Result<Response> {
//!     let body = request.take_body()?;
//!     Ok(Response::new(200, body))
//! }
//!
//! # async fn example() -> Result<()> {
//! let mut request = Request::get("/echo");
//! request.replace_body("Hello, world!");
//! let response = echo_handler(request).await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## JSON Handling
//!
//! ```rust
//! # #[cfg(feature = "json")]
//! # {
//! use http_kit::{Request, Response, Result};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct User {
//!     name: String,
//!     email: String,
//! }
//!
//! async fn create_user(mut request: Request) -> Result<Response> {
//!     let user: User = request.into_json().await?;
//!     // Process user...
//!     Ok(Response::empty().json(&user)?)
//! }
//! # }
//! ```
//!
//! ## Middleware Usage
//!
//! ```rust
//! use http_kit::{Request, Response, Result, Middleware, Endpoint};
//!
//! struct LoggingMiddleware;
//!
//! impl Middleware for LoggingMiddleware {
//!     async fn handle(&self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
//!         println!("Request: {} {}", request.method(), request.uri());
//!         let response = next.respond(request).await?;
//!         println!("Response: {}", response.status());
//!         Ok(response)
//!     }
//! }
//! ```
//!
extern crate alloc;

#[macro_use]
mod macros;

mod error;
pub use error::{Error, Result, ResultExt};

mod body;

#[cfg(feature = "fs")]
pub(crate) mod mime_guess;
pub use body::Body;
pub use body::Error as BodyError;

pub mod middleware;
#[doc(inline)]
pub use middleware::Middleware;

pub mod endpoint;
#[doc(inline)]
pub use endpoint::Endpoint;

mod request;
pub mod utils;
pub use request::Request;
mod response;
pub use response::Response;

#[cfg(feature = "cookie")]
pub use cookie;

pub use http::{header, method, uri, version, Extensions, Method, StatusCode, Uri, Version};
