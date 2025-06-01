#![deny(unsafe_code)]
#![no_std]
#![warn(missing_docs, missing_debug_implementations)]
//! A plenty of utlity for HTTP operation.
//! # Example
//! ```rust
//! use http_kit::{Request,Response};
//!
//! async fn echo(request:Request) -> http_kit::Result<Response>{
//!     let body = request.take_body()?;
//!     Ok(Response::new(200,body))
//! }
//!
//! let mut request = Request::get("/echo");
//! request.replace_body("Hello,world");
//! echo(request).await?;
//!
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
pub use middleware::Middleware;

pub mod endpoint;
pub use endpoint::Endpoint;

mod request;
pub use request::Request;
mod response;
pub use response::Response;

pub use http::{Extensions, Method, StatusCode, Uri, Version, header, method, uri, version};
