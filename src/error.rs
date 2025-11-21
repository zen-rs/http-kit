//! Error types and utilities.
//!
//! This module provides the core error handling infrastructure. The main types are:
//!
//! - [`Error`] - The main error type used throughout HTTP operations
//! - [`Result`] - A specialized Result type alias for HTTP operations
//! - [`ResultExt`] - Extension trait that adds HTTP status code handling
//!
//! The error types integrate with standard Rust error handling while adding HTTP-specific
//! functionality like status codes.
//!
//! # Examples
//!
//! ```rust
//! use http_kit::{Error, Result, ResultExt};
//! use http::StatusCode;
//!
//! // Create an error with a status code
//! let err = Error::msg("not found").set_status(StatusCode::NOT_FOUND);
//!
//! // Add status code to existing Result
//! let result: Result<()> = Ok::<(), std::convert::Infallible>(()).status(StatusCode::OK);
//! ```
//!
use alloc::boxed::Box;
use core::convert::Infallible;
use http::StatusCode;

/// Trait for errors that have an associated HTTP status code.
////
/// This trait extends the standard `Error` trait to include a method for retrieving
/// the HTTP status code associated with the error.
pub trait HttpError: core::error::Error + Send + Sync + 'static {
    /// Returns the HTTP status code associated with this error.
    ////
    /// # Examples
    /////
    /// ```rust
    /// use http_kit::{HttpError,StatusCode};
    /// #[derive(Debug)]
    /// struct MyError;
    ///
    /// impl core::error::Error for MyError {}
    /// impl std::fmt::Display for MyError {
    ///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "My error occurred")
    ///     }
    /// }
    /// impl HttpError for MyError {
    ///     fn status(&self) -> StatusCode {
    ///         StatusCode::INTERNAL_SERVER_ERROR
    ///     }
    /// }
    /// let err = MyError;
    /// assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
    /// ```
    ///
    /// Alternatively, you can use the [`http_error!`](crate::http_error!) macro to build
    /// zero-sized types that already implement `HttpError` with a fixed status code:
    ///
    /// ```rust
    /// use http_kit::{http_error, StatusCode, HttpError};
    ///
    /// http_error!(pub BadGateway, StatusCode::BAD_GATEWAY, "upstream failed");
    /// let err = BadGateway::new();
    /// assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    /// ```
    fn status(&self) -> Option<StatusCode>;
}

/// A boxed HTTP error trait object.
///
/// > Unlike `Box<dyn std::error::Error>`, this type carries HTTP status code information, and implements the `HttpError` trait.
pub type BoxHttpError = Box<dyn HttpError>;

impl core::error::Error for BoxHttpError {}
impl HttpError for BoxHttpError {
    fn status(&self) -> Option<StatusCode> {
        (**self).status()
    }
}

impl HttpError for Infallible {
    fn status(&self) -> Option<StatusCode> {
        unreachable!("Infallible can never be instantiated")
    }
}
