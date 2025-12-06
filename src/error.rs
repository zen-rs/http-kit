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
use alloc::string::String;
use core::convert::Infallible;
use core::fmt;
use http::StatusCode;

/// A concrete error type for HTTP operations.
#[derive(Debug)]
pub struct Error {
    inner: Box<dyn core::error::Error + Send + Sync>,
    status: StatusCode,
}

impl Error {
    /// Create a new error from a message.
    pub fn msg(msg: impl Into<String>) -> Self {
        Self {
            inner: msg.into().into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Create a new error from any standard error type.
    pub fn new(e: impl Into<Box<dyn core::error::Error + Send + Sync>>) -> Self {
        Self {
            inner: e.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Set the HTTP status code for this error.
    pub fn set_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// Trait for errors that have an associated HTTP status code.
///
/// This trait extends the standard `Error` trait to include a method for retrieving
/// the HTTP status code associated with the error.
pub trait HttpError: core::error::Error + Send + Sync + 'static {
    /// Returns the HTTP status code associated with this error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{HttpError,StatusCode};
    /// use thiserror::Error;
    ///
    /// #[derive(Debug, Error)]
    /// #[error("My error occurred")]
    /// struct MyError;
    ///
    /// impl HttpError for MyError {
    ///     fn status(&self) -> StatusCode {
    ///         StatusCode::INTERNAL_SERVER_ERROR
    ///     }
    /// }
    /// let err = MyError;
    /// assert_eq!(err.status(), Some(StatusCode::INTERNAL_SERVER_ERROR));
    /// assert_eq!(err.to_string(), "My error occurred");
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
    /// assert_eq!(err.status(), Some(StatusCode::BAD_GATEWAY));
    /// ```
    fn status(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

impl HttpError for Error {
    fn status(&self) -> StatusCode {
        self.status
    }
}

/// A specialized Result type for HTTP operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Extension trait for adding status codes to Results.
pub trait ResultExt<T> {
    /// Map the error variant to an [`Error`] with the given status code.
    fn status(self, status: StatusCode) -> Result<T, Error>;
}

impl<T, E> ResultExt<T> for core::result::Result<T, E>
where
    E: Into<Box<dyn core::error::Error + Send + Sync>>,
{
    fn status(self, status: StatusCode) -> Result<T, Error> {
        self.map_err(|e| Error::new(e).set_status(status))
    }
}

/// A boxed HTTP error trait object.
///
/// > Unlike `Box<dyn std::error::Error>`, this type carries HTTP status code information, and implements the `HttpError` trait.
pub type BoxHttpError = Box<dyn HttpError>;

impl From<crate::BodyError> for Error {
    fn from(e: crate::BodyError) -> Self {
        Error::new(e)
    }
}

#[cfg(feature = "json")]
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::new(e)
    }
}

impl core::error::Error for BoxHttpError {}
impl HttpError for BoxHttpError {
    fn status(&self) -> StatusCode {
        (**self).status()
    }
}

impl HttpError for Infallible {
    fn status(&self) -> StatusCode {
        unreachable!("Infallible can never be instantiated")
    }
}
