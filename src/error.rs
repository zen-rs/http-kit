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
use core::fmt::{self, Debug, Display};
use http::StatusCode;

/// A concrete error type for HTTP operations.
#[derive(Debug)]
pub struct Error {
    inner: eyre::Report,
    status: StatusCode,
}

impl Error {
    /// Create a new error with a custom message.
    pub fn msg(msg: impl Display + Send + Sync + Debug + 'static) -> Self {
        Self {
            inner: eyre::Report::msg(msg),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Create a new error from any standard error type.
    pub fn new(e: impl Into<eyre::Report>) -> Self {
        Self {
            inner: e.into(),
            status: StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Consume the error and return the inner `eyre::Report`.
    pub fn into_inner(self) -> eyre::Report {
        self.inner
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
    /// assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
    /// assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    /// ```
    fn status(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
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
    E: Into<eyre::Report>,
{
    fn status(self, status: StatusCode) -> Result<T, Error> {
        self.map_err(|e| Error::new(e).set_status(status))
    }
}

impl<T> ResultExt<T> for core::option::Option<T> {
    fn status(self, status: StatusCode) -> Result<T, Error> {
        self.ok_or_else(|| Error::msg("None value").set_status(status))
    }
}

/// A boxed HTTP error trait object.
///
/// > Unlike `Box<dyn std::error::Error>`, this type carries HTTP status code information, and implements the `HttpError` trait.
pub type BoxHttpError = Box<dyn HttpError>;

impl<E> From<E> for Error
where
    E: Into<eyre::Report>,
{
    fn from(e: E) -> Self {
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
