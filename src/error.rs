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
//! let err = Error::new("not found", StatusCode::NOT_FOUND);
//!
//! // Add status code to existing Result
//! let result: Result<()> = Ok(()).status(StatusCode::OK);
//! ```use alloc::boxed::Box;
use alloc::boxed::Box;
use core::{
    fmt,
    ops::{Deref, DerefMut},
};
use http::StatusCode;

/// The error type for HTTP operations.
pub struct Error {
    error: anyhow::Error,
    status: StatusCode,
}

/// A specialized Result type for http operations.
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Create an `Error` object from any error type with the given status code.
    pub fn new<E, S>(error: E, status: S) -> Self
    where
        E: Into<anyhow::Error>,
        S: TryInto<StatusCode>,
        S::Error: fmt::Debug,
    {
        Self {
            error: error.into(),
            status: status.try_into().unwrap(), //may panic if user delivers an illegal code.
        }
    }

    /// Create a `Error` object from a string or a object can be transformed into string.
    pub fn msg<S>(msg: S) -> Self
    where
        S: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        anyhow::Error::msg(msg).into()
    }

    /// Set the status code of the error.Only error status code can be set.
    pub fn set_status<S>(mut self, status: S) -> Self
    where
        S: TryInto<StatusCode>,
        S::Error: fmt::Debug,
    {
        let status = status.try_into().expect("Invalid status code");
        if cfg!(debug_assertions) {
            assert!(
                (400..=599).contains(&status.as_u16()),
                "Expected a status code within 400~599"
            )
        }

        self.status = status;

        self
    }

    /// Return the status code of the error.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Try to downcast the inner error type and return `Box<E>`.
    pub fn downcast<E>(self) -> core::result::Result<Box<E>, Self>
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        let Self { status, error } = self;
        error.downcast().map_err(|error| Self { status, error })
    }

    /// Try to downcast the inner error type and return the reference of the mutable reference of `E`.
    pub fn downcast_ref<E>(&self) -> Option<&E>
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        self.error.downcast_ref()
    }

    /// Try to downcast the inner error type and return `E`.
    pub fn downcast_mut<E>(&mut self) -> Option<&mut E>
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        self.error.downcast_mut()
    }

    /// Discard the status code and return the inner error type.
    pub fn into_inner(self) -> Box<dyn core::error::Error + Send + Sync + 'static> {
        self.error.into()
    }
}

impl<E: Into<anyhow::Error>> From<E> for Error {
    fn from(error: E) -> Self {
        Self::new(error, StatusCode::SERVICE_UNAVAILABLE)
    }
}

impl From<Error> for Box<dyn core::error::Error> {
    fn from(error: Error) -> Self {
        error.error.into()
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.error, f)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl AsRef<dyn core::error::Error + Send + 'static> for Error {
    fn as_ref(&self) -> &(dyn core::error::Error + Send + 'static) {
        self.deref()
    }
}

impl AsMut<dyn core::error::Error + Send + 'static> for Error {
    fn as_mut(&mut self) -> &mut (dyn core::error::Error + Send + 'static) {
        self.deref_mut()
    }
}

impl Deref for Error {
    type Target = dyn core::error::Error + Send + 'static;

    fn deref(&self) -> &Self::Target {
        self.error.deref()
    }
}

impl DerefMut for Error {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.error.deref_mut()
    }
}

/// Provide `status` method for `Result` and `Option`.
pub trait ResultExt<T>
where
    Self: Sized,
{
    /// Wrap the error type with status code.
    /// # Example
    /// ```
    /// use std::io::prelude::*;
    /// use http_kit::{Body,ResultExt};
    /// use async_fs::File;
    /// fn handler() -> http_kit::Result<Body>{
    ///     Ok(Body::from_reader(File::open("index.html").await.status(404)?))
    /// }
    /// ```
    fn status<S>(self, status: S) -> Result<T>
    where
        S: TryInto<StatusCode>,
        S::Error: fmt::Debug;
}

impl<T, E> ResultExt<T> for core::result::Result<T, E>
where
    E: core::error::Error + Send + Sync + 'static,
{
    fn status<S>(self, status: S) -> Result<T>
    where
        S: TryInto<StatusCode>,
        S::Error: fmt::Debug,
    {
        self.map_err(|error| Error::new(error, status))
    }
}

impl<T> ResultExt<T> for Option<T> {
    fn status<S>(self, status: S) -> Result<T>
    where
        S: TryInto<StatusCode>,
        S::Error: fmt::Debug,
    {
        self.ok_or(Error::msg("None Error").set_status(status))
    }
}
