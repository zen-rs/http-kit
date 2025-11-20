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
use core::{
    fmt,
    ops::{Deref, DerefMut},
};
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
    fn status(&self) -> StatusCode;
}

/// The main error type for HTTP operations.
///
/// This error type wraps any error with an associated HTTP status code,
/// providing both the underlying error information and the appropriate
/// HTTP response status.
///
/// # Examples
///
/// ```rust
/// use http_kit::Error;
/// use http::StatusCode;
///
/// // Create from a string message
/// let err = Error::msg("Something went wrong");
///
/// // Create with a specific status code
/// let err = Error::msg("Not found").set_status(StatusCode::NOT_FOUND);
/// ```
pub struct Error {
    error: eyre::Error,
    status: StatusCode,
}

/// A specialized Result type for HTTP operations.
///
/// This is a convenience alias for `Result<T, Error>` that's used throughout
/// the HTTP toolkit to simplify error handling in HTTP contexts.
///
/// # Examples
///
/// ```rust
/// use http_kit::{Result, Error};
/// use http::StatusCode;
///
/// fn example_function() -> Result<String> {
///     Ok("success".to_string())
/// }
///
/// fn failing_function() -> Result<()> {
///     Err(Error::msg("failed").set_status(StatusCode::INTERNAL_SERVER_ERROR))
/// }
/// ```
pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    /// Creates a new `Error` from any error type with the given HTTP status code.
    ///
    /// # Arguments
    ///
    /// * `error` - Any error type that can be converted to `anyhow::Error`
    /// * `status` - HTTP status code (or value convertible to one)
    ///
    /// # Panics
    ///
    /// Panics if the status code is invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    /// use std::io;
    ///
    /// let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    /// let http_err = Error::new(io_err, StatusCode::NOT_FOUND);
    /// ```
    pub fn new<E, S>(error: E, status: S) -> Self
    where
        E: Into<eyre::Error>,
        S: TryInto<StatusCode>,
        S::Error: fmt::Debug,
    {
        Self {
            error: error.into(),
            status: status.try_into().unwrap(), //may panic if user delivers an illegal code.
        }
    }

    /// Creates an `Error` from a message string with a default status code.
    ///
    /// The default status code is `SERVICE_UNAVAILABLE` (503).
    ///
    /// # Arguments
    ///
    /// * `msg` - Any type that implements `Display + Debug + Send + 'static`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    ///
    /// let err = Error::msg("Something went wrong");
    /// let err = Error::msg(format!("Failed to process item {}", 42));
    /// ```
    pub fn msg<S>(msg: S) -> Self
    where
        S: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
       Self { error:  eyre::Error::msg(msg), status: StatusCode::SERVICE_UNAVAILABLE }
    }

    /// Sets the HTTP status code of this error.
    ///
    /// Only error status codes (400-599) can be set. In debug builds,
    /// this method will assert that the status code is in the valid range.
    ///
    /// # Arguments
    ///
    /// * `status` - HTTP status code (or value convertible to one)
    ///
    /// # Panics
    ///
    /// Panics if the status code is invalid or not an error status code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    ///
    /// let err = Error::msg("Not found").set_status(StatusCode::NOT_FOUND);
    /// ```
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

    /// Returns the HTTP status code associated with this error.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    ///
    /// let err = Error::msg("not found").set_status(StatusCode::NOT_FOUND);
    /// assert_eq!(err.status(), StatusCode::NOT_FOUND);
    /// ```
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Attempts to downcast the inner error to a concrete type.
    ///
    /// Returns `Ok(Box<E>)` if the downcast succeeds, or `Err(Self)` if it fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    /// use std::io;
    ///
    /// let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    /// let http_err = Error::new(io_err, StatusCode::NOT_FOUND);
    ///
    /// match http_err.downcast::<io::Error>() {
    ///     Ok(io_error) => println!("Got IO error: {}", io_error),
    ///     Err(original) => println!("Not an IO error: {}", original),
    /// }
    /// ```
    pub fn downcast<E>(self) -> core::result::Result<Box<E>, Self>
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        let Self { status, error } = self;
        error.downcast().map_err(|error| Self { status, error })
    }

    /// Attempts to downcast the inner error to a reference of the concrete type.
    ///
    /// Returns `Some(&E)` if the downcast succeeds, or `None` if it fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    /// use std::io;
    ///
    /// let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    /// let http_err = Error::new(io_err, StatusCode::NOT_FOUND);
    ///
    /// if let Some(io_error) = http_err.downcast_ref::<io::Error>() {
    ///     println!("IO error kind: {:?}", io_error.kind());
    /// }
    /// ```
    pub fn downcast_ref<E>(&self) -> Option<&E>
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        self.error.downcast_ref()
    }

    /// Attempts to downcast the inner error to a mutable reference of the concrete type.
    ///
    /// Returns `Some(&mut E)` if the downcast succeeds, or `None` if it fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    /// use std::io;
    ///
    /// let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
    /// let mut http_err = Error::new(io_err, StatusCode::NOT_FOUND);
    ///
    /// if let Some(io_error) = http_err.downcast_mut::<io::Error>() {
    ///     // Modify the IO error if needed
    /// }
    /// ```
    pub fn downcast_mut<E>(&mut self) -> Option<&mut E>
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        self.error.downcast_mut()
    }

    /// Consumes this error and returns the inner error, discarding the status code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Error;
    /// use http::StatusCode;
    ///
    /// let err = Error::msg("some error").set_status(StatusCode::BAD_REQUEST);
    /// let inner = err.into_inner();
    /// ```
    pub fn into_inner(self) -> Box<dyn core::error::Error + Send + Sync + 'static> {
        self.error.into()
    }
}

impl<E: core::error::Error + Send + Sync + 'static> From<E> for Error {
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

/// Extension trait that adds HTTP status code handling to `Result` and `Option` types.
///
/// This trait provides a convenient `status` method that allows you to associate
/// an HTTP status code with errors when converting them to the HTTP toolkit's
/// `Result` type.
///
/// # Examples
///
/// ```rust
/// use http_kit::{ResultExt, Result};
/// use http::StatusCode;
/// use std::fs;
///
/// fn read_config() -> Result<String> {
///     fs::read_to_string("config.txt")
///         .status(StatusCode::NOT_FOUND)
/// }
///
/// fn get_user_id() -> Result<u32> {
///     Some(42_u32)
///         .status(StatusCode::BAD_REQUEST)
/// }
/// ```
pub trait ResultExt<T>
where
    Self: Sized,
{
    /// Associates an HTTP status code with an error or None value.
    ///
    /// For `Result` types, this wraps any error with the specified status code.
    /// For `Option` types, this converts `None` to an error with the specified status code.
    ///
    /// # Arguments
    ///
    /// * `status` - HTTP status code to associate with the error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{ResultExt, Result};
    /// use http::StatusCode;
    /// use std::fs;
    ///
    /// // With Result
    /// let result: Result<String> = fs::read_to_string("missing.txt")
    ///     .status(StatusCode::NOT_FOUND);
    ///
    /// // With Option
    /// let result: Result<i32> = None
    ///     .status(StatusCode::BAD_REQUEST);
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

/// Constructs an error with a formatted message and an associated HTTP status code.
///
/// This macro simplifies the creation of error values that include both a custom message
/// (formatted using the standard Rust formatting syntax) and an HTTP status code. The status
/// code is converted into a [`StatusCode`] type, and the message is wrapped in an [`Error`].
/// The resulting error has its status set accordingly.
///
/// # Arguments
///
/// * `$fmt` - A format string, as used in [`format!`], describing how to format the error message.
/// * `$status` - An expression that can be converted into a [`StatusCode`]. If the conversion fails,
///   the macro will panic with "Invalid status code".
/// * `$args` - Zero or more additional arguments for the format string.
///
/// # Example
///
/// ```rust
/// extern crate alloc;
/// use http_kit::msg;
///
/// fn example() -> http_kit::Result<()> {
///     let resource_id = "user123";
///     Err(msg!("Resource not found: {}", 404, resource_id))
/// }
/// ```
///
/// This will create an error with the message "Resource not found: user123" and set the status code to 404.
///
/// # Panics
///
/// Panics if the status code cannot be converted into a valid StatusCode.
///
/// # Notes
///
/// - The macro requires that StatusCode and Error types are available in scope.
/// - The macro uses alloc::format! for message formatting, so it requires the alloc crate.
#[macro_export]
macro_rules! msg {
    ($fmt:expr,$status:expr $(, $args:expr)* $(,)?) => {{
        let status: $crate::StatusCode = $status.try_into().expect("Invalid status code");
        let message = alloc::format!($fmt $(, $args)*);
        let error = $crate::Error::msg(message);
        error.set_status(status)
    }};
}
