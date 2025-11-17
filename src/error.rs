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
    fmt::{self, Debug},
    ops::{Deref, DerefMut},
};
use http::StatusCode;

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
    error: Box<dyn HttpError>,
}

/// Trait for errors that have an associated HTTP status code.
///
/// This trait extends the standard `Error` trait to include a method
/// for retrieving the HTTP status code associated with the error.
///
/// Only types implementing this trait can be directly converted into [`Error`]
/// via the `From` implementation. When working with generic
/// [`core::error::Error`] values, prefer the [`ResultExt::status`] helper to
/// attach a status code before returning an [`Error`].
pub trait HttpError: core::error::Error + Send + Sync + 'static {
    /// Returns the associated HTTP status code.
    fn status(&self) -> StatusCode;
}

#[derive(Debug)]
struct MsgError<M: fmt::Display + fmt::Debug + Send + Sync + 'static> {
    msg: M,
}

#[derive(Debug)]
struct WithStatus<E: core::error::Error + Send + Sync + 'static> {
    status: StatusCode,
    error: Box<E>,
}

#[derive(Debug)]
struct BoxedCoreError(Box<dyn core::error::Error + Send + Sync + 'static>);

struct OverrideStatus {
    status: StatusCode,
    inner: Box<dyn HttpError>,
}

#[doc(hidden)]
pub mod __private {
    use http::StatusCode;

    /// Compile-time validator that ensures a literal status code is valid.
    pub const fn assert_status_literal(status: u16) -> u16 {
        if status < 100 || status > 599 {
            panic!("Status code literal must be within 100..=599");
        }
        status
    }

    /// Compile-time validator for constant `StatusCode` values.
    pub const fn assert_status_code(status: StatusCode) -> StatusCode {
        let value = status.as_u16();
        if value < 100 || value > 599 {
            panic!("Status code must be within 100..=599");
        }
        status
    }
}

impl<S: fmt::Display + fmt::Debug + Send + Sync + 'static> core::error::Error for MsgError<S> {}

impl<S: fmt::Display + fmt::Debug + Send + Sync + 'static> fmt::Display for MsgError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.msg, f)
    }
}

impl<E> fmt::Display for WithStatus<E>
where
    E: fmt::Display + core::error::Error + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.error, f)
    }
}

impl<E> core::error::Error for WithStatus<E>
where
    E: core::error::Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.error.source()
    }
}

impl<E> HttpError for WithStatus<E>
where
    E: core::error::Error + Send + Sync + 'static,
{
    fn status(&self) -> StatusCode {
        self.status
    }
}

impl fmt::Display for BoxedCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl core::error::Error for BoxedCoreError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.0.source()
    }
}

impl fmt::Debug for OverrideStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, f)
    }
}

impl fmt::Display for OverrideStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl core::error::Error for OverrideStatus {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.inner.source()
    }
}

impl HttpError for OverrideStatus {
    fn status(&self) -> StatusCode {
        self.status
    }
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
    fn from_http_error<E>(error: E) -> Self
    where
        E: HttpError,
    {
        Self {
            error: Box::new(error),
        }
    }

    fn with_status<E>(error: E, status: StatusCode) -> Self
    where
        E: core::error::Error + Send + Sync + 'static,
    {
        Self::from_http_error(WithStatus {
            status,
            error: Box::new(error),
        })
    }

    /// Creates a new `Error` from any error type with the given HTTP status code.
    ///
    /// # Arguments
    ///
    /// * `error` - Any error type that implements [`core::error::Error`]
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
        E: core::error::Error + Send + Sync + 'static,
        S: TryInto<StatusCode>,
        S::Error: Debug,
    {
        let status = status.try_into().expect("Invalid status code");
        Self::with_status(error, status)
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
    pub fn msg<M>(msg: M) -> Self
    where
        M: fmt::Display + fmt::Debug + Send + Sync + 'static,
    {
        Self::with_status(MsgError { msg }, StatusCode::SERVICE_UNAVAILABLE)
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
        self.error.status()
    }

    /// Sets or overrides the HTTP status code associated with this error.
    ///
    /// This consumes the error and returns a new instance so it can be chained
    /// in builder-style APIs.
    pub fn set_status<S>(self, status: S) -> Self
    where
        S: TryInto<StatusCode>,
        S::Error: Debug,
    {
        let status = status.try_into().expect("Invalid status code");
        let inner = self.into_inner();
        Self::from_http_error(OverrideStatus { status, inner })
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
        let status = self.status();
        let error = (self.error) as Box<dyn core::error::Error + Send + Sync + 'static>;
        match error.downcast::<E>() {
            Ok(err) => Ok(err),
            Err(err) => Err(Self::with_status(BoxedCoreError(err), status)),
        }
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
        let error: &(dyn core::error::Error + Send + Sync + 'static) = &*self.error;
        error.downcast_ref()
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
        let error: &mut (dyn core::error::Error + Send + Sync + 'static) = &mut *self.error;
        error.downcast_mut()
    }

    /// Consumes this error and returns the inner [`HttpError`] trait object.
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
    pub fn into_inner(self) -> Box<dyn HttpError> {
        self.error
    }
}

impl<E> From<E> for Error
where
    E: HttpError,
{
    fn from(error: E) -> Self {
        Self {
            error: Box::new(error),
        }
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

impl AsRef<dyn core::error::Error + Send + Sync + 'static> for Error {
    fn as_ref(&self) -> &(dyn core::error::Error + Send + Sync + 'static) {
        self.deref()
    }
}

impl AsMut<dyn core::error::Error + Send + Sync + 'static> for Error {
    fn as_mut(&mut self) -> &mut (dyn core::error::Error + Send + Sync + 'static) {
        self.deref_mut()
    }
}

impl Deref for Error {
    type Target = dyn HttpError;

    fn deref(&self) -> &Self::Target {
        self.error.as_ref()
    }
}

impl DerefMut for Error {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.error.as_mut()
    }
}

impl AsRef<dyn HttpError> for Error {
    fn as_ref(&self) -> &dyn HttpError {
        self.deref()
    }
}

impl AsMut<dyn HttpError> for Error {
    fn as_mut(&mut self) -> &mut dyn HttpError {
        self.deref_mut()
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
        let status = status.try_into().expect("Invalid status code");
        self.ok_or_else(|| Error::msg("None Error").set_status(status))
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
        let message = $crate::alloc::format!($fmt $(, $args)*);
        let error = $crate::Error::msg(message);
        error.set_status(status)
    }};
}

/// Constructs an [`Error`] with a formatted message and compile-time verified status code.
///
/// The first argument must be an HTTP status code literal (e.g. `404`) or a constant/status-code
/// path (e.g. [`StatusCode::NOT_FOUND`]). When a literal is provided, the macro uses a `const fn`
/// to ensure at compile time that the value lies within the valid HTTP range (`100..=599`).
///
/// # Examples
///
/// ```rust
/// use http_kit::{error, StatusCode};
///
/// let not_found = error!(404, "Resource {} missing", "item-42");
/// assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
///
/// let unavailable = error!(StatusCode::SERVICE_UNAVAILABLE, "try again later");
/// assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
/// ```
#[macro_export]
macro_rules! error {
    ($status:literal, $fmt:expr $(, $args:expr)* $(,)?) => {{
        const __HTTP_KIT_STATUS: u16 =
            $crate::__error_private::assert_status_literal($status);
        let status = $crate::StatusCode::from_u16(__HTTP_KIT_STATUS)
            .expect("status code literal already validated");
        $crate::Error::msg($crate::alloc::format!($fmt $(, $args)*))
            .set_status(status)
    }};
    ($status:path, $fmt:expr $(, $args:expr)* $(,)?) => {{
        const __HTTP_KIT_STATUS: $crate::StatusCode =
            $crate::__error_private::assert_status_code($status);
        $crate::Error::msg($crate::alloc::format!($fmt $(, $args)*))
            .set_status(__HTTP_KIT_STATUS)
    }};
}

/// Returns early with an [`Error`] constructed by [`error!`].
///
/// This macro mirrors the ergonomics of `anyhow::bail!` while enforcing that
/// callers always provide an explicit HTTP status code. The status argument
/// must be either a numeric literal (`404`) or a status constant/path
/// (`StatusCode::BAD_REQUEST`). Literal status codes are validated at
/// compile-time using a `const fn`.
///
/// # Examples
///
/// ```rust
/// use http_kit::{bail, Result, StatusCode};
///
/// fn must_be_even(n: u32) -> Result<()> {
///     if n % 2 != 0 {
///         bail!(StatusCode::BAD_REQUEST, "expected even number, got {}", n);
///     }
///     Ok(())
/// }
/// ```
#[macro_export]
macro_rules! bail {
    ($status:literal, $fmt:expr $(, $args:expr)* $(,)?) => {{
        return Err($crate::error!($status, $fmt $(, $args)*));
    }};
    ($status:path, $fmt:expr $(, $args:expr)* $(,)?) => {{
        return Err($crate::error!($status, $fmt $(, $args)*));
    }};
}
