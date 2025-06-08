//! HTTP response implementation.
//!
//! This module provides the [`Response`] type which represents an HTTP response including
//! headers, status code, version, and body. It offers comprehensive methods for:
//!
//! - **Response creation** - Building responses with different status codes and body types
//! - **Header manipulation** - Setting, getting, and modifying HTTP headers
//! - **Body handling** - Working with various body formats (bytes, strings, JSON, form data, files)
//! - **Extensions** - Storing custom application data associated with the response
//! - **Content types** - Automatic MIME type detection and content type headers
//!
//! The [`Response`] type integrates seamlessly with the body system and provides convenient
//! conversions from common Rust types like `String`, `Vec<u8>`, `Bytes`, etc.
//!
//! # Examples
//!
//! ## Basic Response Creation
//!
//! ```rust
//! use http_kit::{Response, StatusCode};
//!
//! // Simple text response
//! let response = Response::new(StatusCode::OK, "Hello, World!");
//!
//! // Empty response
//! let empty = Response::empty();
//!
//! // Response with custom status
//! let not_found = Response::new(404, "Page not found");
//! ```
//!
//! ## Working with Headers
//!
//! ```rust
//! use http_kit::Response;
//!
//! let response = Response::new(200, "OK")
//!     .header(http::header::CONTENT_TYPE, "text/plain")
//!     .header(http::header::SERVER, "http-kit/1.0");
//! ```
//!
//! ## JSON Responses
//!
//! ```rust
//! # #[cfg(feature = "json")]
//! # {
//! use http_kit::Response;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct User { name: String, id: u32 }
//!
//! let user = User { name: "Alice".to_string(), id: 123 };
//! let response = Response::empty().json(&user)?;
//! # }
//! # Ok::<(), serde_json::Error>(())
//! ```
//!
//! ## File Responses
//!
//! ```rust,no_run
//! # #[cfg(feature = "fs")]
//! # {
//! use http_kit::Response;
//!
//! # async fn example() -> Result<(), std::io::Error> {
//! let response = Response::empty().file("static/index.html").await?;
//! // Content-Type header will be set automatically based on file extension
//! # Ok(())
//! # }
//! # }
//! ```
use core::fmt::Debug;

use crate::{body::BodyFrozen, Body, BodyError};
use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;
use bytestr::ByteStr;
use http::{header::HeaderName, Extensions, HeaderMap, HeaderValue, StatusCode, Version};

/// The HTTP response parts.
pub type ResponseParts = http::response::Parts;

/// An HTTP response with status, headers, and body.
///
/// `Response` represents a complete HTTP response that can be constructed, modified,
/// and sent back to clients. It provides comprehensive methods for working with all
/// aspects of HTTP responses including:
///
/// - **Status codes** - Setting and querying HTTP status codes (200, 404, 500, etc.)
/// - **Headers** - Managing HTTP headers for metadata, caching, content type, etc.
/// - **Body content** - Handling response payloads in various formats
/// - **HTTP version** - Specifying the HTTP protocol version
/// - **Extensions** - Storing custom application data
///
/// The response type integrates with the body system to provide convenient methods
/// for handling different content types like JSON, form data, files, and raw bytes.
///
/// # Examples
///
/// ## Creating Basic Responses
///
/// ```rust
/// use http_kit::{Response, StatusCode};
///
/// // Success response with text
/// let ok = Response::new(200, "Operation successful");
///
/// // Error response
/// let error = Response::new(StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong");
///
/// // Empty response
/// let empty = Response::empty();
/// ```
///
/// ## Building Rich Responses
///
/// ```rust
/// use http_kit::Response;
///
/// let response = Response::new(201, "Created")
///     .header(http::header::LOCATION, "/api/users/123")
///     .header(http::header::CONTENT_TYPE, "text/plain");
/// ```
///
/// ## Working with Body Content
///
/// ```rust
/// # async fn example() -> Result<(), http_kit::BodyError> {
/// use http_kit::Response;
///
/// let mut response = Response::new(200, "Hello, world!");
///
/// // Read the body content
/// let content = response.into_string().await?;
/// assert_eq!(content, "Hello, world!");
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Response {
    parts: ResponseParts,
    body: Body,
}

impl From<http::Response<Body>> for Response {
    fn from(response: http::Response<Body>) -> Self {
        let (parts, body) = response.into_parts();
        Self { parts, body }
    }
}

impl From<Response> for http::Response<Body> {
    fn from(response: Response) -> Self {
        Self::from_parts(response.parts, response.body)
    }
}

macro_rules! impl_response_from {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Response {
                fn from(value: $ty) -> Self {
                    Self::new(StatusCode::OK, value)
                }
            }
        )*
    };
}

impl_response_from![ByteStr, String, Vec<u8>, Bytes, &str, &[u8]];

impl Response {
    /// Creates a new HTTP response with the specified status code and body.
    ///
    /// This is the primary constructor for building responses. The body can be any type
    /// that converts to `Body`, including strings, byte vectors, and `Bytes` objects.
    ///
    /// # Arguments
    ///
    /// * `status` - The HTTP status code (or value convertible to `StatusCode`)
    /// * `body` - The response body (any type convertible to `Body`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, StatusCode};
    ///
    /// // With numeric status code
    /// let response = Response::new(200, "Success");
    ///
    /// // With StatusCode enum
    /// let response = Response::new(StatusCode::CREATED, "Resource created");
    ///
    /// // With byte vector
    /// let response = Response::new(200, vec![72, 101, 108, 108, 111]);
    ///
    /// // With string
    /// let response = Response::new(200, "Hello, world!".to_string());
    /// ```
    pub fn new<S>(status: S, body: impl Into<Body>) -> Self
    where
        S: TryInto<StatusCode>,
        S::Error: Debug,
    {
        let mut response: Self = http::Response::new(body.into()).into();
        response.set_status(status.try_into().unwrap());
        response
    }

    /// Creates an empty HTTP response with status 200 OK.
    ///
    /// This is a convenience method for creating responses that don't need body content,
    /// such as successful operations that only need to indicate completion.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let response = Response::empty();
    /// assert_eq!(response.status(), http::StatusCode::OK);
    /// ```
    pub fn empty() -> Self {
        Self::new(StatusCode::OK, Body::empty())
    }

    /// Returns the HTTP status code of this response.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, StatusCode};
    ///
    /// let response = Response::new(404, "Not found");
    /// assert_eq!(response.status(), StatusCode::NOT_FOUND);
    /// ```
    pub const fn status(&self) -> StatusCode {
        self.parts.status
    }
    /// Returns a mutable reference to the HTTP status code.
    ///
    /// This allows direct modification of the status code.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, StatusCode};
    ///
    /// let mut response = Response::empty();
    /// *response.status_mut() = StatusCode::CREATED;
    /// assert_eq!(response.status(), StatusCode::CREATED);
    /// ```
    pub fn status_mut(&mut self) -> &mut StatusCode {
        &mut self.parts.status
    }

    /// Sets the HTTP status code for this response.
    ///
    /// # Arguments
    ///
    /// * `status` - The new status code
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, StatusCode};
    ///
    /// let mut response = Response::empty();
    /// response.set_status(StatusCode::NOT_FOUND);
    /// assert_eq!(response.status(), StatusCode::NOT_FOUND);
    /// ```
    pub fn set_status(&mut self, status: StatusCode) {
        *self.status_mut() = status;
    }

    /// Returns the HTTP version for this response.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, Version};
    ///
    /// let response = Response::empty();
    /// // Default version is typically HTTP/1.1
    /// assert_eq!(response.version(), Version::HTTP_11);
    /// ```
    pub const fn version(&self) -> Version {
        self.parts.version
    }

    /// Returns a mutable reference to the HTTP version.
    ///
    /// This allows direct modification of the HTTP version.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, Version};
    ///
    /// let mut response = Response::empty();
    /// *response.version_mut() = Version::HTTP_2;
    /// assert_eq!(response.version(), Version::HTTP_2);
    /// ```
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.parts.version
    }

    /// Sets the HTTP version for this response.
    ///
    /// # Arguments
    ///
    /// * `version` - The HTTP version to use
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, Version};
    ///
    /// let mut response = Response::empty();
    /// response.set_version(Version::HTTP_2);
    /// assert_eq!(response.version(), Version::HTTP_2);
    /// ```
    pub fn set_version(&mut self, version: Version) {
        *self.version_mut() = version;
    }

    /// Returns a reference to the HTTP headers.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let response = Response::new(200, "OK")
    ///     .header(http::header::CONTENT_TYPE, "text/plain");
    ///
    /// let headers = response.headers();
    /// assert!(headers.contains_key(http::header::CONTENT_TYPE));
    /// ```
    pub const fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// Returns a mutable reference to the HTTP headers.
    ///
    /// This allows direct manipulation of the header map.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// response.headers_mut().insert(
    ///     http::header::CONTENT_TYPE,
    ///     "application/json".parse().unwrap()
    /// );
    /// ```
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.parts.headers
    }

    /// Returns the first value for the given header name.
    ///
    /// If the header has multiple values, only the first one is returned.
    /// Returns `None` if the header is not present.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name to look up
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let response = Response::new(200, "OK")
    ///     .header(http::header::CONTENT_TYPE, "application/json");
    ///
    /// if let Some(content_type) = response.get_header(http::header::CONTENT_TYPE) {
    ///     assert_eq!(content_type, "application/json");
    /// }
    /// ```
    pub fn get_header(&self, name: HeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    /// Appends a header value without removing existing values.
    ///
    /// If a header with the same name already exists, the new value is added
    /// alongside the existing values rather than replacing them.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name
    /// * `value` - The header value to append
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// response.append_header(http::header::SET_COOKIE, "session=abc123".parse().unwrap());
    /// response.append_header(http::header::SET_COOKIE, "theme=dark".parse().unwrap());
    /// // Both cookies will be present in the response
    /// ```
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers_mut().append(name, value);
    }

    /// Inserts a header value, replacing any existing values.
    ///
    /// If a header with the same name already exists, it is completely replaced
    /// with the new value.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name
    /// * `value` - The header value
    ///
    /// # Returns
    ///
    /// Returns the previous header value if one existed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// let old_value = response.insert_header(
    ///     http::header::SERVER,
    ///     "http-kit/1.0".parse().unwrap()
    /// );
    /// assert!(old_value.is_none());
    ///
    /// let old_value = response.insert_header(
    ///     http::header::SERVER,
    ///     "http-kit/2.0".parse().unwrap()
    /// );
    /// assert!(old_value.is_some());
    /// ```
    pub fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Option<HeaderValue> {
        self.headers_mut().insert(name, value)
    }

    /// Sets an HTTP header and returns the modified response.
    ///
    /// This is a builder-style method that allows method chaining. If you need to
    /// modify an existing response, use [`insert_header`] instead.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name
    /// * `value` - The header value
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let response = Response::new(200, "OK")
    ///     .header(http::header::CONTENT_TYPE, "application/json")
    ///     .header(http::header::SERVER, "http-kit/1.0");
    /// ```
    ///
    /// [`insert_header`]: Response::insert_header
    pub fn header<V>(mut self, name: HeaderName, value: V) -> Self
    where
        V: TryInto<HeaderValue>,
        V::Error: Debug,
    {
        self.insert_header(name, value.try_into().unwrap());
        self
    }

    /// Returns a reference to the response extensions.
    ///
    /// Extensions provide a type-safe way to store additional data associated
    /// with the response that doesn't fit into standard HTTP fields.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let response = Response::empty();
    /// let extensions = response.extensions();
    /// // Check if a specific type is stored
    /// let timing: Option<&u64> = extensions.get();
    /// ```
    pub const fn extensions(&self) -> &Extensions {
        &self.parts.extensions
    }

    /// Returns a mutable reference to the response extensions.
    ///
    /// This allows modification of the extensions map.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// response.extensions_mut().insert(42u32);
    /// ```
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.parts.extensions
    }

    /// Returns a reference to an extension of the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to retrieve from extensions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// response.insert_extension(42u32);
    ///
    /// if let Some(value) = response.get_extension::<u32>() {
    ///     assert_eq!(*value, 42);
    /// }
    /// ```
    pub fn get_extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions().get()
    }

    /// Returns a mutable reference to an extension of the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to retrieve from extensions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// response.insert_extension(42u32);
    ///
    /// if let Some(value) = response.get_mut_extension::<u32>() {
    ///     *value = 100;
    /// }
    /// ```
    pub fn get_mut_extension<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions_mut().get_mut()
    }

    /// Removes and returns an extension of the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to remove from extensions
    ///
    /// # Returns
    ///
    /// Returns the removed value if it existed, or `None` if it wasn't present.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    /// response.insert_extension(42u32);
    ///
    /// let removed = response.remove_extension::<u32>();
    /// assert_eq!(removed, Some(42));
    ///
    /// let removed_again = response.remove_extension::<u32>();
    /// assert_eq!(removed_again, None);
    /// ```
    pub fn remove_extension<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.extensions_mut().remove()
    }

    /// Inserts an extension value, returning any previous value of the same type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to insert into extensions
    ///
    /// # Arguments
    ///
    /// * `extension` - The value to insert
    ///
    /// # Returns
    ///
    /// Returns the previous value of the same type if one existed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::empty();
    ///
    /// let old_value = response.insert_extension(42u32);
    /// assert_eq!(old_value, None);
    ///
    /// let old_value = response.insert_extension(100u32);
    /// assert_eq!(old_value, Some(42));
    /// ```
    pub fn insert_extension<T: Send + Sync + Clone + 'static>(
        &mut self,
        extension: T,
    ) -> Option<T> {
        self.extensions_mut().insert(extension)
    }

    /// Takes the response body, leaving a frozen (unusable) body in its place.
    ///
    /// This method extracts the body from the response while ensuring it cannot
    /// be accessed again. This is useful when you need to consume the body
    /// for processing while preventing accidental double-consumption.
    ///
    /// # Errors
    ///
    /// Returns `BodyFrozen` if the body has already been taken.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::new(200, "Hello, world!");
    /// let body = response.take_body()?;
    /// // response.take_body() would now return an error
    /// # Ok::<(), http_kit::body::BodyFrozen>(())
    /// ```
    pub fn take_body(&mut self) -> Result<Body, BodyFrozen> {
        self.body.take()
    }

    /// Replaces the response body and returns the previous body.
    ///
    /// This method swaps the current body with a new one, returning the
    /// original body. This is useful for body transformations or when
    /// you need to temporarily substitute the body content.
    ///
    /// # Arguments
    ///
    /// * `body` - The new body to set (anything convertible to `Body`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// let mut response = Response::new(200, "Original content");
    /// let old_body = response.replace_body("New content");
    /// // old_body contains "Original content"
    /// // response now contains "New content"
    /// ```
    pub fn replace_body(&mut self, body: impl Into<Body>) -> Body {
        self.body.replace(body.into())
    }

    /// Swaps the response body with another body.
    ///
    /// This method exchanges the contents of the response body with another body,
    /// provided that the response body is not frozen.
    ///
    /// # Arguments
    ///
    /// * `body` - The body to swap with
    ///
    /// # Errors
    ///
    /// Returns `BodyFrozen` if the response body has been frozen/consumed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, Body};
    ///
    /// let mut response = Response::new(200, "Response content");
    /// let mut other_body = Body::from_bytes("Other content");
    /// response.swap_body(&mut other_body)?;
    ///
    /// // Now response contains "Other content"
    /// // and other_body contains "Response content"
    /// # Ok::<(), http_kit::body::BodyFrozen>(())
    /// ```
    pub fn swap_body(&mut self, body: &mut Body) -> Result<(), BodyFrozen> {
        self.body.swap(body)
    }

    /// Transforms the response body using the provided function.
    ///
    /// This method allows you to apply a transformation to the response body
    /// in a functional style, returning a new response with the transformed body.
    ///
    /// # Arguments
    ///
    /// * `f` - A function that takes the current body and returns a new body
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Response, Body};
    ///
    /// let response = Response::new(200, "original")
    ///     .map_body(|body| {
    ///         // Transform body to uppercase JSON
    ///         Body::from_bytes(r#"{"message": "ORIGINAL"}"#)
    ///     });
    /// ```
    pub fn map_body<F>(mut self, f: F) -> Self
    where
        F: FnOnce(Body) -> Body,
    {
        self.body = f(self.body);
        self
    }

    /// Sets the body from a JSON-serializable value.
    ///
    /// This method serializes the provided value to JSON and sets it as the response body.
    /// It also automatically sets the `Content-Type` header to `application/json`.
    ///
    /// # Arguments
    ///
    /// * `value` - Any value that implements `serde::Serialize`
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if JSON serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "json")]
    /// # {
    /// use http_kit::Response;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct ApiResponse { success: bool, message: String }
    ///
    /// let data = ApiResponse {
    ///     success: true,
    ///     message: "Operation completed".to_string(),
    /// };
    ///
    /// let response = Response::empty().json(&data)?;
    /// # }
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, serde_json::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.replace_body(Body::from_json(value)?);
        Ok(self)
    }

    /// Sets the body from a file, streaming its contents.
    ///
    /// This method opens the specified file and streams its contents as the response body.
    /// It automatically detects the MIME type based on the file extension and sets the
    /// appropriate `Content-Type` header.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to read
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the file cannot be opened or read.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "fs")]
    /// # {
    /// use http_kit::Response;
    ///
    /// # async fn example() -> Result<(), std::io::Error> {
    /// let response = Response::empty().file("static/logo.png").await?;
    /// // Content-Type will be automatically set to "image/png"
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "fs")]
    pub async fn file(
        mut self,
        path: impl AsRef<core::path::Path>,
    ) -> Result<Self, core::io::Error> {
        use core::os::unix::ffi::OsStrExt;

        let path = path.as_ref();
        let extension = path.extension().unwrap_or_default().as_bytes();
        let mime = crate::mime_guess::guess(extension).unwrap_or("application/octet-stream");
        self.replace_body(Body::from_file(path).await?);
        self.insert_header(http::header::CONTENT_TYPE, HeaderValue::from_static(mime));
        Ok(self)
    }

    /// Sets the body from a form-serializable value.
    ///
    /// This method serializes the provided value to URL-encoded form data and sets it
    /// as the response body. It also automatically sets the `Content-Type` header to
    /// `application/x-www-form-urlencoded`.
    ///
    /// # Arguments
    ///
    /// * `value` - Any value that implements `serde::Serialize`
    ///
    /// # Errors
    ///
    /// Returns `serde_urlencoded::ser::Error` if form serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "form")]
    /// # {
    /// use http_kit::Response;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct FormData { key: String, value: String }
    ///
    /// let data = FormData {
    ///     key: "name".to_string(),
    ///     value: "Alice".to_string(),
    /// };
    ///
    /// let response = Response::empty().form(&data)?;
    /// # }
    /// # Ok::<(), serde_urlencoded::ser::Error>(())
    /// ```
    #[cfg(feature = "form")]
    pub fn form<T: serde::Serialize>(
        mut self,
        value: &T,
    ) -> Result<Self, serde_urlencoded::ser::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.replace_body(Body::from_form(value)?);
        Ok(self)
    }

    /// Consumes the response body and returns its data as bytes.
    ///
    /// This method takes the response body and reads all its data into memory,
    /// returning it as a `Bytes` object. The body becomes unavailable after this call.
    ///
    /// # Errors
    ///
    /// Returns `BodyError` if:
    /// - The body has already been consumed
    /// - An I/O error occurs while reading streaming data
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut response = Response::new(200, "Hello, world!");
    /// let bytes = response.into_bytes().await?;
    /// assert_eq!(bytes, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_bytes(&mut self) -> Result<Bytes, BodyError> {
        self.take_body()?.into_bytes().await
    }

    /// Consumes the response body and returns its data as a UTF-8 string.
    ///
    /// This method takes the response body, reads all its data into memory,
    /// and converts it to a UTF-8 string. The body becomes unavailable after this call.
    ///
    /// # Errors
    ///
    /// Returns `BodyError` if:
    /// - The body has already been consumed
    /// - An I/O error occurs while reading streaming data
    /// - The body contains invalid UTF-8 sequences
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Response;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut response = Response::new(200, "Hello, world!");
    /// let text = response.into_string().await?;
    /// assert_eq!(text, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_string(&mut self) -> Result<ByteStr, BodyError> {
        self.take_body()?.into_string().await
    }

    /// Deserializes the response body as JSON into the specified type.
    ///
    /// This method reads the response body and attempts to deserialize it as JSON.
    /// It validates that the `Content-Type` header is `application/json` before
    /// attempting deserialization, making it safe for API clients.
    ///
    /// The deserialization is performed with zero-copy when possible by working
    /// directly with the buffered byte data.
    ///
    /// # Errors
    ///
    /// Returns `crate::Error` if:
    /// - The `Content-Type` header is not `application/json`
    /// - The body has already been consumed
    /// - The JSON is malformed or doesn't match the target type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "json")]
    /// # {
    /// use http_kit::Response;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct ApiResponse { success: bool, message: String }
    ///
    /// # async fn example() -> Result<(), http_kit::Error> {
    /// let json_data = r#"{"success": true, "message": "OK"}"#;
    /// let mut response = Response::new(200, json_data)
    ///     .header(http::header::CONTENT_TYPE, "application/json");
    ///
    /// let data: ApiResponse = response.into_json().await?;
    /// assert!(data.success);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "json")]
    pub async fn into_json<'a, T>(&'a mut self) -> Result<T, crate::Error>
    where
        T: serde::Deserialize<'a>,
    {
        use crate::ResultExt;

        assert_content_type!("application/json", self.headers());
        serde_json::from_slice(self.body.as_bytes().await?).status(crate::StatusCode::BAD_REQUEST)
    }

    /// Deserializes the response body as URL-encoded form data into the specified type.
    ///
    /// This method reads the response body and attempts to deserialize it as
    /// `application/x-www-form-urlencoded` data. It validates that the `Content-Type`
    /// header matches before attempting deserialization.
    ///
    /// The deserialization is performed with zero-copy when possible by working
    /// directly with the buffered byte data.
    ///
    /// # Errors
    ///
    /// Returns `crate::Error` if:
    /// - The `Content-Type` header is not `application/x-www-form-urlencoded`
    /// - The body has already been consumed
    /// - The form data is malformed or doesn't match the target type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "form")]
    /// # {
    /// use http_kit::Response;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct FormResponse { status: String, code: u32 }
    ///
    /// # async fn example() -> Result<(), http_kit::Error> {
    /// let form_data = "status=success&code=200";
    /// let mut response = Response::new(200, form_data)
    ///     .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    ///
    /// let data: FormResponse = response.into_form().await?;
    /// assert_eq!(data.status, "success");
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "form")]
    pub async fn into_form<'a, T>(&'a mut self) -> Result<T, crate::Error>
    where
        T: serde::Deserialize<'a>,
    {
        use crate::ResultExt;

        assert_content_type!("application/x-www-form-urlencoded", self.headers());
        serde_urlencoded::from_bytes(self.body.as_bytes().await?)
            .status(crate::StatusCode::BAD_REQUEST)
    }

    /// Sets the MIME type for the response.
    ///
    /// This method sets the `Content-Type` header using a parsed MIME type,
    /// providing type safety and validation for content types.
    ///
    /// # Arguments
    ///
    /// * `mime` - The MIME type to set
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "mime")]
    /// # {
    /// use http_kit::Response;
    /// use mime;
    ///
    /// let response = Response::new(200, "Hello, world!")
    ///     .mime(mime::TEXT_PLAIN);
    /// # }
    /// ```
    #[cfg(feature = "mime")]
    pub fn mime(mut self, mime: mime::Mime) -> Self {
        self.insert_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(mime.as_ref()).unwrap(),
        );
        self
    }

    /// Parses the `Content-Type` header and returns a MIME type.
    ///
    /// This method attempts to parse the `Content-Type` header value as a MIME type,
    /// providing structured access to content type information.
    ///
    /// # Returns
    ///
    /// Returns `Some(mime::Mime)` if the header exists and can be parsed,
    /// or `None` if the header is missing or invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "mime")]
    /// # {
    /// use http_kit::Response;
    /// use mime;
    ///
    /// let response = Response::new(200, "Hello")
    ///     .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    ///
    /// if let Some(mime_type) = response.get_mime() {
    ///     assert_eq!(mime_type.type_(), mime::TEXT);
    ///     assert_eq!(mime_type.subtype(), mime::PLAIN);
    /// }
    /// # }
    /// ```
    #[cfg(feature = "mime")]
    pub fn get_mime(&self) -> Option<mime::Mime> {
        core::str::from_utf8(self.get_header(http::header::CONTENT_TYPE)?.as_bytes())
            .ok()?
            .parse()
            .ok()
    }
}
