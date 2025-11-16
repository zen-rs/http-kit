//! HTTP request/response body handling.
//!
//! This module provides a flexible [`Body`] type that can represent HTTP request and response bodies
//! in various forms while maintaining efficiency and type safety.
//!
//! # Body Representation
//!
//! The body can hold data in different forms:
//!
//! - **Bytes**: For simple in-memory bodies that fit entirely in memory
//! - **AsyncReader**: For streaming from files or other async sources
//! - **Stream**: For general async streaming data with backpressure support
//! - **Frozen**: For consumed bodies that can no longer provide data
//!
//! # Format Support
//!
//! The body type provides convenient methods for working with common formats:
//!
//! - **JSON** (with `json` feature): Serialize/deserialize to/from JSON
//! - **URL-encoded forms** (with `form` feature): Handle form data
//! - **Files** (with `fs` feature): Stream file contents with MIME detection
//! - **Raw bytes**: Direct byte manipulation and string conversion
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```rust
//! use http_kit::Body;
//!
//! // Create empty body
//! let empty = Body::empty();
//!
//! // Create from string
//! let text = Body::from_bytes("Hello world!");
//!
//! // Create from bytes
//! let data = Body::from_bytes(vec![1, 2, 3, 4]);
//! ```
//!
//! ## JSON Handling
//!
/// ```rust
/// # #[cfg(feature = "json")]
/// # {
/// use http_kit::Body;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct User { name: String }
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Create from JSON
/// let user = User { name: "Alice".to_string() };
/// let body = Body::from_json(&user)?;
///
/// // Parse to JSON
/// let mut body = Body::from_bytes(r#"{"name":"Bob"}"#);
/// let user: User = body.into_json().await?;
/// # Ok(())
/// # }
/// # }
/// ```
//
// ## File Streaming
//
// ```rust,no_run
// # #[cfg(feature = "fs")]
// # {
// use http_kit::Body;
//
// // Stream file contents
// let body = Body::from_file("large_file.dat").await?;
// # }
// # Ok::<(), std::io::Error>(())
// ```
mod convert;
mod error_type;
#[cfg(feature = "std")]
mod utils;
use crate::sse::{Event, SseStream};
pub use error_type::Error;
#[cfg(feature = "std")]
extern crate std;
use futures_lite::{ready, Stream, StreamExt};
use http_body::Frame;
use http_body_util::{BodyExt, StreamBody};

#[cfg(feature = "std")]
use self::utils::IntoAsyncRead;
use bytestr::ByteStr;

use bytes::Bytes;
use futures_lite::{AsyncBufRead, AsyncBufReadExt};

use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;
use core::mem::{replace, swap, take};
use core::pin::Pin;
use core::task::{Context, Poll};
type BoxError = Box<dyn core::error::Error + Send + Sync + 'static>;

// A boxed bufreader object.
type BoxBufReader = Pin<Box<dyn AsyncBufRead + Send + Sync + 'static>>;

type BoxHttpBody =
    Pin<Box<dyn http_body::Body<Data = Bytes, Error = BoxError> + Send + Sync + 'static>>;

pub use http_body::Body as HttpBody;

/// Flexible HTTP body that can represent data in various forms.
///
/// `Body` is the core type for representing HTTP request and response bodies.
/// It can efficiently handle different data sources:
///
/// - **In-memory data**: Bytes, strings, vectors
/// - **Streaming data**: Files, network streams, async readers
/// - **Structured data**: JSON, form data (with appropriate features)
///
/// The body automatically manages the underlying representation and provides
/// zero-copy conversions where possible.
///
/// # Examples
///
/// ```rust
/// use http_kit::Body;
///
/// // Create from string
/// let body = Body::from_bytes("Hello, world!");
///
/// // Create empty body
/// let empty = Body::empty();
///
/// // Check if empty (when size is known)
/// if let Some(true) = body.is_empty() {
///     println!("Body is empty");
/// }
/// ```
pub struct Body {
    inner: BodyInner,
}

impl Debug for Body {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Body")
    }
}

impl_error!(
    BodyFrozen,
    "Body was frozen,it may have been consumed by `take()`"
);

enum BodyInner {
    Once(Bytes),
    Reader {
        reader: BoxBufReader,
        length: Option<usize>,
    },
    HttpBody(BoxHttpBody),
    Freeze,
}

impl Default for BodyInner {
    fn default() -> Self {
        Self::Once(Bytes::new())
    }
}

impl Body {
    /// Creates a new empty body.
    ///
    /// This creates a body with zero bytes that can be used as a placeholder
    /// or default value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let body = Body::empty();
    /// assert_eq!(body.len(), Some(0));
    /// ```
    pub const fn empty() -> Self {
        Self {
            inner: BodyInner::Once(Bytes::new()),
        }
    }

    /// Creates a new body from any type implementing `http_body::Body`.
    ///
    /// This method allows wrapping any HTTP body implementation into this
    /// `Body` type, providing a unified interface for different body sources.
    /// The body data will be converted to `Bytes` and errors will be boxed.
    ///
    /// # Type Parameters
    ///
    /// * `B` - The body type implementing `http_body::Body`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    /// use http_body_util::Full;
    /// use bytes::Bytes;
    ///
    /// let http_body = Full::new(Bytes::from("Hello, world!"));
    /// let body = Body::new(http_body);
    /// ```
    pub fn new<B>(body: B) -> Self
    where
        B: Send + Sync + http_body::Body + 'static,
        B::Data: Into<Bytes>,
        B::Error: core::error::Error + Send + Sync,
    {
        Self {
            inner: BodyInner::HttpBody(Box::pin(
                body.map_frame(|result| result.map_data(|data| data.into()))
                    .map_err(|e| {
                        let b: BoxError = Box::new(e);
                        b
                    }),
            )),
        }
    }

    /// Creates a new frozen body that cannot provide data.
    ///
    ///
    ///
    /// A frozen body represents a body that has been consumed and can no longer
    /// provide data. This is typically used internally after a body has been
    /// taken or consumed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let body = Body::frozen();
    /// assert!(body.is_frozen());
    /// ```
    pub const fn frozen() -> Self {
        Self {
            inner: BodyInner::Freeze,
        }
    }

    /// Creates a body from an async buffered reader.
    ///
    /// This method allows streaming data from any source that implements
    /// `AsyncBufRead`, such as files, network connections, or in-memory buffers.
    /// The optional length hint can improve performance for operations that
    /// benefit from knowing the total size.
    ///
    /// # Arguments
    ///
    /// * `reader` - Any type implementing `AsyncBufRead + Send + 'static`
    /// * `length` - Optional hint about the total number of bytes to read
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "fs")]
    /// # {
    /// use http_kit::Body;
    /// use async_fs::File;
    /// use futures_lite::io::BufReader;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let file = File::open("data.txt").await?;
    /// let metadata = file.metadata().await?;
    /// let reader = BufReader::new(file);
    ///
    /// let body = Body::from_reader(reader, metadata.len() as usize);
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    pub fn from_reader(
        reader: impl AsyncBufRead + Send + Sync + 'static,
        length: impl Into<Option<usize>>,
    ) -> Self {
        Self {
            inner: BodyInner::Reader {
                reader: Box::pin(reader),
                length: length.into(),
            },
        }
    }

    /// Creates a body from an async stream of data chunks.
    ///
    /// This method allows creating a body from any stream that yields
    /// `Result<T, E>` where `T` can be converted to `Bytes`. This is useful
    /// for handling data from network sources, databases, or custom generators.
    ///
    /// # Type Parameters
    ///
    /// * `T` - Data type that can be converted to `Bytes`
    /// * `E` - Error type that can be converted to a boxed error
    /// * `S` - Stream type yielding `Result<T, E>`
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    /// use futures_lite::stream;
    ///
    /// # async fn example() {
    /// let data_stream = stream::iter(vec![
    ///     Ok::<_, std::io::Error>("Hello, ".as_bytes()),
    ///     Ok("world!".as_bytes()),
    /// ]);
    ///
    /// let body = Body::from_stream(data_stream);
    /// # }
    /// ```
    pub fn from_stream<T, E, S>(stream: S) -> Self
    where
        T: Into<Bytes> + Send + 'static,
        E: Into<BoxError>,
        S: Stream<Item = Result<T, E>> + Send + Sync + 'static,
    {
        Self {
            inner: BodyInner::HttpBody(Box::pin(StreamBody::new(stream.map(|result| {
                result
                    .map(|data| Frame::data(data.into()))
                    .map_err(|error| error.into())
            })))),
        }
    }
    /// Creates a body from bytes or byte-like data.
    ///
    /// This method accepts any type that can be converted to `Bytes`,
    /// including `String`, `Vec<u8>`, `&str`, `&[u8]`, and `Bytes` itself.
    /// The conversion is zero-copy when possible.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// // From string slice
    /// let body1 = Body::from_bytes("Hello, world!");
    ///
    /// // From String
    /// let body2 = Body::from_bytes("Hello, world!".to_string());
    ///
    /// // From byte vector
    /// let body3 = Body::from_bytes(vec![72, 101, 108, 108, 111]);
    /// ```
    pub fn from_bytes(data: impl Into<Bytes>) -> Self {
        Self {
            inner: BodyInner::Once(data.into()),
        }
    }

    /// Creates a body by streaming the contents of a file.
    ///
    /// This method opens a file and creates a streaming body that reads
    /// the file contents on demand. The file size is determined automatically
    /// and used as a length hint for optimization.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to read
    ///
    /// # Errors
    ///
    /// Returns an `std::io::Error` if the file cannot be opened or its metadata
    /// cannot be read.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "fs")]
    /// # {
    /// use http_kit::Body;
    ///
    /// # async fn example() -> Result<(), std::io::Error> {
    /// let body = Body::from_file("large_document.pdf").await?;
    /// println!("File body created with {} bytes", body.len().unwrap_or(0));
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(all(feature = "fs", feature = "std"))]
    pub async fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let file = async_fs::File::open(path).await?;
        let len = file.metadata().await?.len() as usize;
        Ok(Self::from_reader(
            futures_lite::io::BufReader::new(file),
            len,
        ))
    }

    /// Creates a body by serializing an object to JSON.
    ///
    /// This method serializes any `Serialize` type to JSON and creates
    /// a body containing the JSON string. The resulting body will have
    /// UTF-8 encoded JSON content.
    ///
    /// # Arguments
    ///
    /// * `value` - Any type implementing `serde::Serialize`
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "json")]
    /// # {
    /// use http_kit::Body;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct User {
    ///     name: String,
    ///     age: u32,
    /// }
    ///
    /// let user = User {
    ///     name: "Alice".to_string(),
    ///     age: 30,
    /// };
    ///
    /// let body = Body::from_json(&user)?;
    /// # }
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[cfg(feature = "json")]
    pub fn from_json<T: serde::Serialize>(value: T) -> Result<Self, serde_json::Error> {
        Ok(Self::from_bytes(serde_json::to_string(&value)?))
    }

    /// Creates a body by serializing an object to URL-encoded form data.
    ///
    /// This method serializes any `Serialize` type to `application/x-www-form-urlencoded`
    /// format, commonly used for HTML form submissions.
    ///
    /// # Arguments
    ///
    /// * `value` - Any type implementing `serde::Serialize`
    ///
    /// # Errors
    ///
    /// Returns `serde_urlencoded::ser::Error` if serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "form")]
    /// # {
    /// use http_kit::Body;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct LoginForm {
    ///     username: String,
    ///     password: String,
    /// }
    ///
    /// let form = LoginForm {
    ///     username: "user".to_string(),
    ///     password: "pass".to_string(),
    /// };
    ///
    /// let body = Body::from_form(&form)?;
    /// # }
    /// # Ok::<(), serde_urlencoded::ser::Error>(())
    /// ```
    #[cfg(feature = "form")]
    pub fn from_form<T: serde::Serialize>(value: T) -> Result<Self, serde_urlencoded::ser::Error> {
        Ok(Self::from_bytes(serde_urlencoded::to_string(value)?))
    }

    /// Creates a body from a stream of Server-Sent Events (SSE).
    ///
    /// This method converts a stream of SSE events into a body that can be used
    /// for HTTP responses. The events are formatted according to the SSE specification
    /// and can be consumed by EventSource clients.
    ///
    /// # Type Parameters
    ///
    /// * `S` - Stream type yielding `Result<Event, E>`
    /// * `E` - Error type that can be converted to a boxed error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Body, sse::Event};
    /// use futures_lite::stream;
    ///
    /// # async fn example() {
    /// let events = stream::iter(vec![
    ///     Ok::<_, std::io::Error>(Event::from_data("Hello").with_id("1")),
    ///     Ok(Event::from_data("World").with_id("2")),
    /// ]);
    ///
    /// let body = Body::from_sse(events);
    /// # }
    /// ```
    pub fn from_sse<S, E>(s: S) -> Self
    where
        S: Stream<Item = Result<Event, E>> + Send + Sync + 'static,
        E: Into<BoxError> + Send + Sync + 'static,
    {
        Self {
            inner: BodyInner::HttpBody(Box::pin(
                crate::sse::into_body(s)
                    .map_frame(|result| result.map_data(|data| data))
                    .map_err(|e| e.into()),
            )),
        }
    }

    /// Returns the length of the body in bytes, if known.
    ///
    /// This method returns `Some(length)` for in-memory bodies where the size
    /// is immediately available. For streaming bodies (files, readers, streams),
    /// it returns `None` since the total size may not be known until the entire
    /// body is consumed.
    ///
    /// The returned length is primarily used for optimizations like setting
    /// `Content-Length` headers, but should be considered a hint rather than
    /// a guarantee.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let body = Body::from_bytes("Hello, world!");
    /// assert_eq!(body.len(), Some(13));
    ///
    /// let empty = Body::empty();
    /// assert_eq!(empty.len(), Some(0));
    /// ```
    pub const fn len(&self) -> Option<usize> {
        match &self.inner {
            BodyInner::Once(bytes) => Some(bytes.len()),
            BodyInner::Reader { length, .. } => *length,
            _ => None,
        }
    }

    /// Returns whether the body is empty, if the length is known.
    ///
    /// This method returns `Some(true)` if the body is known to be empty,
    /// `Some(false)` if the body is known to contain data, and `None` if
    /// the body length cannot be determined without consuming it.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let empty = Body::empty();
    /// assert_eq!(empty.is_empty(), Some(true));
    ///
    /// let body = Body::from_bytes("data");
    /// assert_eq!(body.is_empty(), Some(false));
    /// ```
    pub const fn is_empty(&self) -> Option<bool> {
        if let Some(len) = self.len() {
            if len == 0 {
                Some(true)
            } else {
                Some(false)
            }
        } else {
            None
        }
    }

    /// Consumes the body and returns all its data as `Bytes`.
    ///
    /// This method reads the entire body into memory and returns it as a
    /// `Bytes` object. For large bodies or streams, this may consume significant
    /// memory. For streaming bodies, all data will be read and concatenated.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The body is frozen (already consumed)
    /// - An I/O error occurs while reading streaming data
    /// - The underlying stream produces an error
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let body = Body::from_bytes("Hello, world!");
    /// let bytes = body.into_bytes().await?;
    /// assert_eq!(bytes, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_bytes(self) -> Result<Bytes, Error> {
        match self.inner {
            BodyInner::Once(bytes) => Ok(bytes),
            BodyInner::Reader { mut reader, length } => {
                let mut vec = Vec::with_capacity(length.unwrap_or_default());
                loop {
                    let data = reader.fill_buf().await?;
                    if data.is_empty() {
                        break;
                    } else {
                        let len = data.len();
                        vec.extend_from_slice(data);
                        reader.as_mut().consume(len);
                    }
                }
                Ok(vec.into())
            }

            BodyInner::HttpBody(body) => {
                let mut body = body.into_data_stream();

                let first = body.try_next().await?.unwrap_or_default();
                let second = body.try_next().await?;
                if let Some(second) = second {
                    let remain_size_hint = body.size_hint();
                    let mut vec = Vec::with_capacity(
                        first.len()
                            + second.len()
                            + remain_size_hint.1.unwrap_or(remain_size_hint.0),
                    );
                    vec.extend_from_slice(&first);
                    vec.extend_from_slice(&second);
                    while let Some(data) = body.try_next().await? {
                        vec.extend_from_slice(&data);
                    }
                    Ok(vec.into())
                } else {
                    Ok(first)
                }
            }
            BodyInner::Freeze => Err(Error::BodyFrozen),
        }
    }

    /// Consumes the body and returns its data as a UTF-8 string.
    ///
    /// This method reads the entire body into memory and converts it to a
    /// UTF-8 string, returning a `ByteStr` which provides string-like operations
    /// while maintaining the underlying byte representation.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The body is frozen (already consumed)
    /// - An I/O error occurs while reading streaming data
    /// - The body contains invalid UTF-8 sequences
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let body = Body::from_bytes("Hello, world!");
    /// let text = body.into_string().await?;
    /// assert_eq!(text, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_string(self) -> Result<ByteStr, Error> {
        Ok(ByteStr::from_utf8(self.into_bytes().await?)?)
    }

    /// Converts the body into an async buffered reader.
    ///
    /// This method wraps the body in a type that implements `AsyncBufRead`,
    /// allowing it to be used anywhere that expects an async reader. This is
    /// useful for streaming the body data to other async I/O operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    /// use futures_lite::AsyncBufReadExt;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let body = Body::from_bytes("line1\nline2\nline3");
    /// let mut reader = body.into_reader();
    /// let mut line = String::new();
    /// reader.read_line(&mut line).await?;
    /// assert_eq!(line, "line1\n");
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "std")]
    pub fn into_reader(self) -> impl AsyncBufRead + Send {
        IntoAsyncRead::new(self)
    }

    /// Converts the body into a Server-Sent Events (SSE) stream.
    ///
    /// This method transforms the body into a stream of SSE events, which can be used
    /// to handle eventsource responses in HTTP servers or clients.
    pub fn into_sse(self) -> SseStream {
        SseStream::new(self)
    }

    /// Returns a reference to the body data as bytes.
    ///
    /// This method ensures the body data is available as a byte slice and returns
    /// a reference to it. For streaming bodies, this will consume and buffer all
    /// data in memory. The body is modified to store the buffered data internally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The body is frozen (already consumed)
    /// - An I/O error occurs while reading streaming data
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut body = Body::from_bytes("Hello, world!");
    /// let bytes = body.as_bytes().await?;
    /// assert_eq!(bytes, b"Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn as_bytes(&mut self) -> Result<&[u8], Error> {
        self.inner = BodyInner::Once(self.take()?.into_bytes().await?);
        match self.inner {
            BodyInner::Once(ref bytes) => Ok(bytes),
            _ => unreachable!(),
        }
    }

    /// Returns a reference to the body data as a UTF-8 string slice.
    ///
    /// This method ensures the body data is available as a string slice and returns
    /// a reference to it. For streaming bodies, this will consume and buffer all
    /// data in memory first. The body is modified to store the buffered data internally.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The body is frozen (already consumed)
    /// - An I/O error occurs while reading streaming data
    /// - The body contains invalid UTF-8 sequences
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut body = Body::from_bytes("Hello, world!");
    /// let text = body.as_str().await?;
    /// assert_eq!(text, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn as_str(&mut self) -> Result<&str, Error> {
        let data = self.as_bytes().await?;
        Ok(core::str::from_utf8(data)?)
    }

    /// Deserializes the body data as JSON into the specified type.
    ///
    /// This method reads the body data and attempts to deserialize it as JSON.
    /// The deserialization is performed with zero-copy when possible by working
    /// directly with the buffered byte data.
    ///
    /// # Warning
    ///
    /// This method does not validate the `Content-Type` header. If you need
    /// MIME type validation, use `Request::into_json()` or `Response::into_json()`
    /// instead, which check for the `application/json` content type.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The body is frozen (already consumed)
    /// - An I/O error occurs while reading streaming data
    /// - The JSON is malformed or doesn't match the target type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "json")]
    /// # {
    /// use http_kit::Body;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize, PartialEq, Debug)]
    /// struct User {
    ///     name: String,
    ///     age: u32,
    /// }
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let json_data = r#"{"name": "Alice", "age": 30}"#;
    /// let mut body = Body::from_bytes(json_data);
    /// let user: User = body.into_json().await?;
    /// assert_eq!(user.name, "Alice");
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "json")]
    pub async fn into_json<'a, T>(&'a mut self) -> Result<T, Error>
    where
        T: serde::Deserialize<'a>,
    {
        Ok(serde_json::from_slice(self.as_bytes().await?)?)
    }

    /// Deserializes the body data as URL-encoded form data into the specified type.
    ///
    /// This method reads the body data and attempts to deserialize it as
    /// `application/x-www-form-urlencoded` data. The deserialization is performed
    /// with zero-copy when possible by working directly with the buffered byte data.
    ///
    /// # Warning
    ///
    /// This method does not validate the `Content-Type` header. If you need
    /// MIME type validation, use `Request::into_form()` or `Response::into_form()`
    /// instead, which check for the `application/x-www-form-urlencoded` content type.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The body is frozen (already consumed)
    /// - An I/O error occurs while reading streaming data
    /// - The form data is malformed or doesn't match the target type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "form")]
    /// # {
    /// use http_kit::Body;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize, PartialEq, Debug)]
    /// struct LoginForm {
    ///     username: String,
    ///     password: String,
    /// }
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let form_data = "username=alice&password=secret123";
    /// let mut body = Body::from_bytes(form_data);
    /// let form: LoginForm = body.into_form().await?;
    /// assert_eq!(form.username, "alice");
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "form")]
    pub async fn into_form<'a, T>(&'a mut self) -> Result<T, Error>
    where
        T: serde::Deserialize<'a>,
    {
        Ok(serde_urlencoded::from_bytes(self.as_bytes().await?)?)
    }

    /// Replaces this body with a new body and returns the old body.
    ///
    /// This method swaps the current body with the provided body, returning
    /// the original body value. This can be useful for chaining operations
    /// or temporarily substituting body content.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let mut body = Body::from_bytes("original");
    /// let old_body = body.replace(Body::from_bytes("replacement"));
    ///
    /// // `body` now contains "replacement"
    /// // `old_body` contains "original"
    /// ```
    pub fn replace(&mut self, body: Body) -> Body {
        replace(self, body)
    }

    /// Swaps the contents of this body with another body.
    ///
    /// This method exchanges the contents of two bodies, provided that this
    /// body is not frozen. If the body is frozen (already consumed), the
    /// operation fails and returns an error.
    ///
    /// # Errors
    ///
    /// Returns `BodyFrozen` if this body has been frozen/consumed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let mut body1 = Body::from_bytes("first");
    /// let mut body2 = Body::from_bytes("second");
    ///
    /// body1.swap(&mut body2)?;
    ///
    /// // Now body1 contains "second" and body2 contains "first"
    /// # Ok::<(), http_kit::BodyError>(())
    /// ```
    pub fn swap(&mut self, body: &mut Body) -> Result<(), BodyFrozen> {
        if self.is_frozen() {
            Err(BodyFrozen::new())
        } else {
            swap(self, body);
            Ok(())
        }
    }

    /// Consumes and takes the body, leaving a frozen body in its place.
    ///
    /// This method extracts the body content and replaces it with a frozen
    /// (unusable) body. This is useful when you need to move the body to
    /// another location while ensuring the original cannot be used again.
    ///
    /// # Errors
    ///
    /// Returns `BodyFrozen` if the body is already frozen.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let mut body = Body::from_bytes("Hello, world!");
    /// let taken_body = body.take()?;
    ///
    /// // `taken_body` contains the original data
    /// // `body` is now frozen and cannot be used
    /// assert!(body.is_frozen());
    /// # Ok::<(), http_kit::BodyError>(())
    /// ```
    pub fn take(&mut self) -> Result<Self, BodyFrozen> {
        if self.is_frozen() {
            Err(BodyFrozen::new())
        } else {
            Ok(self.replace(Self::frozen()))
        }
    }

    /// Returns `true` if the body is frozen (consumed), `false` otherwise.
    ///
    /// A frozen body is one that has been consumed by operations like `take()`
    /// and can no longer provide data. This is different from an empty body,
    /// which still has a valid state but contains no data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let mut body = Body::from_bytes("data");
    /// assert!(!body.is_frozen());
    ///
    /// let _taken = body.take().unwrap();
    /// assert!(body.is_frozen());
    ///
    /// let frozen = Body::frozen();
    /// assert!(frozen.is_frozen());
    /// ```
    pub const fn is_frozen(&self) -> bool {
        matches!(self.inner, BodyInner::Freeze)
    }

    /// Freezes the body, making it unusable and dropping its content.
    ///
    /// This method converts the body to a frozen state, discarding any data
    /// it contained. After freezing, the body cannot be used for any operations
    /// and will return errors if accessed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let mut body = Body::from_bytes("Hello, world!");
    /// body.freeze();
    ///
    /// assert!(body.is_frozen());
    /// // Any further operations on `body` will fail
    /// ```
    pub fn freeze(&mut self) {
        self.replace(Self::frozen());
    }
}

impl Default for Body {
    fn default() -> Self {
        Self::empty()
    }
}

impl Stream for Body {
    type Item = Result<Bytes, BoxError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut self.inner {
            BodyInner::Once(bytes) => {
                if bytes.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(take(bytes))))
                }
            }
            BodyInner::Reader { reader, length } => {
                let data = ready!(reader.as_mut().poll_fill_buf(cx))?;
                if data.is_empty() {
                    return Poll::Ready(None);
                }
                let data = Bytes::copy_from_slice(data);
                reader.as_mut().consume(data.len());
                if let Some(known_length) = length {
                    *known_length = known_length.saturating_sub(data.len());
                }
                Poll::Ready(Some(Ok(data)))
            }
            BodyInner::HttpBody(stream) => stream
                .as_mut()
                .poll_frame(cx)
                .map_ok(|frame| frame.into_data().unwrap_or_default()),
            BodyInner::Freeze => Poll::Ready(Some(Err(Error::BodyFrozen.into()))),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            BodyInner::Once(bytes) => (bytes.len(), Some(bytes.len())),
            BodyInner::Reader { length, .. } => (0, *length),
            BodyInner::HttpBody(body) => {
                let hint = body.size_hint();
                (hint.lower() as usize, hint.upper().map(|u| u as usize))
            }
            BodyInner::Freeze => (0, None),
        }
    }
}

impl http_body::Body for Body {
    type Data = Bytes;

    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.poll_next(cx)
            .map(|opt| opt.map(|result| result.map(http_body::Frame::data)))
            .map_err(Error::Other)
    }
}
