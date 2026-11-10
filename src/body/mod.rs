//! HTTP request/response body handling.
//!
//! This module provides a flexible [`Body`] type that can represent HTTP request and response bodies
//! in various forms while maintaining efficiency and type safety.
//!
//! # Body Representation
//!
//! A body is a stream of [`BodyFrame`]s: data, trailers and, with the `fs`
//! feature, regions of files. It can hold:
//!
//! - **Bytes**: an in-memory body that fits entirely in memory
//! - **A file region**: part of an owned file, which a server can hand to the
//!   kernel (sendfile, splice) instead of copying it through user space
//! - **A frame stream**: any async source of frames, with backpressure
//! - **Frozen**: a consumed body that can no longer provide data
//!
//! A consumer that needs bytes reads file regions explicitly, through
//! [`Body::into_data_stream`] or [`FileRegion::into_stream`]. The
//! `http_body::Body` implementation reads them out too, since that trait has
//! no frame for a file.
//!
//! # Flavours
//!
//! A body erases its source, so whether it may cross threads is fixed by its
//! [flavour](crate::flavor): [`Body`] is [`GenericBody<Shared>`], whose
//! sources are `Send + Sync`, and [`LocalBody`] is [`GenericBody<Local>`],
//! whose sources need not be. A `Body` converts into a `LocalBody` for free.
//!
//! # Format Support
//!
//! The body type provides convenient methods for working with common formats:
//!
//! - **JSON** (with `json` feature): Serialize/deserialize to/from JSON
//! - **URL-encoded forms** (with `form` feature): Handle form data
//! - **Files** (with `fs` feature): File-region bodies with MIME detection
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
mod convert;
mod error_type;
mod frame;
pub(crate) mod into_bytes;
use crate::flavor::{Flavor, Holds, Local, Shared};
use crate::sse::{Event, SseStream};
pub use error_type::Error;
pub use frame::BodyFrame;
#[cfg(feature = "fs")]
pub use frame::{FileRegion, FileRegionStream};
#[cfg(feature = "std")]
extern crate std;
use futures_lite::{ready, Stream, StreamExt};
use http_body::Frame;
use mime::Mime;

use bytestr::ByteStr;

use bytes::Bytes;

use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;
use core::mem::{replace, swap, take};
use core::pin::Pin;
use core::task::{Context, Poll};

pub use http_body::Body as HttpBody;

/// A body whose sources are `Send + Sync`, so it may cross threads.
pub type Body = GenericBody<Shared>;

/// A body whose sources may be bound to one thread, such as an `Rc` or a
/// socket that a thread-per-core runtime owns.
pub type LocalBody = GenericBody<Local>;

/// Flexible HTTP body that can represent data in various forms.
///
/// `GenericBody` is the core type for representing HTTP request and response
/// bodies, written through its two flavours: [`Body`] and [`LocalBody`].
/// It can efficiently handle different data sources:
///
/// - **In-memory data**: Bytes, strings, vectors
/// - **Streaming data**: network streams and any other source of [`BodyFrame`]s
/// - **File regions** (with the `fs` feature): part of an owned file
/// - **Structured data**: JSON, form data (with appropriate features)
///
/// The body automatically manages the underlying representation and provides
/// zero-copy conversions where possible.
///
/// As a [`Stream`] it yields [`BodyFrame`]s, file regions included; as an
/// `http_body::Body` it yields data and trailers, with each file region read
/// out into data frames.
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
pub struct GenericBody<F: Flavor> {
    mime: Option<Mime>,
    inner: BodyInner<F>,
}

impl<F: Flavor> Debug for GenericBody<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Body")
    }
}

impl_error!(
    BodyFrozen,
    "Body was frozen,it may have been consumed by `take()`"
);

enum BodyInner<F: Flavor> {
    Once(Bytes),
    /// A body that is one file region.
    #[cfg(feature = "fs")]
    File(FileRegion),
    /// A one-region body being read out at the `http_body::Body` boundary.
    #[cfg(feature = "fs")]
    Reading(FileRegionStream),
    Frames(Frames<F>),
    HttpBody(Pin<Box<F::HttpBody>>),
    Freeze,
}

/// A frame stream, with the region it yielded last when that region is being
/// read out at the `http_body::Body` boundary.
struct Frames<F: Flavor> {
    stream: Pin<Box<F::Frames>>,
    // Boxed so a frame-stream body is no larger than an in-memory one: every
    // request and response carries a `Body`, and only a read-out region uses it.
    #[cfg(feature = "fs")]
    reading: Option<Box<FileRegionStream>>,
}

/// Converts an `http_body` frame, which is either data or trailers.
fn from_http_frame(frame: Frame<Bytes>) -> BodyFrame {
    match frame.into_data() {
        Ok(data) => BodyFrame::Data(data),
        Err(frame) => match frame.into_trailers() {
            Ok(trailers) => BodyFrame::Trailers(trailers),
            Err(_) => unreachable!("an http_body frame is either data or trailers"),
        },
    }
}

impl<F: Flavor> Default for BodyInner<F> {
    fn default() -> Self {
        Self::Once(Bytes::new())
    }
}

impl<F: Flavor> GenericBody<F> {
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
            mime: None,
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
        B: http_body::Body + 'static,
        B::Data: Into<Bytes>,
        B::Error: Into<Error>,
        F: Holds<B>,
    {
        Self {
            mime: None,
            inner: BodyInner::HttpBody(F::http_body(body)),
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
            mime: None,
            inner: BodyInner::Freeze,
        }
    }

    /// Creates a body from an async stream of frames.
    ///
    /// This is the general constructor: the stream may mix data, trailers and
    /// (with the `fs` feature) file regions in any order. Its length is not
    /// known up front, so [`len`](Self::len) returns `None`.
    ///
    /// You are responsible for setting the MIME type of the body.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Body, BodyFrame};
    /// use http_kit::header::{HeaderMap, HeaderValue};
    /// use bytes::Bytes;
    /// use futures_lite::stream;
    ///
    /// let mut trailers = HeaderMap::new();
    /// trailers.insert("grpc-status", HeaderValue::from_static("0"));
    /// let body = Body::from_frames(stream::iter([
    ///     Ok::<_, std::io::Error>(BodyFrame::Data(Bytes::from_static(b"payload"))),
    ///     Ok(BodyFrame::Trailers(trailers)),
    /// ]));
    /// ```
    pub fn from_frames<E, S>(stream: S) -> Self
    where
        E: Into<Error> + 'static,
        S: Stream<Item = Result<BodyFrame, E>> + 'static,
        F: Holds<S>,
    {
        Self::from_mapped_frames(stream, |result| result)
    }

    fn from_mapped_frames<I: 'static, E: Into<Error> + 'static, S>(
        stream: S,
        map: fn(I) -> Result<BodyFrame, E>,
    ) -> Self
    where
        S: Stream<Item = I> + 'static,
        F: Holds<S>,
    {
        Self {
            mime: None,
            inner: BodyInner::Frames(Frames {
                stream: F::frames(stream, map),
                #[cfg(feature = "fs")]
                reading: None,
            }),
        }
    }

    /// Creates a body that is one region of a file.
    ///
    /// The body's length is the region's, so a server can announce it as
    /// `Content-Length` and send the region with sendfile or splice.
    ///
    /// You are responsible for setting the MIME type of the body.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use http_kit::{Body, FileRegion};
    ///
    /// # fn example() -> std::io::Result<()> {
    /// let file = std::fs::File::open("video.mp4")?;
    /// // Bytes 1024..2048 of the file, for a range request.
    /// let body = Body::from_file_region(FileRegion::new(file, 1024, 1024));
    /// assert_eq!(body.len(), Some(1024));
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "fs")]
    #[must_use]
    pub const fn from_file_region(region: FileRegion) -> Self {
        Self {
            mime: None,
            inner: BodyInner::File(region),
        }
    }

    /// Creates a body from an async stream of data chunks.
    ///
    /// This method allows creating a body from any stream that yields
    /// `Result<T, E>` where `T` can be converted to `Bytes`. This is useful
    /// for handling data from network sources, databases, or custom generators.
    ///
    /// You are responsible for setting the MIME type of the body.
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
        T: Into<Bytes> + 'static,
        E: Into<Error> + 'static,
        S: Stream<Item = Result<T, E>> + 'static,
        F: Holds<S>,
    {
        Self::from_mapped_frames(stream, |result: Result<T, E>| {
            result.map(|data| BodyFrame::Data(data.into()))
        })
    }
    /// Creates a body from bytes or byte-like data.
    ///
    /// This method accepts any type that can be converted to `Bytes`,
    /// including `String`, `Vec<u8>`, `&str`, `&[u8]`, and `Bytes` itself.
    /// The conversion is zero-copy when possible.
    ///
    /// By default, the MIME type is set to `application/octet-stream`.
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
            mime: Some(mime::APPLICATION_OCTET_STREAM),
            inner: BodyInner::Once(data.into()),
        }
    }

    /// Creates a body from a string slice.
    ///
    ///
    /// This method accepts any type that can be converted to `ByteStr`,
    /// including `String`, `&str`, and `ByteStr` itself.
    /// The conversion is zero-copy when possible.
    ///
    /// By default, the MIME type is set to `text/plain; charset=utf-8`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    /// use bytestr::ByteStr;
    ///
    /// // From string slice
    /// let body1 = Body::from_text("Hello, world!");
    ///
    /// // From String
    /// let body2 = Body::from_text("Hello, world!".to_string());
    /// ```
    pub fn from_text(str: impl Into<ByteStr>) -> Self {
        Self {
            mime: Some(mime::TEXT_PLAIN_UTF_8),
            inner: BodyInner::Once(str.into().into()),
        }
    }

    /// Creates a body that is the whole of a file.
    ///
    /// This method opens the file and builds a one-region body covering it
    /// (see [`from_file_region`](Self::from_file_region)), with the MIME type
    /// guessed from the extension. Opening the file and reading its metadata
    /// run on the [`blocking`] thread pool, so this works on any executor.
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
    #[cfg(feature = "fs")]
    pub async fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self, std::io::Error> {
        let path = path.as_ref();
        let mime = path
            .extension()
            .and_then(|ext| ext.to_str())
            .and_then(|ext| mime_guess::from_ext(ext).first());
        let owned = path.to_path_buf();
        let (file, len) = blocking::unblock(move || {
            let file = std::fs::File::open(owned)?;
            let len = file.metadata()?.len();
            Ok::<_, std::io::Error>((file, len))
        })
        .await?;
        Ok(Self {
            mime,
            ..Self::from_file_region(FileRegion::new(file, 0, len))
        })
    }

    /// Creates a body by serializing an object to JSON.
    ///
    /// This method serializes any `Serialize` type to JSON and creates
    /// a body containing the JSON string. The resulting body will have
    /// UTF-8 encoded JSON content.
    ///
    /// By default, the MIME type is set to `application/json`.
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
        Ok(Self {
            mime: Some(mime::APPLICATION_JSON),
            ..Self::from_bytes(serde_json::to_string(&value)?)
        })
    }

    /// Creates a body by serializing an object to URL-encoded form data.
    ///
    /// This method serializes any `Serialize` type to `application/x-www-form-urlencoded`
    /// format, commonly used for HTML form submissions.
    ///
    /// By default, the MIME type is set to `application/x-www-form-urlencoded`.
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
        Ok(Self {
            mime: Some(mime::APPLICATION_WWW_FORM_URLENCODED),
            ..Self::from_bytes(serde_urlencoded::to_string(value)?)
        })
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
        S: Stream<Item = Result<Event, E>> + 'static,
        E: Into<Error> + 'static,
        F: Holds<S>,
    {
        Self {
            mime: Some(mime::TEXT_EVENT_STREAM),
            ..Self::from_mapped_frames(s, |result: Result<Event, E>| {
                result.map(|event| BodyFrame::Data(Bytes::from(event.encode().into_bytes())))
            })
        }
    }

    /// Returns the MIME type of the body, if known.
    pub fn mime(&self) -> Option<&Mime> {
        self.mime.as_ref()
    }

    /// Sets the MIME type of the body.
    pub fn with_mime(mut self, mime: Mime) -> Self {
        self.mime = Some(mime);
        self
    }

    /// Returns the length of the body in bytes, if known.
    ///
    /// This method returns `Some(length)` for in-memory and file-region bodies,
    /// whose size is known up front. For a frame stream it returns `None`,
    /// since the total size may not be known until the entire body is consumed.
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
    #[must_use]
    pub fn len(&self) -> Option<usize> {
        match &self.inner {
            BodyInner::Once(bytes) => Some(bytes.len()),
            #[cfg(feature = "fs")]
            BodyInner::File(region) => usize::try_from(region.len()).ok(),
            #[cfg(feature = "fs")]
            BodyInner::Reading(stream) => usize::try_from(stream.remaining()).ok(),
            BodyInner::Frames(_) | BodyInner::HttpBody(_) | BodyInner::Freeze => None,
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
    #[must_use]
    pub fn is_empty(&self) -> Option<bool> {
        self.len().map(|len| len == 0)
    }

    /// Consumes the body and returns all its data as `Bytes`.
    ///
    /// This method reads the entire body into memory and returns it as a
    /// `Bytes` object. For large bodies or streams, this may consume significant
    /// memory. For streaming bodies, all data will be read and concatenated,
    /// file regions included; trailers carry no data and are dropped.
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
        if let BodyInner::Once(bytes) = self.inner {
            return Ok(bytes);
        }
        let mut data = self.into_data_stream();

        // A body of one chunk is returned as that chunk, without a copy.
        let first = data.try_next().await?.unwrap_or_default();
        let Some(second) = data.try_next().await? else {
            return Ok(first);
        };
        let remaining = http_body::Body::size_hint(&data.body);
        let remaining = remaining.upper().unwrap_or(remaining.lower());
        let mut vec = Vec::with_capacity(
            first.len() + second.len() + usize::try_from(remaining).unwrap_or_default(),
        );
        vec.extend_from_slice(&first);
        vec.extend_from_slice(&second);
        while let Some(chunk) = data.try_next().await? {
            vec.extend_from_slice(&chunk);
        }
        Ok(vec.into())
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

    /// Converts the body into a stream of its data.
    ///
    /// This is the explicit way for a consumer that needs bytes — a
    /// compressor, a hash, a parser — to read a body: data frames pass through,
    /// file regions are read through [`FileRegion::into_stream`], and trailers,
    /// which carry no data, are dropped.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    /// use futures_lite::StreamExt;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut data = Body::from_bytes("Hello, world!").into_data_stream();
    /// while let Some(chunk) = data.try_next().await? {
    ///     assert_eq!(chunk, "Hello, world!");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub const fn into_data_stream(self) -> DataStream<F> {
        DataStream { body: self }
    }

    /// Converts the body into a Server-Sent Events (SSE) stream.
    ///
    /// This method transforms the body into a stream of SSE events, which can be used
    /// to handle eventsource responses in HTTP servers or clients.
    pub fn into_sse(self) -> SseStream<F> {
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
    pub fn replace(&mut self, body: Self) -> Self {
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
    pub fn swap(&mut self, body: &mut Self) -> Result<(), BodyFrozen> {
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

    /// Returns a copy of the body when its bytes are held in memory.
    ///
    /// A body built from bytes or text can be sent any number of times, so
    /// it is cloned (sharing the underlying `Bytes`). A file region, stream or
    /// frozen body can be read only once and returns `None`: a middleware that
    /// replays a request, such as a retry, must not send it a second time.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Body;
    ///
    /// let body = Body::from_bytes("payload");
    /// assert_eq!(body.try_clone().and_then(|copy| copy.len()), Some(7));
    ///
    /// let frozen = Body::frozen();
    /// assert!(frozen.try_clone().is_none());
    /// ```
    #[must_use]
    pub fn try_clone(&self) -> Option<Self> {
        match &self.inner {
            BodyInner::Once(bytes) => Some(Self {
                mime: self.mime.clone(),
                inner: BodyInner::Once(bytes.clone()),
            }),
            _ => None,
        }
    }

    /// Starts reading `region` out as data, for a consumer that needs bytes.
    #[cfg(feature = "fs")]
    fn read_out(&mut self, region: FileRegion) {
        let stream = region.into_stream();
        match &mut self.inner {
            BodyInner::Frames(frames) => frames.reading = Some(Box::new(stream)),
            // A one-region body has already yielded its region and is empty.
            _ => self.inner = BodyInner::Reading(stream),
        }
    }

    /// Polls the next frame with every file region read out as data: the
    /// shape of `http_body::Body`, which has no frame for a file.
    fn poll_read_frame(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Error>>> {
        #[cfg(feature = "fs")]
        loop {
            match ready!(Pin::new(&mut *self).poll_next(cx)) {
                Some(Ok(BodyFrame::File(region))) => self.read_out(region),
                frame => return Poll::Ready(frame.map(|frame| frame.map(into_http_frame))),
            }
        }
        #[cfg(not(feature = "fs"))]
        Pin::new(self)
            .poll_next(cx)
            .map(|frame| frame.map(|frame| frame.map(into_http_frame)))
    }
}

/// Converts a data or trailers frame; file regions are read out before this.
fn into_http_frame(frame: BodyFrame) -> Frame<Bytes> {
    match frame {
        BodyFrame::Data(data) => Frame::data(data),
        BodyFrame::Trailers(trailers) => Frame::trailers(trailers),
        #[cfg(feature = "fs")]
        BodyFrame::File(_) => unreachable!("file regions are read out before conversion"),
    }
}

/// The data of a [`Body`], with file regions read out and trailers dropped.
///
/// Created by [`GenericBody::into_data_stream`].
#[derive(Debug)]
pub struct DataStream<F: Flavor = Shared> {
    body: GenericBody<F>,
}

impl<F: Flavor> DataStream<F> {
    /// Returns the body the data is read from.
    #[must_use]
    pub fn into_inner(self) -> GenericBody<F> {
        self.body
    }
}

impl<F: Flavor> Stream for DataStream<F> {
    type Item = Result<Bytes, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            let Some(frame) = ready!(self.body.poll_read_frame(cx)) else {
                return Poll::Ready(None);
            };
            if let Ok(data) = frame?.into_data() {
                return Poll::Ready(Some(Ok(data)));
            }
        }
    }
}

impl<F: Flavor> Default for GenericBody<F> {
    fn default() -> Self {
        Self::empty()
    }
}

/// Drops the `Send + Sync` guarantee; the sources are kept as they are.
impl From<Body> for LocalBody {
    fn from(body: Body) -> Self {
        let inner = match body.inner {
            BodyInner::Once(bytes) => BodyInner::Once(bytes),
            #[cfg(feature = "fs")]
            BodyInner::File(region) => BodyInner::File(region),
            #[cfg(feature = "fs")]
            BodyInner::Reading(stream) => BodyInner::Reading(stream),
            BodyInner::Frames(frames) => {
                let stream: Pin<Box<<Local as Flavor>::Frames>> = frames.stream;
                BodyInner::Frames(Frames {
                    stream,
                    #[cfg(feature = "fs")]
                    reading: frames.reading,
                })
            }
            BodyInner::HttpBody(body) => {
                let body: Pin<Box<<Local as Flavor>::HttpBody>> = body;
                BodyInner::HttpBody(body)
            }
            BodyInner::Freeze => BodyInner::Freeze,
        };
        Self {
            mime: body.mime,
            inner,
        }
    }
}

/// The body's frames, file regions included as [`BodyFrame::File`].
///
/// A region that the `http_body::Body` side has started to read out continues
/// here as data frames, so the two views never skip or repeat bytes.
impl<F: Flavor> Stream for GenericBody<F> {
    type Item = Result<BodyFrame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut self.inner {
            BodyInner::Once(bytes) => {
                if bytes.is_empty() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Ok(BodyFrame::Data(take(bytes)))))
                }
            }
            #[cfg(feature = "fs")]
            BodyInner::File(_) => {
                let BodyInner::File(region) = take(&mut self.inner) else {
                    unreachable!("matched a file body above")
                };
                Poll::Ready(Some(Ok(BodyFrame::File(region))))
            }
            #[cfg(feature = "fs")]
            BodyInner::Reading(stream) => match ready!(Pin::new(stream).poll_next(cx)) {
                Some(chunk) => Poll::Ready(Some(chunk.map(BodyFrame::Data).map_err(Error::from))),
                None => {
                    self.inner = BodyInner::default();
                    Poll::Ready(None)
                }
            },
            BodyInner::Frames(frames) => {
                #[cfg(feature = "fs")]
                if let Some(reading) = &mut frames.reading {
                    match ready!(Pin::new(reading).poll_next(cx)) {
                        Some(chunk) => {
                            return Poll::Ready(Some(
                                chunk.map(BodyFrame::Data).map_err(Error::from),
                            ))
                        }
                        None => frames.reading = None,
                    }
                }
                frames.stream.as_mut().poll_next(cx)
            }
            BodyInner::HttpBody(body) => body
                .as_mut()
                .poll_frame(cx)
                .map(|frame| frame.map(|frame| frame.map(from_http_frame))),
            BodyInner::Freeze => Poll::Ready(Some(Err(Error::BodyFrozen))),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.inner {
            BodyInner::Once(bytes) => {
                let frames = usize::from(!bytes.is_empty());
                (frames, Some(frames))
            }
            #[cfg(feature = "fs")]
            BodyInner::File(_) => (1, Some(1)),
            #[cfg(feature = "fs")]
            BodyInner::Reading(stream) => stream.size_hint(),
            BodyInner::Frames(frames) => {
                let (lower, upper) = frames.stream.size_hint();
                #[cfg(feature = "fs")]
                if let Some(reading) = &frames.reading {
                    let (chunks, _) = reading.size_hint();
                    return (
                        lower.saturating_add(chunks),
                        upper.and_then(|upper| upper.checked_add(chunks)),
                    );
                }
                (lower, upper)
            }
            BodyInner::HttpBody(_) | BodyInner::Freeze => (0, None),
        }
    }
}

/// Data and trailers, with each file region read out into data frames
/// through [`FileRegion::into_stream`].
impl<F: Flavor> http_body::Body for GenericBody<F> {
    type Data = Bytes;

    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.get_mut().poll_read_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            BodyInner::Once(bytes) => bytes.is_empty(),
            #[cfg(feature = "fs")]
            BodyInner::File(region) => region.is_empty(),
            #[cfg(feature = "fs")]
            BodyInner::Reading(stream) => stream.remaining() == 0,
            BodyInner::HttpBody(body) => body.is_end_stream(),
            // Polling a frozen body yields `BodyFrozen`; it must not look finished.
            BodyInner::Frames(_) | BodyInner::Freeze => false,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.inner {
            BodyInner::Once(bytes) => http_body::SizeHint::with_exact(bytes.len() as u64),
            #[cfg(feature = "fs")]
            BodyInner::File(region) => http_body::SizeHint::with_exact(region.len()),
            #[cfg(feature = "fs")]
            BodyInner::Reading(stream) => http_body::SizeHint::with_exact(stream.remaining()),
            #[cfg(feature = "fs")]
            BodyInner::Frames(Frames {
                reading: Some(reading),
                ..
            }) => {
                let mut hint = http_body::SizeHint::default();
                hint.set_lower(reading.remaining());
                hint
            }
            BodyInner::HttpBody(body) => body.size_hint(),
            BodyInner::Frames(_) | BodyInner::Freeze => http_body::SizeHint::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use futures_lite::{stream, StreamExt};
    use http_body_util::{BodyExt, StreamBody};

    #[tokio::test]
    async fn basic_body_operations() {
        let empty = Body::empty();
        assert_eq!(empty.len(), Some(0));
        assert_eq!(empty.is_empty(), Some(true));
        assert!(!empty.is_frozen());

        let text_body = Body::from_bytes("Hello, World!");
        assert_eq!(text_body.len(), Some(13));
        assert_eq!(text_body.is_empty(), Some(false));

        let result = text_body.into_bytes().await.unwrap();
        assert_eq!(result.as_ref(), b"Hello, World!");
    }

    #[tokio::test]
    async fn http_body_reports_end_and_exact_size() {
        use http_body::Body as _;

        let empty = Body::empty();
        assert!(empty.is_end_stream());
        assert_eq!(http_body::Body::size_hint(&empty).exact(), Some(0));

        let mut bytes = Body::from_bytes("Hello");
        assert!(!bytes.is_end_stream());
        assert_eq!(http_body::Body::size_hint(&bytes).exact(), Some(5));
        bytes.frame().await.unwrap().unwrap();
        assert!(bytes.is_end_stream());
        assert_eq!(http_body::Body::size_hint(&bytes).exact(), Some(0));

        #[cfg(feature = "fs")]
        {
            let file = TempFile::new("size-hint", b"abcdef");
            let mut region = Body::from_file_region(FileRegion::new(file.open(), 1, 3));
            assert!(!region.is_end_stream());
            assert_eq!(http_body::Body::size_hint(&region).exact(), Some(3));
            let data = region.frame().await.unwrap().unwrap().into_data().unwrap();
            assert_eq!(data.as_ref(), b"bcd");
            assert!(region.frame().await.is_none());
            assert!(region.is_end_stream());
        }

        let unsized_stream = Body::from_stream(stream::iter([Ok::<_, core::convert::Infallible>(
            Bytes::from_static(b"abc"),
        )]));
        assert!(!unsized_stream.is_end_stream());
        assert_eq!(http_body::Body::size_hint(&unsized_stream).exact(), None);

        let wrapped = Body::new(http_body_util::Full::new(Bytes::from_static(b"wrapped")));
        assert!(!wrapped.is_end_stream());
        assert_eq!(http_body::Body::size_hint(&wrapped).exact(), Some(7));
        let wrapped_empty = Body::new(http_body_util::Empty::<Bytes>::new());
        assert!(wrapped_empty.is_end_stream());

        let mut frozen = Body::from_bytes("gone");
        frozen.freeze();
        assert!(!frozen.is_end_stream());
        assert_eq!(http_body::Body::size_hint(&frozen).exact(), None);
    }

    #[tokio::test]
    async fn wrapped_body_keeps_trailers_as_frames_only() {
        fn with_trailers() -> Body {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
            Body::new(StreamBody::new(stream::iter([
                Ok::<_, core::convert::Infallible>(Frame::data(Bytes::from_static(b"data"))),
                Ok(Frame::trailers(trailers)),
            ])))
        }

        let mut body = with_trailers();
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(data.as_ref(), b"data");
        let trailers = body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(trailers["grpc-status"], "0");
        assert!(body.frame().await.is_none());

        let frames: Vec<BodyFrame> = with_trailers().try_collect().await.unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].as_data().unwrap().as_ref(), b"data");
        assert_eq!(frames[1].as_trailers().unwrap()["grpc-status"], "0");

        let chunks: Vec<Bytes> = with_trailers()
            .into_data_stream()
            .try_collect()
            .await
            .unwrap();
        assert_eq!(chunks, [Bytes::from_static(b"data")]);
    }

    /// A file under the temporary directory, removed on drop.
    #[cfg(feature = "fs")]
    struct TempFile(std::path::PathBuf);

    #[cfg(feature = "fs")]
    impl TempFile {
        fn new(name: &str, contents: &[u8]) -> Self {
            let path = std::env::temp_dir()
                .join(alloc::format!("http-kit-{}-{name}.txt", std::process::id()));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }

        fn open(&self) -> std::fs::File {
            std::fs::File::open(&self.0).unwrap()
        }
    }

    #[cfg(feature = "fs")]
    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    // Real multi-byte text: Chinese, Japanese and Korean.
    #[cfg(feature = "fs")]
    const CJK_TEXT: &str =
        "静态文件直接交给内核。静的ファイルはカーネルに直接渡す。정적 파일은 커널에 바로 넘긴다.";

    #[cfg(feature = "fs")]
    fn mixed_body(file: &TempFile) -> (Body, http::HeaderMap) {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", http::HeaderValue::from_static("abc123"));
        let body = Body::from_frames(stream::iter([
            Ok::<_, Error>(BodyFrame::Data(Bytes::from_static(b"head:"))),
            Ok(BodyFrame::File(FileRegion::new(file.open(), 3, 30))),
            Ok(BodyFrame::Data(Bytes::from_static(b":tail"))),
            Ok(BodyFrame::Trailers(trailers.clone())),
        ]));
        (body, trailers)
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn mixed_frames_survive_the_stream() {
        let file = TempFile::new("mixed-stream", CJK_TEXT.as_bytes());
        let (body, trailers) = mixed_body(&file);
        let frames: Vec<BodyFrame> = body.try_collect().await.unwrap();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].as_data().unwrap().as_ref(), b"head:");
        let region = frames[1].as_file().expect("the region stays a region");
        assert_eq!((region.offset(), region.len()), (3, 30));
        assert_eq!(frames[2].as_data().unwrap().as_ref(), b":tail");
        assert_eq!(frames[3].as_trailers(), Some(&trailers));

        let BodyFrame::File(region) = frames.into_iter().nth(1).unwrap() else {
            unreachable!()
        };
        let read: Vec<Bytes> = region.into_stream().try_collect().await.unwrap();
        assert_eq!(read.concat(), &CJK_TEXT.as_bytes()[3..33]);
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn mixed_frames_survive_http_body() {
        let file = TempFile::new("mixed-http-body", CJK_TEXT.as_bytes());
        let (mut body, trailers) = mixed_body(&file);
        let mut data = Vec::new();
        let mut received_trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            assert!(received_trailers.is_none(), "trailers come last");
            match frame.into_data() {
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(frame) => received_trailers = Some(frame.into_trailers().unwrap()),
            }
        }
        let mut expected = b"head:".to_vec();
        expected.extend_from_slice(&CJK_TEXT.as_bytes()[3..33]);
        expected.extend_from_slice(b":tail");
        assert_eq!(data, expected);
        assert_eq!(received_trailers, Some(trailers));

        let (body, _) = mixed_body(&file);
        assert_eq!(body.into_bytes().await.unwrap(), expected);
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn file_region_reads_in_chunks_and_resumes_as_frames() {
        // Larger than one read chunk, so the region takes several reads.
        let contents = CJK_TEXT.repeat(2048);
        let file = TempFile::new("chunks", contents.as_bytes());
        let len = contents.len() as u64 - 7;
        let mut body = Body::from_file_region(FileRegion::new(file.open(), 7, len));
        assert_eq!(body.len(), Some(len as usize));

        // Read one chunk at the http_body boundary, then the rest as frames.
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(body.len(), Some(len as usize - first.len()));
        let mut read = first.to_vec();
        while let Some(frame) = body.try_next().await.unwrap() {
            read.extend_from_slice(frame.as_data().expect("a region being read yields data"));
        }
        assert_eq!(read, &contents.as_bytes()[7..]);
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn file_shorter_than_its_region_fails() {
        let file = TempFile::new("short", b"0123456789");
        let body = Body::from_file_region(FileRegion::new(file.open(), 4, 10));
        let error = body.into_bytes().await.unwrap_err();
        let Error::Io(error) = error else {
            panic!("expected an I/O error, got {error:?}")
        };
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn try_clone_copies_only_in_memory_bodies() {
        let body = Body::from_bytes("replayable").with_mime(mime::TEXT_PLAIN);
        let copy = body.try_clone().expect("an in-memory body clones");
        assert_eq!(copy.mime(), Some(&mime::TEXT_PLAIN));
        assert_eq!(copy.into_bytes().await.unwrap().as_ref(), b"replayable");
        assert_eq!(body.into_bytes().await.unwrap().as_ref(), b"replayable");

        #[cfg(feature = "fs")]
        {
            let file = TempFile::new("try-clone", b"once");
            let region = Body::from_file_region(FileRegion::new(file.open(), 0, 4));
            assert!(region.try_clone().is_none());
        }

        let stream = Body::from_stream(stream::iter(vec![Ok::<_, std::io::Error>(
            Bytes::from_static(b"once"),
        )]));
        assert!(stream.try_clone().is_none());

        assert!(Body::frozen().try_clone().is_none());
    }

    #[tokio::test]
    async fn body_freeze_and_take() {
        let mut body = Body::from_bytes("test data");
        assert!(!body.is_frozen());

        let taken = Body::take(&mut body).unwrap();
        assert!(body.is_frozen());

        let data = taken.into_bytes().await.unwrap();
        assert_eq!(data.as_ref(), b"test data");

        let result = body.into_bytes().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn body_conversions() {
        let vec_data = vec![1, 2, 3, 4, 5];
        let body = Body::from(vec_data.clone());
        let result = body.into_bytes().await.unwrap();
        assert_eq!(result.as_ref(), vec_data.as_slice());

        let str_data = "string conversion test";
        let body = Body::from(str_data);
        let result = body.into_string().await.unwrap();
        assert_eq!(result.as_str(), str_data);

        let string_data = "owned string test".to_string();
        let expected = string_data.clone();
        let body = Body::from(string_data);
        let result = body.into_string().await.unwrap();
        assert_eq!(result.as_str(), expected);

        let slice_data: &[u8] = &[6, 7, 8, 9, 10];
        let body = Body::from(slice_data);
        let result = body.into_bytes().await.unwrap();
        assert_eq!(result.as_ref(), slice_data);
    }

    #[tokio::test]
    async fn body_stream_yields_data_frames() {
        let mut body = Body::from_bytes("streaming test data");
        let mut chunks = Vec::new();

        while let Some(frame) = body.next().await {
            let BodyFrame::Data(chunk) = frame.unwrap() else {
                panic!("an in-memory body yields only data")
            };
            chunks.push(chunk);
        }

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].as_ref(), b"streaming test data");
    }

    #[cfg(feature = "json")]
    #[tokio::test]
    async fn json_roundtrip() {
        use alloc::string::{String, ToString};
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            message: String,
            count: u32,
        }

        let data = TestData {
            message: "JSON test".to_string(),
            count: 42,
        };

        let body = Body::from_json(&data).unwrap();
        let json_str = body.into_string().await.unwrap();
        assert!(json_str.contains("JSON test"));
        assert!(json_str.contains("42"));

        let mut body = Body::from_json(&data).unwrap();
        let parsed: TestData = body.into_json().await.unwrap();
        assert_eq!(parsed, data);
    }

    #[cfg(feature = "form")]
    #[tokio::test]
    async fn form_roundtrip() {
        use alloc::string::String;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct FormData {
            name: String,
            age: u32,
        }

        let data = FormData {
            name: "Alice".to_string(),
            age: 30,
        };

        let body = Body::from_form(&data).unwrap();
        let form_str = body.into_string().await.unwrap();
        assert!(form_str.contains("name=Alice"));
        assert!(form_str.contains("age=30"));

        let mut body = Body::from_form(&data).unwrap();
        let parsed: FormData = body.into_form().await.unwrap();
        assert_eq!(parsed, data);
    }

    #[tokio::test]
    async fn sse_body_creation_sets_mime() {
        let events = stream::iter(vec![
            Ok::<_, Box<dyn core::error::Error + Send + Sync>>(
                crate::sse::Event::from_data("test data").with_id("1"),
            ),
            Ok(crate::sse::Event::from_data("more data").with_id("2")),
        ]);

        let body = Body::from_sse(events);
        assert_eq!(
            body.mime().as_ref().map(|m| m.as_ref()),
            Some("text/event-stream")
        );
    }

    #[tokio::test]
    async fn body_as_str_and_bytes() {
        let mut body = Body::from_bytes("test string");

        let bytes_ref = body.as_bytes().await.unwrap();
        assert_eq!(bytes_ref, b"test string");

        let bytes_ref2 = body.as_bytes().await.unwrap();
        assert_eq!(bytes_ref2, b"test string");

        let mut body2 = Body::from_bytes("test string");
        let str_ref = body2.as_str().await.unwrap();
        assert_eq!(str_ref, "test string");

        let mut invalid_body = Body::from_bytes(vec![0xFF, 0xFE, 0xFD]);
        let result = invalid_body.as_str().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn body_replace_and_swap() {
        let mut body = Body::from_bytes("original");
        let old_body = body.replace(Body::from_bytes("replacement"));

        let new_data = body.into_bytes().await.unwrap();
        let old_data = old_body.into_bytes().await.unwrap();

        assert_eq!(new_data.as_ref(), b"replacement");
        assert_eq!(old_data.as_ref(), b"original");

        let mut body1 = Body::from_bytes("first");
        let mut body2 = Body::from_bytes("second");

        Body::swap(&mut body1, &mut body2).unwrap();

        let data1 = body1.into_bytes().await.unwrap();
        let data2 = body2.into_bytes().await.unwrap();

        assert_eq!(data1.as_ref(), b"second");
        assert_eq!(data2.as_ref(), b"first");

        let mut frozen_body = Body::frozen();
        let mut normal_body = Body::from_bytes("test");
        let result = Body::swap(&mut frozen_body, &mut normal_body);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn body_freeze() {
        let mut body = Body::from_bytes("test");
        assert!(!body.is_frozen());

        body.freeze();
        assert!(body.is_frozen());

        let result = body.into_bytes().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn mime_types() {
        let empty = Body::empty();
        assert!(empty.mime().is_none());

        #[cfg(feature = "json")]
        {
            use serde::Serialize;
            #[derive(Serialize)]
            struct Data {
                val: i32,
            }
            let body = Body::from_json(&Data { val: 1 }).unwrap();
            assert_eq!(body.mime().unwrap().as_ref(), "application/json");
        }

        #[cfg(feature = "form")]
        {
            use serde::Serialize;
            #[derive(Serialize)]
            struct Data {
                val: i32,
            }
            let body = Body::from_form(&Data { val: 1 }).unwrap();
            assert_eq!(
                body.mime().unwrap().as_ref(),
                "application/x-www-form-urlencoded"
            );
        }
    }

    #[cfg(feature = "fs")]
    #[tokio::test]
    async fn file_body_with_mime() {
        let dir = std::env::temp_dir();
        let file_path = dir.join(alloc::format!("http-kit-{}-mime.html", std::process::id()));
        std::fs::write(&file_path, b"<html></html>").unwrap();

        let body = Body::from_file(&file_path).await.unwrap();
        assert_eq!(body.mime().unwrap().as_ref(), "text/html");
        assert_eq!(body.len(), Some(13));
        assert_eq!(body.into_bytes().await.unwrap().as_ref(), b"<html></html>");

        let _ = std::fs::remove_file(file_path);
    }
}
