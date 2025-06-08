//! Utility types and functions for HTTP operations.
//!
//! This module provides convenient re-exports of commonly used types and utilities
//! that are helpful when working with HTTP requests, responses, and async operations.
//! These re-exports save you from having to import these dependencies directly.
//!
//! # Exported Types
//!
//! - [`Bytes`] - Efficient byte buffer for HTTP body data
//! - [`ByteStr`] - UTF-8 validated byte string for text content
//! - All items from `futures_lite` - Async utilities and traits
//!
//! # Examples
//!
//! ## Working with Bytes
//!
//! ```rust
//! use http_kit::utils::Bytes;
//!
//! let data = Bytes::from("Hello, world!");
//! assert_eq!(data.len(), 13);
//! ```
//!
//! ## Working with ByteStr
//!
//! ```rust
//! use http_kit::utils::ByteStr;
//!
//! let text = ByteStr::from_static("Hello, world!");
//! assert_eq!(text.as_str(), "Hello, world!");
//! ```
//!
//! ## Async Operations
//!
//! ```rust
//! use http_kit::utils::{AsyncReadExt, AsyncWriteExt};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Use async I/O traits for streaming operations
//! # Ok(())
//! # }
//! ```

/// Efficient, reference-counted byte buffer for HTTP body data.
///
/// `Bytes` is a cheaply cloneable and sliceable chunk of contiguous memory.
/// It's ideal for HTTP body content as it allows zero-copy operations when
/// possible and efficient sharing of data between different parts of your application.
///
/// This is a re-export from the `bytes` crate.
///
/// # Examples
///
/// ```rust
/// use http_kit::utils::Bytes;
///
/// let data = Bytes::from("HTTP body content");
/// let slice = data.slice(0..4);  // Zero-copy slice
/// assert_eq!(slice, "HTTP");
/// ```
pub use bytes::Bytes;

/// UTF-8 validated byte string optimized for text content.
///
/// `ByteStr` provides a string-like interface over byte data while maintaining
/// the underlying byte representation. It's particularly useful for HTTP text
/// content where you need both string operations and efficient byte access.
///
/// This is a re-export from the `bytestr` crate.
///
/// # Examples
///
/// ```rust
/// use http_kit::utils::ByteStr;
///
/// let text = ByteStr::from_static("Content-Type: application/json");
/// assert_eq!(text.len(), 30);
/// assert!(text.starts_with("Content-Type"));
/// ```
pub use bytestr::ByteStr;

/// Complete async runtime utilities and traits.
///
/// This re-exports all items from `futures_lite`, providing:
///
/// - **Async I/O traits**: `AsyncRead`, `AsyncWrite`, `AsyncBufRead`, etc.
/// - **Stream utilities**: `Stream`, `StreamExt` for async iteration
/// - **Future utilities**: `FutureExt`, `future::ready`, `future::pending`
/// - **Async combinators**: `join!`, `try_join!`, `select!`
/// - **I/O utilities**: Async file operations, networking, etc.
///
/// This saves you from having to import `futures_lite` directly and provides
/// all the async primitives needed for HTTP operations.
///
/// # Examples
///
/// ## Stream Processing
///
/// ```rust
/// use http_kit::utils::{stream, StreamExt};
///
/// # async fn example() {
/// let data = vec!["chunk1", "chunk2", "chunk3"];
/// let mut stream = stream::iter(data);
///
/// while let Some(chunk) = stream.next().await {
///     println!("Processing: {}", chunk);
/// }
/// # }
/// ```
///
/// ## Async I/O
///
/// ```rust
/// use http_kit::utils::{AsyncReadExt, AsyncWriteExt};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // These traits are available for async I/O operations
/// # Ok(())
/// # }
/// ```
pub use futures_lite::*;
