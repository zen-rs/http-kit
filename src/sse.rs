//! Server-Sent Events (SSE) implementation module.
//!
//! This module provides functionality for handling Server-Sent Events, a web standard
//! that allows a server to push data to a web page in real-time. SSE is useful for
//! applications that need to stream live data to clients, such as chat applications,
//! live feeds, or real-time notifications.
//!
//! The module includes utilities for formatting SSE messages, managing event streams,
//! and handling the SSE protocol according to the W3C specification.
//!
//! # Examples
//!
//! ```rust
//! // Basic SSE event creation and formatting
//! use http_kit::sse::*;
//!
//! let event = SseEvent::new()
//!     .data("Hello, World!")
//!     .event_type("message");
//! ```
use alloc::string::{String, ToString};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use pin_project_lite::pin_project;
use serde::Serialize;
use serde_json::to_value;
use sse_stream::SseBody;

use crate::Body;

#[doc(inline)]
pub use sse_stream::Error;

/// Represents a Server-Sent Event that can be sent to clients.
#[derive(Debug)]
pub struct Event(sse_stream::Sse);

impl Event {
    /// Creates a new Server-Sent Event with the given ID and data.
    pub fn new<T: Serialize>(id: impl Into<String>, data: T) -> Self {
        let value = to_value(data).unwrap();
        let data = value
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| value.to_string());
        Self(sse_stream::Sse::default().data(data).id(id))
    }
}

pub(crate) fn into_body<S, E>(
    stream: S,
) -> impl http_body::Body<Data = Bytes, Error = E> + Send + Sync
where
    S: Stream<Item = Result<Event, E>> + Send + Sync,
    E: Send + Sync,
{
    SseBody::new(stream.map(|event| event.map(|event| event.0)))
}

pin_project! {
    /// A stream wrapper for Server-Sent Events over an HTTP body.
    ///
    /// This struct provides a way to parse an incoming HTTP body as a stream of
    /// Server-Sent Events, allowing you to process SSE data asynchronously.
    pub struct SseStream {
        #[pin]
        inner: sse_stream::SseStream<Body>,
    }
}

impl SseStream {
    /// Creates a new SSE stream from an HTTP body.
    ///
    /// This function wraps the provided body in an SSE stream parser that can
    /// asynchronously parse Server-Sent Events from the body data.
    pub fn new(body: Body) -> Self {
        Self {
            inner: sse_stream::SseStream::new(body),
        }
    }
}

impl Stream for SseStream {
    type Item = Result<Event, sse_stream::Error>;

    fn poll_next(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Option<Self::Item>> {
        self.project().inner.poll_next(cx).map_ok(Event)
    }
}
