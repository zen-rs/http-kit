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
//! use http_kit::sse::Event;
//!
//! let event = Event::from_data("Hello, World!").with_id("my-id");
//! ```

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use bytes::Bytes;
use core::error::Error as StdError;
use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures_lite::{Stream, StreamExt};
use http_body::Frame;
use http_body_util::StreamBody;
use pin_project_lite::pin_project;
use serde::Serialize;
use serde_json::to_string;

use crate::Body;

/// Represents a Server-Sent Event that can be sent to clients.
#[derive(Debug)]
pub struct Event {
    event: Option<String>,
    data: String,
    id: Option<String>,
    retry: Option<u64>,
}

impl Event {
    /// Creates a new SSE event from JSON-serializable data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::sse::Event;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct Message { text: String }
    ///
    /// let msg = Message { text: "Hello".to_string() };
    /// let event = Event::new(&msg);
    /// ```
    pub fn new<T: Serialize>(data: &T) -> Self {
        Self::from_data(to_string(&data).expect("Failed to serialize data"))
    }

    /// Creates a new SSE event from string data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::sse::Event;
    ///
    /// let event = Event::from_data("Hello, World!");
    /// ```
    pub fn from_data<T: Into<String>>(data: T) -> Self {
        Self {
            event: None,
            data: data.into(),
            id: None,
            retry: None,
        }
    }

    /// Returns the event ID if set.
    pub const fn id(&self) -> Option<&str> {
        if let Some(id) = self.id.as_ref() {
            Some(id.as_str())
        } else {
            None
        }
    }

    /// Returns the event type if set.
    pub const fn event(&self) -> Option<&str> {
        if let Some(event) = self.event.as_ref() {
            Some(event.as_str())
        } else {
            None
        }
    }

    /// Returns the retry duration in milliseconds if set.
    pub const fn retry(&self) -> Option<u64> {
        self.retry
    }

    /// Returns the raw text data of the event.
    pub const fn text_data(&self) -> &str {
        self.data.as_str()
    }

    /// Deserializes the event data as JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be deserialized as the specified type.
    pub fn data<T>(&self) -> Result<T, serde_json::Error>
    where
        T: for<'de> serde::Deserialize<'de>,
    {
        serde_json::from_str(self.text_data())
    }

    /// Sets the event ID.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::sse::Event;
    ///
    /// let event = Event::from_data("Hello").with_id("msg-123");
    /// ```
    pub fn with_id<T: Into<String>>(mut self, id: T) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Sets the event type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::sse::Event;
    ///
    /// let event = Event::from_data("Hello").with_event("message");
    /// ```
    pub fn with_event<T: Into<String>>(mut self, event: T) -> Self {
        self.event = Some(event.into());
        self
    }

    /// Encodes the event as an SSE-formatted string.
    ///
    /// The output follows the SSE specification format:
    /// - `event: <type>` (optional)
    /// - `data: <data>`
    /// - `id: <id>` (optional)
    /// - `retry: <milliseconds>` (optional)
    /// - Empty line to end the event
    pub fn encode(&self) -> String {
        let mut encoded = String::new();
        if let Some(event) = self.event() {
            encoded.push_str("event: ");
            encoded.push_str(event);
            encoded.push('\n');
        }
        encoded.push_str("data: ");
        encoded.push_str(&self.data);
        encoded.push('\n');

        if let Some(id) = self.id() {
            encoded.push_str("id: ");
            encoded.push_str(id);
            encoded.push('\n');
        }
        if let Some(retry) = self.retry() {
            encoded.push_str("retry: ");
            encoded.push_str(&retry.to_string());
            encoded.push('\n');
        }

        encoded.push('\n');
        encoded
    }
}

pub(crate) fn into_body<S, E>(
    stream: S,
) -> impl http_body::Body<Data = Bytes, Error = E> + Send + Sync
where
    S: Stream<Item = Result<Event, E>> + Send + Sync,
    E: Send + Sync,
{
    StreamBody::new(
        stream.map(|result| {
            result.map(|event| Frame::data(Bytes::from(event.encode().into_bytes())))
        }),
    )
}

pin_project! {
    /// A stream wrapper for Server-Sent Events over an HTTP body.
    ///
    /// This struct provides a way to parse an incoming HTTP body as a stream of
    /// Server-Sent Events, allowing you to process SSE data asynchronously.
    pub struct SseStream{
        #[pin]
        body:Body,
        buffer: Vec<u8>,
        partial_event: PartialEvent,
    }
}

#[derive(Default, Debug)]
struct PartialEvent {
    id: Option<String>,
    event: Option<String>,
    data: Vec<String>,
    retry: Option<u64>,
}

impl SseStream {
    /// Creates a new SSE stream from an HTTP body.
    ///
    /// This function wraps the provided body in an SSE stream parser that can
    /// asynchronously parse Server-Sent Events from the body data.
    pub fn new(body: Body) -> Self {
        Self {
            body,
            buffer: Vec::new(),
            partial_event: PartialEvent::default(),
        }
    }
}

/// Errors that can occur while parsing Server-Sent Events.
#[derive(Debug, Clone)]
pub enum ParseError {
    /// The underlying body stream encountered an error
    BodyError(String),
    /// Invalid UTF-8 encoding in the SSE data
    InvalidUtf8,
    /// Invalid retry value (not a valid number)
    InvalidRetryValue,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BodyError(e) => write!(f, "Body stream error: {}", e),
            ParseError::InvalidUtf8 => write!(f, "Invalid UTF-8 in SSE data"),
            ParseError::InvalidRetryValue => write!(f, "Invalid retry value in SSE event"),
        }
    }
}

impl StdError for ParseError {}

impl Stream for SseStream {
    type Item = Result<Event, ParseError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            // Try to parse an event from the buffer
            if let Some(event) = parse_event_from_buffer(this.buffer, this.partial_event) {
                return Poll::Ready(Some(Ok(event)));
            }

            // If no complete event, read more data from the body
            match this.body.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    this.buffer.extend_from_slice(&frame);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Some(Err(ParseError::BodyError(e.to_string()))));
                }
                Poll::Ready(None) => {
                    // Stream ended, check if we have a partial event to emit
                    if !this.partial_event.data.is_empty() {
                        let event = Event {
                            id: this.partial_event.id.take(),
                            event: this.partial_event.event.take(),
                            data: this.partial_event.data.join("\n"),
                            retry: this.partial_event.retry.take(),
                        };
                        this.partial_event.data.clear();
                        return Poll::Ready(Some(Ok(event)));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn parse_event_from_buffer(
    buffer: &mut Vec<u8>,
    partial_event: &mut PartialEvent,
) -> Option<Event> {
    // Find the next double newline (event separator)
    let mut i = 0;
    while i < buffer.len() {
        if i + 1 < buffer.len() && buffer[i] == b'\n' && buffer[i + 1] == b'\n' {
            // Found event separator
            let event_data = buffer.drain(..=i + 1).collect::<Vec<u8>>();

            // Parse the event lines
            let event_str = String::from_utf8_lossy(&event_data);
            for line in event_str.lines() {
                if line.is_empty() {
                    continue;
                }

                if let Some(data) = line.strip_prefix("data: ") {
                    partial_event.data.push(data.to_string());
                } else if let Some(event_type) = line.strip_prefix("event: ") {
                    partial_event.event = Some(event_type.to_string());
                } else if let Some(id) = line.strip_prefix("id: ") {
                    partial_event.id = Some(id.to_string());
                } else if let Some(retry_str) = line.strip_prefix("retry: ") {
                    if let Ok(retry) = retry_str.parse::<u64>() {
                        partial_event.retry = Some(retry);
                    }
                } else if line == ":" || line.starts_with(": ") {
                    // Comment line, ignore
                    continue;
                }
            }

            // If we have data, emit an event
            if !partial_event.data.is_empty() {
                let event = Event {
                    id: partial_event.id.take(),
                    event: partial_event.event.take(),
                    data: partial_event.data.join("\n"),
                    retry: partial_event.retry.take(),
                };
                partial_event.data.clear();
                return Some(event);
            }
        }

        // Check for single newline to process incomplete lines
        if buffer[i] == b'\n' {
            let line_data = buffer.drain(..=i).collect::<Vec<u8>>();
            let line = String::from_utf8_lossy(&line_data);
            let line = line.trim_end_matches('\n');

            if let Some(data) = line.strip_prefix("data: ") {
                partial_event.data.push(data.to_string());
            } else if let Some(event_type) = line.strip_prefix("event: ") {
                partial_event.event = Some(event_type.to_string());
            } else if let Some(id) = line.strip_prefix("id: ") {
                partial_event.id = Some(id.to_string());
            } else if let Some(retry_str) = line.strip_prefix("retry: ") {
                if let Ok(retry) = retry_str.parse::<u64>() {
                    partial_event.retry = Some(retry);
                }
            }

            // Reset i since we modified the buffer
            i = 0;
        } else {
            i += 1;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use futures_lite::StreamExt;

    #[tokio::test]
    async fn test_parse_simple_event() {
        let data = b"data: Hello World\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Hello World");
        assert_eq!(event.event(), None);
        assert_eq!(event.id(), None);
    }

    #[tokio::test]
    async fn test_parse_event_with_type() {
        let data = b"event: message\ndata: Test message\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Test message");
        assert_eq!(event.event(), Some("message"));
    }

    #[tokio::test]
    async fn test_parse_event_with_id() {
        let data = b"id: 123\ndata: Event with ID\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Event with ID");
        assert_eq!(event.id(), Some("123"));
    }

    #[tokio::test]
    async fn test_parse_event_with_retry() {
        let data = b"retry: 5000\ndata: Event with retry\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Event with retry");
        assert_eq!(event.retry(), Some(5000));
    }

    #[tokio::test]
    async fn test_parse_multiline_data() {
        let data = b"data: Line 1\ndata: Line 2\ndata: Line 3\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Line 1\nLine 2\nLine 3");
    }

    #[tokio::test]
    async fn test_parse_multiple_events() {
        let data = b"data: First event\n\ndata: Second event\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event1 = stream.next().await.unwrap().unwrap();
        assert_eq!(event1.text_data(), "First event");

        let event2 = stream.next().await.unwrap().unwrap();
        assert_eq!(event2.text_data(), "Second event");
    }

    #[tokio::test]
    async fn test_parse_event_with_all_fields() {
        let data = b"id: abc-123\nevent: update\nretry: 3000\ndata: Complete event\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Complete event");
        assert_eq!(event.event(), Some("update"));
        assert_eq!(event.id(), Some("abc-123"));
        assert_eq!(event.retry(), Some(3000));
    }

    #[tokio::test]
    async fn test_ignore_comments() {
        let data = b": This is a comment\ndata: Actual data\n: Another comment\n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "Actual data");
    }

    #[tokio::test]
    async fn test_event_encoding() {
        let event = Event::from_data("Test message")
            .with_id("123")
            .with_event("message");

        let encoded = event.encode();
        assert!(encoded.contains("event: message\n"));
        assert!(encoded.contains("data: Test message\n"));
        assert!(encoded.contains("id: 123\n"));
        assert!(encoded.ends_with("\n\n"));
    }

    #[tokio::test]
    async fn test_json_serialization() {
        #[derive(Serialize, serde::Deserialize, PartialEq, Debug)]
        struct TestData {
            message: String,
            count: u32,
        }

        let data = TestData {
            message: "Hello".to_string(),
            count: 42,
        };

        let event = Event::new(&data);
        assert!(event.text_data().contains("\"message\":\"Hello\""));
        assert!(event.text_data().contains("\"count\":42"));

        // Test deserialization
        let decoded: TestData = event.data().unwrap();
        assert_eq!(decoded, data);
    }

    #[tokio::test]
    async fn test_stream_chunked_data() {
        // Simulate data coming in chunks
        let data = vec![
            Bytes::from("data: Part"),
            Bytes::from("ial message\n"),
            Bytes::from("\ndata: Second"),
            Bytes::from(" event\n\n"),
        ];

        let mut combined = Vec::new();
        for chunk in data {
            combined.extend_from_slice(&chunk);
        }
        let body = Body::from(Bytes::from(combined));
        let mut sse_stream = SseStream::new(body);

        let event1 = sse_stream.next().await.unwrap().unwrap();
        assert_eq!(event1.text_data(), "Partial message");

        let event2 = sse_stream.next().await.unwrap().unwrap();
        assert_eq!(event2.text_data(), "Second event");
    }

    #[tokio::test]
    async fn test_empty_data_field() {
        let data = b"event: ping\ndata: \n\n";
        let body = Body::from(Bytes::from(&data[..]));
        let mut stream = SseStream::new(body);

        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.text_data(), "");
        assert_eq!(event.event(), Some("ping"));
    }
}
