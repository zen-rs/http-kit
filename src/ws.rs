//! Shared websocket types exposed by the public API without leaking backend dependencies.

extern crate std;

use std::{fmt, io};

use alloc::{string::String, vec::Vec};

/// Result type used by websocket operations.
pub type WebSocketResult<T> = Result<T, WebSocketError>;

/// Lightweight websocket configuration used across targets.
#[derive(Clone, Debug, Default)]
pub struct WebSocketConfig {
    /// Maximum incoming message size in bytes. `None` removes the limit.
    pub max_message_size: Option<usize>,
}

/// Close frame representation that avoids depending on tungstenite types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebSocketCloseFrame {
    /// Close code sent to peer.
    pub code: u16,
    /// Human readable close reason.
    pub reason: String,
}

impl WebSocketCloseFrame {
    /// Build a close frame from code and reason.
    pub fn new(code: u16, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }
}

/// Message wrapper that mirrors the common websocket frames we need.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSocketMessage {
    /// Text payload.
    Text(String),
    /// Binary payload.
    Binary(Vec<u8>),
    /// Ping control frame.
    Ping(Vec<u8>),
    /// Pong control frame.
    Pong(Vec<u8>),
    /// Close control frame.
    Close(Option<WebSocketCloseFrame>),
}

impl WebSocketMessage {
    /// Create a text message.
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// Create a binary message.
    pub fn binary(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Binary(bytes.into())
    }

    /// Returns true when the message is textual.
    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    /// Consume and return the text payload if present.
    pub fn into_text(self) -> Result<String, Self> {
        match self {
            Self::Text(text) => Ok(text),
            other => Err(other),
        }
    }

    /// Deserialize JSON text message into a typed value.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError::Protocol`] if the message is not text or JSON deserialization fails.
    #[cfg(feature = "json")]
    pub fn into_json<T: serde::de::DeserializeOwned>(self) -> WebSocketResult<T> {
        match self {
            Self::Text(text) => serde_json::from_str(&text).map_err(WebSocketError::from),
            _ => Err(WebSocketError::Protocol(
                "Expected text message for JSON deserialization".into(),
            )),
        }
    }

    /// Try to deserialize JSON text message, returning None if not text.
    ///
    /// Returns `None` for non-text messages, or `Some(Result)` for text messages.
    #[cfg(feature = "json")]
    pub fn try_into_json<T: serde::de::DeserializeOwned>(self) -> Option<WebSocketResult<T>> {
        match self {
            Self::Text(text) => Some(serde_json::from_str(&text).map_err(WebSocketError::from)),
            _ => None,
        }
    }

    /// Returns true when the message is binary.
    #[must_use]
    pub const fn is_binary(&self) -> bool {
        matches!(self, Self::Binary(_))
    }

    /// Consume and return the binary payload if present.
    pub fn into_binary(self) -> Result<Vec<u8>, Self> {
        match self {
            Self::Binary(data) => Ok(data),
            other => Err(other),
        }
    }

    /// Returns true when the message is a close frame.
    #[must_use]
    pub const fn is_close(&self) -> bool {
        matches!(self, Self::Close(_))
    }
}

/// Errors produced by websocket operations.
#[derive(Debug)]
pub enum WebSocketError {
    /// Underlying IO/transport failure.
    Transport(io::Error),
    /// Protocol-level failure.
    Protocol(String),
}

impl From<io::Error> for WebSocketError {
    fn from(error: io::Error) -> Self {
        Self::Transport(error)
    }
}

impl fmt::Display for WebSocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(err) => write!(f, "transport error: {err}"),
            Self::Protocol(err) => write!(f, "protocol error: {err}"),
        }
    }
}

impl std::error::Error for WebSocketError {}

#[cfg(feature = "json")]
impl From<serde_json::Error> for WebSocketError {
    fn from(error: serde_json::Error) -> Self {
        use alloc::string::ToString;

        Self::Protocol(error.to_string())
    }
}
