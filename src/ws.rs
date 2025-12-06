use alloc::{borrow::ToOwned, string::String, vec::Vec};
use bytes::Bytes;
use bytestr::ByteStr;

/// Message transmitted over a websocket connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WebSocketMessage {
    /// UTF-8 text payload.
    Text(ByteStr),
    /// Binary payload.
    Binary(Bytes),
}

/// Configuration applied when establishing a websocket connection.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct WebSocketConfig {
    /// Maximum incoming websocket message size in bytes.
    /// `None` means no limit.
    pub max_message_size: Option<usize>,

    /// Maximum incoming websocket frame size in bytes.
    /// `None` means no limit.
    pub max_frame_size: Option<usize>,
}

const DEFAULT_MAX_MESSAGE_SIZE: Option<usize> = Some(64 << 20);
const DEFAULT_MAX_FRAME_SIZE: Option<usize> = Some(16 << 20);

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }
}

impl WebSocketConfig {
    /// Override the maximum incoming websocket message size in bytes.
    ///
    /// `None` means no limit.
    ///
    /// Defaults to 64 MiB.
    #[must_use]
    pub const fn with_max_message_size(mut self, max_message_size: Option<usize>) -> Self {
        self.max_message_size = max_message_size;
        self
    }

    /// Override the maximum incoming websocket frame size in bytes.
    ///
    /// `None` means no limit.
    ///
    /// Defaults to 16 MiB.
    #[must_use]
    pub const fn with_max_frame_size(mut self, max_frame_size: Option<usize>) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }
}

impl WebSocketMessage {
    /// Construct a text message.
    #[must_use]
    pub fn text(value: impl Into<ByteStr>) -> Self {
        Self::Text(value.into())
    }

    /// Construct a binary message.
    #[must_use]
    pub fn binary(value: impl Into<Bytes>) -> Self {
        Self::Binary(value.into())
    }

    /// Returns the payload as text when possible.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Binary(_) => None,
        }
    }

    /// Returns the payload as raw bytes when possible.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Text(_) => None,
            Self::Binary(bytes) => Some(bytes),
        }
    }

    /// Converts the payload into owned text when possible.
    #[must_use]
    pub fn into_text(self) -> Option<ByteStr> {
        match self {
            Self::Text(text) => Some(text),
            Self::Binary(_) => None,
        }
    }

    /// Converts the payload into owned bytes when possible.
    #[must_use]
    pub fn into_bytes(self) -> Option<Bytes> {
        match self {
            Self::Text(_) => None,
            Self::Binary(bytes) => Some(bytes),
        }
    }
}

impl From<String> for WebSocketMessage {
    fn from(value: String) -> Self {
        Self::Text(value.into())
    }
}

impl From<ByteStr> for WebSocketMessage {
    fn from(value: ByteStr) -> Self {
        Self::Text(value)
    }
}

impl From<&str> for WebSocketMessage {
    fn from(value: &str) -> Self {
        Self::Text(value.to_owned().into())
    }
}

impl From<Bytes> for WebSocketMessage {
    fn from(value: Bytes) -> Self {
        Self::Binary(value)
    }
}

impl From<Vec<u8>> for WebSocketMessage {
    fn from(value: Vec<u8>) -> Self {
        Self::Binary(value.into())
    }
}

impl From<&[u8]> for WebSocketMessage {
    fn from(value: &[u8]) -> Self {
        Self::Binary(value.to_vec().into())
    }
}
