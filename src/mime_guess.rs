//! MIME type guessing from file extensions.
//!
//! This module provides simple MIME type detection based on file extensions.
//! It supports common web and media file formats and returns standard MIME
//! type strings that can be used in HTTP `Content-Type` headers.
//!
//! # Examples
//!
//! ```rust
//! use http_kit::mime_guess::guess;
//!
//! assert_eq!(guess(b"json"), Some("application/json"));
//! assert_eq!(guess(b"png"), Some("image/png"));
//! assert_eq!(guess(b"unknown"), None);
//! ```

/// Guesses the MIME type from a file extension.
///
/// This function takes a file extension as bytes and returns the corresponding
/// MIME type string if recognized. It supports common web and media formats
/// including images, videos, audio, text files, and web assets.
///
/// The matching is case-sensitive and expects lowercase extensions without
/// the leading dot.
///
/// # Arguments
///
/// * `extension` - The file extension as bytes (without the leading dot)
///
/// # Returns
///
/// Returns `Some(&'static str)` with the MIME type if the extension is recognized,
/// or `None` if the extension is unknown.
///
/// # Examples
///
/// ```rust
/// use http_kit::mime_guess::guess;
///
/// // Common web formats
/// assert_eq!(guess(b"html"), None); // Not in the supported list
/// assert_eq!(guess(b"css"), Some("text/css"));
/// assert_eq!(guess(b"js"), Some("text/javascript"));
/// assert_eq!(guess(b"json"), Some("application/json"));
///
/// // Image formats
/// assert_eq!(guess(b"png"), Some("image/png"));
/// assert_eq!(guess(b"jpg"), Some("image/jpeg"));
/// assert_eq!(guess(b"jpeg"), Some("image/jpeg"));
/// assert_eq!(guess(b"gif"), Some("image/gif"));
/// assert_eq!(guess(b"webp"), Some("image/webp"));
/// assert_eq!(guess(b"svg"), Some("image/svg+xml"));
///
/// // Audio formats
/// assert_eq!(guess(b"mp3"), Some("audio/mpeg"));
/// assert_eq!(guess(b"wav"), Some("audio/wav"));
/// assert_eq!(guess(b"aac"), Some("audio/aac"));
///
/// // Video formats
/// assert_eq!(guess(b"mp4"), Some("video/mp4"));
/// assert_eq!(guess(b"avi"), Some("video/x-msvideo"));
///
/// // Other formats
/// assert_eq!(guess(b"txt"), Some("text/plain"));
/// assert_eq!(guess(b"ttf"), Some("font/ttf"));
///
/// // Unknown extension
/// assert_eq!(guess(b"unknown"), None);
/// ```
pub const fn guess(extension: &[u8]) -> Option<&'static str> {
    match extension {
        b"aac" => Some("audio/aac"),
        b"avi" => Some("video/x-msvideo"),
        b"css" => Some("text/css"),
        b"gif" => Some("image/gif"),
        b"jpeg" | b"jpg" => Some("image/jpeg"),
        b"js" => Some("text/javascript"),
        b"json" => Some("application/json"),
        b"mp3" => Some("audio/mpeg"),
        b"mp4" => Some("video/mp4"),
        b"png" => Some("image/png"),
        b"svg" => Some("image/svg+xml"),
        b"ttf" => Some("font/ttf"),
        b"txt" => Some("text/plain"),
        b"wav" => Some("audio/wav"),
        b"webp" => Some("image/webp"),
        _ => None,
    }
}
