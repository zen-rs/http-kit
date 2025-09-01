#[cfg(feature = "std")]
extern crate std;

use super::{BodyFrozen, BoxError};
use core::error::Error as coreError;
use core::fmt::Display;
use core::str::Utf8Error;

/// Error type for body operations.
///
/// This enum represents all possible errors that can occur when working with HTTP body data,
/// including I/O errors, encoding issues, serialization failures, and body state errors.
///
/// # Examples
///
/// ```rust
/// use http_kit::BodyError;
///
/// // Handle different error types
/// match some_body_operation() {
///     Err(BodyError::BodyFrozen) => println!("Body was already consumed"),
///     #[cfg(feature = "json")]
///     Err(BodyError::JsonError(e)) => println!("JSON error: {}", e),
///     Err(e) => println!("Other error: {}", e),
///     Ok(result) => println!("Success: {:?}", result),
/// }
/// # fn some_body_operation() -> Result<(), BodyError> { Ok(()) }
/// ```
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An I/O error occurred during body operations.
    ///
    /// This typically happens when reading from streams, files, or other I/O sources.
    #[cfg(feature = "std")]
    Io(std::io::Error),
    /// Invalid UTF-8 data was encountered when converting body to string.
    ///
    /// This error occurs when trying to interpret body bytes as UTF-8 text
    /// but the bytes don't form valid UTF-8 sequences.
    Utf8(Utf8Error),
    /// The body has been consumed and cannot provide data anymore.
    ///
    /// This is distinct from a normal empty body - it indicates that the body
    /// was previously taken or frozen and is no longer available for operations.
    /// This typically happens after calling `take()` on a body.
    BodyFrozen,
    /// JSON serialization or deserialization failed.
    ///
    /// This error occurs when trying to convert between Rust types and JSON
    /// using the `from_json()` or `into_json()` methods.
    #[cfg(feature = "json")]
    JsonError(serde_json::Error),
    /// Form data serialization failed.
    ///
    /// This error occurs when trying to serialize a Rust type to URL-encoded form data
    /// using the `from_form()` method.
    #[cfg(feature = "form")]
    SerializeForm(serde_urlencoded::ser::Error),
    /// Form data deserialization failed.
    ///
    /// This error occurs when trying to deserialize URL-encoded form data
    /// to a Rust type using the `into_form()` method.
    #[cfg(feature = "form")]
    DeserializeForm(serde_urlencoded::de::Error),
    /// Other error types not covered by specific variants.
    ///
    /// This is a catch-all for any other error that can occur during body operations,
    /// typically errors from underlying libraries or custom implementations.
    Other(BoxError),
}

macro_rules! impl_body_error {
    ($(($field:tt,$ty:ty $(,$feature:tt)?)),*) => {
        $(
            $(#[cfg(feature = $feature)])*
            impl From<$ty> for Error {
                fn from(error: $ty) -> Self {
                    Self::$field(error)
                }
            }
        )*

        impl Display for Error {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self {
                    $(
                        $(#[cfg(feature = $feature)])*
                        Self::$field(error) => error.fmt(f),
                    )*
                    Self::BodyFrozen => BodyFrozen::new().fmt(f),
                }
            }
        }

        impl coreError for Error {
            fn source(&self) -> Option<&(dyn coreError + 'static)> {
                match self {
                    $(
                        $(#[cfg(feature = $feature)])*
                        Self::$field(error) => error.source(),
                    )*
                    Error::BodyFrozen => None,
                }
            }
        }

    };
}

#[cfg(feature = "std")]
impl_body_error![
    (Io, std::io::Error),
    (Utf8, Utf8Error),
    (Other, BoxError),
    (JsonError, serde_json::Error, "json"),
    (SerializeForm, serde_urlencoded::ser::Error, "form"),
    (DeserializeForm, serde_urlencoded::de::Error, "form")
];

#[cfg(not(feature = "std"))]
impl_body_error![
    (Utf8, Utf8Error),
    (Other, BoxcoreError),
    (JsonError, serde_json::Error, "json"),
    (SerializeForm, serde_urlencoded::ser::Error, "form"),
    (DeserializeForm, serde_urlencoded::de::Error, "form")
];

impl From<BodyFrozen> for Error {
    fn from(_error: BodyFrozen) -> Self {
        Self::BodyFrozen
    }
}
