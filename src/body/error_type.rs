#[cfg(feature = "std")]
extern crate std;

use super::{BodyFrozen, BoxcoreError};
use core::error::Error as coreError;
use core::fmt::Display;
use core::str::Utf8Error;

/// Error type around `Body`.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An Error caused by a inner I/O error.
    #[cfg(feature = "std")]
    Io(std::io::Error),
    /// The inner object provides a illgal UTF-8 chunk.
    Utf8(Utf8Error),
    /// The body has been consumed and can not provide data anymore.It is distinguished from a normal empty body.
    BodyFrozen,
    #[cfg(feature = "json")]
    /// Fail to serialize/deserialize object to JSON.
    JsonError(serde_json::Error),
    #[cfg(feature = "form")]
    /// Fail to serialize object to a form.
    SerializeForm(serde_urlencoded::ser::Error),
    #[cfg(feature = "form")]
    /// Fail to deserialize a form to object.
    DeserializeForm(serde_urlencoded::de::Error),
    /// Other inner error.
    Other(BoxcoreError),
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
    (Other, BoxcoreError),
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
