macro_rules! impl_error {
    ($ty:ident,$message:expr) => {
        #[doc = concat!("The error type of `", stringify!($ty), "`.")]
        #[derive(Debug)]
        pub struct $ty {
            _priv: (),
        }

        impl $ty {
            pub(crate) fn new() -> Self {
                Self { _priv: () }
            }
        }

        impl core::fmt::Display for $ty {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str($message)
            }
        }

        impl core::error::Error for $ty {}
    };
}

/// Defines a zero-sized type that implements [`HttpError`] with a custom formatter.
///
/// This macro is intended for library users who want lightweight marker error types
/// that only carry a status code and a display representation.
#[macro_export]
macro_rules! http_error_fmt {
    ($(#[$meta:meta])* $vis:vis $name:ident, $status:expr, |$ty_self:pat, $fmt:ident| $body:expr $(,)?) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        $vis struct $name {
            _priv: (),
        }

        impl $name {
            /// Creates a new instance of this error type.
            pub const fn new() -> Self {
                Self { _priv: () }
            }
        }

        impl ::core::default::Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                let $ty_self = self;
                let $fmt = f;
                $body
            }
        }

        impl ::core::error::Error for $name {}

        impl $crate::HttpError for $name {
            fn status(&self) -> ::core::option::Option<$crate::StatusCode> {
                ::core::option::Option::Some($status)
            }
        }
    };
}

/// Defines a zero-sized [`HttpError`] type that renders as a static message.
///
/// # Examples
///
/// ```rust
/// use http_kit::{http_error, StatusCode, HttpError};
///
/// http_error!(
///     /// Reported when a resource is missing.
///     pub NotFoundError,
///     StatusCode::NOT_FOUND,
///     "resource not found"
/// );
///
/// let err = NotFoundError::new();
/// assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
/// assert_eq!(err.to_string(), "resource not found");
/// ```
#[macro_export]
macro_rules! http_error {
    ($(#[$meta:meta])* $vis:vis $name:ident, $status:expr, $message:expr $(,)?) => {
        $crate::http_error_fmt!(
            $(#[$meta])*
            $vis $name,
            $status,
            |_, f| { f.write_str($message) },
        );
    };
}

#[cfg(test)]
mod tests {
    use crate::{HttpError, StatusCode};
    use alloc::string::ToString;

    http_error!(
        /// Error returned when testing macros for missing resources.
        pub MacroNotFound,
        StatusCode::NOT_FOUND,
        "macro missing"
    );

    http_error_fmt!(
        /// Custom formatted macro error used in tests.
        pub MacroDisplayError,
        StatusCode::BAD_REQUEST,
        |_, f| write!(f, "bad request (400)"),
    );

    #[test]
    fn http_error_macros_create_expected_types() {
        let not_found = MacroNotFound::new();
        assert_eq!(not_found.status(), Some(StatusCode::NOT_FOUND));
        assert_eq!(not_found.to_string(), "macro missing");

        let display = MacroDisplayError::new();
        assert_eq!(display.status(), Some(StatusCode::BAD_REQUEST));
        assert_eq!(display.to_string(), "bad request (400)");
    }
}
