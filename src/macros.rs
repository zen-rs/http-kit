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
            fn status(&self) -> $crate::StatusCode {
                $status
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
/// assert_eq!(err.status(), StatusCode::NOT_FOUND);
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

/// Implements [`SendEndpoint`](crate::SendEndpoint) for concrete endpoint
/// types by forwarding to their [`Endpoint`](crate::Endpoint) implementation.
///
/// It compiles only where the type's `respond` future is `Send`, which the
/// compiler checks for each named type. A generic type writes the impl by
/// hand, calling `respond_send` on its generic parts.
///
/// # Examples
///
/// ```rust
/// use http_kit::{impl_send_endpoint, Body, BoxHttpError, Endpoint, Request, Response};
///
/// struct Hello;
///
/// impl Endpoint for Hello {
///     type Error = BoxHttpError;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
///         Ok(Response::new(Body::from_bytes("Hello")))
///     }
/// }
///
/// impl_send_endpoint!(Hello);
/// ```
#[macro_export]
macro_rules! impl_send_endpoint {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $crate::SendEndpoint for $ty {
                fn respond_send(
                    &mut self,
                    request: &mut $crate::Request,
                ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<
                        $crate::Response,
                        <Self as $crate::Endpoint>::Error,
                    >,
                > + ::core::marker::Send {
                    $crate::Endpoint::respond(self, request)
                }
            }
        )+
    };
}

/// Implements [`SendMiddleware`](crate::SendMiddleware) for concrete
/// middleware types by forwarding to their
/// [`Middleware`](crate::Middleware) implementation, with `next` passed
/// through [`SendNext`](crate::endpoint::SendNext).
///
/// It compiles only where the type's `handle` future is `Send` given a `Send`
/// `next`, which the compiler checks for each named type.
///
/// # Examples
///
/// ```rust
/// use http_kit::{impl_send_middleware, middleware::MiddlewareError, BoxHttpError};
/// use http_kit::{Endpoint, Middleware, Request, Response};
///
/// struct Logging;
///
/// impl Middleware for Logging {
///     type Error = BoxHttpError;
///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
///         println!("{}", request.uri());
///         next.respond(request).await.map_err(MiddlewareError::Endpoint)
///     }
/// }
///
/// impl_send_middleware!(Logging);
/// ```
#[macro_export]
macro_rules! impl_send_middleware {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl $crate::SendMiddleware for $ty {
                fn handle_send<E: $crate::SendEndpoint>(
                    &mut self,
                    request: &mut $crate::Request,
                    next: E,
                ) -> impl ::core::future::Future<
                    Output = ::core::result::Result<
                        $crate::Response,
                        $crate::middleware::MiddlewareError<
                            <E as $crate::Endpoint>::Error,
                            <Self as $crate::Middleware>::Error,
                        >,
                    >,
                > + ::core::marker::Send {
                    $crate::Middleware::handle(
                        self,
                        request,
                        $crate::endpoint::SendNext::new(next),
                    )
                }
            }
        )+
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
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
        assert_eq!(not_found.to_string(), "macro missing");

        let display = MacroDisplayError::new();
        assert_eq!(display.status(), StatusCode::BAD_REQUEST);
        assert_eq!(display.to_string(), "bad request (400)");
    }
}
