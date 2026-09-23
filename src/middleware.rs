//! Middleware functionality for HTTP request and response processing.
//!
//! This module provides the core infrastructure for implementing middleware in the HTTP processing
//! pipeline. Middleware allows you to modify or inspect HTTP requests and responses during processing,
//! enabling functionality like:
//!
//! - Request/response logging
//! - Authentication and authorization
//! - Request timeouts
//! - Response compression
//! - Custom headers
//! - Request/response transformation
//!
//! # Usage
//!
//! Implement the [`Middleware`] trait to create custom middleware:
//!
//! ```rust
//! use http_kit::{Request, Response, Result, Endpoint, middleware::Middleware, BoxHttpError};
//! use http_kit::middleware::MiddlewareError;
//!
//! struct MyMiddleware;
//!
//! impl Middleware for MyMiddleware {
//!     type Error = BoxHttpError;
//!     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
//!         // Pre-processing
//!         let response = next.respond(request).await.map_err(MiddlewareError::Endpoint)?;
//!         // Post-processing
//!         Ok(response)
//!     }
//! }
//! ```
//!
//! The middleware can then be composed with endpoints using [`WithMiddleware`].
//! Multiple middleware can be chained together using tuples like `(Middleware1, Middleware2)`.
use crate::{endpoint::EndpointImpl, error::BoxHttpError, Endpoint, HttpError, Request, Response};
use alloc::boxed::Box;
use core::{
    any::type_name,
    convert::Infallible,
    fmt::{Debug, Display},
    future::Future,
    ops::DerefMut,
    pin::Pin,
};
use http::StatusCode;
/// Trait for implementing middleware that can process HTTP requests and responses.
///
/// Middleware sits between the initial request and the final endpoint, allowing you to
/// implement cross-cutting concerns like authentication, logging, rate limiting, compression,
/// and other request/response transformations.
///
/// Middleware operates in a chain where each middleware can:
/// - Inspect and modify the incoming request
/// - Decide whether to call the next middleware/endpoint in the chain
/// - Inspect and modify the outgoing response
/// - Handle errors and implement fallback behavior
///
/// # Implementation Pattern
///
/// A typical middleware implementation follows this pattern:
/// 1. Pre-process the request (logging, validation, etc.)
/// 2. Call `next.respond(request).await` to continue the chain
/// 3. Post-process the response (add headers, transform body, etc.)
/// 4. Return the final response
///
/// # Examples
///
/// ## Request Logging Middleware
///
/// ```rust
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body, BoxHttpError};
/// use http_kit::middleware::MiddlewareError;
///
/// struct LoggingMiddleware;
///
/// impl Middleware for LoggingMiddleware {
///     type Error = BoxHttpError;
///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
///         println!("Incoming: {} {}", request.method(), request.uri());
///
///         let response = next.respond(request).await.map_err(MiddlewareError::Endpoint)?;
///
///         println!("Outgoing: {}", response.status());
///         Ok(response)
///     }
/// }
/// ```
///
/// ## Authentication Middleware
///
/// ```rust
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, StatusCode, Body, BoxHttpError};
/// use http_kit::middleware::MiddlewareError;
///
/// struct AuthMiddleware {
///     required_token: String,
/// }
///
/// impl Middleware for AuthMiddleware {
///     type Error = BoxHttpError;
///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
///         if let Some(auth_header) = request.headers().get(http::header::AUTHORIZATION) {
///             if auth_header.as_bytes() == self.required_token.as_bytes() {
///                 return next.respond(request).await.map_err(MiddlewareError::Endpoint);
///             }
///         }
///
///         Ok(Response::new(Body::from_bytes("Authentication required")))
///     }
/// }
/// ```
///
/// ## Response Header Middleware
///
/// ```rust
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body, BoxHttpError};
/// use http_kit::middleware::MiddlewareError;
///
/// struct HeaderMiddleware;
///
/// impl Middleware for HeaderMiddleware {
///     type Error = BoxHttpError;
///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
///         let mut response = next.respond(request).await.map_err(MiddlewareError::Endpoint)?;
///
///         response.headers_mut().insert(
///             http::header::SERVER,
///             http::HeaderValue::from_static("http-kit/1.0")
///         );
///
///         Ok(response)
///     }
/// }
/// ```
pub trait Middleware: Send {
    /// The error type that this middleware can produce.
    type Error: HttpError;
    /// Processes a request through the middleware chain.
    ///
    /// This method receives the current request and a `next` parameter representing
    /// the next step in the processing chain (either another middleware or the final endpoint).
    /// The middleware can:
    ///
    /// - Modify the request before passing it to `next`
    /// - Decide whether to call `next` at all (for auth, rate limiting, etc.)
    /// - Transform the response returned by `next`
    /// - Handle errors and provide fallback responses
    ///
    /// # Arguments
    ///
    /// * `request` - Mutable reference to the HTTP request being processed
    /// * `next` - The next step in the processing chain (middleware or endpoint)
    ///
    /// # Returns
    ///
    /// Returns a `Result<Response>` which can either be:
    /// - `Ok(response)` - A successful HTTP response
    /// - `Err(error)` - An error with an associated HTTP status code
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body, BoxHttpError};
    /// use http_kit::middleware::MiddlewareError;
    ///
    /// struct TimingMiddleware;
    ///
    /// impl Middleware for TimingMiddleware {
    ///     type Error = BoxHttpError;
    ///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
    ///         let start = std::time::Instant::now();
    ///
    ///         // Call the next middleware or endpoint
    ///         let response = next.respond(request).await.map_err(MiddlewareError::Endpoint)?;
    ///
    ///         let duration = start.elapsed();
    ///         println!("Request processed in {:?}", duration);
    ///
    ///         Ok(response)
    ///     }
    /// }
    /// ```
    fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        next: E,
    ) -> impl Future<Output = Result<Response, MiddlewareError<E::Error, Self::Error>>> + Send;
}

/// Error type for middleware that can represent errors from either the middleware itself or the endpoint it wraps.
#[derive(Debug)]
pub enum MiddlewareError<N, E> {
    /// Error originating from the endpoint being called.
    Endpoint(N),
    /// Error originating from the middleware itself.
    Middleware(E),
}

impl<N: HttpError, E: HttpError> Display for MiddlewareError<N, E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MiddlewareError::Endpoint(e) => write!(f, "Endpoint error: {}", e),
            MiddlewareError::Middleware(e) => write!(f, "Middleware error: {}", e),
        }
    }
}

impl<N: HttpError, E: HttpError> core::error::Error for MiddlewareError<N, E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MiddlewareError::Endpoint(e) => e.source(),
            MiddlewareError::Middleware(e) => e.source(),
        }
    }
}

impl<N: HttpError, E: HttpError> HttpError for MiddlewareError<N, E> {
    fn status(&self) -> StatusCode {
        match self {
            MiddlewareError::Endpoint(e) => e.status(),
            MiddlewareError::Middleware(e) => e.status(),
        }
    }
}

pub(crate) trait MiddlewareImpl: Send {
    fn handle_inner<'this, 'req, 'next, 'fut>(
        &'this mut self,
        request: &'req mut Request,
        next: &'next mut dyn EndpointImpl,
    ) -> Pin<Box<dyn 'fut + Future<Output = Result<Response, BoxHttpError>> + Send>>
    where
        'this: 'fut,
        'req: 'fut,
        'next: 'fut;
    fn name(&self) -> &'static str {
        type_name::<Self>()
    }
}

impl<'a> Endpoint for &mut (dyn EndpointImpl + 'a) {
    type Error = BoxHttpError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.respond_inner(request).await
    }
}

impl<T: Middleware> MiddlewareImpl for T {
    fn handle_inner<'this, 'req, 'next, 'fut>(
        &'this mut self,
        request: &'req mut Request,
        next: &'next mut dyn EndpointImpl,
    ) -> Pin<Box<dyn 'fut + Future<Output = Result<Response, BoxHttpError>> + Send>>
    where
        'this: 'fut,
        'req: 'fut,
        'next: 'fut,
    {
        Box::pin(async move {
            self.handle(request, next)
                .await
                .map_err(|e| Box::new(e) as BoxHttpError)
        })
    }
}

impl<M: Middleware> Middleware for &mut M {
    type Error = M::Error;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        Middleware::handle(*self, request, next).await
    }
}

impl<M: Middleware> Middleware for Box<M> {
    type Error = M::Error;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        Middleware::handle(self.deref_mut(), request, next).await
    }
}

/// Error type for middleware tuples, representing errors from either middleware.
#[derive(Debug)]
pub enum MiddlewareTupleError<E1: HttpError, E2: HttpError> {
    /// Error from the first middleware in the tuple.
    First(E1),
    /// Error from the second middleware in the tuple.
    Second(E2),
}

impl<A, B> Display for MiddlewareTupleError<A, B>
where
    A: HttpError,
    B: HttpError,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MiddlewareTupleError::First(e) => write!(f, "First middleware error: {}", e),
            MiddlewareTupleError::Second(e) => write!(f, "Second middleware error: {}", e),
        }
    }
}

impl<A, B> core::error::Error for MiddlewareTupleError<A, B>
where
    A: HttpError,
    B: HttpError,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            MiddlewareTupleError::First(e) => e.source(),
            MiddlewareTupleError::Second(e) => e.source(),
        }
    }
}

impl<A, B> HttpError for MiddlewareTupleError<A, B>
where
    A: HttpError,
    B: HttpError,
{
    fn status(&self) -> StatusCode {
        match self {
            MiddlewareTupleError::First(e) => e.status(),
            MiddlewareTupleError::Second(e) => e.status(),
        }
    }
}

/// Type-erased middleware that can hold any middleware implementation behind a trait object.
///
/// `AnyMiddleware` provides dynamic dispatch for middleware, allowing you to store
/// different middleware types in the same collection or pass them around without
/// knowing their concrete types at compile time. This is particularly useful for:
///
/// - Building flexible middleware chains with different middleware types
/// - Plugin systems where middleware is loaded dynamically
/// - Configuration-driven middleware stacks
/// - Storing middleware in collections or registries
pub struct AnyMiddleware(Box<dyn MiddlewareImpl>);

impl Debug for AnyMiddleware {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("AnyMiddleware[{}]", self.name()))
    }
}

impl AnyMiddleware {
    /// Creates a new type-erased middleware wrapper around the given middleware implementation.
    ///
    /// This method takes any type that implements `Middleware` and wraps it in an
    /// `AnyMiddleware` that can be stored alongside other middleware of different types.
    /// The original middleware type information is erased, but the functionality is preserved.
    ///
    /// # Arguments
    ///
    /// * `middleware` - Any middleware implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Middleware, Endpoint, middleware::AnyMiddleware, Body, BoxHttpError};
    /// use http_kit::middleware::MiddlewareError;
    ///
    /// struct CustomMiddleware {
    ///     prefix: String,
    /// }
    ///
    /// impl Middleware for CustomMiddleware {
    ///     type Error = BoxHttpError;
    ///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
    ///         println!("{}: Processing {}", self.prefix, request.uri());
    ///         next.respond(request).await.map_err(MiddlewareError::Endpoint)
    ///     }
    /// }
    ///
    /// let middleware = CustomMiddleware { prefix: "API".to_string() };
    /// let any_middleware = AnyMiddleware::new(middleware);
    /// ```
    pub fn new(middleware: impl Middleware + 'static) -> Self {
        AnyMiddleware(Box::new(middleware))
    }

    /// Returns the type name of the underlying middleware implementation.
    ///
    /// This method provides introspection capabilities for debugging, logging,
    /// or monitoring purposes. The returned string is the fully qualified type name
    /// of the original middleware type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Middleware, Endpoint, middleware::AnyMiddleware, Body, BoxHttpError};
    /// use http_kit::middleware::MiddlewareError;
    ///
    /// struct MyMiddleware;
    /// impl Middleware for MyMiddleware {
    ///     type Error = BoxHttpError;
    ///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
    ///         next.respond(request).await.map_err(MiddlewareError::Endpoint)
    ///     }
    /// }
    ///
    /// let any_middleware = AnyMiddleware::new(MyMiddleware);
    /// println!("Middleware type: {}", any_middleware.name());
    /// // Output: Middleware type: my_crate::MyMiddleware
    /// ```
    pub fn name(&self) -> &'static str {
        self.0.name()
    }
}

impl Middleware for AnyMiddleware {
    type Error = BoxHttpError;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        self.0
            .handle_inner(request, &mut next)
            .await
            .map_err(MiddlewareError::<E::Error, _>::Middleware)
    }
}

/// No-op middleware implementation for the unit type.
///
/// This implementation allows `()` to be used as a middleware that does nothing
/// but pass the request through to the next handler. This is useful for:
/// - Default values in generic contexts
/// - Conditional middleware application
/// - Testing scenarios where middleware is optional
impl Middleware for () {
    type Error = Infallible;
    async fn handle<E: Endpoint>(
        &mut self,
        request: &mut Request,
        mut next: E,
    ) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
        next.respond(request)
            .await
            .map_err(MiddlewareError::<_, Self::Error>::Endpoint)
    }
}
