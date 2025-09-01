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
//! use http_kit::{Request, Response, Result, Endpoint, middleware::Middleware};
//!
//! struct MyMiddleware;
//!
//! impl Middleware for MyMiddleware {
//!     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
//!         // Pre-processing
//!         let response = next.respond(request).await?;
//!         // Post-processing
//!         Ok(response)
//!     }
//! }
//! ```
//!
//! The middleware can then be composed with endpoints using [`WithMiddleware`].
//! Multiple middleware can be chained together using tuples like `(Middleware1, Middleware2)`.
use crate::{
    endpoint::{EndpointImpl, WithMiddleware},
    Endpoint, Request, Response, Result,
};
use alloc::boxed::Box;
use core::{any::type_name, fmt::Debug, future::Future, ops::DerefMut, pin::Pin};
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
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body};
///
/// struct LoggingMiddleware;
///
/// impl Middleware for LoggingMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         println!("Incoming: {} {}", request.method(), request.uri());
///
///         let response = next.respond(request).await?;
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
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, StatusCode, Body};
///
/// struct AuthMiddleware {
///     required_token: String,
/// }
///
/// impl Middleware for AuthMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         if let Some(auth_header) = request.headers().get(http::header::AUTHORIZATION) {
///             if auth_header.as_bytes() == self.required_token.as_bytes() {
///                 return next.respond(request).await;
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
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body};
///
/// struct HeaderMiddleware;
///
/// impl Middleware for HeaderMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         let mut response = next.respond(request).await?;
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
pub trait Middleware: Send + Sync {
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
    /// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body};
    ///
    /// struct TimingMiddleware;
    ///
    /// impl Middleware for TimingMiddleware {
    ///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
    ///         let start = std::time::Instant::now();
    ///
    ///         // Call the next middleware or endpoint
    ///         let response = next.respond(request).await?;
    ///
    ///         let duration = start.elapsed();
    ///         println!("Request processed in {:?}", duration);
    ///
    ///         Ok(response)
    ///     }
    /// }
    /// ```
    fn handle(
        &mut self,
        request: &mut Request,
        next: impl Endpoint,
    ) -> impl Future<Output = Result<Response>> + Send + Sync;
}

pub(crate) trait MiddlewareImpl: Send + Sync {
    fn handle_inner<'this, 'req, 'next, 'fut>(
        &'this mut self,
        request: &'req mut Request,
        next: &'next dyn EndpointImpl,
    ) -> Pin<Box<dyn 'fut + Future<Output = Result<Response>> + Send + Sync>>
    where
        'this: 'fut,
        'req: 'fut,
        'next: 'fut;
    fn name(&self) -> &'static str {
        type_name::<Self>()
    }
}

impl Endpoint for &dyn EndpointImpl {
    async fn respond(&mut self, request: &mut Request) -> Result<Response> {
        self.respond_inner(request).await
    }
}

impl<T: Middleware> MiddlewareImpl for T {
    fn handle_inner<'this, 'req, 'next, 'fut>(
        &'this mut self,
        request: &'req mut Request,
        next: &'next dyn EndpointImpl,
    ) -> Pin<Box<dyn 'fut + Future<Output = Result<Response>> + Send + Sync>>
    where
        'this: 'fut,
        'req: 'fut,
        'next: 'fut,
    {
        Box::pin(self.handle(request, next))
    }
}

impl<M: Middleware> Middleware for &mut M {
    async fn handle(&mut self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        Middleware::handle(*self, request, next).await
    }
}

impl<M: Middleware> Middleware for Box<M> {
    async fn handle(&mut self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        Middleware::handle(self.deref_mut(), request, next).await
    }
}

/// Middleware implementation for tuples of two middleware types.
///
/// This allows you to combine two middleware into a single unit where the first
/// middleware wraps the second middleware, which in turn wraps the endpoint.
/// The execution order is: `self.0` → `self.1` → endpoint.
///
/// # Examples
///
/// ```rust
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, Body};
///
/// struct LoggingMiddleware;
/// impl Middleware for LoggingMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         println!("Before request");
///         let response = next.respond(request).await;
///         println!("After request");
///         response
///     }
/// }
///
/// struct TimingMiddleware;
/// impl Middleware for TimingMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         let start = std::time::Instant::now();
///         let response = next.respond(request).await;
///         println!("Elapsed: {:?}", start.elapsed());
///         response
///     }
/// }
///
/// // Combine middleware using tuple syntax
/// let combined = (LoggingMiddleware, TimingMiddleware);
/// // Execution order: LoggingMiddleware → TimingMiddleware → endpoint
/// ```
impl<T1: Middleware, T2: Middleware> Middleware for (T1, T2) {
    async fn handle(&mut self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        self.0
            .handle(request, WithMiddleware::new(next, &mut self.1))
            .await
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
///
/// # Performance Considerations
///
/// Using `AnyMiddleware` involves dynamic dispatch and heap allocation, which has
/// a small performance overhead compared to using concrete types directly. However,
/// this overhead is typically negligible in HTTP server contexts where network I/O
/// dominates performance characteristics.
///
/// # Examples
///
/// ## Storing Mixed Middleware Types
///
/// ```rust
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, middleware::AnyMiddleware, Body};
///
/// struct LoggingMiddleware;
/// impl Middleware for LoggingMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         println!("Request: {}", request.uri());
///         next.respond(request).await
///     }
/// }
///
/// struct TimingMiddleware;
/// impl Middleware for TimingMiddleware {
///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
///         let start = std::time::Instant::now();
///         let response = next.respond(request).await;
///         println!("Duration: {:?}", start.elapsed());
///         response
///     }
/// }
///
/// // Store different middleware types in a collection
/// let middleware_stack: Vec<AnyMiddleware> = vec![
///     AnyMiddleware::new(LoggingMiddleware),
///     AnyMiddleware::new(TimingMiddleware),
/// ];
/// ```
///
/// ## Dynamic Middleware Configuration
///
/// ```rust
/// use http_kit::{Request, Response, Result, Middleware, Endpoint, middleware::AnyMiddleware, Body};
///
/// fn create_middleware(name: &str) -> Option<AnyMiddleware> {
///     match name {
///         "logging" => Some(AnyMiddleware::new(LoggingMiddleware)),
///         "timing" => Some(AnyMiddleware::new(TimingMiddleware)),
///         _ => None,
///     }
/// }
///
/// # struct LoggingMiddleware;
/// # impl Middleware for LoggingMiddleware {
/// #     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
/// #         next.respond(request).await
/// #     }
/// # }
/// # struct TimingMiddleware;
/// # impl Middleware for TimingMiddleware {
/// #     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
/// #         next.respond(request).await
/// #     }
/// # }
/// ```
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
    /// use http_kit::{Request, Response, Result, Middleware, Endpoint, middleware::AnyMiddleware, Body};
    ///
    /// struct CustomMiddleware {
    ///     prefix: String,
    /// }
    ///
    /// impl Middleware for CustomMiddleware {
    ///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
    ///         println!("{}: Processing {}", self.prefix, request.uri());
    ///         next.respond(request).await
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
    /// use http_kit::{Request, Response, Result, Middleware, Endpoint, middleware::AnyMiddleware, Body};
    ///
    /// struct MyMiddleware;
    /// impl Middleware for MyMiddleware {
    ///     async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
    ///         next.respond(request).await
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
    async fn handle(&mut self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        self.0.handle_inner(request, &next).await
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
    async fn handle(&mut self, request: &mut Request, mut next: impl Endpoint) -> Result<Response> {
        next.respond(request).await
    }
}
