//! HTTP endpoint abstraction for request handling.
//!
//! This module provides the core [`Endpoint`] trait and supporting types for building
//! HTTP request handlers. Endpoints represent the final destination for HTTP requests
//! and are responsible for generating appropriate responses.
//!
//! # Core Concepts
//!
//! - **Endpoint**: A trait for types that can handle HTTP requests and produce responses
//! - **Middleware Integration**: Endpoints can be combined with middleware for cross-cutting concerns
//! - **Type Erasure**: Support for dynamic dispatch through [`AnyEndpoint`]
//! - **Composition**: Endpoints can be wrapped and combined in various ways
//!
//! # Examples
//!
//! ## Basic Endpoint Implementation
//!
//! ```rust
//! use http_kit::{Request, Response, Endpoint, Body};
//! use core::convert::Infallible;
//!
//! struct HelloEndpoint;
//!
//! impl Endpoint for HelloEndpoint {
//!     type Error = Infallible;
//!     async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
//!         Ok(Response::new(Body::from_bytes("Hello, World!")))
//!     }
//! }
//! ```
//!
//! ## Endpoint with Request Processing
//!
//! ```rust
//! use http_kit::{Request, Response, Result, Endpoint, Body, Error};
//!
//! struct EchoEndpoint;
//!
//! impl Endpoint for EchoEndpoint {
//!     type Error = Error;
//!     async fn respond(&mut self, request: &mut Request) -> Result<Response> {
//!         let body = std::mem::replace(request.body_mut(), Body::empty());
//!         Ok(Response::new(body))
//!     }
//! }
//! ```
//!
//! ## Using with Middleware
//!
//! ```rust
//! use http_kit::{Request, Response, Result, Endpoint, Middleware, endpoint::WithMiddleware, Body, Error};
//! use http_kit::middleware::MiddlewareError;
//!
//! struct LoggingMiddleware;
//!
//! impl Middleware for LoggingMiddleware {
//!     type Error = Error;
//!     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
//!         println!("Processing request to {}", request.uri());
//!         next.respond(request).await.map_err(MiddlewareError::Endpoint)
//!     }
//! }
//!
//! struct MyEndpoint;
//! impl Endpoint for MyEndpoint {
//!     type Error = Error;
//!     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
//!         Ok(Response::new(Body::from_bytes("OK")))
//!     }
//! }
//!
//! let endpoint_with_logging = WithMiddleware::new(MyEndpoint, LoggingMiddleware);
//! ```

use core::{any::type_name, fmt::Debug, future::Future, ops::DerefMut, pin::Pin};

use alloc::boxed::Box;

use crate::{
    error::BoxHttpError, middleware::MiddlewareError, HttpError, Middleware, Request, Response,
};

/// A trait for types that can handle HTTP requests and generate responses.
///
/// Endpoints represent the final destination in the HTTP request processing pipeline.
/// They receive a mutable reference to the request (allowing them to consume the body
/// or modify headers) and return a response or error.
///
/// # Implementation Notes
///
/// - Endpoints must be `Send` to work in async contexts
/// - The request parameter is mutable, allowing body consumption and header modification
/// - Implementations should handle errors gracefully and return appropriate HTTP status codes
/// - Endpoints can be combined with middleware for additional functionality
///
/// # Examples
///
/// ## Simple Text Response
///
/// ```rust
/// use http_kit::{Request, Response, Result, Endpoint, Body, Error};
///
/// struct GreetingEndpoint {
///     name: String,
/// }
///
/// impl Endpoint for GreetingEndpoint {
///     type Error = Error;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
///         let message = format!("Hello, {}!", self.name);
///         Ok(Response::new(Body::from_bytes(message)))
///     }
/// }
/// ```
///
/// ## JSON API Endpoint
///
/// ```rust
/// # #[cfg(feature = "json")]
/// # {
/// use http::StatusCode;
/// use http_kit::{Request, Response, Result, Endpoint, Body, HttpError, BodyError};
/// use serde::{Serialize, Deserialize};
/// use thiserror::Error;
///
/// #[derive(Debug, Error)]
/// enum ApiError {
///     #[error("json error: {0}")]
///     Json(#[from] serde_json::Error),
///     #[error("body error: {0}")]
///     Body(#[from] BodyError),
/// }
///
/// impl HttpError for ApiError {
///     fn status(&self) -> StatusCode {
///         match self {
///             Self::Json(_) => StatusCode::BAD_REQUEST,
///             Self::Body(_) => StatusCode::INTERNAL_SERVER_ERROR,
///         }
///     }
/// }
///
/// #[derive(Serialize, Deserialize)]
/// struct User { name: String, age: u32 }
///
/// struct UserEndpoint;
///
/// impl Endpoint for UserEndpoint {
///     type Error = ApiError;
///     async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
///         match request.method().as_str() {
///             "GET" => {
///                 let user = User { name: "Alice".into(), age: 30 };
///                 let body = Body::from_json(&user)?;
///                 Ok(Response::new(body))
///             }
///             "POST" => {
///                 let user: User = request
///                     .body_mut()
///                     .into_json()
///                     .await?;
///                 // Process user...
///                 let body = Body::from_json(&user)?;
///                 Ok(Response::new(body))
///             }
///             _ => Ok(Response::new(Body::from_bytes("Method Not Allowed")))
///         }
///     }
/// }
/// # }
/// ```
pub trait Endpoint: Send {
    /// The error type returned by this endpoint.
    type Error: HttpError;
    /// Processes an HTTP request and generates a response.
    ///
    /// This method receives a mutable reference to the request, allowing it to:
    /// - Consume the request body with `take_body()` or similar methods
    /// - Read headers, URI, method, and other request metadata
    /// - Modify request state if needed (though this is less common)
    ///
    /// The method should return either a successful `Response` or an `Error`
    /// with an appropriate HTTP status code.
    ///
    /// # Arguments
    ///
    /// * `request` - Mutable reference to the HTTP request being processed
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Endpoint, Body, Error};
    ///
    /// struct StatusEndpoint;
    ///
    /// impl Endpoint for StatusEndpoint {
    ///     type Error = Error;
    ///     async fn respond(&mut self, request: &mut Request) -> Result<Response> {
    ///         let status = format!("Method: {}, URI: {}", request.method(), request.uri());
    ///         Ok(Response::new(Body::from_bytes(status)))
    ///     }
    /// }
    /// ```
    fn respond(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

impl<E: Endpoint> Endpoint for &mut E {
    type Error = E::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        Endpoint::respond(*self, request).await
    }
}

impl<E: Endpoint> Endpoint for Box<E> {
    type Error = E::Error;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        Endpoint::respond(self.deref_mut(), request).await
    }
}

/// A wrapper that combines an endpoint with middleware.
///
/// `WithMiddleware` allows you to compose an endpoint with middleware to add
/// cross-cutting concerns like logging, authentication, rate limiting, etc.
/// The middleware is executed first and can decide whether to call the endpoint
/// and how to process the response.
///
/// # Type Parameters
///
/// * `E` - The endpoint type that implements `Endpoint`
/// * `M` - The middleware type that implements `Middleware`
///
/// # Examples
///
/// ```rust
/// use http_kit::{Request, Response, Result, Endpoint, Middleware, endpoint::WithMiddleware, Body, Error};
/// use http_kit::middleware::MiddlewareError;
///
/// struct TimingMiddleware;
/// impl Middleware for TimingMiddleware {
///     type Error = Error;
///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
///         let start = std::time::Instant::now();
///         let response = next.respond(request).await;
///         let duration = start.elapsed();
///         println!("Request took {:?}", duration);
///         response.map_err(MiddlewareError::Endpoint)
///     }
/// }
///
/// struct HelloEndpoint;
/// impl Endpoint for HelloEndpoint {
///     type Error = Error;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
///         Ok(Response::new(Body::from_bytes("Hello")))
///     }
/// }
///
/// let timed_endpoint = WithMiddleware::new(HelloEndpoint, TimingMiddleware);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithMiddleware<E: Endpoint, M: Middleware> {
    endpoint: E,
    middleware: M,
}

impl<E: Endpoint, M: Middleware> WithMiddleware<E, M> {
    /// Creates a new endpoint that wraps the given endpoint with middleware.
    ///
    /// When the resulting endpoint handles a request, the middleware will be
    /// executed first. The middleware can then decide whether to call the
    /// wrapped endpoint and how to process its response.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - The endpoint to wrap
    /// * `middleware` - The middleware to apply
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Endpoint, Middleware, endpoint::WithMiddleware, Body, Error};
    /// use http_kit::middleware::MiddlewareError;
    ///
    /// struct AuthMiddleware { token: String }
    /// impl Middleware for AuthMiddleware {
    ///     type Error = Error;
    ///     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
    ///         if let Some(auth) = request.headers().get(http::header::AUTHORIZATION) {
    ///             if auth.as_bytes() == self.token.as_bytes() {
    ///                 return next.respond(request).await.map_err(MiddlewareError::Endpoint);
    ///             }
    ///         }
    ///         Ok(Response::new(Body::from_bytes("Unauthorized")))
    ///     }
    /// }
    ///
    /// struct SecretEndpoint;
    /// impl Endpoint for SecretEndpoint {
    ///     type Error = Error;
    ///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
    ///         Ok(Response::new(Body::from_bytes("Secret data")))
    ///     }
    /// }
    ///
    /// let auth_middleware = AuthMiddleware { token: "secret".to_string() };
    /// let protected_endpoint = WithMiddleware::new(SecretEndpoint, auth_middleware);
    /// ```
    pub fn new(endpoint: E, middleware: M) -> Self {
        Self {
            endpoint,
            middleware,
        }
    }
}

impl<E: Endpoint, M: Middleware> Endpoint for WithMiddleware<E, M> {
    type Error = MiddlewareError<E::Error, M::Error>;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.middleware.handle(request, &mut self.endpoint).await
    }
}

pub(crate) trait EndpointImpl: Send {
    fn respond_inner<'this, 'req, 'fut>(
        &'this mut self,
        request: &'req mut Request,
    ) -> Pin<Box<dyn 'fut + Send + Future<Output = Result<Response, BoxHttpError>>>>
    where
        'this: 'fut,
        'req: 'fut;
    fn name(&self) -> &'static str {
        type_name::<Self>()
    }
}

/// Type-erased endpoint that can hold any endpoint implementation behind a trait object.
///
/// `AnyEndpoint` provides dynamic dispatch for endpoints, allowing you to store
/// different endpoint types in the same collection or pass them around without
/// knowing their concrete types at compile time. This is useful for building
/// flexible routing systems or plugin architectures.
///
/// # Performance Notes
///
/// Using `AnyEndpoint` involves dynamic dispatch and heap allocation, which has
/// a small performance overhead compared to using concrete types directly.
/// However, this is often negligible in HTTP server contexts.
///
/// # Examples
///
/// ```rust
/// use http_kit::{Request, Response, Result, Endpoint, endpoint::AnyEndpoint, Body, Error};
///
/// struct HelloEndpoint;
/// impl Endpoint for HelloEndpoint {
///     type Error = Error;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
///         Ok(Response::new(Body::from_bytes("Hello")))
///     }
/// }
///
/// struct GoodbyeEndpoint;
/// impl Endpoint for GoodbyeEndpoint {
///     type Error = Error;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
///         Ok(Response::new(Body::from_bytes("Goodbye")))
///     }
/// }
///
/// // Store different endpoint types in a collection
/// let endpoints: Vec<AnyEndpoint> = vec![
///     AnyEndpoint::new(HelloEndpoint),
///     AnyEndpoint::new(GoodbyeEndpoint),
/// ];
/// ```
pub struct AnyEndpoint(Box<dyn EndpointImpl>);

impl Debug for AnyEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("AnyEndpoint[{}]", self.name()))
    }
}

impl AnyEndpoint {
    /// Creates a new type-erased endpoint wrapper around the given endpoint implementation.
    ///
    /// This method takes any type that implements `Endpoint` and wraps it in a
    /// `AnyEndpoint` that can be stored alongside other endpoints of different types.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - Any endpoint implementation
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Endpoint, endpoint::AnyEndpoint, Body, Error};
    ///
    /// struct MyEndpoint {
    ///     message: String,
    /// }
    ///
    /// impl Endpoint for MyEndpoint {
    ///     type Error = Error;
    ///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
    ///         Ok(Response::new(Body::from_bytes(self.message.clone())))
    ///     }
    /// }
    ///
    /// let endpoint = MyEndpoint { message: "Hello!".to_string() };
    /// let any_endpoint = AnyEndpoint::new(endpoint);
    /// ```
    pub fn new(endpoint: impl Endpoint + 'static) -> Self {
        Self(Box::new(endpoint))
    }

    /// Returns the type name of the underlying endpoint implementation.
    ///
    /// This can be useful for debugging, logging, or introspection purposes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Result, Endpoint, endpoint::AnyEndpoint, Body, Error};
    ///
    /// struct MyEndpoint;
    /// impl Endpoint for MyEndpoint {
    ///     type Error = Error;
    ///     async fn respond(&mut self, _request: &mut Request) -> Result<Response> {
    ///         Ok(Response::new(Body::from_bytes("OK")))
    ///     }
    /// }
    ///
    /// let any_endpoint = AnyEndpoint::new(MyEndpoint);
    /// println!("Endpoint type: {}", any_endpoint.name());
    /// ```
    pub fn name(&self) -> &'static str {
        self.0.name()
    }
}

impl<E: Endpoint> EndpointImpl for E {
    fn respond_inner<'this, 'req, 'fut>(
        &'this mut self,
        request: &'req mut Request,
    ) -> Pin<Box<dyn 'fut + Send + Future<Output = Result<Response, BoxHttpError>>>>
    where
        'this: 'fut,
        'req: 'fut,
    {
        Box::pin(async move {
            Endpoint::respond(self, request)
                .await
                .map_err(|e| Box::new(e) as BoxHttpError)
        })
    }
}

impl Endpoint for AnyEndpoint {
    type Error = BoxHttpError;
    /// Processes an HTTP request using the underlying endpoint implementation.
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.0.respond_inner(request).await
    }
}
