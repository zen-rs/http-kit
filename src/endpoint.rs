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
//! - **Type Erasure**: Support for dynamic dispatch through [`AnyEndpoint`] and [`AnySendEndpoint`]
//! - **Composition**: Endpoints can be wrapped and combined in various ways
//!
//! # Threads
//!
//! [`Endpoint`] requires nothing to be `Send`: an endpoint may hold an `Rc` or
//! a per-thread pool and serve a thread-per-core runtime. A concrete endpoint
//! built from `Send` parts has a `Send` future all the same, so it still goes
//! to `tokio::spawn`. Generic code cannot see that, so code that moves an
//! endpoint's future across threads without knowing its type bounds on
//! [`SendEndpoint`] instead.
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
//! use http_kit::{Request, Response, Endpoint, Body, BoxHttpError};
//!
//! struct EchoEndpoint;
//!
//! impl Endpoint for EchoEndpoint {
//!     type Error = BoxHttpError;
//!     async fn respond(&mut self, request: &mut Request) -> Result<Response,Self::Error> {
//!         let body = std::mem::replace(request.body_mut(), Body::empty());
//!         Ok(Response::new(body))
//!     }
//! }
//! ```
//!
//! ## Using with Middleware
//!
//! ```rust
//! use http_kit::{Request, Response, Endpoint, Middleware, endpoint::WithMiddleware, Body, BoxHttpError};
//! use http_kit::middleware::MiddlewareError;
//!
//! struct LoggingMiddleware;
//!
//! impl Middleware for LoggingMiddleware {
//!     type Error = BoxHttpError;
//!     async fn handle<E: Endpoint>(&mut self, request: &mut Request, mut next: E) -> Result<Response, MiddlewareError<E::Error, Self::Error>> {
//!         println!("Processing request to {}", request.uri());
//!         next.respond(request).await.map_err(MiddlewareError::Endpoint)
//!     }
//! }
//!
//! struct MyEndpoint;
//! impl Endpoint for MyEndpoint {
//!     type Error = BoxHttpError;
//!     async fn respond(&mut self, _request: &mut Request) -> Result<Response,Self::Error> {
//!         Ok(Response::new(Body::from_bytes("OK")))
//!     }
//! }
//!
//! let endpoint_with_logging = WithMiddleware::new(MyEndpoint, LoggingMiddleware);
//! ```

use core::{any::type_name, fmt::Debug, future::Future, ops::DerefMut, pin::Pin};

use alloc::boxed::Box;

use crate::{
    error::BoxHttpError,
    flavor::{Flavor, Shared},
    middleware::{MiddlewareError, SendMiddleware},
    HttpError, Middleware, Request, Response,
};

/// A trait for types that can handle HTTP requests and generate responses.
///
/// Endpoints represent the final destination in the HTTP request processing pipeline.
/// They receive a mutable reference to the request (allowing them to consume the body
/// or modify headers) and return a response or error.
///
/// `F` is the [flavour](crate::flavor) of the request and response bodies:
/// [`Shared`] unless stated. An endpoint that does not care implements the
/// trait for every `F`.
///
/// # Implementation Notes
///
/// - Neither the endpoint nor its future has to be `Send`; both are `Send`
///   when what they hold is. See [`SendEndpoint`] for generic code that needs it.
/// - The request parameter is mutable, allowing body consumption and header modification
/// - Implementations should handle errors gracefully and return appropriate HTTP status codes
/// - Endpoints can be combined with middleware for additional functionality
///
/// # Examples
///
/// ## Simple Text Response
///
/// ```rust
/// use http_kit::{Request, Response, Endpoint, Body, BoxHttpError};
///
/// struct GreetingEndpoint {
///     name: String,
/// }
///
/// impl Endpoint for GreetingEndpoint {
///     type Error = BoxHttpError;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
///         let message = format!("Hello, {}!", self.name);
///         Ok(Response::new(Body::from_bytes(message)))
///     }
/// }
/// ```
///
/// ## Per-thread State
///
/// ```rust
/// use std::{cell::Cell, rc::Rc};
/// use http_kit::{flavor::Local, Endpoint, LocalBody, LocalRequest, LocalResponse};
/// use core::convert::Infallible;
///
/// struct Counter(Rc<Cell<u64>>);
///
/// impl Endpoint<Local> for Counter {
///     type Error = Infallible;
///     async fn respond(&mut self, _request: &mut LocalRequest) -> Result<LocalResponse, Self::Error> {
///         self.0.set(self.0.get() + 1);
///         Ok(LocalResponse::new(LocalBody::from_text(self.0.get().to_string())))
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
pub trait Endpoint<F: Flavor = Shared> {
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
    /// use http_kit::{Request, Response, Endpoint, Body, BoxHttpError};
    ///
    /// struct StatusEndpoint;
    ///
    /// impl Endpoint for StatusEndpoint {
    ///     type Error = BoxHttpError;
    ///     async fn respond(&mut self, request: &mut Request) -> Result<Response,Self::Error> {
    ///         let status = format!("Method: {}, URI: {}", request.method(), request.uri());
    ///         Ok(Response::new(Body::from_bytes(status)))
    ///     }
    /// }
    /// ```
    fn respond(
        &mut self,
        request: &mut Request<F>,
    ) -> impl Future<Output = Result<Response<F>, Self::Error>>;
}

/// An [`Endpoint`] whose future is `Send`, for generic code that moves it
/// across threads.
///
/// A concrete endpoint's future is `Send` whenever what it holds is, and
/// code that knows the type sees that without this trait. Code generic over
/// the endpoint cannot, so it bounds on `SendEndpoint` and calls
/// [`respond_send`](Self::respond_send). For a concrete type the
/// implementation forwards to [`Endpoint::respond`], which
/// [`impl_send_endpoint!`](crate::impl_send_endpoint) writes for you:
///
/// ```rust
/// use core::future::Future;
/// use http_kit::{Body, BoxHttpError, Endpoint, Request, Response, SendEndpoint};
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
/// impl SendEndpoint for Hello {
///     fn respond_send(
///         &mut self,
///         request: &mut Request,
///     ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
///         self.respond(request)
///     }
/// }
///
/// fn serve<E: SendEndpoint + 'static>(mut endpoint: E) {
///     let task = async move {
///         let mut request = Request::new(Body::empty());
///         endpoint.respond_send(&mut request).await
///     };
///     # fn assert_send(_: impl Send) {}
///     assert_send(task); // fit for a work-stealing executor
/// }
///
/// serve(Hello);
/// ```
pub trait SendEndpoint: Endpoint + Send {
    /// Processes a request like [`Endpoint::respond`], with a `Send` future.
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send;
}

impl<F: Flavor, E: Endpoint<F>> Endpoint<F> for &mut E {
    type Error = E::Error;
    fn respond(
        &mut self,
        request: &mut Request<F>,
    ) -> impl Future<Output = Result<Response<F>, Self::Error>> {
        Endpoint::respond(*self, request)
    }
}

impl<E: SendEndpoint> SendEndpoint for &mut E {
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        SendEndpoint::respond_send(*self, request)
    }
}

impl<F: Flavor, E: Endpoint<F>> Endpoint<F> for Box<E> {
    type Error = E::Error;
    fn respond(
        &mut self,
        request: &mut Request<F>,
    ) -> impl Future<Output = Result<Response<F>, Self::Error>> {
        Endpoint::respond(self.deref_mut(), request)
    }
}

impl<E: SendEndpoint> SendEndpoint for Box<E> {
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        SendEndpoint::respond_send(self.deref_mut(), request)
    }
}

/// A [`SendEndpoint`] seen as an [`Endpoint`] whose `respond` is
/// [`respond_send`](SendEndpoint::respond_send).
///
/// It is how a concrete middleware implements
/// [`SendMiddleware`]: it passes its `next` through `SendNext` to its own
/// [`Middleware::handle`], whose future then holds only `Send` parts.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SendNext<E>(E);

impl<E> SendNext<E> {
    /// Wraps `endpoint`.
    pub const fn new(endpoint: E) -> Self {
        Self(endpoint)
    }

    /// Returns the wrapped endpoint.
    pub fn into_inner(self) -> E {
        self.0
    }
}

impl<E: SendEndpoint> Endpoint for SendNext<E> {
    type Error = E::Error;
    fn respond(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> {
        self.0.respond_send(request)
    }
}

impl<E: SendEndpoint> SendEndpoint for SendNext<E> {
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        self.0.respond_send(request)
    }
}

/// A wrapper that combines an endpoint with middleware.
///
/// `WithMiddleware` allows you to compose an endpoint with middleware to add
/// cross-cutting concerns like logging, authentication, rate limiting, etc.
/// The middleware is executed first and can decide whether to call the endpoint
/// and how to process the response.
///
/// It is an [`Endpoint`] of whatever flavour both parts serve, and a
/// [`SendEndpoint`] when the endpoint is one and the middleware is a
/// [`SendMiddleware`].
///
/// # Type Parameters
///
/// * `E` - The endpoint type that implements `Endpoint`
/// * `M` - The middleware type that implements `Middleware`
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WithMiddleware<E, M> {
    endpoint: E,
    middleware: M,
}

impl<E, M> WithMiddleware<E, M> {
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
    pub const fn new(endpoint: E, middleware: M) -> Self {
        Self {
            endpoint,
            middleware,
        }
    }

    /// The wrapped endpoint.
    pub const fn endpoint(&self) -> &E {
        &self.endpoint
    }

    /// The middleware applied to the endpoint.
    pub const fn middleware(&self) -> &M {
        &self.middleware
    }
}

impl<F: Flavor, E: Endpoint<F>, M: Middleware<F>> Endpoint<F> for WithMiddleware<E, M> {
    type Error = MiddlewareError<E::Error, M::Error>;
    fn respond(
        &mut self,
        request: &mut Request<F>,
    ) -> impl Future<Output = Result<Response<F>, Self::Error>> {
        self.middleware.handle(request, &mut self.endpoint)
    }
}

impl<E: SendEndpoint, M: SendMiddleware> SendEndpoint for WithMiddleware<E, M> {
    fn respond_send(
        &mut self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
        self.middleware.handle_send(request, &mut self.endpoint)
    }
}

type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;
type SendBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(crate) trait EndpointImpl<F: Flavor> {
    fn respond_inner<'a>(
        &'a mut self,
        request: &'a mut Request<F>,
    ) -> LocalBoxFuture<'a, Result<Response<F>, BoxHttpError>>;
    fn name(&self) -> &'static str;
}

impl<F: Flavor, E: Endpoint<F>> EndpointImpl<F> for E {
    fn respond_inner<'a>(
        &'a mut self,
        request: &'a mut Request<F>,
    ) -> LocalBoxFuture<'a, Result<Response<F>, BoxHttpError>> {
        Box::pin(async move {
            Endpoint::respond(self, request)
                .await
                .map_err(|e| Box::new(e) as BoxHttpError)
        })
    }
    fn name(&self) -> &'static str {
        type_name::<E>()
    }
}

pub(crate) trait SendEndpointImpl: Send {
    fn respond_inner<'a>(
        &'a mut self,
        request: &'a mut Request,
    ) -> SendBoxFuture<'a, Result<Response, BoxHttpError>>;
    fn name(&self) -> &'static str;
}

impl<E: SendEndpoint> SendEndpointImpl for E {
    fn respond_inner<'a>(
        &'a mut self,
        request: &'a mut Request,
    ) -> SendBoxFuture<'a, Result<Response, BoxHttpError>> {
        Box::pin(async move {
            self.respond_send(request)
                .await
                .map_err(|e| Box::new(e) as BoxHttpError)
        })
    }
    fn name(&self) -> &'static str {
        type_name::<E>()
    }
}

impl<'a, F: Flavor> Endpoint<F> for &mut (dyn EndpointImpl<F> + 'a) {
    type Error = BoxHttpError;
    async fn respond(&mut self, request: &mut Request<F>) -> Result<Response<F>, Self::Error> {
        EndpointImpl::respond_inner(&mut **self, request).await
    }
}

impl<'a> Endpoint for &mut (dyn SendEndpointImpl + 'a) {
    type Error = BoxHttpError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        SendEndpointImpl::respond_inner(&mut **self, request).await
    }
}

impl<'a> SendEndpoint for &mut (dyn SendEndpointImpl + 'a) {
    async fn respond_send(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        SendEndpointImpl::respond_inner(&mut **self, request).await
    }
}

/// Type-erased endpoint that can hold any endpoint implementation behind a trait object.
///
/// `AnyEndpoint` provides dynamic dispatch for endpoints, allowing you to store
/// different endpoint types in the same collection or pass them around without
/// knowing their concrete types at compile time. This is useful for building
/// flexible routing systems or plugin architectures.
///
/// It is the local flavour: the endpoint may be `!Send`, and so are
/// `AnyEndpoint` and its future. [`AnySendEndpoint`] is the `Send` one.
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
/// use http_kit::{Request, Response, Endpoint, endpoint::AnyEndpoint, Body, BoxHttpError};
///
/// struct HelloEndpoint;
/// impl Endpoint for HelloEndpoint {
///     type Error = BoxHttpError;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
///         Ok(Response::new(Body::from_bytes("Hello")))
///     }
/// }
///
/// struct GoodbyeEndpoint;
/// impl Endpoint for GoodbyeEndpoint {
///     type Error = BoxHttpError;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response,Self::Error> {
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
pub struct AnyEndpoint<F: Flavor = Shared>(Box<dyn EndpointImpl<F>>);

impl<F: Flavor> Debug for AnyEndpoint<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("AnyEndpoint[{}]", self.name()))
    }
}

impl<F: Flavor> AnyEndpoint<F> {
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
    /// use http_kit::{Request, Response, Endpoint, endpoint::AnyEndpoint, Body, BoxHttpError};
    ///
    /// struct MyEndpoint {
    ///     message: String,
    /// }
    ///
    /// impl Endpoint for MyEndpoint {
    ///     type Error = BoxHttpError;
    ///     async fn respond(&mut self, _request: &mut Request) -> Result<Response,Self::Error> {
    ///         Ok(Response::new(Body::from_bytes(self.message.clone())))
    ///     }
    /// }
    ///
    /// let endpoint = MyEndpoint { message: "Hello!".to_string() };
    /// let any_endpoint = AnyEndpoint::new(endpoint);
    /// ```
    pub fn new(endpoint: impl Endpoint<F> + 'static) -> Self {
        Self(Box::new(endpoint))
    }

    /// Returns the type name of the underlying endpoint implementation.
    ///
    /// This can be useful for debugging, logging, or introspection purposes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Response, Endpoint, endpoint::AnyEndpoint, Body, BoxHttpError};
    ///
    /// struct MyEndpoint;
    /// impl Endpoint for MyEndpoint {
    ///     type Error = BoxHttpError;
    ///     async fn respond(&mut self, _request: &mut Request) -> Result<Response,BoxHttpError> {
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

impl<F: Flavor> Endpoint<F> for AnyEndpoint<F> {
    type Error = BoxHttpError;
    async fn respond(&mut self, request: &mut Request<F>) -> Result<Response<F>, Self::Error> {
        self.0.respond_inner(request).await
    }
}

/// Type-erased [`SendEndpoint`]: the `Send` flavour of [`AnyEndpoint`].
///
/// Both it and its future are `Send`, so it can be stored in a router that a
/// work-stealing executor drives.
///
/// # Examples
///
/// ```rust
/// use core::future::Future;
/// use http_kit::{endpoint::AnySendEndpoint, Body, BoxHttpError, Endpoint, Request, Response, SendEndpoint};
///
/// struct Hello;
/// impl Endpoint for Hello {
///     type Error = BoxHttpError;
///     async fn respond(&mut self, _request: &mut Request) -> Result<Response, Self::Error> {
///         Ok(Response::new(Body::from_bytes("Hello")))
///     }
/// }
/// impl SendEndpoint for Hello {
///     fn respond_send(
///         &mut self,
///         request: &mut Request,
///     ) -> impl Future<Output = Result<Response, Self::Error>> + Send {
///         self.respond(request)
///     }
/// }
///
/// let endpoint = AnySendEndpoint::new(Hello);
/// # fn assert_send(_: impl Send) {}
/// assert_send(endpoint);
/// ```
pub struct AnySendEndpoint(Box<dyn SendEndpointImpl>);

impl Debug for AnySendEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("AnySendEndpoint[{}]", self.name()))
    }
}

impl AnySendEndpoint {
    /// Erases `endpoint`.
    pub fn new(endpoint: impl SendEndpoint + 'static) -> Self {
        Self(Box::new(endpoint))
    }

    /// Returns the type name of the underlying endpoint implementation.
    pub fn name(&self) -> &'static str {
        self.0.name()
    }
}

impl Endpoint for AnySendEndpoint {
    type Error = BoxHttpError;
    async fn respond(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.0.respond_inner(request).await
    }
}

impl SendEndpoint for AnySendEndpoint {
    async fn respond_send(&mut self, request: &mut Request) -> Result<Response, Self::Error> {
        self.0.respond_inner(request).await
    }
}
