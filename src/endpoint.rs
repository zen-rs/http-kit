//! HTTP endpoint.
//!
//! An endpoint is a request handler that processes incoming HTTP requests and
//! returns responses. Endpoints can be combined with [`Middleware`] to add common
//! functionality like logging, authentication, etc.
//!
//! # Examples
//!
//! ```
//! use http_kit::{Request, Response, Result};
//!
//! struct MyEndpoint;
//!
//! impl Endpoint for MyEndpoint {
//!     async fn respond(&self, request: &mut Request) -> Result<Response> {
//!         Ok(Response::new())
//!     }
//! }
//! ```

use core::{any::type_name, fmt::Debug, pin::Pin};

use alloc::boxed::Box;

use crate::{Middleware, Request, Response, Result};

/// A HTTP request processor.
pub trait Endpoint: Send + Sync {
    /// The endpoint handles request and return a response.
    fn respond(
        &self,
        request: &mut Request,
    ) -> impl Future<Output = Result<Response>> + Send + Sync;
}

impl<T: Endpoint> Endpoint for &T {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        Endpoint::respond(*self, request).await
    }
}

/// A wrapper that combines an endpoint with middleware.
///
/// This structure allows composing an endpoint with middleware to add additional
/// functionality like logging, authentication, etc. The middleware will be executed
/// before and/or after the endpoint's response handling.
#[derive(Debug)]
pub struct WithMiddleware<E: Endpoint, M: Middleware> {
    endpoint: E,
    middleware: M,
}

impl<E: Endpoint, M: Middleware> WithMiddleware<E, M> {
    /// Creates a new `WithMiddleware` that wraps the given endpoint and middleware.
    ///
    /// The middleware will be executed when handling requests, allowing it to
    /// process the request before reaching the endpoint and/or modify the response
    /// after the endpoint handles it.
    pub fn new(endpoint: E, middleware: M) -> Self {
        Self {
            endpoint,
            middleware,
        }
    }
}

impl<E: Endpoint, M: Middleware> Endpoint for WithMiddleware<E, M> {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        self.middleware.handle(request, &self.endpoint).await
    }
}

pub(crate) trait EndpointImpl: Send + Sync {
    fn respond_inner<'this, 'req, 'fut>(
        &'this self,
        request: &'req mut Request,
    ) -> Pin<Box<dyn 'fut + Send + Sync + Future<Output = Result<Response>>>>
    where
        'this: 'fut,
        'req: 'fut;
    fn name(&self) -> &'static str {
        type_name::<Self>()
    }
}

/// Type-erased endpoint that can hold any endpoint implementation behind a trait object.
pub struct AnyEndpoint(Box<dyn EndpointImpl>);

impl Debug for AnyEndpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("AnyEndpoint[{}]", self.name()))
    }
}

impl AnyEndpoint {
    /// Creates a new type-erased endpoint wrapper around the given endpoint implementation.
    pub fn new(endpoint: impl Endpoint + 'static) -> Self {
        Self(Box::new(endpoint))
    }
}

impl<E: Endpoint> EndpointImpl for E {
    fn respond_inner<'this, 'req, 'fut>(
        &'this self,
        request: &'req mut Request,
    ) -> Pin<Box<dyn 'fut + Send + Sync + Future<Output = Result<Response>>>>
    where
        'this: 'fut,
        'req: 'fut,
    {
        Box::pin(self.respond(request))
    }
}

impl Endpoint for AnyEndpoint {
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        self.0.respond_inner(request).await
    }
}
