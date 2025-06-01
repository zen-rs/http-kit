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
//! use http_kit::{Request, Response, Result, middleware::Middleware};
//!
//! struct MyMiddleware;
//!
//! impl Middleware for MyMiddleware {
//!     async fn handle(&self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
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
    Endpoint, Request, Response, Result,
    endpoint::{EndpointImpl, WithMiddleware},
};
use alloc::boxed::Box;
use core::{any::type_name, fmt::Debug, pin::Pin};
/// Middleware allows reading and modifying requests or responses during the request handling process.
/// It is often used to implement functionalities such as timeouts, compression, etc.
pub trait Middleware: Send + Sync {
    /// Handle this request and return a response.Call `next` method of `Next` to handle remain middleware chain.
    fn handle(
        &self,
        request: &mut Request,
        next: impl Endpoint,
    ) -> impl Future<Output = Result<Response>> + Send + Sync;
}

pub(crate) trait MiddlewareImpl: Send + Sync {
    fn handle_inner<'this, 'req, 'next, 'fut>(
        &'this self,
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
    async fn respond(&self, request: &mut Request) -> Result<Response> {
        self.respond_inner(request).await
    }
}

impl<T: Middleware> MiddlewareImpl for T {
    fn handle_inner<'this, 'req, 'next, 'fut>(
        &'this self,
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

impl<T: Middleware> Middleware for &T {
    async fn handle(&self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        Middleware::handle(*self, request, next).await
    }
}

impl<T1: Middleware, T2: Middleware> Middleware for (T1, T2) {
    async fn handle(&self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        self.0
            .handle(request, WithMiddleware::new(next, &self.1))
            .await
    }
}

/// Type erased middleware which allows storing different middleware implementations behind a
/// common interface.
pub struct AnyMiddleware(Box<dyn MiddlewareImpl>);

impl Debug for AnyMiddleware {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(format_args!("AnyMiddleware[{}]", self.name()))
    }
}

impl AnyMiddleware {
    /// Creates a new type-erased middleware wrapper around the given middleware implementation.
    pub fn new(middleware: impl Middleware + 'static) -> Self {
        AnyMiddleware(Box::new(middleware))
    }

    /// Returns the type name of the underlying middleware implementation.
    pub fn name(&self) -> &'static str {
        self.0.name()
    }
}

impl Middleware for AnyMiddleware {
    async fn handle(&self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        self.0.handle_inner(request, &next).await
    }
}

impl Middleware for () {
    async fn handle(&self, request: &mut Request, next: impl Endpoint) -> Result<Response> {
        next.respond(request).await
    }
}
