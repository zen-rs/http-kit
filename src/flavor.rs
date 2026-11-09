//! Whether a body, request or response may cross threads.
//!
//! A [`Body`](crate::Body) erases the stream behind it, so whether it is
//! `Send` cannot come from that stream: it is chosen by a flavour.
//!
//! - [`Shared`] bodies hold only `Send + Sync` streams and are themselves
//!   `Send + Sync`, so a request can be handed to a work-stealing executor.
//!   [`Body`](crate::Body), [`Request`](crate::Request) and
//!   [`Response`](crate::Response) are this flavour.
//! - [`Local`] bodies hold any stream, an `Rc` or a socket bound to the thread
//!   that accepted it included, and stay on the thread that built them.
//!   [`LocalBody`](crate::LocalBody) is this flavour.
//!
//! [`Endpoint`](crate::Endpoint) and [`Middleware`](crate::Middleware) take
//! the flavour of the request they serve as a parameter, `Shared` unless
//! stated, so one implementation can serve either.

use alloc::boxed::Box;
use bytes::Bytes;
use core::pin::Pin;
use futures_lite::{Stream, StreamExt};

use crate::body::{into_bytes::IntoBytes, BodyFrame, Error};

mod sealed {
    pub trait Sealed {}
}

/// The flavour of a body: [`Shared`] or [`Local`].
///
/// The trait is sealed; its associated types are the erased forms a body of
/// this flavour holds.
pub trait Flavor: sealed::Sealed + Sized + 'static {
    /// A stream of frames, as a body of this flavour holds it.
    #[doc(hidden)]
    type Frames: ?Sized + Stream<Item = Result<BodyFrame, Error>>;
    /// An `http_body::Body`, as a body of this flavour holds it.
    #[doc(hidden)]
    type HttpBody: ?Sized + http_body::Body<Data = Bytes, Error = Error>;
}

/// Bodies that may cross threads: every part is `Send + Sync`.
#[derive(Debug)]
pub enum Shared {}

/// Bodies that stay on one thread: no part needs to be `Send` or `Sync`.
#[derive(Debug)]
pub enum Local {}

impl sealed::Sealed for Shared {}
impl sealed::Sealed for Local {}

impl Flavor for Shared {
    type Frames = dyn Stream<Item = Result<BodyFrame, Error>> + Send + Sync;
    type HttpBody = dyn http_body::Body<Data = Bytes, Error = Error> + Send + Sync;
}

impl Flavor for Local {
    type Frames = dyn Stream<Item = Result<BodyFrame, Error>>;
    type HttpBody = dyn http_body::Body<Data = Bytes, Error = Error>;
}

/// A flavour whose bodies can hold a `T`: [`Local`] holds any `'static` value,
/// [`Shared`] one that is also `Send + Sync`.
///
/// It is the bound a body constructor places on its source, so building a
/// [`Body`](crate::Body) from a `!Send` stream fails to compile while a
/// [`LocalBody`](crate::LocalBody) accepts it.
pub trait Holds<T>: Flavor {
    /// Boxes `stream`, mapping each item to a frame with `map`.
    #[doc(hidden)]
    fn frames<I: 'static, E: Into<Error> + 'static>(
        stream: T,
        map: fn(I) -> Result<BodyFrame, E>,
    ) -> Pin<Box<Self::Frames>>
    where
        T: Stream<Item = I> + 'static;

    /// Boxes an `http_body::Body`.
    #[doc(hidden)]
    fn http_body(body: T) -> Pin<Box<Self::HttpBody>>
    where
        T: http_body::Body + 'static,
        T::Data: Into<Bytes>,
        T::Error: Into<Error>;
}

fn frame_stream<S, I, E>(
    stream: S,
    map: fn(I) -> Result<BodyFrame, E>,
) -> impl Stream<Item = Result<BodyFrame, Error>>
where
    S: Stream<Item = I>,
    E: Into<Error>,
{
    stream.map(move |item| map(item).map_err(Into::into))
}

impl<T: Send + Sync> Holds<T> for Shared {
    fn frames<I: 'static, E: Into<Error> + 'static>(
        stream: T,
        map: fn(I) -> Result<BodyFrame, E>,
    ) -> Pin<Box<Self::Frames>>
    where
        T: Stream<Item = I> + 'static,
    {
        Box::pin(frame_stream(stream, map))
    }

    fn http_body(body: T) -> Pin<Box<Self::HttpBody>>
    where
        T: http_body::Body + 'static,
        T::Data: Into<Bytes>,
        T::Error: Into<Error>,
    {
        Box::pin(IntoBytes::new(body))
    }
}

impl<T> Holds<T> for Local {
    fn frames<I: 'static, E: Into<Error> + 'static>(
        stream: T,
        map: fn(I) -> Result<BodyFrame, E>,
    ) -> Pin<Box<Self::Frames>>
    where
        T: Stream<Item = I> + 'static,
    {
        Box::pin(frame_stream(stream, map))
    }

    fn http_body(body: T) -> Pin<Box<Self::HttpBody>>
    where
        T: http_body::Body + 'static,
        T::Data: Into<Bytes>,
        T::Error: Into<Error>,
    {
        Box::pin(IntoBytes::new(body))
    }
}
