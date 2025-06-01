//! A HTTP response.
//!
//! This module provides the [`Response`] type which represents an HTTP response including
//! headers, status code, version, and body. It offers comprehensive methods for:
//!
//! - Creating responses with different body types
//! - Manipulating headers and status codes
//! - Handling body content in various formats (bytes, string, JSON, form data)
//! - Managing HTTP extensions
//! - Setting MIME types and content type headers
//!
//! The [`Response`] type implements conversions from common body types like `String`, `Vec<u8>`,
//! `Bytes` etc. It also integrates with the `http` crate's types.
//!
//! # Examples
//!
//! ```
//! # use http_kit::{Response, StatusCode};
//! let mut response = Response::new(StatusCode::OK, "Hello World!");
//! response.set_status(StatusCode::CREATED);
//! response.insert_header("X-Custom", "value");
//! ```
//!
//! JSON responses (requires `json` feature):
//!
//! ```
//! # use http_kit::Response;
//! # use serde::Serialize;
//! #[derive(Serialize)]
//! struct User { name: String }
//!
//! let user = User { name: "Alice".into() };
//! let response = Response::empty().json(&user)?;
//! ```
use core::fmt::Debug;

use crate::{Body, BodyError, body::BodyFrozen};
use alloc::string::String;
use alloc::vec::Vec;
use bytes::Bytes;
use bytestr::ByteStr;
use http::{Extensions, HeaderMap, HeaderValue, StatusCode, Version, header::HeaderName};

/// The HTTP response parts.
pub type ResponseParts = http::response::Parts;

/// A HTTP response.
#[derive(Debug)]
pub struct Response {
    parts: ResponseParts,
    body: Body,
}

impl From<http::Response<Body>> for Response {
    fn from(response: http::Response<Body>) -> Self {
        let (parts, body) = response.into_parts();
        Self { parts, body }
    }
}

impl From<Response> for http::Response<Body> {
    fn from(response: Response) -> Self {
        Self::from_parts(response.parts, response.body)
    }
}

macro_rules! impl_response_from {
    ($($ty:ty),*) => {
        $(
            impl From<$ty> for Response {
                fn from(value: $ty) -> Self {
                    Self::new(StatusCode::OK, value)
                }
            }
        )*
    };
}

impl_response_from![ByteStr, String, Vec<u8>, Bytes, &str, &[u8]];

impl Response {
    /// Create a new `Response` with a body.
    pub fn new<S>(status: S, body: impl Into<Body>) -> Self
    where
        S: TryInto<StatusCode>,
        S::Error: Debug,
    {
        let mut response: Self = http::Response::new(body.into()).into();
        response.set_status(status.try_into().unwrap());
        response
    }

    /// Create a empty `Response`.
    pub fn empty() -> Self {
        Self::new(StatusCode::OK, Body::empty())
    }

    /// Return the status code.
    pub const fn status(&self) -> StatusCode {
        self.parts.status
    }
    /// Return the mutable reference of status code.
    pub fn status_mut(&mut self) -> &mut StatusCode {
        &mut self.parts.status
    }

    /// Set the status code.
    pub fn set_status(&mut self, status: StatusCode) {
        *self.status_mut() = status;
    }

    /// Return the HTTP version.
    pub const fn version(&self) -> Version {
        self.parts.version
    }

    /// Return the mutable reference of HTTP version.
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.parts.version
    }

    /// Set the HTTP version by `version`
    pub fn set_version(&mut self, version: Version) {
        *self.version_mut() = version;
    }

    /// Return the reference of the HTTP header.
    pub const fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// Return the mutable reference of the HTTP header.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.parts.headers
    }

    /// Acquire the first value of header by header name.
    pub fn get_header(&self, name: HeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    /// Append a header,the previous header (if exists) wouldn't be removed.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers_mut().append(name, value);
    }

    /// Insert a header,if the header already exists,the previous header will be removed.
    pub fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Option<HeaderValue> {
        self.headers_mut().insert(name, value)
    }

    /// Set HTTP header.
    pub fn header<V>(mut self, name: HeaderName, value: V) -> Self
    where
        V: TryInto<HeaderValue>,
        V::Error: Debug,
    {
        self.insert_header(name, value.try_into().unwrap());
        self
    }

    /// Return the reference of the extension.
    pub const fn extensions(&self) -> &Extensions {
        &self.parts.extensions
    }

    /// Return the mutable reference of the extension.
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.parts.extensions
    }

    /// Returns a refernece of associated extension.
    pub fn get_extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions().get()
    }

    /// Returns a mutable refernece of associated extension.
    pub fn get_mut_extension<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions_mut().get_mut()
    }

    /// Remove a type from extensions.
    pub fn remove_extension<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.extensions_mut().remove()
    }

    /// Insert a type into extensions,if the type already exists,the old value will be returned.
    pub fn insert_extension<T: Send + Sync + Clone + 'static>(
        &mut self,
        extension: T,
    ) -> Option<T> {
        self.extensions_mut().insert(extension)
    }

    /// Take the response body,leaving a frozen body.
    pub fn take_body(&mut self) -> Result<Body, BodyFrozen> {
        self.body.take()
    }

    /// Replace the value of the response body and return the old body.
    pub fn replace_body(&mut self, body: impl Into<Body>) -> Body {
        self.body.replace(body.into())
    }

    /// Swap the value of the response body with another body if the original body is not frozen.
    pub fn swap_body(&mut self, body: &mut Body) -> Result<(), BodyFrozen> {
        self.body.swap(body)
    }

    /// Map the body to a different value.
    pub fn map_body<F>(mut self, f: F) -> Self
    where
        F: FnOnce(Body) -> Body,
    {
        self.body = f(self.body);
        self
    }

    /// Set the body from a JSON.
    /// This method will set `Content-type` header automatically.
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize>(mut self, value: &T) -> Result<Self, serde_json::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.replace_body(Body::from_json(value)?);
        Ok(self)
    }

    /// Set the body from a file.
    /// This method will try to guess MIME by the extension of file.
    #[cfg(feature = "fs")]
    pub async fn file(
        mut self,
        path: impl AsRef<core::path::Path>,
    ) -> Result<Self, core::io::Error> {
        use core::os::unix::ffi::OsStrExt;

        let path = path.as_ref();
        let extension = path.extension().unwrap_or_default().as_bytes();
        let mime = crate::mime_guess::guess(extension).unwrap_or("application/octet-stream");
        self.replace_body(Body::from_file(path).await?);
        self.insert_header(http::header::CONTENT_TYPE, HeaderValue::from_static(mime));
        Ok(self)
    }

    /// Set the body from a form.
    /// This method will set `Content-type` header automatically.
    #[cfg(feature = "form")]
    pub fn form<T: serde::Serialize>(
        mut self,
        value: &T,
    ) -> Result<Self, serde_urlencoded::ser::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.replace_body(Body::from_form(value)?);
        Ok(self)
    }

    /// Consume and read response body as a chunk of bytes.
    pub async fn into_bytes(&mut self) -> Result<Bytes, BodyError> {
        self.take_body()?.into_bytes().await
    }

    /// Consume and read response body as UTF-8 string.
    pub async fn into_string(&mut self) -> Result<ByteStr, BodyError> {
        self.take_body()?.into_string().await
    }

    /// Prepare data in the inner representation,then try to read the body as JSON.
    /// This method allows you to deserialize data with zero copy.
    /// Tip: This method will fail if `content-type` header is mismatched.
    #[cfg(feature = "json")]
    pub async fn into_json<'a, T>(&'a mut self) -> Result<T, crate::Error>
    where
        T: serde::Deserialize<'a>,
    {
        use crate::ResultExt;

        assert_content_type!("application/json", self.headers());
        serde_json::from_slice(self.body.as_bytes().await?).status(crate::StatusCode::BAD_REQUEST)
    }

    /// Prepare data in the inner representation,then try to read the body as a form.
    /// This method allows you to deserialize data with zero copy.
    /// Tip: This method will fail if `content-type` header is mismatched.
    #[cfg(feature = "form")]
    pub async fn into_form<'a, T>(&'a mut self) -> Result<T, crate::Error>
    where
        T: serde::Deserialize<'a>,
    {
        use crate::ResultExt;

        assert_content_type!("application/x-www-form-urlencoded", self.headers());
        serde_urlencoded::from_bytes(self.body.as_bytes().await?)
            .status(crate::StatusCode::BAD_REQUEST)
    }

    /// Set the MIME.
    #[cfg(feature = "mime")]
    pub fn mime(mut self, mime: mime::Mime) -> Self {
        self.insert_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(mime.as_ref()).unwrap(),
        );
        self
    }

    /// Try to parse the header and return a `Mime` instance.
    #[cfg(feature = "mime")]
    pub fn get_mime(&self) -> Option<mime::Mime> {
        Some(
            core::str::from_utf8(self.get_header(http::header::CONTENT_TYPE)?.as_bytes())
                .ok()?
                .parse()
                .ok()?,
        )
    }
}
