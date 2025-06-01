//! HTTP request implementation.
//!
//! This module provides the [`Request`] type representing an HTTP request with methods to:
//!
//! - Create requests for different HTTP methods (GET, POST, PUT, DELETE)
//! - Manipulate request headers and body
//! - Access and modify extensions
//! - Perform conversions between body formats (JSON, form-data, files)
//!
//! The module integrates with common serialization formats and provides convenience
//! methods for handling request data in various formats.
//!
//! # Features
//!
//! The following features gates are available:
//!
//! - `json` - Enables JSON serialization/deserialization support via serde_json
//! - `form` - Enables form data handling via serde_urlencoded
//! - `fs` - Enables file upload support with MIME type detection
//! - `mime` - Enables MIME type parsing and manipulation
//!
//! # Examples
//!
//! ```rust,no_run
//! use http_kit::Request;
//!
//! let req = Request::get("https://api.example.com")
//!     .header("Accept", "application/json")
//!     .header("User-Agent", "http-kit");
//! ```
//!
use crate::{Body, BodyError, body::BodyFrozen};
use bytes::Bytes;
use bytestr::ByteStr;
use core::fmt::Debug;
use http::{Extensions, HeaderMap, HeaderValue, Method, Uri, Version, header::HeaderName};

type RequestParts = http::request::Parts;

/// An HTTP request.
#[derive(Debug)]
pub struct Request {
    parts: RequestParts,
    body: Body,
}

impl From<http::Request<Body>> for Request {
    fn from(request: http::Request<Body>) -> Self {
        let (parts, body) = request.into_parts();
        Self { parts, body }
    }
}

impl From<Request> for http::Request<Body> {
    fn from(request: Request) -> Self {
        Self::from_parts(request.parts, request.body)
    }
}

impl Request {
    /// Create a new `Request`.
    pub fn new<U>(method: Method, uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        http::Request::builder()
            .method(method)
            .uri(uri.try_into().unwrap())
            .body(Body::empty())
            .unwrap()
            .into()
    }

    /// Create a GET `Request`.
    pub fn get<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::GET, uri)
    }

    /// Create a POST `Request`.
    pub fn post<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::POST, uri)
    }

    /// Create a PUT `Request`.
    pub fn put<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::PUT, uri)
    }

    /// Create a DELETE `Request`.
    pub fn delete<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::DELETE, uri)
    }
    /// Return the reference of request parts.
    pub const fn parts(&self) -> &RequestParts {
        &self.parts
    }

    /// Return the mutable reference of request parts.
    pub fn parts_mut(&mut self) -> &mut RequestParts {
        &mut self.parts
    }

    /// Return the reference of request method.
    pub const fn method(&self) -> &Method {
        &self.parts.method
    }

    /// Return the mutable reference of request method.
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.parts.method
    }

    /// Set the request method by `method`
    pub fn set_method(&mut self, method: Method) {
        *self.method_mut() = method;
    }

    /// Return the reference of request URI.
    pub const fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// Return the mutable reference of URI.
    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.parts.uri
    }

    /// Rewrite the HTTP uri.
    pub fn set_uri(&mut self, uri: Uri) {
        *self.uri_mut() = uri;
    }
    /// Return the HTTP version.
    pub const fn version(&self) -> Version {
        self.parts.version
    }

    /// Return the mutable reference of the HTTP version.
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.parts.version
    }
    /// Set the HTTP version by `version`.
    pub fn set_version(&mut self, version: Version) {
        *self.version_mut() = version;
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

    /// Append a header,the previous header (if it exists) wouldn't be removed.
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers_mut().append(name, value);
    }

    /// Insert a header,if the header already exists,the previous header will be removed.
    pub fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Option<HeaderValue> {
        self.headers_mut().insert(name, value)
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

    /// Take the request body,leaving a frozen body.
    pub fn take_body(&mut self) -> Result<Body, BodyFrozen> {
        self.body.take()
    }

    /// Replace the value of the request body and return the old body.
    pub fn replace_body(&mut self, body: impl Into<Body>) -> Body {
        self.body.replace(body.into())
    }

    /// Swap the value of the request body with another body if the orginal body is not frozen.
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

    #[cfg(feature = "json")]
    /// Set the body from a JSON.
    /// This method will set `Content-type` header automatically.
    pub fn json<T: serde::Serialize>(mut self, value: T) -> Result<Self, serde_json::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.replace_body(Body::from_json(value)?);
        Ok(self)
    }

    #[cfg(feature = "form")]
    /// Set the body from a form.
    /// This method will set `Content-type` header automatically.
    pub fn form<T: serde::Serialize>(
        mut self,
        value: T,
    ) -> Result<Self, serde_urlencoded::ser::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.replace_body(Body::from_form(value)?);
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

    /// Consume and read request body as a chunk of bytes.
    pub async fn into_bytes(&mut self) -> Result<Bytes, BodyError> {
        self.take_body()?.into_bytes().await
    }

    /// Consume and read request body as UTF-8 string.
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
