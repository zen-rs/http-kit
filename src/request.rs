//! HTTP request implementation.
//!
//! This module provides the [`Request`] type representing an HTTP request with methods to:
//!
//! - Create requests for different HTTP methods (GET, POST, PUT, DELETE)
//! - Manipulate request headers and body
//! - Access and modify extensions for storing custom data
//! - Perform conversions between body formats (JSON, form-data, files)
//! - Handle request metadata like URI, method, version, and headers
//!
//! The module integrates with common serialization formats and provides convenience
//! methods for handling request data in various formats while maintaining type safety.
//!
//! # Features
//!
//! The following feature gates are available:
//!
//! - `json` - Enables JSON serialization/deserialization support via serde_json
//! - `form` - Enables form data handling via serde_urlencoded
//! - `fs` - Enables file upload support with MIME type detection
//! - `mime` - Enables MIME type parsing and manipulation
//!
//! # Examples
//!
//! ## Creating Basic Requests
//!
//! ```rust
//! use http_kit::Request;
//!
//! // GET request
//! let get_req = Request::get("https://api.example.com/users");
//!
//! // POST request with headers
//! let post_req = Request::post("https://api.example.com/users")
//!     .header(http::header::CONTENT_TYPE, "application/json")
//!     .header(http::header::USER_AGENT, "http-kit/1.0");
//! ```
//!
//! ## Working with Request Bodies
//!
//! ```rust
//! # #[cfg(feature = "json")]
//! # {
//! use http_kit::Request;
//! use serde::Serialize;
//!
//! #[derive(Serialize)]
//! struct User { name: String, email: String }
//!
//! let user = User {
//!     name: "Alice".to_string(),
//!     email: "alice@example.com".to_string(),
//! };
//!
//! let request = Request::post("https://api.example.com/users")
//!     .json(&user)?;
//! # }
//! # Ok::<(), serde_json::Error>(())
//! ```
//!
use crate::{body::BodyFrozen, Body, BodyError};
use bytes::Bytes;
use bytestr::ByteStr;
use core::fmt::Debug;
use http::{
    header::{GetAll, HeaderName},
    Extensions, HeaderMap, HeaderValue, Method, Uri, Version,
};

type RequestParts = http::request::Parts;

/// An HTTP request with headers, body, and metadata.
///
/// `Request` represents an HTTP request that can be constructed, modified, and processed.
/// It provides methods for working with all aspects of HTTP requests including:
///
/// - **HTTP method** (GET, POST, PUT, DELETE, etc.)
/// - **URI/URL** for the request target
/// - **Headers** for metadata like content type, authorization, etc.
/// - **Body** for request payload data
/// - **Extensions** for storing custom application data
/// - **HTTP version** information
///
/// The request type integrates with the body system to provide convenient methods
/// for handling different content types like JSON, form data, and files.
///
/// # Examples
///
/// ## Basic Request Creation
///
/// ```rust
/// use http_kit::Request;
/// use http::{Method, Uri};
///
/// // Using convenience methods
/// let get_req = Request::get("/api/users");
/// let post_req = Request::post("/api/users");
///
/// // Using the general constructor
/// let put_req = Request::new(Method::PUT, "/api/users/123");
/// ```
///
/// ## Working with Headers
///
/// ```rust
/// use http_kit::Request;
///
/// let mut request = Request::get("/api/data")
///     .header(http::header::ACCEPT, "application/json")
///     .header(http::header::USER_AGENT, "MyApp/1.0");
///
/// // Access headers
/// if let Some(accept) = request.get_header(http::header::ACCEPT) {
///     println!("Accept header: {:?}", accept);
/// }
/// ```
///
/// ## Request Body Handling
///
/// ```rust
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use http_kit::Request;
///
/// let mut request = Request::post("/api/echo");
/// request.replace_body("Hello, server!");
///
/// // Take body for processing
/// let body = request.take_body()?;
/// let data = body.into_bytes().await?;
/// # Ok(())
/// # }
/// ```
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
    /// Creates a new HTTP request with the specified method and URI.
    ///
    /// This is the general-purpose constructor for creating requests. For common
    /// HTTP methods, consider using the convenience methods like [`Request::get`],
    /// [`Request::post`], etc.
    ///
    /// # Arguments
    ///
    /// * `method` - The HTTP method (GET, POST, PUT, DELETE, etc.)
    /// * `uri` - The request URI/URL
    ///
    /// # Panics
    ///
    /// Panics if the URI cannot be parsed into a valid `Uri`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Method;
    ///
    /// let request = Request::new(Method::PATCH, "/api/users/123");
    /// assert_eq!(request.method(), &Method::PATCH);
    /// ```
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

    /// Creates a new GET request with the specified URI.
    ///
    /// This is a convenience method for creating GET requests, which are commonly
    /// used for retrieving data from servers.
    ///
    /// # Arguments
    ///
    /// * `uri` - The request URI/URL
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users");
    /// assert_eq!(request.method(), &http::Method::GET);
    /// assert_eq!(request.uri().path(), "/api/users");
    /// ```
    pub fn get<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::GET, uri)
    }

    /// Creates a new POST request with the specified URI.
    ///
    /// This is a convenience method for creating POST requests, which are commonly
    /// used for submitting data to servers, creating resources, or triggering actions.
    ///
    /// # Arguments
    ///
    /// * `uri` - The request URI/URL
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::post("/api/users");
    /// assert_eq!(request.method(), &http::Method::POST);
    /// ```
    pub fn post<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::POST, uri)
    }

    /// Creates a new PUT request with the specified URI.
    ///
    /// This is a convenience method for creating PUT requests, which are commonly
    /// used for updating or replacing resources on the server.
    ///
    /// # Arguments
    ///
    /// * `uri` - The request URI/URL
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::put("/api/users/123");
    /// assert_eq!(request.method(), &http::Method::PUT);
    /// ```
    pub fn put<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::PUT, uri)
    }

    /// Creates a new DELETE request with the specified URI.
    ///
    /// This is a convenience method for creating DELETE requests, which are commonly
    /// used for removing resources from the server.
    ///
    /// # Arguments
    ///
    /// * `uri` - The request URI/URL
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::delete("/api/users/123");
    /// assert_eq!(request.method(), &http::Method::DELETE);
    /// ```
    pub fn delete<U>(uri: U) -> Self
    where
        U: TryInto<Uri>,
        U::Error: Debug,
    {
        Self::new(Method::DELETE, uri)
    }
    /// Returns a reference to the request parts.
    ///
    /// The request parts contain all the HTTP metadata including method, URI,
    /// version, headers, and extensions, but not the body.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users");
    /// let parts = request.parts();
    /// println!("Method: {}, URI: {}", parts.method, parts.uri);
    /// ```
    pub const fn parts(&self) -> &RequestParts {
        &self.parts
    }

    /// Returns a mutable reference to the request parts.
    ///
    /// This allows modification of the HTTP metadata including method, URI,
    /// version, headers, and extensions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Method;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.parts_mut().method = Method::POST;
    /// assert_eq!(request.method(), &Method::POST);
    /// ```
    pub fn parts_mut(&mut self) -> &mut RequestParts {
        &mut self.parts
    }

    /// Returns a reference to the HTTP method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Method;
    ///
    /// let request = Request::post("/api/data");
    /// assert_eq!(request.method(), &Method::POST);
    /// ```
    pub const fn method(&self) -> &Method {
        &self.parts.method
    }

    /// Returns a mutable reference to the HTTP method.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Method;
    ///
    /// let mut request = Request::get("/api/users");
    /// *request.method_mut() = Method::POST;
    /// assert_eq!(request.method(), &Method::POST);
    /// ```
    pub fn method_mut(&mut self) -> &mut Method {
        &mut self.parts.method
    }

    /// Sets the HTTP method for this request.
    ///
    /// # Arguments
    ///
    /// * `method` - The new HTTP method
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Method;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.set_method(Method::PUT);
    /// assert_eq!(request.method(), &Method::PUT);
    /// ```
    pub fn set_method(&mut self, method: Method) {
        *self.method_mut() = method;
    }

    /// Returns a reference to the request URI.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users?page=1");
    /// assert_eq!(request.uri().path(), "/api/users");
    /// assert_eq!(request.uri().query(), Some("page=1"));
    /// ```
    pub const fn uri(&self) -> &Uri {
        &self.parts.uri
    }

    /// Returns a mutable reference to the request URI.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// *request.uri_mut() = "/api/posts".parse().unwrap();
    /// assert_eq!(request.uri().path(), "/api/posts");
    /// ```
    pub fn uri_mut(&mut self) -> &mut Uri {
        &mut self.parts.uri
    }

    /// Sets the request URI.
    ///
    /// # Arguments
    ///
    /// * `uri` - The new URI for the request
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.set_uri("/api/posts".parse().unwrap());
    /// assert_eq!(request.uri().path(), "/api/posts");
    /// ```
    pub fn set_uri(&mut self, uri: Uri) {
        *self.uri_mut() = uri;
    }
    /// Returns the HTTP version for this request.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Version;
    ///
    /// let request = Request::get("/api/users");
    /// // Default version is typically HTTP/1.1
    /// assert_eq!(request.version(), Version::HTTP_11);
    /// ```
    pub const fn version(&self) -> Version {
        self.parts.version
    }

    /// Returns a mutable reference to the HTTP version.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Version;
    ///
    /// let mut request = Request::get("/api/users");
    /// *request.version_mut() = Version::HTTP_2;
    /// assert_eq!(request.version(), Version::HTTP_2);
    /// ```
    pub fn version_mut(&mut self) -> &mut Version {
        &mut self.parts.version
    }
    /// Sets the HTTP version for this request.
    ///
    /// # Arguments
    ///
    /// * `version` - The HTTP version to use
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    /// use http::Version;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.set_version(Version::HTTP_2);
    /// assert_eq!(request.version(), Version::HTTP_2);
    /// ```
    pub fn set_version(&mut self, version: Version) {
        *self.version_mut() = version;
    }

    /// Sets an HTTP header and returns the modified request.
    ///
    /// This is a builder-style method that allows method chaining. If you need to
    /// modify an existing request, use [`insert_header`] instead.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name
    /// * `value` - The header value
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users")
    ///     .header(http::header::ACCEPT, "application/json")
    ///     .header(http::header::USER_AGENT, "MyApp/1.0");
    /// ```
    ///
    /// [`insert_header`]: Request::insert_header
    pub fn header<V>(mut self, name: HeaderName, value: V) -> Self
    where
        V: TryInto<HeaderValue>,
        V::Error: Debug,
    {
        self.insert_header(name, value.try_into().unwrap());
        self
    }

    /// Returns a reference to the HTTP headers.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users")
    ///     .header(http::header::ACCEPT, "application/json");
    ///
    /// let headers = request.headers();
    /// assert!(headers.contains_key(http::header::ACCEPT));
    /// ```
    pub const fn headers(&self) -> &HeaderMap {
        &self.parts.headers
    }

    /// Returns a mutable reference to the HTTP headers.
    ///
    /// This allows direct manipulation of the header map.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.headers_mut().insert(
    ///     http::header::ACCEPT,
    ///     "application/json".parse().unwrap()
    /// );
    /// ```
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.parts.headers
    }

    /// Returns the first value for the given header name.
    ///
    /// If the header has multiple values, only the first one is returned.
    /// Returns `None` if the header is not present.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name to look up
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users")
    ///     .header(http::header::ACCEPT, "application/json");
    ///
    /// if let Some(accept) = request.get_header(http::header::ACCEPT) {
    ///     assert_eq!(accept, "application/json");
    /// }
    /// ```
    pub fn get_header(&self, name: HeaderName) -> Option<&HeaderValue> {
        self.headers().get(name)
    }

    /// Returns an iterator over all values for a header name.
    ///
    /// This method retrieves all values for a specific header, unlike [`get_header`]
    /// which only returns the first value. This is useful for headers that can
    /// have multiple values like `Accept` or `Set-Cookie`.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name to get values for
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.append_header(http::header::ACCEPT, "text/html".parse().unwrap());
    /// request.append_header(http::header::ACCEPT, "application/json".parse().unwrap());
    ///
    /// // Iterate over all Accept header values
    /// for accept in request.get_headers(http::header::ACCEPT) {
    ///     println!("Accept: {}", accept.to_str().unwrap());
    /// }
    /// ```
    ///
    /// [`get_header`]: Request::get_header
    pub fn get_headers(&self, name: HeaderName) -> GetAll<'_, HeaderValue> {
        self.headers().get_all(name)
    }

    /// Appends a header value without removing existing values.
    ///
    /// If a header with the same name already exists, the new value is added
    /// alongside the existing values rather than replacing them.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name
    /// * `value` - The header value to append
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.append_header(http::header::ACCEPT, "application/json".parse().unwrap());
    /// request.append_header(http::header::ACCEPT, "text/html".parse().unwrap());
    /// // Now the Accept header has both values
    /// ```
    pub fn append_header(&mut self, name: HeaderName, value: HeaderValue) {
        self.headers_mut().append(name, value);
    }

    /// Inserts a header value, replacing any existing values.
    ///
    /// If a header with the same name already exists, it is completely replaced
    /// with the new value.
    ///
    /// # Arguments
    ///
    /// * `name` - The header name
    /// * `value` - The header value
    ///
    /// # Returns
    ///
    /// Returns the previous header value if one existed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// let old_value = request.insert_header(
    ///     http::header::USER_AGENT,
    ///     "MyApp/1.0".parse().unwrap()
    /// );
    /// assert!(old_value.is_none());
    ///
    /// let old_value = request.insert_header(
    ///     http::header::USER_AGENT,
    ///     "MyApp/2.0".parse().unwrap()
    /// );
    /// assert!(old_value.is_some());
    /// ```
    pub fn insert_header(&mut self, name: HeaderName, value: HeaderValue) -> Option<HeaderValue> {
        self.headers_mut().insert(name, value)
    }

    /// Returns a reference to the request extensions.
    ///
    /// Extensions provide a type-safe way to store additional data associated
    /// with the request that doesn't fit into standard HTTP fields.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let request = Request::get("/api/users");
    /// let extensions = request.extensions();
    /// // Check if a specific type is stored
    /// let user_id: Option<&u32> = extensions.get();
    /// ```
    pub const fn extensions(&self) -> &Extensions {
        &self.parts.extensions
    }

    /// Returns a mutable reference to the request extensions.
    ///
    /// This allows modification of the extensions map.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.extensions_mut().insert(42u32);
    /// ```
    pub fn extensions_mut(&mut self) -> &mut Extensions {
        &mut self.parts.extensions
    }

    /// Returns a reference to an extension of the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to retrieve from extensions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.insert_extension(42u32);
    ///
    /// if let Some(value) = request.get_extension::<u32>() {
    ///     assert_eq!(*value, 42);
    /// }
    /// ```
    pub fn get_extension<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions().get()
    }

    /// Returns a mutable reference to an extension of the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to retrieve from extensions
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.insert_extension(42u32);
    ///
    /// if let Some(value) = request.get_mut_extension::<u32>() {
    ///     *value = 100;
    /// }
    /// ```
    pub fn get_mut_extension<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions_mut().get_mut()
    }

    /// Removes and returns an extension of the specified type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to remove from extensions
    ///
    /// # Returns
    ///
    /// Returns the removed value if it existed, or `None` if it wasn't present.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    /// request.insert_extension(42u32);
    ///
    /// let removed = request.remove_extension::<u32>();
    /// assert_eq!(removed, Some(42));
    ///
    /// let removed_again = request.remove_extension::<u32>();
    /// assert_eq!(removed_again, None);
    /// ```
    pub fn remove_extension<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.extensions_mut().remove()
    }

    /// Inserts an extension value, returning any previous value of the same type.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type to insert into extensions
    ///
    /// # Arguments
    ///
    /// * `extension` - The value to insert
    ///
    /// # Returns
    ///
    /// Returns the previous value of the same type if one existed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::get("/api/users");
    ///
    /// let old_value = request.insert_extension(42u32);
    /// assert_eq!(old_value, None);
    ///
    /// let old_value = request.insert_extension(100u32);
    /// assert_eq!(old_value, Some(42));
    /// ```
    pub fn insert_extension<T: Send + Sync + Clone + 'static>(
        &mut self,
        extension: T,
    ) -> Option<T> {
        self.extensions_mut().insert(extension)
    }

    /// Takes the request body, leaving a frozen (unusable) body in its place.
    ///
    /// This method extracts the body from the request while ensuring it cannot
    /// be accessed again. This is useful when you need to consume the body
    /// for processing while preventing accidental double-consumption.
    ///
    /// # Errors
    ///
    /// Returns `BodyFrozen` if the body has already been taken.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::post("/api/data");
    /// request.replace_body("Hello, world!");
    ///
    /// let body = request.take_body()?;
    /// // request.take_body() would now return an error
    /// # Ok::<(), http_kit::BodyError>(())
    /// ```
    pub fn take_body(&mut self) -> Result<Body, BodyFrozen> {
        self.body.take()
    }

    /// Replaces the request body and returns the previous body.
    ///
    /// This method swaps the current body with a new one, returning the
    /// original body. This is useful for body transformations or when
    /// you need to temporarily substitute the body content.
    ///
    /// # Arguments
    ///
    /// * `body` - The new body to set (anything convertible to `Body`)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// let mut request = Request::post("/api/data");
    /// request.replace_body("Original content");
    ///
    /// let old_body = request.replace_body("New content");
    /// // old_body contains "Original content"
    /// // request now contains "New content"
    /// ```
    pub fn replace_body(&mut self, body: impl Into<Body>) -> Body {
        self.body.replace(body.into())
    }

    /// Swaps the request body with another body.
    ///
    /// This method exchanges the contents of the request body with another body,
    /// provided that the request body is not frozen.
    ///
    /// # Arguments
    ///
    /// * `body` - The body to swap with
    ///
    /// # Errors
    ///
    /// Returns `BodyFrozen` if the request body has been frozen/consumed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Body};
    ///
    /// let mut request = Request::post("/api/data");
    /// request.replace_body("Request content");
    ///
    /// let mut other_body = Body::from_bytes("Other content");
    /// request.swap_body(&mut other_body)?;
    ///
    /// // Now request contains "Other content"
    /// // and other_body contains "Request content"
    /// # Ok::<(), http_kit::BodyError>(())
    /// ```
    pub fn swap_body(&mut self, body: &mut Body) -> Result<(), BodyFrozen> {
        self.body.swap(body)
    }

    /// Transforms the request body using the provided function.
    ///
    /// This method allows you to apply a transformation to the request body
    /// in a functional style, returning a new request with the transformed body.
    ///
    /// # Arguments
    ///
    /// * `f` - A function that takes the current body and returns a new body
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::{Request, Body};
    ///
    /// let request = Request::post("/api/data")
    ///     .map_body(|body| {
    ///         // Transform empty body to contain JSON
    ///         Body::from_bytes(r#"{"message": "Hello"}"#)
    ///     });
    /// ```
    pub fn map_body<F>(mut self, f: F) -> Self
    where
        F: FnOnce(Body) -> Body,
    {
        self.body = f(self.body);
        self
    }

    /// Sets the body from a JSON-serializable value.
    ///
    /// This method serializes the provided value to JSON and sets it as the request body.
    /// It also automatically sets the `Content-Type` header to `application/json`.
    ///
    /// # Arguments
    ///
    /// * `value` - Any value that implements `serde::Serialize`
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if JSON serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "json")]
    /// # {
    /// use http_kit::Request;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct User { name: String, age: u32 }
    ///
    /// let user = User { name: "Alice".to_string(), age: 30 };
    /// let request = Request::post("/api/users").json(&user)?;
    /// # }
    /// # Ok::<(), serde_json::Error>(())
    /// ```
    #[cfg(feature = "json")]
    pub fn json<T: serde::Serialize>(mut self, value: T) -> Result<Self, serde_json::Error> {
        use http::header;

        self.insert_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.replace_body(Body::from_json(value)?);
        Ok(self)
    }

    /// Sets the body from a form-serializable value.
    ///
    /// This method serializes the provided value to URL-encoded form data and sets it
    /// as the request body. It also automatically sets the `Content-Type` header to
    /// `application/x-www-form-urlencoded`.
    ///
    /// # Arguments
    ///
    /// * `value` - Any value that implements `serde::Serialize`
    ///
    /// # Errors
    ///
    /// Returns `serde_urlencoded::ser::Error` if form serialization fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "form")]
    /// # {
    /// use http_kit::Request;
    /// use serde::Serialize;
    ///
    /// #[derive(Serialize)]
    /// struct LoginForm { username: String, password: String }
    ///
    /// let form = LoginForm {
    ///     username: "alice".to_string(),
    ///     password: "secret".to_string(),
    /// };
    /// let request = Request::post("/login").form(&form)?;
    /// # }
    /// # Ok::<(), serde_urlencoded::ser::Error>(())
    /// ```
    #[cfg(feature = "form")]
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

    /// Sets the body from a file, streaming its contents.
    ///
    /// This method opens the specified file and streams its contents as the request body.
    /// It automatically detects the MIME type based on the file extension and sets the
    /// appropriate `Content-Type` header.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file to read
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the file cannot be opened or read.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # #[cfg(feature = "fs")]
    /// # {
    /// use http_kit::Request;
    ///
    /// # async fn example() -> Result<(), std::io::Error> {
    /// let request = Request::post("/upload").file("document.pdf").await?;
    /// // Content-Type will be automatically set based on .pdf extension
    /// # Ok(())
    /// # }
    /// # }
    /// ```
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

    /// Consumes the request body and returns its data as bytes.
    ///
    /// This method takes the request body and reads all its data into memory,
    /// returning it as a `Bytes` object. The body becomes unavailable after this call.
    ///
    /// # Errors
    ///
    /// Returns `BodyError` if:
    /// - The body has already been consumed
    /// - An I/O error occurs while reading streaming data
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut request = Request::post("/api/data");
    /// request.replace_body("Hello, world!");
    ///
    /// let bytes = request.into_bytes().await?;
    /// assert_eq!(bytes, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_bytes(&mut self) -> Result<Bytes, BodyError> {
        self.take_body()?.into_bytes().await
    }

    /// Consumes the request body and returns its data as a UTF-8 string.
    ///
    /// This method takes the request body, reads all its data into memory,
    /// and converts it to a UTF-8 string. The body becomes unavailable after this call.
    ///
    /// # Errors
    ///
    /// Returns `BodyError` if:
    /// - The body has already been consumed
    /// - An I/O error occurs while reading streaming data
    /// - The body contains invalid UTF-8 sequences
    ///
    /// # Examples
    ///
    /// ```rust
    /// use http_kit::Request;
    ///
    /// # async fn example() -> Result<(), http_kit::BodyError> {
    /// let mut request = Request::post("/api/echo");
    /// request.replace_body("Hello, world!");
    ///
    /// let text = request.into_string().await?;
    /// assert_eq!(text, "Hello, world!");
    /// # Ok(())
    /// # }
    /// ```
    pub async fn into_string(&mut self) -> Result<ByteStr, BodyError> {
        self.take_body()?.into_string().await
    }

    /// Deserializes the request body as JSON into the specified type.
    ///
    /// This method reads the request body and attempts to deserialize it as JSON.
    /// It validates that the `Content-Type` header is `application/json` before
    /// attempting deserialization, making it safe for API endpoints.
    ///
    /// The deserialization is performed with zero-copy when possible by working
    /// directly with the buffered byte data.
    ///
    /// # Errors
    ///
    /// Returns `crate::Error` if:
    /// - The `Content-Type` header is not `application/json`
    /// - The body has already been consumed
    /// - The JSON is malformed or doesn't match the target type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "json")]
    /// # {
    /// use http_kit::Request;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct User { name: String, age: u32 }
    ///
    /// # async fn example() -> Result<(), http_kit::Error> {
    /// let json_data = r#"{"name": "Alice", "age": 30}"#;
    /// let mut request = Request::post("/api/users")
    ///     .header(http::header::CONTENT_TYPE, "application/json");
    /// request.replace_body(json_data);
    ///
    /// let user: User = request.into_json().await?;
    /// assert_eq!(user.name, "Alice");
    /// # Ok(())
    /// # }
    /// # }
    /// ```
    #[cfg(feature = "json")]
    pub async fn into_json<'a, T>(&'a mut self) -> Result<T, crate::Error>
    where
        T: serde::Deserialize<'a>,
    {
        use crate::ResultExt;

        assert_content_type!("application/json", self.headers());

        serde_json::from_slice(self.body.as_bytes().await?).status(crate::StatusCode::BAD_REQUEST)
    }

    /// Deserializes the request body as URL-encoded form data into the specified type.
    ///
    /// This method reads the request body and attempts to deserialize it as
    /// `application/x-www-form-urlencoded` data. It validates that the `Content-Type`
    /// header matches before attempting deserialization.
    ///
    /// The deserialization is performed with zero-copy when possible by working
    /// directly with the buffered byte data.
    ///
    /// # Errors
    ///
    /// Returns `crate::Error` if:
    /// - The `Content-Type` header is not `application/x-www-form-urlencoded`
    /// - The body has already been consumed
    /// - The form data is malformed or doesn't match the target type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "form")]
    /// # {
    /// use http_kit::Request;
    /// use serde::Deserialize;
    ///
    /// #[derive(Deserialize)]
    /// struct LoginForm { username: String, password: String }
    ///
    /// # async fn example() -> Result<(), http_kit::Error> {
    /// let form_data = "username=alice&password=secret";
    /// let mut request = Request::post("/login")
    ///     .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    /// request.replace_body(form_data);
    ///
    /// let form: LoginForm = request.into_form().await?;
    /// assert_eq!(form.username, "alice");
    /// # Ok(())
    /// # }
    /// # }
    /// ```
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
    /// Sets the MIME type for the request.
    ///
    /// This method sets the `Content-Type` header using a parsed MIME type,
    /// providing type safety and validation for content types.
    ///
    /// # Arguments
    ///
    /// * `mime` - The MIME type to set
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "mime")]
    /// # {
    /// use http_kit::Request;
    /// use mime;
    ///
    /// let request = Request::post("/api/data")
    ///     .mime(mime::APPLICATION_JSON);
    /// # }
    /// ```
    #[cfg(feature = "mime")]
    pub fn mime(mut self, mime: mime::Mime) -> Self {
        self.insert_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_str(mime.as_ref()).unwrap(),
        );
        self
    }

    /// Parses the `Content-Type` header and returns a MIME type.
    ///
    /// This method attempts to parse the `Content-Type` header value as a MIME type,
    /// providing structured access to content type information.
    ///
    /// # Returns
    ///
    /// Returns `Some(mime::Mime)` if the header exists and can be parsed,
    /// or `None` if the header is missing or invalid.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "mime")]
    /// # {
    /// use http_kit::Request;
    /// use mime;
    ///
    /// let request = Request::post("/api/data")
    ///     .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8");
    ///
    /// if let Some(mime_type) = request.get_mime() {
    ///     assert_eq!(mime_type.type_(), mime::APPLICATION);
    ///     assert_eq!(mime_type.subtype(), mime::JSON);
    /// }
    /// # }
    /// ```
    #[cfg(feature = "mime")]
    pub fn get_mime(&self) -> Option<mime::Mime> {
        core::str::from_utf8(self.get_header(http::header::CONTENT_TYPE)?.as_bytes())
            .ok()?
            .parse()
            .ok()
    }
}
