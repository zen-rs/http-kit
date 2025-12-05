# http-kit

[![crates.io](https://img.shields.io/crates/v/http_kit.svg)](https://crates.io/crates/http_kit) [![doc.rs](https://img.shields.io/badge/docs-latest-blue.svg?style=flat-square)](https://docs.rs/http_kit)

A flexible and ergonomic HTTP toolkit for Rust that provides high-level abstractions for HTTP operations while maintaining performance and type safety.

## Features

- **Type-safe HTTP primitives** - Request, Response, Headers, and Body types with strong type checking
- **Streaming support** - Efficient handling of large payloads through streaming interfaces
- **Body transformations** - Convert between different body formats (JSON, form data, files) with zero-copy when possible
- **Middleware system** - Extensible middleware architecture for request/response processing
- **Async/await ready** - Built on top of `futures-lite` for async I/O operations

## Optional Features

- `json` - JSON serialization/deserialization via serde_json
- `form` - Form data handling via serde_urlencoded
- `fs` - File upload support with MIME type detection
- `mime` - MIME type parsing and manipulation
- `http_body` - Implementation of http_body traits

## Example

```rust
use http_kit::{Request, Response, Result};

async fn handler(mut req: Request) -> Result<Response> {
    // Parse JSON request body
    let user = req.into_json().await?;

    // Create JSON response
    Response::empty()
        .status(200)
        .json(&user)
}
```

## License

This project is licensed under the MIT license.
