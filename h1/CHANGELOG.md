# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.1](https://github.com/zen-rs/http-kit/compare/h1/v0.6.0...h1/v0.6.1) - 2026-11-11

### Other

- updated the following local packages: http-kit-io, http-kit

## [0.6.0](https://github.com/zen-rs/http-kit/compare/h1/v0.5.0...h1/v0.6.0) - 2026-11-11

### Added

- *(body)* [**breaking**] poll_frame_offering takes an optional offer
- *(h1)* send queued buffers through write_all_owned
- *(io)* [**breaking**] zero-copy send for large writes on io_uring
- *(h1)* [**breaking**] receive through ReadOwned
- [**breaking**] per-request receive deadlines, and typed failures for a body that ends early
- *(io)* [**breaking**] per-capability traits replace Io, and a resolver joins them

### Other

- *(h1)* drop an unused import
- *(h1)* reuse one pipe per connection for spliced bodies

## [0.5.0](https://github.com/zen-rs/http-kit/compare/h1/v0.4.0...h1/v0.5.0) - 2026-11-11

### Added

- *(h1)* [**breaking**] splice bodies in both directions

### Fixed

- *(h1)* offer the pipe after decoding framing, before reading

## [0.4.0](https://github.com/zen-rs/http-kit/compare/h1/v0.3.0...h1/v0.4.0) - 2026-11-10

### Added

- *(h1)* [**breaking**] make the connection settings non-exhaustive
- *(h1)* [**breaking**] add a client read timeout

## [0.3.0](https://github.com/zen-rs/http-kit/compare/h1/v0.2.3...h1/v0.3.0) - 2026-11-10

### Added

- *(h1)* hand back a request the connection never wrote

### Other

- Merge pull request #98 from zen-rs/fix/93-h1-try-send
- *(body)* [**breaking**] share a file region's file through an Arc

## [0.2.3](https://github.com/zen-rs/http-kit/compare/h1/v0.2.2...h1/v0.2.3) - 2026-11-10

### Fixed

- *(tls,h1)* a peer that closes first is not an error

## [0.2.2](https://github.com/zen-rs/http-kit/compare/h1/v0.2.1...h1/v0.2.2) - 2026-11-10

### Other

- *(h1)* create the 100-continue channels only for requests that expect it, and keep the outbox and head buffer per connection
- *(h1)* parse a head with more fields than the stack slots hold
- *(h1)* parse heads into stack-held header slots

## [0.2.1](https://github.com/zen-rs/http-kit/compare/h1/v0.2.0...h1/v0.2.1) - 2026-11-10

### Other

- updated the following local packages: http-kit-io

## [0.2.0](https://github.com/zen-rs/http-kit/compare/h1/v0.1.1...h1/v0.2.0) - 2026-11-10

### Added

- *(io)* [**breaking**] Unix-domain stream listeners

## [0.1.1](https://github.com/zen-rs/http-kit/compare/h1/v0.1.0...h1/v0.1.1) - 2026-11-10

### Other

- updated the following local packages: http-kit-io, http-kit

## [0.1.0](https://github.com/zen-rs/http-kit/releases/tag/http-kit-h1-v0.1.0) - 2026-11-10

### Added

- *(h1)* absolute-form client targets and close-delimited coded responses
- *(h1)* header-read, keep-alive idle, body-read and 100-continue timeouts
- *(h1)* add http-kit-h1, a sans-IO HTTP/1.1 server and client

### Fixed

- *(h1)* an idle keep-alive deadline closes the connection normally

### Other

- *(h1)* pass a timer to the new client tests
- Merge origin/dev into feat/40-h1-client-proxy
