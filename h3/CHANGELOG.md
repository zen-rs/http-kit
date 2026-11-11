# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2](https://github.com/zen-rs/http-kit/compare/h3/v0.6.1...h3/v0.6.2) - 2026-11-11

### Other

- updated the following local packages: http-kit-io, http-kit

## [0.6.1](https://github.com/zen-rs/http-kit/compare/h3/v0.6.0...h3/v0.6.1) - 2026-11-11

### Other

- updated the following local packages: http-kit-io, http-kit

## [0.6.0](https://github.com/zen-rs/http-kit/compare/h3/v0.5.0...h3/v0.6.0) - 2026-11-11

### Added

- *(io)* [**breaking**] zero-copy send for large writes on io_uring
- [**breaking**] per-request receive deadlines, and typed failures for a body that ends early
- *(io)* [**breaking**] per-capability traits replace Io, and a resolver joins them

### Other

- *(h3)* clone the compio driver into the curl server

## [0.5.0](https://github.com/zen-rs/http-kit/compare/h3/v0.4.0...h3/v0.5.0) - 2026-11-11

### Added

- *(h1)* [**breaking**] splice bodies in both directions

## [0.4.0](https://github.com/zen-rs/http-kit/compare/h3/v0.3.0...h3/v0.4.0) - 2026-11-11

### Added

- *(h3)* [**breaking**] make the transport, server and client settings non-exhaustive
- *(h3)* give back a request that left nothing on the wire

### Fixed

- *(h3)* [**breaking**] show the Verifier the stapled OCSP response

### Other

- Merge pull request #115 from zen-rs/fix/108-h3-try-send

## [0.3.0](https://github.com/zen-rs/http-kit/compare/h3/v0.2.2...h3/v0.3.0) - 2026-11-10

### Added

- *(h3)* verify the server's chain with a caller's function and expose handshake completion

## [0.2.2](https://github.com/zen-rs/http-kit/compare/h3/v0.2.1...h3/v0.2.2) - 2026-11-10

### Other

- updated the following local packages: http-kit-io, http-kit

## [0.2.1](https://github.com/zen-rs/http-kit/compare/http-kit-h3-v0.2.0...http-kit-h3-v0.2.1) - 2026-11-10

### Other

- updated the following local packages: http-kit-io

## [0.2.0](https://github.com/zen-rs/http-kit/compare/http-kit-h3-v0.1.1...http-kit-h3-v0.2.0) - 2026-11-10

### Added

- *(h3)* [**breaking**] build on http-kit-io 0.3 and re-export it

### Fixed

- *(h3)* re-export http-kit-io only where the crate depends on it

## [0.1.1](https://github.com/zen-rs/http-kit/compare/http-kit-h3-v0.1.0...http-kit-h3-v0.1.1) - 2026-11-10

### Other

- updated the following local packages: http-kit-io

## [0.1.0](https://github.com/zen-rs/http-kit/compare/http-kit-h3-v0.0.0...http-kit-h3-v0.1.0) - 2026-11-10

### Added

- *(h3)* use each datagram's destination address
- *(h3)* validate client addresses with a stateless Retry
- *(h3)* HTTP/3 server and client on quiche

### Fixed

- *(h3)* keep driver state off the caller's stack

### Other

- install an HTTP/3 curl for h3's interop test; depend on http-kit 0.5
