# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.2](https://github.com/zen-rs/http-kit/compare/tls/v0.4.1...tls/v0.4.2) - 2026-11-11

### Other

- updated the following local packages: http-kit-io, http-kit, http-kit-h1

## [0.4.1](https://github.com/zen-rs/http-kit/compare/tls/v0.4.0...tls/v0.4.1) - 2026-11-11

### Other

- updated the following local packages: http-kit-io, http-kit, http-kit-h1

## [0.4.0](https://github.com/zen-rs/http-kit/compare/tls/v0.3.0...tls/v0.4.0) - 2026-11-11

### Added

- *(io)* [**breaking**] zero-copy send for large writes on io_uring
- *(io)* [**breaking**] multishot receive into the runtime's provided buffer ring
- *(tls)* [**breaking**] a typed handshake error
- *(io)* [**breaking**] per-capability traits replace Io, and a resolver joins them

### Fixed

- *(tls)* positioned read on WASI

## [0.3.0](https://github.com/zen-rs/http-kit/compare/tls/v0.2.2...tls/v0.3.0) - 2026-11-11

### Added

- *(tls)* [**breaking**] splice on kernel TLS connections

### Other

- *(tls)* count spliced bytes in the counting write half

## [0.2.2](https://github.com/zen-rs/http-kit/compare/tls/v0.2.1...tls/v0.2.2) - 2026-11-10

### Other

- updated the following local packages: http-kit-h1

## [0.2.1](https://github.com/zen-rs/http-kit/compare/tls/v0.2.0...tls/v0.2.1) - 2026-11-10

### Fixed

- *(tls)* mark the kernel socket reader as a socket half
- *(tls)* one Transport impl for every Split of transport halves

## [0.2.0](https://github.com/zen-rs/http-kit/compare/tls/v0.1.0...tls/v0.2.0) - 2026-11-10

### Added

- *(tls)* run a TLS session over another TLS stream

### Other

- *(tls)* require the counting wrapper to be a transport where it is used

## [0.1.0](https://github.com/zen-rs/http-kit/compare/tls/v0.0.0...tls/v0.1.0) - 2026-11-10

### Added

- *(tls)* rustls over owned-buffer streams, with kernel TLS on Linux

### Fixed

- *(tls,h1)* a peer that closes first is not an error
- *(tls)* build kernel TLS on ktls-sys, and compile on Linux

### Other

- *(tls)* send no session tickets in the truncation test
- *(tls)* take TCP_ULP from libc
