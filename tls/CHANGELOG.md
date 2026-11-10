# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
