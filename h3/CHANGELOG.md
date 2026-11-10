# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
