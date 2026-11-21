# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/zen-rs/http-kit/compare/h2/v0.0.0...h2/v0.1.0) - 2026-11-21

### Added

- *(h2)* add owned-buffer I/O driver, client/server API, and conformance suites
- *(h2)* sans-IO HTTP/2 protocol core, HPACK, and SIMD field validation

### Fixed

- *(h2)* treat post-handshake idle TLS disconnects without close_notify as clean EOF
- *(h2)* prevent pending-write poll spin, order pipe splice reads, and fix x86/Windows CI
- *(h2)* tighten stream teardown, HPACK size updates, and target gates

### Other

- replace the cargo-machete job with cargo::unused_dependencies
- *(h2)* add Linux kTLS Transport bound on abrupt TLS drop helper
