# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0](https://github.com/zen-rs/http-kit/compare/v0.5.2...v0.6.0) - 2026-11-10

### Other

- Merge pull request #96 from zen-rs/fix/91-tls-nested
- Merge pull request #95 from zen-rs/fix/90-io-unix-nodelay
- Merge pull request #98 from zen-rs/fix/93-h1-try-send
- Merge pull request #97 from zen-rs/fix/92-h3-verify-ready
- *(tls)* require the counting wrapper to be a transport where it is used
- Merge remote-tracking branch 'origin/dev' into fix/91-tls-nested
- *(body)* import Read only where the cursor check runs
- *(body)* check the shared file's cursor only where positioned reads keep it
- *(body)* [**breaking**] share a file region's file through an Arc

## [0.5.2](https://github.com/zen-rs/http-kit/compare/v0.5.1...v0.5.2) - 2026-11-10

### Added

- *(tls)* rustls over owned-buffer streams, with kernel TLS on Linux

### Fixed

- *(release)* tag http-kit-h3 h3/v<version>
- *(tls,h1)* a peer that closes first is not an error
- *(tls)* build kernel TLS on ktls-sys, and compile on Linux

### Other

- Merge remote-tracking branch 'origin/dev' into feat/79-tls
- *(tls)* send no session tickets in the truncation test
- *(tls)* take TCP_ULP from libc
- load the kernel TLS module on Linux

## [0.5.1](https://github.com/zen-rs/http-kit/compare/v0.5.0...v0.5.1) - 2026-11-10

### Added

- *(h3)* use each datagram's destination address
- *(io)* report a datagram's destination address and send from a chosen source on Windows
- *(h3)* validate client addresses with a stateless Retry
- *(io)* report a datagram's destination address and send from a chosen source
- *(h3)* HTTP/3 server and client on quiche

### Fixed

- *(h3)* keep driver state off the caller's stack

### Other

- Merge pull request #57 from zen-rs/feat/51-h3-retry
- Merge origin/dev into feat/55-io-windows-pktinfo
- Merge origin/dev into feat/51-h3-retry
- run the full OS matrix on a PR labelled os:all
- Merge origin/dev into feat/52-io-recv-dest
- install an HTTP/3 curl for h3's interop test; depend on http-kit 0.5
- Merge origin/dev into feat/35-http-kit-h3
- tag the main crate v<version> and the others <dir>/v<version>

## [0.5.0](https://github.com/zen-rs/http-kit/compare/http-kit-v0.4.4...http-kit-v0.5.0) - 2026-11-10

### Added

- *(h1)* absolute-form client targets and close-delimited coded responses
- *(h1)* header-read, keep-alive idle, body-read and 100-continue timeouts
- *(h1)* add http-kit-h1, a sans-IO HTTP/1.1 server and client
- impl_send_endpoint! and impl_send_middleware!
- [**breaking**] drop the mandatory Send/Sync bounds on Endpoint, Body and middleware
- *(io)* add http-kit-io, runtime-neutral owned-buffer I/O
- *(body)* [**breaking**] data, trailers and file-region frames

### Fixed

- *(h1)* an idle keep-alive deadline closes the connection normally
- *(io)* drop a no-op drop of the borrowed msghdr

### Other

- *(h1)* pass a timer to the new client tests
- Merge origin/dev into feat/40-h1-client-proxy
- Merge origin/dev into feat/40-h1-client-proxy
- Merge pull request #42 from zen-rs/feat/32-drop-send
- Merge pull request #37 from zen-rs/feat/31-body-frames
- run tests, lints and feature checks across the workspace
- drop the typos check
- run on pull requests only, tiered by target branch

## [0.4.4](https://github.com/zen-rs/http-kit/compare/v0.4.3...v0.4.4) - 2026-10-29

### Fixed

- *(body)* pass trailers through poll_frame
- *(body)* report end of stream and exact size hint

### Other

- *(body)* drop an unused import

## [0.4.3](https://github.com/zen-rs/http-kit/compare/v0.4.2...v0.4.3) - 2026-09-23

### Added

- *(body)* try_clone copies a body whose bytes are in memory ([#11](https://github.com/zen-rs/http-kit/pull/11))

### Fixed

- gate websocket JSON helpers on the json feature and repair stale doc examples

### Other

- publish on push to main; crates.io refuses workflow_run tokens ([#14](https://github.com/zen-rs/http-kit/pull/14))
- Merge remote-tracking branch 'origin/main' into chore/sync-main-into-dev
- run tests with cargo nextest ([#10](https://github.com/zen-rs/http-kit/pull/10))
- publish to crates.io via OIDC trusted publishing ([#8](https://github.com/zen-rs/http-kit/pull/8))
- gate pull requests into main so only dev may merge ([#9](https://github.com/zen-rs/http-kit/pull/9))
- use stable toolchain
- use stable toolchain
- add rust-cache to dep-check workflow
- add weekly dependency check workflow

## [0.4.2](https://github.com/zen-rs/http-kit/compare/v0.4.1...v0.4.2) - 2025-12-09

### Added

- add method to convert Error into a boxed HTTP error trait object

## [0.4.1](https://github.com/zen-rs/http-kit/compare/v0.4.0...v0.4.1) - 2025-12-09

### Added

- replace Error with BoxHttpError in Endpoint and Middleware implementations
- integrate eyre for enhanced error handling in HTTP operations
- add status handling to Option type in ResultExt

## [0.4.0](https://github.com/zen-rs/http-kit/compare/v0.3.0...v0.4.0) - 2025-12-08

### Other

- Update HttpError trait documentation to return StatusCode directly
- Add JSON serialization support to WebSocketMessage
- Refactor HttpError trait to return StatusCode directly instead of Option<StatusCode>
- Refactor WebSocketMessage Close variant to remove Bytes and update close message constructor
- Refactor close message constructor in WebSocketMessage to accept any type that can be converted to a byte slice
- Refactor WebSocketMessage enum to include Bytes in Close variant and update close message constructor
- Remove Frame variant from WebSocketMessage enum
- Add Frame and Close message constructors to WebSocketMessage
- Enhance WebSocketMessage::into_json to support custom deserialization types
- Add ping and pong message construction methods to WebSocketMessage
- Add JSON message construction and conversion methods to WebSocketMessage
- Refactor WebSocket types and configuration for improved clarity and structure
- Update bytestr dependency version to 0.3.1 for improved functionality and compatibility.
- Refactor error handling to remove Option from status in Error struct and related traits
- Remove installation instructions from README.md to streamline documentation.
