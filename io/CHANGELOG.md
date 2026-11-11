# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.2](https://github.com/zen-rs/http-kit/compare/io/v0.6.1...io/v0.6.2) - 2026-11-11

### Fixed

- *(io)* report what a compio file round sent before it failed

## [0.6.1](https://github.com/zen-rs/http-kit/compare/io/v0.6.0...io/v0.6.1) - 2026-11-11

### Fixed

- *(io)* start no task when a stream with a file slot drops

## [0.6.0](https://github.com/zen-rs/http-kit/compare/io/v0.5.0...io/v0.6.0) - 2026-11-11

### Added

- *(io)* [**breaking**] name stream sockets by registered file slots on io_uring
- *(io)* [**breaking**] zero-copy send for large writes on io_uring
- *(io)* [**breaking**] multishot receive into the runtime's provided buffer ring
- *(io)* [**breaking**] per-capability traits replace Io, and a resolver joins them

### Other

- *(io)* drop an unused import
- Merge remote-tracking branch 'origin/main' into feat/124-multishot-accept
- *(io)* accept with one multishot submission on io_uring

## [0.5.0](https://github.com/zen-rs/http-kit/compare/io/v0.4.0...io/v0.5.0) - 2026-11-11

### Added

- *(tls)* [**breaking**] splice on kernel TLS connections
- *(io)* socket-to-socket splice through a pipe

### Fixed

- *(io)* build the pipe types without a runtime feature
- *(io)* splice into a socket without holding a kernel worker

## [0.4.0](https://github.com/zen-rs/http-kit/compare/io/v0.3.2...io/v0.4.0) - 2026-11-10

### Added

- *(io)* connect to Unix-domain sockets and set TCP_NODELAY on streams

## [0.3.2](https://github.com/zen-rs/http-kit/compare/io/v0.3.1...io/v0.3.2) - 2026-11-10

### Added

- *(io)* write with control messages, and descriptors on split halves

## [0.3.1](https://github.com/zen-rs/http-kit/compare/io/v0.3.0...io/v0.3.1) - 2026-11-10

### Added

- *(io)* adopt a connected compio TCP stream

## [0.3.0](https://github.com/zen-rs/http-kit/compare/io/v0.2.0...io/v0.3.0) - 2026-11-10

### Added

- *(io)* [**breaking**] Unix-domain stream listeners

### Fixed

- *(io)* give compio sockets their descriptor on every Unix path

## [0.2.0](https://github.com/zen-rs/http-kit/compare/io/v0.1.0...io/v0.2.0) - 2026-11-10

### Added

- *(io)* report a datagram's destination address and send from a chosen source on Windows
- *(io)* report a datagram's destination address and send from a chosen source

## [0.1.0](https://github.com/zen-rs/http-kit/releases/tag/http-kit-io-v0.1.0) - 2026-11-10

### Added

- *(io)* add http-kit-io, runtime-neutral owned-buffer I/O

### Fixed

- *(io)* drop a no-op drop of the borrowed msghdr

### Other

- run tests, lints and feature checks across the workspace
