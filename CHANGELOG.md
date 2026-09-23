# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
