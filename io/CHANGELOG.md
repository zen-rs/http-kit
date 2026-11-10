# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
