# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
