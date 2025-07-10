# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2] - 2025-07-10

### Added

- Use `Digest::update` instead of `copy` for `Request::for_file`
- Use Display for printing errors

### Fixed

- Wrap `sha2::Sha512` in an adapter providing the `std::io::Write` implementation
- *(deps)* Update Rust crate russh to v0.53.0
- Use shorter names for agent socket path in `ssh-roundtrip` test
- *(deps)* update rust crate russh to 0.52.0

### Other

- Fix violations of MD007
- Fix violations of MD022 and MD032 in changelogs
- Reformat all TOML files with `taplo`
- Sort derives using `cargo sort-derives`

## [0.1.1] - 2025-04-22

### Added

- Add `Response::v1` for creating version 1 signing responses
- Add signing specifications to mdbook
- Add `signstar-request-signature send` subcommand for sending signing requests
- Add API to programmatically send signing requests

### Other

- *(deps)* make `log` a workspace dependency
- Add documentation and enable strict lints for `signstar-request-signature`
- Improve code documentation in signstar-request-signature
- Add documentation for Signing Responses
- Switch to rustfmt style edition 2024

## [0.1.0] - 2024-12-13

### Added

- Add minimal binary for producing hash states
