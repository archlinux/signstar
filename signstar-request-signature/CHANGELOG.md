# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-28

### Added

- *(deps)* Update rustcrypto crates
- Always require the `user` argument when running `signstar-request-signature send`
- Always require `expect` attributes instead of `allow`s
- Use configuration file when sending signing requests
- Make executable and related dependencies optional in `signstar-request-signature`

### Fixed

- [**breaking**] Diversify the logger setup for journald and terminal
- *(deps)* More strictly lock the version ranges for custom dependencies
- *(deps)* Update Rust crate russh to v0.63.3
- Use `NonZeroU32` for exit status code failures
- *(deps)* Update Rust crate russh to v0.62.1
- *(deps)* Update Rust crate russh to 0.61.0
- *(deps)* Update Rust crate hmac to 0.13.0 and sha1 to 0.11.0
- *(deps)* Update Rust crate russh to 0.59.0
- Remove unnecessary call to `into`
- *(deps)* Update Rust crate russh to 0.58.0
- *(deps)* Update Rust crate russh to 0.57.0
- Update test vectors for sha2 hasher state
- *(deps)* Update Rust crate russh to v0.55.0

### Other

- Enforce binary ID for `_containerized-integration-test` tests
- Convert `allow`s into `expect`s
- Remove redundant denies that are defined using workspace lints
- Format all JSON files using `biome`
- *(deps)* Update Rust crate ssh-agent-lib to v0.6.0
- Use `digest-io` dependency instead of our own struct
- *(deps)* Move `sha1` crate to workspace dependencies
- *(deps)* Move `serde_json` crate to workspace dependencies
- Use base64ct instead of base64 in `signstar-request-signature`
- *(deps)* Update dependencies
- *(cargo)* Move crate `clap-verbosity-flag` to workspace dependencies
- *(cargo)* Use crate `tokio` from workspace dependencies
- *(cargo)* Move crate `tempfile` to workspace dependencies

## [0.1.3] - 2025-08-19

### Added

- Add logging with verbosity to `signstar-request-signature`

### Fixed

- *(deps)* Update Rust crate russh to 0.54.0

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
