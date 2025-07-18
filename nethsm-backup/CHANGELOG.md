# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-07-10

### Added

- Use new integration test feature for all crates instead of `#[ignore]`
- [**breaking**] Fold `nethsm-tests` into `nethsm` as a `test` submodule

### Fixed

- Add explicit lifetime to silence clippy lint

### Other

- Fix violations of MD022 and MD032 in changelogs
- Reformat all TOML files with `taplo`

## [0.1.1] - 2025-04-22

### Added

- Require `Debug` to be implemented in public items

### Other

- *(Cargo.toml)* Fix formatting
- *(deps)* make `log` a workspace dependency
- *(nethsm-backup)* Log inner errors
- Add documentation and enable strict lints for `nethsm-backup`
- Switch to rustfmt style edition 2024

## [0.1.0] - 2024-12-08

### Added

- Add `nethsm-backup` library

### Other

- *(README)* Add links to latest (un)released crate documentation
- *(cargo)* Consolidate dependencies with workspace dependencies
