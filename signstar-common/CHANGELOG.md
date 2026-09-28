# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-28

### Added

- Implement `signstar-download-key-certificates`
- Add types for certificate request and response
- [**breaking**] Introduce a crate-level error type for signstar-common
- Add `BackendType` to track information about supported HSM types
- Add trait `BackendCheck` to check backend functionality
- *(cargo)* Use workspace lints
- Rely on `log::Level` instead of `nethsm::LogLevel` for defaults

### Fixed

- [**breaking**] Diversify the logger setup for journald and terminal
- Try to connect to journald socket instead of relying on `connected_to_journal`

### Other

- *(deps)* Move `simplelog` crate to workspace dependencies
- *(README)* Improve information about available features
- Document all publicly visible items

## [0.1.2] - 2025-08-19

### Added

- Add systemd journal logging module to `signstar-common`

## [0.1.1] - 2025-07-10

### Other

- Fix violations of MD022 and MD032 in changelogs
- Reformat all TOML files with `taplo`

## [0.1.0] - 2025-04-22

### Added

- Add `signstar-common` crate to provide common facilities
