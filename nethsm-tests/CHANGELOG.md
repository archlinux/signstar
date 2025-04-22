# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2025-04-22

### Added
- Re-export `rustainers::Container` for ease of use
- [**breaking**] Initialize `NetHsm` using a `Connection`

### Fixed
- Use `WaitStrategy::HttpSuccess` for checking NetHSM status

### Other
- Switch to rustfmt style edition 2024

## [0.1.2] - 2024-12-08

### Other
- *(README)* Add links to latest (un)released crate documentation
- *(cargo)* Consolidate dependencies with workspace dependencies

## [0.1.1] - 2024-11-27

### Other
- Update libc crate as the previously used version was yanked

## [0.1.0] - 2024-11-26

### Added
- Introduce `nethsm-tests` for easier integration testing

### Other
- Consolidate contributing and licensing information
