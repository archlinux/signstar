# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-27

### Added

- [**breaking**] Move definition of signing API to signstar-common
- Add support for retrieving certificates for HTTP YubiHSM2

### Other

- Upgrade signstar-yubihsm2 crate to 0.2.0
- *(deps)* Update Rust crate httpmock to 0.9.0
- Deprecate crate in favor of a future, more generic one

## [0.1.0] - 2026-09-29

### Added

- Implement `signstar-download-key-certificates`

### Other

- Add documentation for NetHSM test routes
