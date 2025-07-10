# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-07-10

### Added

- Log errors if the command returned with a non-zero status
- [**breaking**] Fold `signstar-test` into `signstar-config` as a separate `test` module
- Add `signstar-sign`

### Fixed

- Update `rcgen` code for new API
- *(deps)* Update Rust crate which to v8

### Other

- *(deps)* Update Rust crate rcgen to 0.14.0
- Reformat all TOML files with `taplo`
- Remove use of deprecated `tempfile::TempDir::into_path`
