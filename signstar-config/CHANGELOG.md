# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2025-07-10

### Added

- Add `nethsm` module to interact with NetHSM backends.
- *(test-helpers)* Add helpers for NetHSM backend testing
- [**breaking**] Fold `signstar-test` into `signstar-config` as a separate `test` module
- Introduce `signstar-test` for common test utilities
- Expose all binaries, not only examples in integration tests
- Add `AdminCredentials::get_default_administrator`
- Ensure data for `AdminCredentials` is valid
- Replace the use of `Credentials` with `FullCredentials`
- Replace `User` with `nethsm::FullCredentials`
- Use `nethsm_config::Passphrase` for all administrative passphrases
- Add `signstar-config` crate to handle Signstar host configs

### Fixed

- *(deps)* Update Rust crate which to v8
- *(deps)* update rust crate nix to 0.30.0
- Box the `confy::ConfyError` so that the error size does not explode
- Only fail to load as non-root in `AdminCredentials::load`

### Other

- *(fixtures)* Add more administrator users and diversify key contexts
- Move constants for configuration file contents to test modules
- Reformat all TOML files with `taplo`
- Sort derives using `cargo sort-derives`
- Fix clippy lints regarding variables in `format!`
