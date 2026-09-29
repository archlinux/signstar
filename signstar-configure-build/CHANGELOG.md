# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-09-29

### Added

- [**breaking**] Rename `SystemUserMapping` variant for WireGuard config downloads
- Add `NetHsmUserMapping::CertificateRetrieval`
- Add `YubiHsm2UserMapping::CertificateRetrieval`
- *(deps)* Update rustcrypto crates
- [**breaking**] Support sets of filters with `Config::user_backend_connections`
- Add created users to the `_yubihsm2` group
- Add logging to `signstar-configure-build`
- Port to new `Config` format
- *(cargo)* Rename `mockhsm` feature to `_yubihsm2-mockhsm`
- *(cargo)* Add a `mockhsm` feature, switching on the `yubihsm2` feature
- Add metrics related variants for `UserMapping`
- Add `UserMapping::SystemYubiHsm2Backup`
- Add `UserMapping::YubiHsmOnlyAdmin`
- *(cargo)* Use workspace lints
- Add `UserMapping::SystemYubiHsmOperatorSigning` for YubiHSM2
- [**breaking**] Use `signstar_crypto::key::SigningKeySetup` in `UserMapping`
- [**breaking**] Support using different HSM backends in `SignstarConfig`

### Fixed

- Align the naming of `signstar-download-key-certificates`
- Fix `DisableForwarding` instruction
- Disable all SSH forwarding features for Signstar host system users
- [**breaking**] Diversify the logger setup for journald and terminal
- Set a random passphrase for created users
- *(deps)* Update Rust crate sysinfo to v0.39.0
- *(deps)* Update Rust crate nix to 0.31.0
- *(deps)* Update Rust crate sysinfo to v0.38.0

### Other

- Remove warning for `_yubihsm2-mockhsm` feature debug requirement
- *(fixtures)* Consolidate the naming of system users in configs
- [**breaking**] Use `AuthorizedKeyEntry`/`SystemUserId` via `config` module
- *(README)* Improve information about available features
- Make `AuthorizedKeyEntry` a newtype for `Entry` not `String`
- *(cargo)* Move `nix` crate to workspace dependencies
- [**breaking**] Change name to `UserMapping::YubiHsm2OnlyAdmin`
- [**breaking**] Change name to `UserMapping::SystemYubiHsm2OperatorSigning`
- Make `Error::NoForceCommandForMapping` more generic
- Use clap's '-V'/`--version` integration instead of a custom one
- Document all publicly visible items

## [0.3.0] - 2025-08-19

### Added

- Replace `HermeticParallelConfig` with `SignstarConfig`

### Fixed

- *(deps)* Update Rust crate sysinfo to v0.37.0
- *(deps)* Update Rust crate sysinfo to 0.36.0

### Other

- Use `signstar-sign` when configuring accounts for signing

## [0.2.0] - 2025-07-10

### Added

- Use Display for printing errors
- Rely on `signstar-common` crate for default locations

### Fixed

- *(deps)* update rust crate nix to 0.30.0
- *(deps)* update rust crate sysinfo to 0.35.0
- *(deps)* update rust crate sysinfo to v0.34.0

### Other

- Fix violations of MD007
- Fix violations of MD022 and MD032 in changelogs
- Reformat all TOML files with `taplo`
- Sort derives using `cargo sort-derives`
- Switch to rustfmt style edition 2024
- Add `non_admin_secret_handling` to example configuration
- Add `admin_secret_handling` to example configuration

## [0.1.2] - 2024-12-08

### Fixed

- *(deps)* update rust crate sysinfo to 0.33.0

### Other

- *(README)* Add links to latest (un)released crate documentation

## [0.1.1] - 2024-11-27

### Other

- Update libc crate as the previously used version was yanked

## [0.1.0] - 2024-11-26

### Added

- Add build-time configuration tool for signstar host

### Other

- Consolidate contributing and licensing information
