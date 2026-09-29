# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-29

### Added

- Add `NetHsmUserMapping::CertificateRetrieval`
- Add `YubiHsm2UserMapping::CertificateRetrieval`
- [**breaking**] Support sets of filters with `Config::user_backend_connections`
- [**breaking**] Extend `CryptographicKeyContext::OpenPgp` with `notations`
- Append Signer's UID to issued signatures
- Port to new `Config` format
- *(cargo)* Rename `mockhsm` feature to `_yubihsm2-mockhsm`
- *(cargo)* Rename `test-helpers` feature to `_test-helpers`
- Use `yubihsm::device::SerialNumber` in `YubiHsmConnection`
- Add support for YubiHSM signing to `signstar-sign`
- Move OpenPGP related logic out of `nethsm` into `signstar-crypto`
- [**breaking**] Use `UserWithPassphrase` instead of `FullCredentials`
- Add `BackendConnection::YubiHsm2` for YubiHSM2 backend connections
- [**breaking**] Use `signstar_crypto::key::SigningKeySetup` in `UserMapping`
- [**breaking**] Support using different HSM backends in `SignstarConfig`

### Fixed

- [**breaking**] Diversify the logger setup for journald and terminal
- Update test vectors for sha2 hasher state
- Use debug builds with all features for testing `signstar-yubihsm2`

### Other

- Add documentation for NetHSM test routes
- Rely on coverage collection functionality in change-user-run
- Remove warning for `_yubihsm2-mockhsm` feature debug requirement
- Enforce binary ID for `_containerized-integration-test` tests
- [**breaking**] Expose all signstar_crypto errors over top-level Error type
- Add writing of authorized keys files to `SystemUserConfig::apply`
- [**breaking**] Use `AuthorizedKeyEntry`/`SystemUserId` via `config` module
- [**breaking**] Add all available config fixtures to `ConfigFileVariant`
- Imply `yubihsm2` with `mockhsm` feature and guard tests
- *(README)* Improve information about available features
- Use base64ct instead of base64 in `signstar-sign`
- *(cargo)* Move crate `clap-verbosity-flag` to workspace dependencies
- *(cargo)* Move crate `tempfile` to workspace dependencies
- [**breaking**] Change name to `UserMapping::SystemYubiHsm2OperatorSigning`

## [0.1.1] - 2025-08-19

### Added

- Use `change-user-run` crate instead of `signstar_config::test`
- Add `SignstarConfig` for the configuration on Signstar hosts
- Enable generation of shell completions and man pages for `signstar-sign`
- Add logging with verbosity to `signstar-sign`

### Other

- Collect coverage produced by tests run (partially) as other user

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
