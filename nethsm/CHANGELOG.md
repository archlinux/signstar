# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.0] - 2025-08-19

### Added

- Use one location for NetHSM image tag to make it consistent everywhere
- [**breaking**] Remove NIST P-224 as it has been removed upstream

### Fixed

- Remove suppression for `missing_docs` as `rstest` now does not trigger this lint

## [0.9.2] - 2025-07-10

### Other

- update Cargo.toml dependencies

## [0.9.1] - 2025-07-09

### Added

- Add `Display` impl for `CryptographicKeyContext`
- Add `NetHsm::get_current_user` to retrieve current auth user
- Add `NetHsm::get_url` to retrieve the current URL
- [**breaking**] Allow detecting when the certificate has not been uploaded
- Use new integration test feature for all crates instead of `#[ignore]`
- Add debug logs to all `NetHsm` methods
- Expose default max idle connections and timeout as consts
- Derive strums `AsRefStr` and `Display` for `NamespaceSupport`
- Implement `AsRef<KeyFlags>` for `KeyUsageFlags`
- Implement `Display` for `Credentials`
- Implement `Display` for `Passphrase`
- Implement `Display` for `Connection`
- Implement `Display` for `ConnectionSecurity`
- Implement `Display` for `HostCertificateFingerprints`
- Implement `Display` for `CertFingerprint`
- Derive `Copy` for `BootMode`
- Allow creating `CryptographicKeyContext` from `SignedPublicKey`
- Create `KeyMechanism` from `nethsm_sdk_rs::models::KeyMechanism`
- Automatically remove containers started by the test
- [**breaking**] Fold `nethsm-tests` into `nethsm` as a `test` submodule

### Fixed

- Do not remove creds before adding them in `NetHsm::add_credentials`
- Inline the variable to avoid the `clippy::uninlined_format_args` lint warning
- *(deps)* [**breaking**] upgrade rpgp to 0.16.0

### Other

- Fix violations of MD022 and MD032 in changelogs
- *(deps)* Move `pgp` to workspace dependencies
- Reformat all TOML files with `taplo`
- Sort derives using `cargo sort-derives`
- Fix clippy lints regarding variables in `format!`
- Stop adding Certification flag to generated primary keys

## [0.8.0] - 2025-04-22

### Added

- Add `OpenPgpUserIdList::first`
- Add `From<nethsm_sdk_rs::models::UserRole>` for `UserRole`
- [**breaking**] Return a list of `KeyId`s, not `String`s from `NetHsm::get_keys`
- [**breaking**] Return `NamespaceId`s not `String`s from `NetHsm::get_namespaces`
- [**breaking**] Return a list of `UserId`s not `String`s from `NetHsm::get_users`
- [**breaking**] Rely on `NamespaceId` instead of `String` for robustness
- Publicly re-export `chrono::DateTime` and `chrono::Utc`
- [**breaking**] make `openpgp_sign_state` always return an armored OpenPGP signature
- Require `Debug` to be implemented in public items
- Add `NetHsm::set_agent`, allowing to modify the connection agent
- [**breaking**] Initialize `NetHsm` using a `Connection`
- Add `FullCredentials` which requires passphrases for credentials
- Add custom `serde::Serialize` for `Passphrase`
- Derive `serde::Deserialize` for `Passphrase`
- Derive `Default` for `Passphrase`
- Derive `Clone` for `Credentials`
- Derive `Debug` for `Credentials`
- Rely on `aws-lc-rs` as default crypto provider for `rustls`

### Fixed

- *(deps)* update rust crate pgp to 0.15

### Other

- Move `nethsm::key::Error` to top of doc for easier discovery
- *(tests)* Change equality asserts to use `assert_eq!` for better error messages
- Wrap inner errors in I/O other errors for error propagation
- *(nethsm)* Log inner errors in `nethsm::openpgp` module
- Add documentation for the `nethsm` crate and require it globally
- Create `Agent` for `NetHsm` in a `tls::create_agent`
- Adjust `NetHsm::new` for the use of `Connection`
- Move `nethsm_config::Connection` to `nethsm::Connection`
- Move `Url` to a `connection` module and improve error handling
- Switch to rustfmt style edition 2024

## [0.7.3] - 2024-12-13

### Added

- Add `NetHsm::openpgp_sign_state`

## [0.7.2] - 2024-12-08

### Added

- Add `validate_backup` to validate NetHSM backups
- Add `Passphrase::expose_borrowed`

### Other

- *(README)* Add links to latest (un)released crate documentation
- *(deps)* Update dependencies to fix security issues
- *(cargo)* Consolidate dependencies with workspace dependencies

## [0.7.1] - 2024-11-27

### Other

- Update libc crate as the previously used version was yanked

## [0.7.0] - 2024-11-26

### Added

- Introduce `nethsm-tests` for easier integration testing
- Derive `Copy` for `nethsm::UserRole`
- Implement `AsRef<str>` for `NamespaceId` to return string slice
- Rely on `serde`'s `into` and `try_from` attributes for `KeyId`
- Rely on `serde`'s `into` and `try_from` attributes  for `UserId`
- Add `SigningKeySetup` struct to track key setups for signing
- Add `CryptographicKeyContext` to track a key's crypto context
- [**breaking**] Provide version with `OpenPgpVersion` when creating OpenPGP certificate
- [**breaking**] Use `OpenPgpUserId` for User ID when creating OpenPGP certificate
- Add `OpenPgpVersion` to track OpenPGP version
- Add `OpenPgpUserId` and `OpenPgpUserIdList` for OpenPGP User IDs
- Add function to validate `SignatureType` against other key data
- Derive `Deserialize` and `Serialize` for `SignatureType`
- Derive `Hash`, `Eq` and `PartialEq` for some types

### Fixed

- *(deps)* update rust crate picky-asn1-x509 to 0.14.0
- Properly truncate digests for ECDSA signing schemes
- Make serde use `TryFrom<String>` for deserialization
- *(deps)* Update dependencies removing yanked crate
- *(deps)* Migrate to rpgp v0.14.0
- Print more details on errors
- *(deps)* Update `secrecy` to version `0.10.2`
- *(deps)* update rust crate strum to 0.26.0
- Read real value of the RSA modulus instead of using a hardcoded one

### Other

- Consolidate contributing and licensing information
- *(deps)* Update dependencies and fix license ID
- *(cargo)* Move same-crate, feature-incompatible crates to workspace
- *(cargo)* Move common dependencies to workspace dependencies
- *(cargo)* Move shared dependencies to workspace dependencies
- *(cargo)* Move package metadata to workspace
- Use correct link to upstream Error type in `nethsm_sdk::Message`
- Add docs for and spacing between `nethsm::key::Error` variants
- *(deps)* update rust crate rstest to 0.23.0
- Refactor error cases to use `Error::UnsupportedKeyFormat`
- *(deps)* update rust crate rustainers to 0.13.0

## [0.6.0] - 2024-09-11

### Added

- Ensure valid bit length when generating RSA TLS keys
- Ensure valid bit length for block cipher and RSA keys

### Fixed

- Adjust broken links in `KeyId` documentation

### Other

- [**breaking**] Introduce `nethsm::KeyId` type
- Improve documentation for Error variant `Error::Key`
- [**breaking**] Remove unused Error variant `Error::KeyData`
- Provide function to check KeyType - KeyMechanism compatibility
- [**breaking**] Use `u32` instead of `i32` for ports and lengths

## [0.5.0] - 2024-09-06

### Fixed

- *(deps)* [**breaking**] update rust crate rustls-native-certs to 0.8.0
- Pad secret keys with zeros before sending them to NetHSM
- Use correct function for constructing MPIs

### Other

- Make `SignatureType` a copy type
- Import keys of all supported types
- *(Cargo.toml)* Remove duplicate rand development dependency
- Replace ed25519-compact with ed25519-dalek in all tests

## [0.4.0] - 2024-08-30

### Added

- Validate namespace access using `UserId` method
- Add `UserId` and `NamespaceId` types for handling User IDs
- Add facilities for namespace administration
- Add facilities for OpenPGP certificate creation and signing
- Add support for PEM-encoded private keys in `key import`

### Fixed

- *(Cargo.toml)* Have cargo-machete ignore the md-5 dependency
- Do not require `Administrator` role when executing `unlock`
- Adjust the test to remove credentials as they are not needed in `unlock`
- Adjust functions as `update_file` does not need to be async
- Reduce the number of direct dependencies
- *(README.md)* Remove license attribution as it is in reuse config

### Other

- Remove warning from `NetHsm::restore` method
- Adapt existing documentation for the use of namespaces
- Adapt and extend tests for use of namespaces
- [**breaking**] Move `Credentials` and `Passphrase` to user module
- Adjust information on output format on public key retrieval
- Adjust documentation on authentication for unlock call
- Split tests for retrieval of TLS public key
- Fix user role requirements for backup retrieval
- *(deps)* update rust crate rstest to 0.22.0
- Pin nethsm container image version to c16fe4ed
- *(nethsm/tests/config.rs)* Fix create_backup test
- Simplify license attribution setup for entire project

## [0.3.0] - 2024-07-12

### Added

- Add functions to return key type specific lists of key mechanisms
- Extend FromStr for ConnectionSecurity to cover case sensitivity
- Derive strum::IntoStaticStr for various types
- Derive strum::EnumIter for various types
- [**breaking**] Assemble connection configuration only when it is needed
- [**breaking**] Use secrecy for passphrase zeroing
- Publicly re-export all required nethsm-sdk-rs models

### Fixed

- *(nethsm/src/nethsm_sdk.rs)* Fix spelling mistake in error message

### Other

- Switch rustls's crypto provider to ring
- Describe output data types for signing functionality
- *(Cargo.toml)* Remove strum_macros as it is unused
- Assemble user agent string from crate data
- Make container setup with fixtures more robust
- Use TestResult for all doc tests

## [0.2.0] - 2024-05-10

### Added

- [**breaking**] Use PrivateKeyImport for import of private key material
- Provide own LogLevel
- Provide own EncryptMode
- Provide own DecryptMode
- Provide own KeyMechanism
- Provide own TlsKeyType
- Provide own KeyType
- Provide own UserRole
- Derive Clone for SignatureType
- Derive strum::{Display,EnumString} for BootMode
- Add handling of /config/tls/public.pem endpoint
- Add handling of /system/info endpoint
- Add handling of /health/ready endpoint
- Add handling of /health/alive endpoint

### Fixed

- Simplify use of strum macros for SignatureType

### Other

- Rely on global use of serde for Message
- Extend KeyType to validate a list of KeyMechanisms
- Add dedicated tests for /health/state endpoint handling

## [0.1.1] - 2024-05-04

### Added

- Use custom url type to validate the connection to a NetHSM
- Implement Serialize/Deserialize for ConnectionSecurity

### Other

- Use re-exported facilities instead of nethsm_sdk_rs directly
- *(README.md)* Adjust test setup for new podman requirements
- *(container)* Use rustainers instead of podman-api

## [0.1.0] - 2024-03-22

### Added

- Add library for controlling a NetHSM
