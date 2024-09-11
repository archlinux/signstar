# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
