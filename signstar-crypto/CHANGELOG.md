# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-28

### Added

- Sort `CryptographicKeyContext` and implement `PartialOrd` and `Ord`
- [**breaking**] Introduce a crate-level error type for signstar-common
- *(deps)* [**breaking**] Update crate nethsm-sdk-rs to 4.0.0
- *(deps)* Update rustcrypto crates
- *(deps)* Upgrade crate `yubihsm2` to 0.45.0
- Use better defaults for `OpenPgpKeyUsageFlags`
- [**breaking**] Extend `CryptographicKeyContext::OpenPgp` with `notations`
- Derive `Clone` for `OpenPgpKeyUsageFlags`
- *(deps)* Upgrade crate `yubihsm2` to 0.44.0
- Return `Result<Option<usize>, Error>` for certificate size estimation
- Add size validation of `YubiHsm2UserMapping` instances in a `YubiHsm2Config`
- Add `EmptyEd25519Signer` for easy certificate size estimation
- Append Signer's UID to issued signatures
- Implement `TryFrom<yubihsm::Algorithm>` for `KeyType`
- Add support for P-256, P-384 and (partially) P-512 Brainpool
- Add support for ECC K-256 (Koblitz)
- Add back NIST P-224 support
- Add `Passphrase::check_against_policy`
- Add `Passphrase::new_with_policy`
- Add `PassphrasePolicy` to describe `Passphrase` policies
- Add `len` and `is_empty` methods for `Passphrase`
- Implement creating `Passphrase` from a file path
- [**breaking**] Drop MD5 from supported algorithms and dependencies
- Publicly expose default values for Shamir's Secret Sharing (SSS)
- Derive `AsRefStr` for `NonAdministrativeSecretHandling`
- Add `AdministrativeSecretHandling` enum
- Add reading and writing of non-administrative secrets
- Derive `Ord` and `PartialOrd` for `OpenPgpUserIdList`
- Derive `Ord` and `PartialOrd` for `OpenPgpUserId`
- Implement `Ord` and `PartialOrd` for `OpenPgpUserIdType`
- Implement `Display` for `OpenPgpUserIdType`
- Derive `Ord` and `PartialOrd` for `OpenPgpVersion`
- Derive `Ord` and `PartialOrd` for `CryptographicKeyContext`
- Skip serializing `SigningKeySetup::key_length` if it is `None`
- Derive `Ord` and `PartialOrd` for `SigningKeySetup`
- Move OpenPGP related logic out of `nethsm` into `signstar-crypto`
- Add `Passphrase::generate` to generate new passphrases
- Add the `UserWithPassphrase` trait
- Add `SigningKeySetup` to describe environments for signing keys
- Make `PrivateKeyData` publicly accessible
- Add `Passphrase` type to handle passphrases
- Add types for cryptographic key ingestion and import
- Add `key` module providing various types for cryptographic keys
- Add an `openpgp` module for simple OpenPGP related types
- Initialize bare `signstar-crypto` crate

### Fixed

- [**breaking**] Diversify the logger setup for journald and terminal
- *(deps)* More strictly lock the version ranges for custom dependencies
- [**breaking**] Correctly generate certificates with multiple User IDs
- *(deps)* Update Rust crate pgp to 0.20
- remove unused import
- Replace returning errors to direct `panic`s to avoid clippy lints

### Other

- Rely on coverage collection functionality in change-user-run
- Enforce `_containerized-integration-test` feature for test module
- Enforce binary ID for `_containerized-integration-test` tests
- Improve `CryptographicKeyContext::openpgp_cert_size` documentation
- [**breaking**] Move `Error::UnsupportedNetHsmKeyMechanism` to `key` module
- [**breaking**] Expose all signstar_crypto errors over top-level Error type
- *(README)* Improve information about available features
- *(deps)* Update Rust crate pgp to 0.19
- Use serde `Deserialize`/`Serialize` top-level in `openpgp` module
- Feature-guard unit tests that require the `nethsm` feature
- Expose `SignedSecretKey` through `nethsm`
