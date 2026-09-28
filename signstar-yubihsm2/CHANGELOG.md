# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-28

### Added

- *(deps)* Update rustcrypto crates
- *(deps)* Upgrade crate `yubihsm2` to 0.45.0
- Add labels to generated YubiHSM objects
- Add `Label::from_truncated_str` to create `Label` from `str`
- Implement creating `Connector` from `Connection`
- Implement `BackendCheck` for YubiHSM2 `Connection`
- [**breaking**] Extend `CryptographicKeyContext::OpenPgp` with `notations`
- Derive `strum::Display` for `ObjectAlgorithm`
- Serialize `AsymmetricAlgorithm` using `kebab-case`
- Derive `strum::Display` for `WrapKeyKind`
- Derive `strum::Display` for `OpaqueDataAlgorithm`
- Add `YubiHsm2SigningKey::close_session`
- Add `YubiHsm2SigningKey::new`
- Publicly re-export `yubihsm::Client`
- Implement `Display` for `ObjectId`
- Add support for changing the currently used authentication key
- *(deps)* Upgrade crate `yubihsm2` to 0.44.0
- Implement `Label` from `yubihsm::object::Label`
- Implement comparison, ordering and hashing for `Label`
- Add `ObjectAlgorithm` to describe YubiHSM2 object algorithms
- Add `AsymmetricAlgorithm` to describe asymmetric key algorithms
- Implement `WrapKeyKind` from `yubihsm::wrap::Algorithm`
- Derive `Hash` for `WrapKeyKind`
- Derive `PartialOrd` and `Ord` for `WrapKeyKind`
- Derive serde `Deserialize` and `Serialize` for `WrapAlgorithm`
- Derive `PartialOrd` and `Ord` for `WrapAlgorithm`
- Implement `Vec<Vec<CommandReturnValue>>` from `ScenarioReturnValue`
- Add support for retrieving opaque data from a YubiHSM2 to `Command`
- Add support for putting opaque data into the YubiHSM2 to `Command`
- Implement creating `yubihsm::object::Label` from `Label`
- Add serde `Deserialize`/`Serialize` support for `Label`
- Fail on `\0` characters in `Label::from_str`
- Publicly re-export `yubihsm::object::Info`
- Publicly re-export `yubihsm::Connector`
- Implement `AsRef<BTreeSet<Domain>>` for `Domains`
- Implement `AsRef<BTreeSet<Capability>>` for `Capabilities`
- Add `Credentials::id` to return the `Id`
- Add constructor for `Scenario`
- Implement the listing of YubiHSM2 objects based on filter sets
- [**breaking**] Hide all file-backed types behind the "cli" feature
- Expose `CommandName` publicly
- Add `ScenarioReturnValue::chains` returning return values
- Add `YubiHsmWrapKeyFromWrapKey` to create `yubihsm::wrap::Key`
- Add `WrapKeyFromPassphrase` creating `WrapKey` from `Passphrase`
- Add `WrapKey` as strong-typed abstraction for `yubihsm::wrap::Key`
- Add `WrapKeyKind` mapping to `yubihsm::wrap::Algorithm`
- Derive `Clone` and `Copy` for `ObjectId`
- Derive `Clone` for `KeyInfo`
- [**breaking**] Use file-backed authentication only for the CLI
- Add `AuthenticationKey`, wrapping `yubihsm::authentication::Key`
- Add `FileBackedCredentials` for credentials based on file contents
- Implement creating `Capabilities` from `yubihsm::Capability`
- Implement `Display` for `Capabilities`
- Implement `Display` for `Domains`
- Derive strum's `AsRefStr` and `Display` for `Domain`
- Add all (upstream) available variants for the `Capability` enum
- Derive `strum::AsRefStr` for `Capability` and serialize correctly
- Derive `Hash` for `Domains`
- Derive `PartialOrd` and `Ord` for `Domains`
- Derive `Hash` for `Capabilities`
- Derive `PartialOrd` and `Ord` for `Capabilities`
- Derive `PartialOrd` and `Ord` for `Capability`
- Add `wrap-ed25519` subcommand to `signstar-yubihsm2 backup`
- Add support for clap for `Domain` objects
- Rely on `Domains::bits` in `Domains::to_be_bytes`
- Add `Domains::bits` to return the underlying bits value
- Re-export `yubihsm::capability::Capability`
- Re-export `yubihsm::command::Code`
- Add `backup dump` subcommand to `signstar-yubihsm2`
- Add `backup` module to `signstar-yubihsm2`
- [**breaking**] Allow specifying multiple domains per key object
- Add `Connection` to describe the connection to a YubiHSM2
- *(cargo)* Remove `serde` from default features
- *(cargo)* Rename `mockhsm` feature to `_yubihsm2-mockhsm`
- Use `Id` in `signstar-yubihsm2::Credentials`
- Add `Id` as a low-level YubiHSM2 Object ID representation
- Implement `Display` for `Domain`
- Derive `Hash` for `Domain`
- Derive `PartialOrd` and `Ord` for `Domain`
- Derive `Eq` for `Domain`
- Add YubiHSM provisioning CLI
- Use `yubihsm::device::SerialNumber` in `YubiHsmConnection`
- Re-export `yubihsm::Domain` and `yubihsm::device::SerialNumber`
- Add `signstar_yubihsm2::signer` to sign with YubiHSM2 keys
- Add optional `serde` support for `Credentials`
- Add `Credentials` for handling YubiHSM2 authentication
- Add bare `signstar-yubihsm2` crate

### Fixed

- [**breaking**] Diversify the logger setup for journald and terminal
- *(deps)* Update Rust crate ccm to 0.6.0
- *(deps)* Update Rust crate argon2 to 0.6.0
- [**breaking**] Correctly generate certificates with multiple User IDs
- Use `WrapKey` for wrapping keys, not `AuthenticationKey`
- Don't require mutability in `From` implementations for `Domains`
- Fix clippy lints reported by Rust stable
- *(cargo)* Only require `clap-verbosity-flag` for `cli` feature
- Properly separate `mockhsm` and `serde` features
- Move time import to not cause issues with `mockhsm` disabled
- Use debug builds with all features for testing `signstar-yubihsm2`

### Other

- Remove warning for `_yubihsm2-mockhsm` feature debug requirement
- [**breaking**] Remove unused types `LogDigest` and `LOG_DIGEST_SIZE`
- [**breaking**] Replace signstar-yubihsm2's `Id` with `yubihsm::object::Id`
- [**breaking**] Switch from yubihsm.rs to yubihsm2
- Convert `allow`s into `expect`s
- Improve `ScenarioReturnValue::persist_file_backed_scenario`
- Improve `ScenarioReturnValue::compare_with_file_backed_scenario`
- Expand the docs for `FileBackedScenarioReturnValueMismatch`
- [**breaking**] Separate writing to output file from default library functions
- [**breaking**] Rename `Command` variants to match `yubishm` functions
- [**breaking**] Make serialization of command output optional
- *(cargo)* Move crate `yubihsm` to workspace dependencies
- Use `AuthenticationKey` instead of custom function
- [**breaking**] Replace `Auth` with `FileBackedCredentials`
- [**breaking**] Restructure `Scenario` as chain of authenticated commands
- Format all JSON files using `biome`
- Use top-level use statements for external types
- [**breaking**] Expose all signstar_crypto errors over top-level Error type
- [**breaking**] Standardize on snake_case for scenario object representation
- Move module files to mod.rs files
- Sort `From`/`TryFrom` implementations for `Domains`
- [**breaking**] Adhere to upstream naming convention in `Capability` variants
- Use `BTreeSet` instead of `HashSet` in `Capabilities`
- Use `BTreeSet` instead of `HashSet` for `Domains`
- Derive `Eq` and `PartialEq` for object identifiers
- [**breaking**] Introduce `Label` type and use that in `InnerFormat`
- [**breaking**] Use dedicated `Capabilities` type in `InnerFormat`
- Add documentation describing YubiHSM Wrap (YHW) format
- *(README)* Improve information about available features
- [**breaking**] Rely on `Id` in `Auth` and `Command` for increased robustness
- [**breaking**] Use `Id` in `KeyInfo` to increase robustness
- [**breaking**] Rely on `Id` in `ObjectId` for increased robustness
- *(deps)* Move `serde_json` crate to workspace dependencies
- *(deps)* Move `clap-verbosity-flag` to workspace dependencies
- *(deps)* Update Rust crate pgp to 0.19
