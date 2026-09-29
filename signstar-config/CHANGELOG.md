# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-29

### Added

- Implement `signstar-download-key-certificates`
- [**breaking**] Rename `SystemUserMapping` variant for WireGuard config downloads
- [**breaking**] Remove `wrapping_key_id` from `YubiHsm2UserMapping::Backup`
- Sort `SystemUserMapping` and implement `Ord` and `PartialOrd`
- Add `NetHsmUserMapping::CertificateRetrieval`
- Add `YubiHsm2UserMapping::CertificateRetrieval`
- [**breaking**] Introduce a crate-level error type for signstar-common
- *(deps)* [**breaking**] Update crate nethsm-sdk-rs to 4.0.0
- *(deps)* Update rustcrypto crates
- Implement creating `NetHsmAdminCredentials` from `Config`
- Implement creating `YubiHsm2AdminCredentials` from `Config`
- Emit a warning on missing (but configured) system users
- Derive, `Eq` and `PartialEq` for `Config` and `SystemConfig`
- Re-export `signstar_yubihsm2::Connection` in `yubihsm2` module
- Add labels to generated YubiHSM objects
- Add permissions missing in the administrative key
- [**breaking**] Export types from `signstar-yubihsm2` via the `yubihsm2` module
- Export types from the `yubihsm2` crate via the `yubihsm2` module
- Export types from the `nethsm` crate via the `nethsm` module
- [**breaking**] Support sets of filters with `Config::user_backend_connections`
- [**breaking**] Extend `CryptographicKeyContext::OpenPgp` with `notations`
- Add module implementing `StateDiff` for YubiHSM2
- Add `YubiHsm2Backend` to configure YubiHSM2s based on configs
- Implement `Display` for `StateDiffReport`
- [**breaking**] Add `YubiHsm2AdminCredentials::default_administrator`
- Add `YubiHsm2AdminCredentials::administrators`
- Add `AuthType` to `YubiHsm2ConfigUserData`
- Add `YubiHsm2UserMapping::authentication_key_info`
- Add `YubiHsm2Config::WRAP_KEY_ID`
- [**breaking**] Change `YubiHsm2UserMapping::domains` to always return `Domains`
- Return `Result<Option<usize>, Error>` for certificate size estimation
- Add size validation of `YubiHsm2UserMapping` instances in a `YubiHsm2Config`
- Always require `expect` attributes instead of `allow`s
- Add `YubiHsm2ConfigState` as `YubiHsm2Config` state representation
- Derive `Ord` and `PartialOrd` for `StateOrigin`
- Derive `Eq` and `PartialEq` for `StateOrigin`
- [**breaking**] Move `backup_passphrase` method to `AdminCredentials` trait
- [**breaking**] Move `iteration` method to `AdminCredentials` trait
- Rely on stricter `PassphrasePolicy` for `YubiHsm2AdminCredentials`
- Rely on stricter `PassphrasePolicy` in `NetHsmAdminCredentials`
- Add `NetHsmDiff` for `NetHsmConfigState` and `NetHsmBackendState`
- Implement `StateOriginInfo` for `NetHsmConfigState`
- Allow returning validated admin users from `NetHsmAdminCredentials`
- Implement `StateOriginInfo` for `NetHsmBackendState`
- Implement `Display` for `NetHsmConfigUserKeyData`
- Implement `Display` for `NetHsmConfigUserData`
- Derive `Eq` and `PartialEq` for `NetHsmBackendState`
- Implement state comparison for system user data
- Add new state comparison mechanism based on common traits
- Add `NetHsmConfigState` as `NetHsmConfig` representation
- Add `SystemUserConfigState` tracking system user data in `Config`
- Add `SystemUserHostState` tracking system users on the host
- Implement `MappingAuthorizedKeyEntry` for `UserBackendConnection`
- Allow writing authorized key file with `MappingAuthorizedKeyEntry`
- Implement `ConfigSystemUserData` for `Config`
- Implement creating `SystemUserData` from `YubiHsm2UserMapping`
- Implement creating `SystemUserData` from `NetHsmUserMapping`
- Implement creating `SystemUserData` from `SystemUserMapping`
- Add `SystemUserId::root` to return the root user
- Add `ConfigSystemUserData` trait returning `SystemUserData`
- Add `SystemUserData` to track the different kinds of system users
- Add `PartialEq` between `KeyState` and `NetHsmConfigUserKeyData`
- Add `PartialEq` between `UserState` and `NetHsmConfigUserData`
- Derive `Hash`, `Ord`, `PartialOrd` for `KeyState`
- Derive `Hash`, `Ord`, `PartialOrd` for `UserState`
- Derive `Hash`, `Ord`, `PartialOrd` for `KeyCertificateState`
- Add `YubiHsm2UserMapping::capability`
- Add `YubiHsm2Config::CAP_SIGNING` tracking signing capabilities
- Add `YubiHsm2Config::CAP_HERMETIC_AUDIT_LOG`
- Add `YubiHsm2Config::CAP_BACKUP` tracking backup capabilities
- Add `YubiHsm2Config::CAP_AUDIT_LOG` tracking audit log capabilities
- Add `YubiHsm2UserMapping::CAP_ADMIN` to track admin capabilities
- Add `YubiHsm2Config::AUDIT_COMMANDS` to track commands to audit
- Move Signstar config fixtures to central workspace location
- Remove `SignstarConfig` in favor of `Config`
- Port from `SignstarConfg` to `Config` in NetHSM backend handling
- Support creating `SignstarConfigNetHsmState` from `NetHsmConfig`
- Derive `PartialEq` and `Eq` for `SignstarConfigNetHsmState`
- Port to new `Config` format
- *(cargo)* Add `_yubihsm2-mockhsm` feature
- Add `SystemUserId::from_current_unix_user`
- Switch from `YubiHsmConnection` to `signstar_yubihsm2::Connection`
- *(cargo)* Remove `serde` from default features
- [**breaking**] Drop MD5 from supported algorithms and dependencies
- *(cargo)* Rename `test-helpers` feature to `_test-helpers`
- Add new YAML based config file format
- Derive `Eq` and `PartialEq` for `NetHsmConfig`
- Derive `Eq` and `PartialEq` for `YubiHsm2Config`
- Add `SystemUserMapping` and `SystemConfig`
- Add `YubiHsm2UserMapping` and `YubiHsm2Config`
- Add `NetHsmUserMapping` and `NetHsmConfig`
- Add traits used for retrieving data from generic user mappings
- Use `Id` in `signstar-yubihsm2::Credentials`
- Add `TryFrom<nix::unistd::User>` for `SystemUserId`
- Implement `AsRef<Entry>` for `AuthorizedKeyEntry`
- Implement `Ord` and `PartialOrd` for `AuthorizedKeyEntry`
- Use `yubihsm::device::SerialNumber` in `YubiHsmConnection`
- Derive `Ord` and `PartialOrd` for `yubihsmconnection`
- Derive `Ord` and `PartialOrd` for `NetHsmMetricsUsers`
- Derive `Ord` and `PartialOrd` for `SystemUserId`
- Add metrics related variants for `UserMapping`
- Add `UserMapping::SystemYubiHsm2Backup`
- Add administrative credentials handling for YubiHSM2 backends
- Add `UserMapping::YubiHsmOnlyAdmin`
- Generically load creds with `ExtendedUserMapping::load_credentials`
- Add `UserMapping::backend_users`
- [**breaking**] Generically return non-administrative creds when writing them
- Add `UserMapping::backend_users_with_new_passphrase`
- Add `AsRef<UserId>` for `SystemWideUserId`
- Add `UserMappingFilter` and `BackendUserKind`
- [**breaking**] Use `UserWithPassphrase` instead of `FullCredentials`
- Add `UserMapping::SystemYubiHsmOperatorSigning` for YubiHSM2
- Add `BackendConnection::YubiHsm2` for YubiHSM2 backend connections
- Add the `yubihsm2` module to handle YubiHSM2 backends
- [**breaking**] Use `signstar_crypto::key::SigningKeySetup` in `UserMapping`
- [**breaking**] Rely on `signstar_crypto` for common cryptographic key types
- Add `AdminCredentials` trait for generic admin creds handling
- [**breaking**] Rename `AdminCredentials` to `NetHsmAdminCredentials`
- [**breaking**] Support using different HSM backends in `SignstarConfig`

### Fixed

- Filter more robustly in `Config::user_backend_connections`
- Reset the backend, if default credentials are still usable
- [**breaking**] Diversify the logger setup for journald and terminal
- Fix capabilities required for signing data
- Remove filtering of internal YubiHSM2 objects
- Add missing `ExportWrapped` permission to the administrative set
- *(deps)* Update Rust crate serde-saphyr to v1
- [**breaking**] Correctly generate certificates with multiple User IDs
- Remove useless borrows in formatting
- Allow only max one tag for user and key data in the NetHSM backend
- *(deps)* Update Rust crate garde to 0.23.0
- Only add NetHSM admins when both setup in config and admin creds
- *(cargo)* Move `num-enum` to workspace dependencies
- *(deps)* Update Rust crate toml to v1
- *(deps)* Update Rust crate nix to 0.31.0
- [**breaking**] Track the wrapping key id in `UserMapping::SystemYubiHsm2Backup`
- Rewrite panicking branches to avoid clippy warnings
- Replace returning errors to direct `panic`s to avoid clippy lints

### Other

- Rely on coverage collection functionality in change-user-run
- Add `ConfigFileVariant::contains_backend`, checking for backend
- Remove warning for `_yubihsm2-mockhsm` feature debug requirement
- Add man page for the Signstar configuration file
- *(fixtures)* Consolidate the naming of system users in configs
- Use `SystemPrepareConfig` to prepare config/usermapping tests
- Use `SystemPrepareConfig` to prepare YubiHSM2 admin creds tests
- Ignore (potentially variable) OpenPGPv4 certificate sizes
- Enforce binary ID for `_containerized-integration-test` tests
- [**breaking**] Move state handling for `YubiHsm2Config` to `state` module
- Remove unnecessary feature gate from `yubihsm2::config` module
- [**breaking**] Replace signstar-yubihsm2's `Id` with `yubihsm::object::Id`
- [**breaking**] Use `signstar-yubihsm2` types for the `YubiHsm2UserMapping`
- [**breaking**] Expose unlock `Passphrase` instead of raw string reference
- [**breaking**] Expose backup `Passphrase` instead of raw string reference
- [**breaking**] Rename `NetHsmAdminCredentials::get_namespace_administrators`
- [**breaking**] Rename `NetHsmAdminCredentials::get_default_administrator`
- [**breaking**] Rename `NetHsmAdminCredentials::get_administrators`
- [**breaking**] Rename `NetHsmAdminCredentials::get_unlock_passphrase`
- [**breaking**] Rename `NetHsmAdminCredentials::get_backup_passphrase`
- [**breaking**] Rename `NetHsmAdminCredentials::get_iteration`
- [**breaking**] Move `IterationMismatch` from `nethsm` to crate `Error`
- *(cargo)* Move `insta` to workspace dependencies
- *(cargo)* Move `garde` to workspace dependencies
- *(cargo)* Move `toml` to workspace dependencies
- *(cargo)* Move `pretty_assertions` to workspace dependencies
- [**breaking**] Expose all signstar_crypto errors over top-level Error type
- [**breaking**] Return optional `Domains` from `YubiHsm2UserMapping::domains`
- [**breaking**] Remove `StateHandling` based state comparison
- Streamline the use of "NetHSM" in the `config` module
- [**breaking**] Track `NetHsmConfig`, not `Config` in `NetHsmBackend`
- Move `NetHsmBackend` state representation to `backend` module
- Consolidate `config::file` test modules targeting no backend
- [**breaking**] Rename `NetHsmState` to `NetHsmBackendState`
- Rename `NetHsmConfigState` to `NetHsmConfigStateLegacy`
- Add writing of authorized keys files to `SystemUserConfig::apply`
- [**breaking**] Remove unused `StateComparisonFailure`
- [**breaking**] Require `Any` for the `StateHandling` trait
- [**breaking**] Rename state structs for `NetHsmConfig` data
- [**breaking**] Rely on `change-user-run` to detect command availability
- [**breaking**] Remove `ErrorExitCode`
- [**breaking**] Render the `error` module private
- [**breaking**] Use `AdminCredentials` via `admin_credentials` module
- [**breaking**] Only expose `KeyCertificateState` through `config` module
- [**breaking**] Use `config::Error` only via `config` module
- [**breaking**] Use `AuthorizedKeyEntry`/`SystemUserId` via `config` module
- [**breaking**] Only re-export used members of the `nethsm::state` module
- [**breaking**] Don't re-export `nethsm::Error` on the crate-level
- [**breaking**] Use `NetHsmBackend` through the `nethsm` module
- [**breaking**] Remove re-export of `nethsm::NetHsmMetricsUsers`
- [**breaking**] Remove re-export of `nethsm::FilterUserKeys`
- [**breaking**] Use `NetHsmAdminCredentials` from the `nethsm` module
- [**breaking**] Rename `SignstarConfigNetHsmState` to `NetHsmConfigState`
- [**breaking**] Render `UserStates` and `KeyStates` private structs
- [**breaking**] Merge `config::state::nethsm` with `nethsm::state`
- [**breaking**] Add all available config fixtures to `ConfigFileVariant`
- Use `pretty_assertions` for improved output using `assert_eq`
- Add helpers to `test` module for preparing systems with a `Config`
- Update fixtures to use localhost and cover all mapping variants
- Add fixtures for YubiHSM2 mockhsm
- Test roundtripping Signstar configs using YubiHSM2 mockhsm
- Ignore mockhsm fixtures when only testing with `yubihsm2` feature
- *(README)* Describe all current features in feature section
- *(cargo)* Remove `_integration-test` feature
- Don't require the `nethsm` feature for integration tests
- Add integration tests for non-admin secrets creation/loading
- Use `Passphrase` from `signstar-crypto` not `nethsm`
- Check creation and loading of backend user secrets
- Check use of Unix users in usermapping implementations
- Expose common functionality for containerized integration tests
- [**breaking**] Only expose selected items of the `nethsm::config` module
- *(deps)* Update Rust crate pgp to 0.19
- Make `AuthorizedKeyEntry` a newtype for `Entry` not `String`
- *(cargo)* Move crate `tempfile` to workspace dependencies
- *(cargo)* Move `nix` crate to workspace dependencies
- Lock the backend when comparing config and NetHSM state
- [**breaking**] More generically represent config and backend state
- [**breaking**] Change name to `UserMapping::YubiHsm2OnlyAdmin`
- [**breaking**] Change name to `UserMapping::SystemYubiHsm2OperatorSigning`
- Simplify `UserMapping` matches using `..`
- Split tests for `UserMapping` methods into modules per backend
- Separate `nethsm::admin_credentials` integration tests
- Explain capabilities on `UserMapping::SystemYubiHsmOperatorSigning`
- [**breaking**] Remove `SystemWideUserId` and use the `nethsm` crate instead
- Consolidate the documentation on HSM backends
- Add info logging to `ExtendedUserMapping` credentials methods
- [**breaking**] Use `String`, not `UserId` in `CredentialsLoadingError`
- [**breaking**] Return `KeyId` from `UserMapping::get_nethsm_user_key_and_tag`
- [**breaking**] Use `signstar_crypto::passphrase::Passphrase`
- Rename `UserMapping::get_key_ids`
- Rename `UserMapping::get_tags`
- Rename `UserMapping::get_namespaces`
- Rename `UserMapping::has_system_and_nethsm_user`
- Move `NetHsmMetricsUsers`, `FilterUserKeys` to `crate::nethsm`
- Move `NetHsmAdminCredentials` to `signstar_config::nethsm`

## [0.2.0] - 2025-08-19

### Added

- Use `change-user-run` crate instead of `signstar_config::test`
- Add `SignstarConfig` for the configuration on Signstar hosts

### Fixed

- *(deps)* Update Rust crate toml to 0.9.0

### Other

- Collect coverage produced by tests run (partially) as other user
- Remove the use of `confy`
- Initialize logger using `signstar_common::logging::setup_logging`

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
