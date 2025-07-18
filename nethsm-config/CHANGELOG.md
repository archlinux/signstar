# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2025-07-10

### Fixed

- [**breaking**] Rearchitecture `UserMapping::get_nethsm_user_role_and_tag`

### Other

- Fix violations of MD022 and MD032 in changelogs
- Reformat all TOML files with `taplo`
- Sort derives using `cargo sort-derives`
- Fix clippy lints regarding variables in `format!`

## [0.3.0] - 2025-04-22

### Added

- Add `HermeticParallelConfig::get_iteration`
- Add `UserMapping::get_nethsm_user_role_and_tag`
- Add `UserMapping::get_nethsm_user_key_and_tag`
- Add `FilterUserKeys` to allow filtering `UserMapping` contents
- Add `UserMapping::get_nethsm_users_and_roles`
- Add `NetHsmMetricsUsers::get_users_and_roles`
- [**breaking**] Rely on `NamespaceId` instead of `String` for robustness
- [**breaking**] Initialize `NetHsm` using a `Connection`
- Add `HermeticParallelConfig::get_extended_mapping_for_user`
- Add `ExtendedUserMapping`
- Add HermeticParellelConfig::get_non_administrative_secret_handling
- Add `HermeticParallelConfig::get_administrative_secret_handling`
- Add `UserMapping::has_system_and_nethsm_user`
- Derive useful `strum` macros for `AdministrativeSecretHandling`
- Set non-administrative secret handling in `ParallelHermeticConfig`
- Add `NonAdministrativeSecretHandling`
- Set administrative secret handling in `ParallelHermeticConfig`
- Add `AdministrativeSecretHandling`

### Fixed

- Adjust code to fix nightly clippy lint

### Other

- Move `nethsm_config::Connection` to `nethsm::Connection`
- *(cargo)* Move zeroize to workspace dependencies
- *(cargo)* Move confy to workspace dependencies
- Switch to rustfmt style edition 2024
- Fix minor spelling issue in config.rs
- *(deps)* update rust crate dirs to v6

## [0.2.2] - 2024-12-08

### Other

- *(README)* Add links to latest (un)released crate documentation

## [0.2.1] - 2024-11-27

### Other

- Update libc crate as the previously used version was yanked

## [0.2.0] - 2024-11-26

### Added

- Add `HermeticParallelConfig` as hermetic, parallel configuration
- [**breaking**] Allow tracking inner error message in `config::Error::Load`
- Add `UserMapping`, mapping system and NetHsm users and their roles
- Add `NetHsmMetricsUsers` for tracking metrics and operator users
- Add `SystemWideUserId` for a guaranteed to be system-wide `UserId`
- Add `AuthorizedKeyEntry` and `AuthorizedKeyEntryList` for SSH keys
- Add `SystemUserId` as representation of a system user name
- Derive `Copy` for `nethsm::UserRole`
- Derive `Eq`, `Hash` and `PartialEq` for `Connection`

### Fixed

- Provide the config name from settings when loading a configuration
- Extend documentation for `ConfigInteractivity::NonInteractive`
- Return borrowed from `ConfigCredentials::get_passphrase`
- *(deps)* Update dependencies removing yanked crate
- Adjust test names so they are isolated

### Other

- Consolidate contributing and licensing information
- *(deps)* Update dependencies and fix license ID
- *(cargo)* Move common dependencies to workspace dependencies
- *(cargo)* Move shared dependencies to workspace dependencies
- *(cargo)* Move package metadata to workspace
- Move `ConfigCredentials` to credentials module
- *(deps)* update rust crate rstest to 0.23.0

## [0.1.1] - 2024-09-11

### Other

- Upgrade nethsm crate to 0.6.0

## [0.1.0] - 2024-09-06

### Added

- Add nethsm-config crate as common configuration library

### Other

- Upgrade nethsm crate to 0.5.0
