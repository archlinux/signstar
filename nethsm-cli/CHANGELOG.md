# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] - 2025-04-22

### Added

- [**breaking**] make `openpgp_sign_state` always return an armored OpenPGP signature
- Add `signstar-request-signature send` subcommand for sending signing requests

### Fixed

- *(README)* Use even more `rpacket` instead of `sq` for OpenPGP packet dumping
- *(README)* Use `rpacket` instead of `sq` for OpenPGP packet dumping

### Other

- Switch to rustfmt style edition 2024

## [0.6.0] - 2024-12-13

### Added

- Add `nethsm openpgp sign-state` command

## [0.5.0] - 2024-12-08

### Added

- Add `nethsm system validate-backup` command

### Other

- *(README)* Add links to latest (un)released crate documentation

## [0.4.1] - 2024-11-27

### Other

- update Cargo.lock dependencies

## [0.4.0] - 2024-11-26

### Added

- [**breaking**] Provide version with `OpenPgpVersion` when creating OpenPGP certificate
- [**breaking**] Use `OpenPgpUserId` for User ID when creating OpenPGP certificate

### Fixed

- *(deps)* Update dependencies removing yanked crate
- *(deps)* update rust crate strum to 0.26.0

### Other

- Consolidate contributing and licensing information
- *(cargo)* Use workspace dependencies for `clap` and `nethsm-config`
- *(deps)* Update dependencies and fix license ID
- Use easier to understand `no_run` attribute
- *(cargo)* Move common dependencies to workspace dependencies
- *(cargo)* Move shared dependencies to workspace dependencies
- *(cargo)* Move package metadata to workspace
- Use `Display` in rendered docs instead of `Debug` representation
- *(deps)* update rust crate rstest to 0.23.0
- Use `expression_format` for easier to read help strings

## [0.3.0] - 2024-09-11

### Fixed

- Allow generating Curve25519 key by default

### Other

- Upgrade nethsm-config crate to 0.1.1
- Upgrade nethsm crate to 0.6.0
- Adapt subcommand documentation for the use of namespaces
- [**breaking**] Introduce `nethsm::KeyId` type
- [**breaking**] Use `u32` instead of `i32` for ports and lengths

## [0.2.2] - 2024-09-06

### Fixed

- Distinguish restore of provisioned and unprovisioned device

### Other

- Upgrade nethsm crate to 0.5.0
- Switch to nethsm-config crate from own modules

## [0.2.1] - 2024-08-31

### Fixed

- Name the command explicitly so that clap_allgen can use it

## [0.2.0] - 2024-08-30

### Added

- Allow providing global `--passphrase-file` option multiple times
- Allow providing the global `--user` option multiple times
- Add subcommands for managing namespaces
- Add `UserId` and `NamespaceId` types for handling User IDs
- Add shell completion and manpages generation
- *(cli)* Add `nethsm openpgp import`
- *(cli)* Add `openpgp sign` subcommand
- *(cli)* Add `openpgp add` command
- Add support for PEM-encoded private keys in `key import`

### Fixed

- Adjust format option documentation for `nethsm key import`
- When printing user tags, only show return value not Result
- [**breaking**] Rename function for creating an OpenPGP certificate
- Retrieving a key certificate may be done in the Operator role too
- Do not require `Administrator` role when executing `unlock`

### Other

- Create release 0.4.0 for nethsm
- *(README.md)* Extend examples to cover the use of namespaces
- *(README.md)* Simplify OpenPGP examples with environment variables
- *(README.md)* Standardize OpenPGP User IDs used in examples
- *(README.md)* Sort `nethsm` options alphabetically before arguments
- *(README.md)* Disambiguate key names from tag names
- Remove cleanup from the rendered README
- Document the formats of certificates
- Fix user role requirements for backup retrieval
- *(deps)* update rust crate rstest to 0.22.0
- Make integration tests more robust
- Simplify license attribution setup for entire project

## [0.1.0] - 2024-07-13

### Added

- Add CLI for the nethsm library

### Other

- Add documentation for nethsm-cli crate
