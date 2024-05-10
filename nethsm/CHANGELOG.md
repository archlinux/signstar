# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
