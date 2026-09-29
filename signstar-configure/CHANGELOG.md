# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-29

### Added

- Make `cli` module public

## [0.1.0] - 2026-09-29

### Added

- *(systemd)* Connect stdout and stderr to journal
- Add systemd units for `signstar-configure`
- Add the `signstar-configure` command line interface
- Add library support for backend configuration
- Initialize the `signstar-configure` crate

### Fixed

- Persist new admin credentials before synchronization of backend
- *(systemd)* Fix use of `OnCalendar` in the signstar-configure timer
- [**breaking**] Diversify the logger setup for journald and terminal

### Other

- Add architecture document
