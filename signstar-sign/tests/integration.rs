//! Integration tests for signstar-config modules.

#![cfg(feature = "_containerized-integration-test")]

#[cfg(any(feature = "nethsm", feature = "_yubihsm2-mockhsm"))]
pub mod operator_signing;
