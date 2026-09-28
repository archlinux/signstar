//! Integration tests for signstar-config modules.
#![cfg(feature = "_containerized-integration-test")]

/// The location of cargo-llvm-cov `.profraw` files when running a command as a different user.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

pub mod admin_credentials;

pub mod config;

pub mod usermapping;
