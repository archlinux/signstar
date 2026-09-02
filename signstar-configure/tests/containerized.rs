//! Containerized integration tests for `signstar-configure`.
#![cfg(feature = "_containerized-integration-test")]

#[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
pub mod all_backends;
pub mod config;
#[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
pub mod nethsm_backend;
#[cfg(all(feature = "yubihsm2", not(feature = "nethsm")))]
pub mod yubihsm2_backend;
