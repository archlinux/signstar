//! Integration tests for signstar-config modules.
#[cfg(feature = "_containerized-integration-test")]
pub mod admin_credentials;

#[cfg(feature = "_containerized-integration-test")]
pub mod config;

#[cfg(feature = "_containerized-integration-test")]
pub mod non_admin_credentials;
