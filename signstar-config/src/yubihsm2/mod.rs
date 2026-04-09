//! Handling of users and keys in a YubiHSM2 backend.

pub mod admin_credentials;
mod config;

pub use config::{Error as YubiHSM2ConfigError, YubiHsm2Config, YubiHsm2UserMapping};
// Re-export of types used from the signstar_yubihsm2 crate.
pub use signstar_yubihsm2::object::Domain;
