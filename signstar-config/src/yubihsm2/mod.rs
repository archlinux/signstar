//! Handling of users and keys in a YubiHSM2 backend.

pub mod admin_credentials;
mod backend;
mod config;
mod error;

pub use backend::{YubiHsm2Backend, YubiHsm2BackendState};
pub use config::{
    Error as YubiHSM2ConfigError,
    YubiHsm2Config,
    YubiHsm2ConfigState,
    YubiHsm2ConfigUserData,
    YubiHsm2ConfigUserKeyData,
    YubiHsm2UserMapping,
};
pub use error::Error;
// Re-export of types used from the signstar_yubihsm2 crate.
pub use signstar_yubihsm2::object::Domain;
