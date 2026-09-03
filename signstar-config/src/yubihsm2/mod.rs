//! Handling of users and keys in a YubiHSM2 backend.

pub mod admin_credentials;
mod backend;
mod config;
mod error;
mod state;

pub use backend::YubiHsm2Backend;
pub use config::{Error as YubiHSM2ConfigError, YubiHsm2Config, YubiHsm2UserMapping};
pub use error::Error;
pub use state::{YubiHsm2BackendState, YubiHsm2ConfigState, YubiHsm2Diff};

/// Re-export of types from the yubihsm2 crate.
pub mod yubihsm2_export {
    pub use signstar_yubihsm2::yubihsm::{Connector, Id};
}

/// Re-export of types from the signstar-yubihsm2 crate.
pub mod signstar_yubihsm2_export {
    pub use signstar_yubihsm2::{Credentials, object::Domain};
}
