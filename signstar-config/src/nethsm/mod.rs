//! Handling of users and keys in a NetHSM backend.

mod admin_credentials;
mod backend;
mod config;
mod error;
mod state;

pub use admin_credentials::NetHsmAdminCredentials;
pub(crate) use backend::{KeyState, UserState};
pub use backend::{NetHsmBackend, NetHsmBackendState};
pub use config::{
    Error as NetHsmConfigError,
    FilterUserKeys,
    NetHsmConfig,
    NetHsmConfigState,
    NetHsmConfigUserData,
    NetHsmConfigUserKeyData,
    NetHsmMetricsUsers,
    NetHsmUserKeysFilter,
    NetHsmUserMapping,
};
pub use error::Error;
pub use state::NetHsmStateType;
pub(crate) use state::{NetHsmKeyStateDiscrepancy, NetHsmUserStateDiscrepancy};
