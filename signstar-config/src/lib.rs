#![doc = include_str!("../README.md")]

pub mod admin_credentials;
pub mod config;
pub mod error;
pub mod nethsm;
pub mod non_admin_credentials;
#[cfg(feature = "test-helpers")]
pub mod test;
pub mod utils;

pub use admin_credentials::AdminCredentials;
pub use config::{
    base::{
        AdministrativeSecretHandling,
        BackendConnection,
        NonAdministrativeSecretHandling,
        SignstarConfig,
    },
    credentials::{AuthorizedKeyEntry, SystemUserId, SystemWideUserId},
    error::Error as ConfigError,
    mapping::{ExtendedUserMapping, FilterUserKeys, NetHsmMetricsUsers, UserMapping},
};
pub use error::{Error, ErrorExitCode};
pub use nethsm::{
    admin_credentials::NetHsmAdminCredentials,
    backend::NetHsmBackend,
    error::Error as NetHsmBackendError,
    state::{KeyState, State, UserState},
};
pub use non_admin_credentials::{
    CredentialsLoading,
    CredentialsLoadingError,
    CredentialsLoadingErrors,
};
