#![doc = include_str!("../README.md")]

pub mod admin_credentials;
pub mod config;
pub mod error;
pub mod nethsm;
pub mod non_admin_credentials;
#[cfg(feature = "test-helpers")]
pub mod test;
pub mod utils;
#[cfg(feature = "yubihsm2")]
pub mod yubihsm2;

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
    mapping::{ExtendedUserMapping, UserMapping},
};
pub use error::{Error, ErrorExitCode};
pub use nethsm::{
    admin_credentials::NetHsmAdminCredentials,
    backend::NetHsmBackend,
    config::{FilterUserKeys, NetHsmMetricsUsers},
    error::Error as NetHsmBackendError,
    state::{KeyState, State, UserState},
};
pub use non_admin_credentials::{
    CredentialsLoading,
    CredentialsLoadingError,
    CredentialsLoadingErrors,
};
