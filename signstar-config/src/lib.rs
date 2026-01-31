#![doc = include_str!("../README.md")]

pub mod admin_credentials;
pub mod config;
pub mod error;
#[cfg(feature = "nethsm")]
pub mod nethsm;
#[cfg(feature = "nethsm")]
pub mod non_admin_credentials;
pub mod state;
#[cfg(feature = "test-helpers")]
pub mod test;
pub mod utils;
#[cfg(feature = "yubihsm2")]
pub mod yubihsm2;

pub use admin_credentials::AdminCredentials;
pub use config::{
    base::AdministrativeSecretHandling,
    credentials::{AuthorizedKeyEntry, SystemUserId},
    error::Error as ConfigError,
};
#[cfg(feature = "nethsm")]
pub use config::{
    base::{BackendConnection, NonAdministrativeSecretHandling, SignstarConfig},
    mapping::{BackendUserKind, ExtendedUserMapping, UserMapping, UserMappingFilter},
};
pub use error::{Error, ErrorExitCode};
#[cfg(feature = "nethsm")]
pub use nethsm::{
    FilterUserKeys,
    NetHsmMetricsUsers,
    admin_credentials::NetHsmAdminCredentials,
    backend::NetHsmBackend,
    error::Error as NetHsmBackendError,
};
#[cfg(feature = "nethsm")]
pub use non_admin_credentials::{
    CredentialsLoading,
    CredentialsLoadingError,
    CredentialsLoadingErrors,
};
