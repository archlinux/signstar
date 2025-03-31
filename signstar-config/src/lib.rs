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
pub use config::load_config;
pub use error::{Error, ErrorExitCode};
pub use nethsm::{
    backend::{FullNetHsmBackend, NetHsmBackend},
    error::Error as NetHsmBackendError,
    state::{KeyState, NetHsmState, UserState},
};
pub use non_admin_credentials::{
    CredentialsLoading,
    CredentialsLoadingError,
    CredentialsLoadingErrors,
    SecretsReader,
    SecretsWriter,
};
