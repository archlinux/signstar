#![doc = include_str!("../README.md")]

pub mod admin_credentials;
pub mod config;
pub mod error;
pub mod non_admin_credentials;
pub mod utils;

pub use admin_credentials::{AdminCredentials, User};
pub use config::load_config;
pub use error::{Error, ErrorExitCode};
pub use non_admin_credentials::{
    CredentialsLoading,
    CredentialsLoadingError,
    CredentialsLoadingErrors,
    SecretsReader,
    SecretsWriter,
};
