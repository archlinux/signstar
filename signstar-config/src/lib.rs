#![doc = include_str!("../README.md")]

pub mod admin_credentials;
pub mod config;
pub mod error;
#[cfg(feature = "nethsm")]
pub mod nethsm;
pub mod state;
#[cfg(feature = "_test-helpers")]
pub mod test;
pub mod utils;
#[cfg(feature = "yubihsm2")]
pub mod yubihsm2;

pub use admin_credentials::AdminCredentials;
pub use config::{
    credentials::{AuthorizedKeyEntry, SystemUserId},
    error::Error as ConfigError,
};
pub use error::{Error, ErrorExitCode};
#[cfg(feature = "nethsm")]
pub use nethsm::{
    FilterUserKeys,
    NetHsmMetricsUsers,
    backend::NetHsmBackend,
    error::Error as NetHsmBackendError,
};
