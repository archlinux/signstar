//! Creation and loading of secrets from files.

mod admin;
mod common;
mod error;
mod non_admin;

pub use admin::AdministrativeSecretHandling;
pub use error::Error;
pub use non_admin::{
    NonAdministrativeSecretHandling,
    load_passphrase_from_secrets_file,
    write_passphrase_to_secrets_file,
};
