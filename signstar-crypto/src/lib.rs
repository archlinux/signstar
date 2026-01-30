#![doc = include_str!("../README.md")]

mod error;
pub mod key;
pub mod openpgp;
pub mod passphrase;
pub mod secret_file;
pub mod signer;
#[cfg(feature = "_test-helpers")]
pub mod test;
pub mod traits;

pub use error::Error;
pub use secret_file::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};
