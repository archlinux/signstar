#![doc = include_str!("../README.md")]

mod error;
mod signer;
mod user;

pub use error::Error;
pub use signer::YubiHsm2SigningKey;
pub use user::Credentials;

/// Re-exports of the upstream [`yubihsm`] library.
pub mod yubihsm {
    pub use yubihsm::Domain;
    pub use yubihsm::device::SerialNumber;
}
