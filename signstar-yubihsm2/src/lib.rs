#![doc = include_str!("../README.md")]

pub mod automation;
pub mod backup;
mod connection;
mod error;
pub mod object;
mod signer;
mod user;

pub use connection::Connection;
pub use error::Error;
pub use signer::YubiHsm2SigningKey;
pub use user::{Credentials, FileBackedCredentials};

/// Re-exports of the upstream [`yubihsm`] library.
pub mod yubihsm {
    pub use yubihsm::{
        Connector,
        Domain,
        capability::Capability,
        command::Code,
        device::SerialNumber,
        object::{Entry, Filter, Id, Info},
    };
}
