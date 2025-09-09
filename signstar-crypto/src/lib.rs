#![doc = include_str!("../README.md")]

mod error;
pub mod key;
pub mod openpgp;
pub mod passphrase;

pub use error::Error;
