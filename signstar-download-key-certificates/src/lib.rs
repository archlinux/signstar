//! Library for the retrieval of key certificates.

#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
use signstar_common::request_api::Certificate;

#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
use crate::error::Error;

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
mod backend;
#[cfg(feature = "cli")]
pub mod cli;
pub mod error;

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
pub use backend::load_certificates;

/// Loads [`Certificate`]s from signing keys used in Signstar configuration.
///
/// # Errors
///
/// Always returns an error, because no HSM backend support is compiled in.
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
pub fn load_certificates() -> Result<Vec<Certificate>, Error> {
    Err(Error::NoBackend)
}
