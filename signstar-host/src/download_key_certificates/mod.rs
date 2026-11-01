//! Retrieval of key certificates from Signstar hosts.

mod error;

pub use error::Error;
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
use signstar_common::request_api::Certificate;

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
mod backend;
#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod cli;

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
