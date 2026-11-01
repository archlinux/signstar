//! Retrieval of signatures for signing requests on Signstar hosts.

#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod cli;
mod error;

pub use error::Error;
