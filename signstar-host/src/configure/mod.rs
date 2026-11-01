//! Configuration of Signstar hosts during runtime.

#[cfg(feature = "cli")]
#[doc(hidden)]
pub mod cli;
mod error;
mod host;
mod result;

pub use error::Error;
pub use host::HostConfiguration;
pub use result::ConfigurationResult;
