#![doc = include_str!("../README.md")]

#[cfg(feature = "cli")]
pub mod cli;
mod config;
mod error;
mod host;
mod result;

#[cfg(feature = "cli")]
pub use cli::Cli;
pub use config::load_config;
pub use error::Error;
pub use host::HostConfiguration;
pub use result::ConfigurationResult;
