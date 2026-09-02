#![doc = include_str!("../README.md")]

mod config;
mod error;
mod host;
mod result;

pub use config::load_config;
pub use error::Error;
pub use host::HostConfiguration;
pub use result::ConfigurationResult;
