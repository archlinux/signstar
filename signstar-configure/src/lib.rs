//! Configuration of Signstar hosts and their backends.

mod backend;
mod config;
mod error;

pub use backend::BackendSync;
pub use config::load_config;
pub use error::Error;
