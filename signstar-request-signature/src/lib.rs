#![doc = include_str!("../README.md")]

mod error;

#[cfg(feature = "cli")]
pub mod cli;
pub mod ssh;

pub use error::Error;
