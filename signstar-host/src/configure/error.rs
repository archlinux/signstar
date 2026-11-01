//! Error handling.

/// An error that may occur when configuring Signstar hosts and their backends during runtime.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`std::num::ParseIntError`] occurred.
    #[cfg(feature = "yubihsm2")]
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
}
