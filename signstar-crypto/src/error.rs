//! Error handling.

/// An error that may occur when working with cryptographic types for Signstar.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error related to OpenPGP occurred.
    #[error("OpenPGP error: {0}")]
    OpenPgp(#[from] crate::openpgp::Error),
}
