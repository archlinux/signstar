//! YubiHSM-related errors.

/// YubiHSM error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Client error.
    #[error(transparent)]
    Client(#[from] yubihsm::client::Error),

    /// Device error.
    #[error(transparent)]
    Device(#[from] yubihsm::device::Error),
}
