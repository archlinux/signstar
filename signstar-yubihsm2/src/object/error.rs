//! Error handling for objects used in signstar-yubihsm2.

/// The error that may occur when using a YubiHSM2 device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An ID is invalid.
    #[error("YubiHSM2 ID {id} is invalid, because {reason}")]
    InvalidId {
        /// The reason why the `id` is invalid.
        ///
        /// This is supposed to complete the sentence "YubiHSM2 ID {id} is invalid, because ".
        reason: String,

        /// The invalid ID.
        id: String,
    },
}
