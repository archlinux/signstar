//! YubiHSM-related errors.

/// YubiHSM error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Client error.
    #[error("YubiHSM client operation failed while {context}:\n{source}")]
    Client {
        /// The context in which an HSM error occurred.
        ///
        /// This is meant to complete the sentence "YubiHSM client operation failed while ".
        context: &'static str,

        /// The source error,
        source: yubihsm::client::Error,
    },

    /// Device error.
    #[error("YubiHSM device operation failed while {context}:\n{source}")]
    Device {
        /// The context in which an HSM error occurred.
        ///
        /// This is meant to complete the sentence "YubiHSM device operation failed while ".
        context: &'static str,

        /// The source error,
        source: yubihsm::device::Error,
    },
}
