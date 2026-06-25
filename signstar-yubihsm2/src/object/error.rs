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

    /// Empty set of domains encountered.
    #[error("Empty set of domains encountered")]
    EmptySetOfDomains,

    /// A [`getrandom::Error`] occurred.
    #[error("Get random error while {context}: {source}")]
    GetRandom {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Get random error while ".
        context: &'static str,

        /// The error source.
        source: getrandom::Error,
    },

    /// An [`argon2::Error`] occurred.
    #[error("Argon2 error while {context}: {source}")]
    Argon2 {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Argon2 error while ".
        context: &'static str,

        /// The error source.
        source: argon2::Error,
    },
}
