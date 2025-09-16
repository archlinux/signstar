//! Error handling.

/// The error that may occur when using a YubiHSM2 device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A client operation failed.
    #[error("YubiHSM client operation failed while {context}:\n{source}")]
    Client {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "YubiHSM client operation failed while ".
        context: &'static str,

        /// The source error.
        source: yubihsm::client::Error,
    },

    /// A device operation failed.
    #[error("YubiHSM device operation failed while {context}:\n{source}")]
    Device {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "YubiHSM device operation failed while ".
        context: &'static str,

        /// The source error.
        source: yubihsm::device::Error,
    },

    /// A device operation failed.
    #[error("Certificate generation failed while {context}:\n{source}")]
    CertificateGeneration {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Certificate generation failed while ".
        context: &'static str,

        /// The source error.
        source: signstar_crypto::signer::error::Error,
    },
}
