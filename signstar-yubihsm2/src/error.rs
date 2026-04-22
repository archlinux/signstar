//! Error handling.

use std::path::PathBuf;

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
    #[error("YubiHSM domain operation failed while {context}:\n{source}")]
    Domain {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "YubiHSM domain operation failed while ".
        context: &'static str,

        /// The source error.
        source: yubihsm::domain::Error,
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

    /// An I/O error occurred for a file.
    #[error("I/O error for file {path} while {context}: {source}")]
    IoPath {
        /// The path to the file for which the error occurred.
        path: PathBuf,
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence "I/O error for file {path} while ".
        context: &'static str,
        /// The error source.
        source: std::io::Error,
    },

    /// An I/O error occurred for a file.
    #[error("JSON serialization error while {context}: {source}")]
    #[cfg(feature = "serde")]
    Json {
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence "JSON serialization error while ".
        context: &'static str,
        /// The error source.
        source: serde_json::Error,
    },

    /// An I/O error occurred for a file.
    #[error("Deserialization of the wrap file failed while {context}: {source}")]
    InvalidWrap {
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence "Deserialization of the wrap file failed while
        /// ".
        context: &'static str,
        /// The error source.
        source: yubihsm::wrap::Error,
    },

    /// A generic I/O error occurred.
    #[error("I/O error occurred while {context}: {source}")]
    Io {
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence "I/O error occurred while ".
        context: &'static str,
        /// The error source.
        source: std::io::Error,
    },

    /// Attempted to use functionality guarded by the "_yubihsm2-mockhsm" feature.
    #[cfg(not(feature = "_yubihsm2-mockhsm"))]
    #[error("The '_yubihsm2-mockhsm' feature is not available")]
    MockHsmUnavailable,

    /// A YubiHSM2 object error occurred.
    #[error(transparent)]
    Object(#[from] crate::object::Error),

    /// A YubiHSM2 backup error occurred.
    #[error(transparent)]
    Backup(#[from] crate::backup::Error),
}
