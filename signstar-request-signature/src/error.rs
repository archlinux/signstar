//! Error handling.

use std::path::PathBuf;

use crate::ssh::client::ConnectConfig;

/// Signature request processing error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No configuration files present.
    #[error("No configuration files present in any of the default paths:\n {paths}", paths = ConnectConfig::CONFIG_ORDER.iter().map(|path| format!("- {path}")).collect::<Vec<_>>().join("\n"))]
    ConfigMissing,

    /// An I/O error occurred.
    #[error("I/O error while {context}: {source}")]
    Io {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "I/O error at path {path} while ".
        context: String,

        /// The error source.
        source: std::io::Error,
    },

    /// An I/O error occurred at a specific path.
    #[error("I/O error at path {path} while {context}: {source}")]
    IoPath {
        /// The path where the I/O error occurred.
        path: PathBuf,

        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "I/O error at path {path} while ".
        context: String,

        /// The error source.
        source: std::io::Error,
    },

    /// Requesting signing via SSH failed.
    #[error("SSH client error: {0}")]
    SshClient(#[from] crate::ssh::client::Error),

    /// A signstar-common error occurred.
    #[error("Signstar-common error: {0}")]
    SignstarCommon(#[from] signstar_common::Error),

    /// TOML deserialization error.
    #[error("TOML deserialization error: {0}")]
    Toml(#[from] toml::de::Error),

    /// A garde validation error occurred.
    #[error("Validation error while {context}: {source}")]
    Validation {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Validation error while ".
        context: String,

        /// The error source.
        source: garde::Report,
    },
}
