//! Error handling for the `nethsm` CLI.

use std::path::PathBuf;

use chrono::{DateTime, Utc};

use crate::SystemState;

/// The error that may occur when using the "nethsm" command line interface.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A config error
    #[error("Configuration issue: {0}")]
    Config(#[from] crate::cli::config::Error),

    /// The NetHSM is locked
    #[error("The NetHsm is locked")]
    Locked,

    /// The NetHSM is failed
    #[error("The NetHSM is failed")]
    Failed,

    /// The NetHSM is failed
    #[error("The NetHSM system state is unknown: {system_state:?}")]
    UnknownSystemState {
        /// The unknown system state.
        system_state: SystemState,
    },

    /// An I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Unable to open output file
    #[error("Failed to open output file: {0}")]
    OutputFileOpen(PathBuf),

    /// Unable to open output file
    #[error("The output file exists already: {0}")]
    OutputFileExists(PathBuf),

    /// Error processing backup file
    #[error("Backup file is corrupted: {0}")]
    Backup(#[from] crate::backup::Error),

    /// Request deserialization error
    #[error("Request deserialization failed: {0}")]
    Request(#[from] Box<signstar_request_signature::Error>),

    /// Processing a signing request failed.
    #[error("Signing request processing error: {0}")]
    SigningRequest(String),

    /// Given time cannot be represented in OpenPGP.
    #[error("Given time cannot be represented in OpenPGP: {0}")]
    InvalidTime(DateTime<Utc>),

    /// An option is missing
    #[error(
        "The \"{0}\" option must be provided for this command if more than one environment is defined."
    )]
    OptionMissing(String),
}
