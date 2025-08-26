//! Administrative credentials handling for a NetHSM backend.

use std::path::PathBuf;

/// An error that may occur when handling administrative credentials for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is no top-level administrator.
    #[error("There is no top-level administrator but at least one is required")]
    AdministratorMissing,

    /// There is no top-level administrator with the name "admin".
    #[error("The default top-level administrator \"admin\" is missing")]
    AdministratorNoDefault,

    /// A credentials file can not be created.
    #[error("The credentials file {path} can not be created:\n{source}")]
    CredsFileCreate {
        /// The path to a credentials file administrative secrets can not be stored.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },

    /// A credentials file does not exist.
    #[error("The credentials file {path} does not exist")]
    CredsFileMissing {
        /// The path to a missing credentials file.
        path: PathBuf,
    },

    /// A credentials file is not a file.
    #[error("The credentials file {path} is not a file")]
    CredsFileNotAFile {
        /// The path to a credentials file that is not a file.
        path: PathBuf,
    },

    /// A credentials file can not be written to.
    #[error("The credentials file {path} can not be written to:\n{source}")]
    CredsFileWrite {
        /// The path to a credentials file that can not be written to.
        path: PathBuf,
        /// The source error
        source: std::io::Error,
    },

    /// A passphrase is too short.
    #[error(
        "The passphrase for {context} is too short (should be at least {minimum_length} characters)"
    )]
    PassphraseTooShort {
        /// The context in which the passphrase is used.
        ///
        /// This is inserted into the sentence "The _context_ passphrase is not long enough"
        context: String,

        /// The minimum length of a passphrase.
        minimum_length: usize,
    },
}
