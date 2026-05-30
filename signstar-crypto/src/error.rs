//! Error handling.

use std::path::PathBuf;

/// An error that may occur when working with cryptographic types for Signstar.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`change_user_run::Error`] occurred.
    #[error(transparent)]
    ChangeUserRun(#[from] change_user_run::Error),

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

    /// An error related to keys occurred.
    #[error("Key error: {0}")]
    Key(#[from] crate::key::Error),

    /// An error related to OpenPGP occurred.
    #[error("OpenPGP error: {0}")]
    OpenPgp(#[from] crate::openpgp::Error),

    /// An error related to passphrase handling occurred.
    #[error("Passphrase error: {0}")]
    Passphrase(#[from] crate::passphrase::Error),

    /// An error related to secret file reading or writing occurred.
    #[error("Secret file error: {0}")]
    SecretFile(#[from] crate::secret_file::Error),

    /// An error related to raw signing occurred.
    #[error("Signer error: {0}")]
    Signer(#[from] crate::signer::error::Error),

    /// A test helper error occurred.
    #[error("Test helper error: {0}")]
    #[cfg(feature = "_test-helpers")]
    TestHelper(#[from] crate::test::Error),

    /// An unsupported key mechanism has been encountered.
    #[error("Unsupported key mechanism: {0}")]
    #[cfg(feature = "nethsm")]
    UnsupportedNetHsmKeyMechanism(nethsm_sdk_rs::models::KeyMechanism),
}
