//! Error handling.

/// An error that may occur when working with cryptographic types for Signstar.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`change_user_run::Error`] occurred.
    #[error(transparent)]
    ChangeUserRun(#[from] change_user_run::Error),

    /// An error related to OpenPGP occurred.
    #[error("OpenPGP error: {0}")]
    OpenPgp(#[from] crate::openpgp::Error),

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
}
