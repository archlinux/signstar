//! Error handling.

/// An error that may occur when downloading the certificates of signing keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
    /// No HSM backend support is compiled in.
    #[error("No HSM backend support compiled in")]
    NoBackend,

    /// The configuration offers no connection for a backend.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No connection set for the backend")]
    NoConnection,

    /// No credentials found for current system user.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No credentials for the system user {user}")]
    NoCredentials {
        /// The username that does not have credentials associated.
        user: String,
    },

    /// Username cannot be converted to backend-specific format.
    #[error("No credentials for the system user {user}")]
    InvalidUser {
        /// The username for which the conversion fails.
        user: String,
    },

    /// Signing key is using a key context that is unsupported.
    #[error("Unsupported key context for signing key: {signing_key_id}")]
    UnsupportedKeyContext {
        /// The identifier of the signing key.
        signing_key_id: String,
    },
}
