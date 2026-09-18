//! Error handling.

/// An error that may occur when downloading the certificates of signing keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
    /// No HSM backend support is compiled in.
    #[error("No HSM backend support compiled in")]
    NoBackend,

    /// No credentials found for current system user.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No credentials for the system user {user}")]
    NoCredentials {
        /// The username that does not have credentials associated.
        user: String,
    },

    /// Configuration error.
    #[error("Signstar config error: {0}")]
    Config(#[from] signstar_config::Error),

    /// NetHSM error.
    #[cfg(feature = "nethsm")]
    #[error("NetHSM error: {0}")]
    NetHsm(#[from] nethsm::Error),

    /// JSON serialization error.
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    /// A signstar-common error.

    #[error(transparent)]
    SignstarCommon(#[from] signstar_common::Error),

    /// A signstar-crypto error.
    #[error(transparent)]
    SignstarCrypto(#[from] signstar_crypto::Error),

    /// YubiHSM error.
    #[cfg(feature = "yubihsm2")]
    #[error(transparent)]
    YubiHsm(#[from] signstar_yubihsm2::Error),
}
