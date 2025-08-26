//! Error handling for [`NetHsm`].

#[cfg(doc)]
use crate::{NetHsm, connection};

/// An error that may occur when using a NetHSM.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wraps a [`rustls::Error`] for issues with rustls based TLS setups
    #[error("TLS error: {0}")]
    Rustls(#[from] rustls::Error),

    /// A Base64 encoded string can not be decode
    #[error("Decoding Base64 string failed: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// A generic error with a custom message
    #[error("NetHSM error: {0}")]
    Default(String),

    /// The loading of TLS root certificates from the platform's native certificate store failed
    #[error("Loading system TLS certs failed: {0:?}")]
    CertLoading(Vec<rustls_native_certs::Error>),

    /// No TLS root certificates from the platform's native certificate store could be added
    ///
    /// Provides the number certificates that failed to be added
    #[error("Unable to load any system TLS certs ({failed} failed)")]
    NoSystemCertsAdded {
        /// The number of certificates that failed to be added.
        failed: usize,
    },

    /// A call to the NetHSM API failed
    #[error("NetHSM API error: {0}")]
    Api(String),

    /// An error occurred in the [`connection`] module.
    #[error("NetHSM connection error:\n{0}")]
    Connection(#[from] crate::connection::Error),

    /// An error with a key occurred
    #[error("Key error: {0}")]
    Key(#[from] crate::key::Error),

    /// User data error
    #[error("User data error: {0}")]
    User(#[from] crate::user::Error),

    /// A [`signstar_crypto::signer::error::Error`] occurred.
    #[error(transparent)]
    SignstarCryptoSigner(#[from] signstar_crypto::signer::error::Error),

    /// A signstar_crypto key error.
    #[error("A signstar_crypto key error:\n{0}")]
    SignstarCryptoKey(#[from] signstar_crypto::key::Error),

    /// A signstar_crypto key error.
    #[error("A signstar_crypto passphrase error:\n{0}")]
    SignstarCryptoPassphrase(#[from] signstar_crypto::passphrase::Error),
}
