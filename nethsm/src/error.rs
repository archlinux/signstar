//! Error handling for [`NetHsm`].

#[cfg(doc)]
use crate::{NetHsm, connection};

/// An error that may occur when using a NetHSM.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Base64 encoded string can not be decode
    #[error("Decoding Base64 string failed: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// A generic error with a custom message
    #[error("NetHSM error: {0}")]
    Default(String),

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

    /// A [`signstar_crypto::Error`] occurred.
    #[error(transparent)]
    SignstarCrypto(#[from] signstar_crypto::Error),

    /// An compatibility issue occurred in the NetHSM SDK translation interface.
    #[error("Compatibility issue with nethsm-sdk-rs: {0}")]
    NetHsmSdkRsCompatibility(#[from] crate::nethsm_sdk::Error),
}
