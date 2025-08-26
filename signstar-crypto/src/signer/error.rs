//! Contains [`Error`] enum for the low-level signer interface.

use pgp::{crypto::hash::HashAlgorithm, types::PublicParams};

/// An error that may occur when working with OpenPGP data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Certificate for the key has not been initialized
    #[error("Certificate for the key has not been initialized")]
    CertificateMissing,

    /// Elliptic curve error
    #[error("Elliptic curve error: {0}")]
    EllipticCurve(#[from] p256::elliptic_curve::Error),

    /// Provided key data is invalid
    #[error("Key data invalid: {0}")]
    KeyData(String),

    /// OpenPGP error
    #[error("rPGP error: {0}")]
    Pgp(#[from] pgp::errors::Error),

    /// The Transferable Secret Key is passphrase protected
    #[error("Transferable Secret Key is passphrase protected")]
    PrivateKeyPassphraseProtected,

    /// Multiple component keys are unsupported
    #[error("Unsupported multiple component keys")]
    UnsupportedMultipleComponentKeys,

    /// Invalid signature returned from the HSM
    #[error("Invalid signature {signature_type} encountered while {context}")]
    InvalidSignature {
        /// The context in which an invalid signature has been detected.
        ///
        /// This is meant to complete the sentence "Invalid signature encountered
        /// while ".
        context: &'static str,

        /// Signature type encountered when this error occurred.
        signature_type: String,
    },

    /// Unsupported hash requested
    #[error("Unsupported hash requested: {actual}. Supported hash must be {expected}")]
    UnsupportedHashAlgorithm {
        /// The hash algorithm that has been used.
        actual: HashAlgorithm,

        /// The hash algorithm that is supported.
        expected: HashAlgorithm,
    },

    /// The key format used is unsupported
    #[error("Unsupported key format: {public_params:?}")]
    UnsupportedKeyFormat {
        /// The unsupported public key parameters.
        public_params: Box<PublicParams>,
    },

    /// A signstar_crypto key  error.
    #[error("A signstar_crypto key error:\n{0}")]
    SignstarCryptoKey(#[from] crate::key::Error),

    /// An HSM operation error.
    #[error("HSM operation failed while {context}:\n{source}")]
    Hsm {
        /// The context in which an HSM error occurred.
        ///
        /// This is meant to complete the sentence "HSM operation failed
        /// while ".
        context: &'static str,
        /// The source error.
        source: Box<dyn std::error::Error + 'static + Send + Sync>,
    },

    /// An error that may occur when working with OpenPGP data.
    #[error(transparent)]
    OpenPgp(#[from] crate::openpgp::Error),
}
