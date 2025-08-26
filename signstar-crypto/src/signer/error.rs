//! Contains [`Error`] enum for the low-level signer interface.

use pgp::{
    crypto::hash::HashAlgorithm,
    types::{Fingerprint, PublicParams},
};

use crate::key::base::SignatureType;

/// An error that may occur when working with OpenPGP data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Certificate for the key has not been initialized
    #[error("There is no OpenPGP certificate for the key")]
    OpenPpgCertificateMissing,

    /// Elliptic curve error
    #[error("Elliptic curve error: {0}")]
    EllipticCurve(#[from] p256::elliptic_curve::Error),

    /// Public key data is invalid.
    #[error("Public key data is invalid because {context}")]
    InvalidPublicKeyData {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Public key data is invalid because ".
        context: String,
    },

    /// An OpenPGP error occurred.
    #[error("OpenPGP error: {0}")]
    Pgp(#[from] pgp::errors::Error),

    /// An OpenPGP Transferable Secret Key (TSK) is passphrase protected.
    #[error(
        "The OpenPGP Transferable Secret Key (TSK) with fingerprint {fingerprint} is passphrase protected"
    )]
    OpenPgpTskIsPassphraseProtected {
        /// The OpenPGP fingerprint of the TSK.
        fingerprint: Fingerprint,
    },

    /// An OpenPGP Transferable Secret Key (TSK) contains multiple component keys.
    #[error(
        "The OpenPGP Transferable Secret Key (TSK) with fingerprint {fingerprint} contains multiple component keys, which is not supported"
    )]
    OpenPgpTskContainsMultipleComponentKeys {
        /// The OpenPGP fingerprint of the TSK.
        fingerprint: Fingerprint,
    },

    /// An invalid signature is encountered.
    #[error("Invalid signature {signature_type} encountered while {context}")]
    InvalidSignature {
        /// The context in which an invalid signature has been detected.
        ///
        /// This is meant to complete the sentence "Invalid signature encountered
        /// while ".
        context: &'static str,

        /// Signature type encountered when this error occurred.
        signature_type: SignatureType,
    },

    /// An unsupported hash algorithm is requested.
    #[error("Unsupported hash algorithm requested. Expected {expected}, but got {actual}")]
    UnsupportedHashAlgorithm {
        /// The hash algorithm that has been used.
        actual: HashAlgorithm,

        /// The hash algorithm that is supported.
        expected: HashAlgorithm,
    },

    /// An unsupported signature algorithm is requested.
    #[error("Unsupported signature algorithm requested: {0}")]
    UnsupportedSignatureAlgorithm(SignatureType),

    /// The key format used is unsupported
    #[error("Unsupported key format {public_params:?} encountered while {context}")]
    UnsupportedKeyFormat {
        /// The context in which an unsupported key format has been detected.
        ///
        /// This is meant to complete the sentence "Unsupported key format encountered
        /// while ".
        context: &'static str,

        /// The unsupported public key parameters.
        public_params: Box<PublicParams>,
    },

    /// A [`crate::key::Error`]  error.
    #[error(transparent)]
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
