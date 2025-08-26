//! Traits and associated structures for low-level signer interface.

use crate::signer::error::Error;

/// Represents a signing key for low-level operations.
pub trait RawSigningKey {
    /// Returns key identifier as a string.
    ///
    /// Each signing key has an identifier in a implementation defined format.
    /// This function will convert that to a [`String`].
    fn key_id(&self) -> String;

    /// Signs a raw digest.
    ///
    /// The digest is without any framing and the result should be a vector of raw signature parts.
    ///
    /// # Errors
    ///
    /// If the operation fails, the implementation should return an appropriate error.
    /// The [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error>;

    /// Returns certificate bytes associated with this signing key, if any.
    ///
    /// This interface does not interpret the certificate in any way but only reflects on whether a
    /// certificate is set or not.
    ///
    /// # Errors
    ///
    /// If the operation fails, the implementation should return an appropriate error.
    /// The [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn certificate(&self) -> Result<Option<Vec<u8>>, Error>;

    /// Returns raw public parts of the signing key.
    ///
    /// The implementation of the [`RawSigningKey`] trait implies that a signing key exists and also
    /// provides public parts.
    /// The returned [`RawPublicKey`] is used for generating technology-specific certificates.
    ///
    /// # Errors
    ///
    /// If the operation fails, the implementation should return an appropriate error.
    /// The [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn public(&self) -> Result<RawPublicKey, Error>;
}

/// Representation of a public key associated with a [`RawSigningKey`] implementation.
#[derive(Debug)]
pub enum RawPublicKey {
    /// Ed25519 public key.
    Ed25519(Vec<u8>),
    /// RSA public key.
    Rsa {
        /// Modulus of the RSA key.
        modulus: Vec<u8>,
        /// Exponent of the RSA key.
        exponent: Vec<u8>,
    },
    /// NIST P-256 public key.
    P256(Vec<u8>),
    /// NIST P-348 public key.
    P384(Vec<u8>),
    /// NIST P-521 public key.
    P521(Vec<u8>),
}
