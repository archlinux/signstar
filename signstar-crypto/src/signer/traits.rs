//! Traits and associated structures for low-level signer interface.

use crate::signer::error::Error;

/// Represents a signing key for low-level operations.
pub trait RawSigningKey {
    /// Signs a raw digest.
    ///
    /// The digest is without any framing and the result should be a vector of raw signature parts.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation should return appropriate error.
    /// [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error>;

    /// Returns certificate bytes associated with this signing key, if any.
    ///
    /// This interface does not interpret the certificate in any way but has a notion of certificate
    /// being set or unset.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation should return appropriate error.
    /// [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn certificate(&self) -> Result<Option<Vec<u8>>, Error>;

    /// Returns raw public parts of this signing key.
    ///
    /// Implementation of this trait implies that the signing key exists and as such always has
    /// public parts. The public key is used for generating application-specific certificates.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation should return appropriate error.
    /// [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn public(&self) -> Result<RawPublicKey, Error>;
}

/// Represents a public key associated with the [signing key][RawSigningKey].
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
