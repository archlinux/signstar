//! Common components used in state handling.

use std::fmt::Display;

#[cfg(doc)]
use pgp::composed::SignedPublicKey;
use signstar_crypto::key::CryptographicKeyContext;

/// The state of a key certificate.
///
/// Key certificates are technology specific and carry information on the context in which a key is
/// used. They can be derived e.g. from Signstar backends or Signstar configuration files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyCertificateState {
    /// A [`CryptographicKeyContext`] describing the context in which a certificate is used.
    KeyContext(CryptographicKeyContext),

    /// There is no key certificate for the key.
    Empty,

    /// A key certificate could not be retrieved due to an error.
    Error {
        /// A string containing the error message.
        message: String,
    },

    /// The key certificate cannot be turned into a [`CryptographicKeyContext`].
    NotACryptographicKeyContext {
        /// A message explaining that and why the [`CryptographicKeyContext`] cannot be created.
        message: String,
    },

    /// The key certificate cannot be turned into a [`SignedPublicKey`] (an OpenPGP certificate).
    NotAnOpenPgpCertificate {
        /// A message explaining why the key certificate cannot be converted to a
        /// [`SignedPublicKey`].
        message: String,
    },
}

impl Display for KeyCertificateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyContext(context) => write!(f, "{context}"),
            Self::Empty => write!(f, "Empty"),
            Self::Error { message } => {
                write!(f, "Error retrieving key certificate - {message}")
            }
            Self::NotACryptographicKeyContext { message } => {
                write!(f, "Not a cryptographic key context - \"{message}\"")
            }
            Self::NotAnOpenPgpCertificate { message } => {
                write!(f, "Not an OpenPGP certificate - \"{message}\"")
            }
        }
    }
}
