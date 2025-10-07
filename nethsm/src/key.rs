use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};
use signstar_crypto::key::MIN_RSA_BIT_LENGTH;

use crate::TlsKeyType;

/// An error that can occur when dealing with keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Elliptic curve TLS keys do not support providing a length
    #[error("Elliptic curve key ({tls_key_type}) does not support setting length")]
    TlsKeyLengthUnsupported { tls_key_type: TlsKeyType },

    /// RSA TLS key type requires setting a length
    #[error("Generating a key of type {tls_key_type} requires setting a length")]
    TlsKeyLengthRequired { tls_key_type: TlsKeyType },

    /// RSA TLS key is generated with unsafe key length (smaller than 2048)
    #[error(
        "RSA keys shorter than {MIN_RSA_BIT_LENGTH} are not supported. A key length of {key_length} is unsafe!"
    )]
    InvalidTlsKeyLengthRsa { key_length: u32 },

    /// One or more [`KeyId`]s are not valid.
    #[error("Invalid Key ID{}: {}", if key_ids.len() == 1 {"s"} else { " "}, key_ids.join(", "))]
    InvalidKeyIds {
        /// A list of strings representing invalid [`KeyId`]s.
        key_ids: Vec<String>,
    },

    /// A signstar_crypto key  error.
    #[error("A signstar_crypto::key error:\n{0}")]
    SignstarCryptoKey(#[from] signstar_crypto::key::Error),
}

/// A unique key identifier for a private key on a NetHSM.
///
/// A [`KeyId`]s must be in the character set `[a-z0-9]` and must not be empty.
/// It is used in [key management] on a NetHSM and is unique in its scope.
/// The same [`KeyId`] may exist system-wide and in one or several [namespaces], but no duplicate
/// [`KeyId`] can exist system-wide or in the same namespace.
///
/// [key management]: https://docs.nitrokey.com/nethsm/operation#key-management
/// [namespaces]: https://docs.nitrokey.com/nethsm/administration#namespaces
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct KeyId(String);

impl KeyId {
    /// Constructs a new Key ID from a `String`.
    ///
    /// Validates the input string and returns [`crate::Error::Key`]
    /// if it is invalid.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`][`crate::Error`] if
    /// * string contains characters outside of the allowed range (`[a-z0-9]`)
    /// * string is empty
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::KeyId;
    ///
    /// assert!(KeyId::new("key1".into()).is_ok());
    /// assert!(KeyId::new("key".into()).is_ok());
    ///
    /// // the input can not contain invalid chars
    /// assert!(KeyId::new("key1#".into()).is_err());
    /// assert!(KeyId::new("key~1".into()).is_err());
    ///
    /// // the key must be non-empty
    /// assert!(KeyId::new("".into()).is_err());
    /// ```
    pub fn new(key_id: String) -> Result<Self, Error> {
        if key_id.is_empty()
            || !key_id.chars().all(|char| {
                char.is_numeric() || (char.is_ascii_lowercase() && char.is_ascii_alphabetic())
            })
        {
            return Err(Error::InvalidKeyIds {
                key_ids: vec![key_id],
            });
        }

        Ok(Self(key_id))
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<KeyId> for String {
    fn from(value: KeyId) -> Self {
        value.0
    }
}

impl FromStr for KeyId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.into())
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl TryFrom<&str> for KeyId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl TryFrom<&String> for KeyId {
    type Error = Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::from_str(value)
    }
}

impl TryFrom<String> for KeyId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Ensures that a [`TlsKeyType`] is compatible with an optional key length
///
/// # Errors
///
/// Returns an [`Error::Key`][`crate::Error::Key`] if
/// * `tls_key_type` is one of [`TlsKeyType::Curve25519`], [`TlsKeyType::EcP224`],
///   [`TlsKeyType::EcP256`], [`TlsKeyType::EcP384`] or [`TlsKeyType::EcP521`] and `length` is
///   [`Some`].
/// * `tls_key_type` is [`TlsKeyType::Rsa`] and `length` is [`None`].
/// * `tls_key_type` is [`TlsKeyType::Rsa`] and `length` is not [`Some`] value equal to or greater
///   than [`MIN_RSA_BIT_LENGTH`].
///
/// # Examples
///
/// ```
/// use nethsm::{TlsKeyType, tls_key_type_matches_length};
///
/// # fn main() -> testresult::TestResult {
/// tls_key_type_matches_length(TlsKeyType::Curve25519, None)?;
/// tls_key_type_matches_length(TlsKeyType::EcP224, None)?;
/// tls_key_type_matches_length(TlsKeyType::Rsa, Some(2048))?;
///
/// // this fails because elliptic curve keys have their length set intrinsically
/// assert!(tls_key_type_matches_length(TlsKeyType::Curve25519, Some(2048)).is_err());
/// // this fails because a bit length of 1024 is unsafe to use for RSA keys
/// assert!(tls_key_type_matches_length(TlsKeyType::Rsa, Some(1024)).is_err());
/// # Ok(())
/// # }
/// ```
pub fn tls_key_type_matches_length(
    tls_key_type: TlsKeyType,
    length: Option<u32>,
) -> Result<(), Error> {
    match tls_key_type {
        TlsKeyType::Curve25519
        | TlsKeyType::EcP224
        | TlsKeyType::EcP256
        | TlsKeyType::EcP384
        | TlsKeyType::EcP521 => {
            if length.is_some() {
                Err(Error::TlsKeyLengthUnsupported { tls_key_type })
            } else {
                Ok(())
            }
        }
        TlsKeyType::Rsa => match length {
            None => Err(Error::TlsKeyLengthRequired { tls_key_type }),
            Some(length) => {
                if length < MIN_RSA_BIT_LENGTH {
                    Err(Error::InvalidTlsKeyLengthRsa { key_length: length })
                } else {
                    Ok(())
                }
            }
        },
    }
}
