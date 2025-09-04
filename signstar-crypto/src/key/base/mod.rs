//! Cryptographic key handling.

#[cfg(feature = "nethsm")]
pub mod nethsm;

use std::fmt::Display;

use pgp::{composed::SignedPublicKey, types::KeyDetails as _};
use serde::{Deserialize, Serialize};
use strum::{EnumIter, EnumString, IntoStaticStr};

use crate::{
    key::error::Error,
    openpgp::{OpenPgpUserId, OpenPgpUserIdList, OpenPgpVersion},
};

/// A mode for decrypting a message
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum DecryptMode {
    /// Decryption using the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC)
    AesCbc,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using an MD-5 hash
    OaepMd5,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-1 hash
    OaepSha1,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-224 hash
    OaepSha224,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-256 hash
    OaepSha256,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-384 hash
    OaepSha384,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-512 hash
    OaepSha512,

    /// RSA decryption following the PKCS#1 standard
    Pkcs1,

    /// Raw RSA decryption
    #[default]
    Raw,
}

/// A mode for encrypting a message
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum EncryptMode {
    /// Encryption using the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC)
    #[default]
    AesCbc,
}

/// The format of a key
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    EnumString,
    EnumIter,
    IntoStaticStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum KeyFormat {
    /// Privacy-Enhanced Mail (PEM) format.
    Pem,

    /// ASN.1 DER binary format.
    #[default]
    Der,
}

/// The minimum bit length for an RSA key
///
/// This follows recommendations from [NIST Special Publication 800-57 Part 3 Revision 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf) (January 2015).
pub const MIN_RSA_BIT_LENGTH: u32 = 2048;

/// The algorithm type of a key
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    EnumString,
    EnumIter,
    IntoStaticStr,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum KeyType {
    /// A Montgomery curve key over a prime field for the prime number 2^255-19
    #[default]
    Curve25519,

    /// An elliptic-curve key over a prime field for a prime of size 256 bit
    EcP256,

    /// An elliptic-curve key over a prime field for a prime of size 384 bit
    EcP384,

    /// An elliptic-curve key over a prime field for a prime of size 521 bit
    EcP521,

    /// A generic key used for block ciphers
    Generic,

    /// An RSA key
    Rsa,
}

/// A mechanism which can be used with a key
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    EnumString,
    EnumIter,
    IntoStaticStr,
    Hash,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum KeyMechanism {
    /// Decryption using the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC)
    AesDecryptionCbc,

    /// Encryption using the Advanced Encryption Standard (AES) with Cipher Block Chaining (CBC)
    AesEncryptionCbc,

    /// Signing following the Elliptic Curve Digital Signature Algorithm (ECDSA)
    EcdsaSignature,

    /// Signing following the Edwards-curve Digital Signature Algorithm (EdDSA)
    #[default]
    EdDsaSignature,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using an MD-5 hash
    RsaDecryptionOaepMd5,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-1 hash
    RsaDecryptionOaepSha1,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-224 hash
    RsaDecryptionOaepSha224,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-256 hash
    RsaDecryptionOaepSha256,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-384 hash
    RsaDecryptionOaepSha384,

    /// RSA decryption with Optimal Asymmetric Encryption Padding (OAEP) using a SHA-512 hash
    RsaDecryptionOaepSha512,

    /// RSA decryption following the PKCS#1 standard
    RsaDecryptionPkcs1,

    /// Raw RSA decryption
    RsaDecryptionRaw,

    /// RSA signing following the PKCS#1 standard
    RsaSignaturePkcs1,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using an MD-5 hash
    RsaSignaturePssMd5,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-1 hash
    RsaSignaturePssSha1,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-224 hash
    RsaSignaturePssSha224,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-256 hash
    RsaSignaturePssSha256,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-384 hash
    RsaSignaturePssSha384,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-512 hash
    RsaSignaturePssSha512,
}

impl KeyMechanism {
    /// Returns key mechanisms specific to Curve25519 key types
    pub fn curve25519_mechanisms() -> Vec<KeyMechanism> {
        vec![KeyMechanism::EdDsaSignature]
    }

    /// Returns key mechanisms specific to elliptic curve key types
    pub fn elliptic_curve_mechanisms() -> Vec<KeyMechanism> {
        vec![KeyMechanism::EcdsaSignature]
    }

    /// Returns key mechanisms specific to generic key types
    pub fn generic_mechanisms() -> Vec<KeyMechanism> {
        vec![
            KeyMechanism::AesDecryptionCbc,
            KeyMechanism::AesEncryptionCbc,
        ]
    }

    /// Returns key mechanisms specific to RSA key types
    pub fn rsa_mechanisms() -> Vec<KeyMechanism> {
        vec![
            KeyMechanism::RsaDecryptionRaw,
            KeyMechanism::RsaDecryptionPkcs1,
            KeyMechanism::RsaDecryptionOaepMd5,
            KeyMechanism::RsaDecryptionOaepSha1,
            KeyMechanism::RsaDecryptionOaepSha224,
            KeyMechanism::RsaDecryptionOaepSha256,
            KeyMechanism::RsaDecryptionOaepSha384,
            KeyMechanism::RsaDecryptionOaepSha512,
            KeyMechanism::RsaSignaturePkcs1,
            KeyMechanism::RsaSignaturePssMd5,
            KeyMechanism::RsaSignaturePssSha1,
            KeyMechanism::RsaSignaturePssSha224,
            KeyMechanism::RsaSignaturePssSha256,
            KeyMechanism::RsaSignaturePssSha384,
            KeyMechanism::RsaSignaturePssSha512,
        ]
    }
}

/// The type of a signature.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    strum::Display,
    EnumString,
    EnumIter,
    IntoStaticStr,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum SignatureType {
    /// Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field
    /// for a prime of size 256 bit
    EcdsaP256,

    /// Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field
    /// for a prime of size 384 bit
    EcdsaP384,

    /// Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field
    /// for a prime of size 521 bit
    EcdsaP521,

    /// Signing following the Edwards-curve Digital Signature Algorithm (EdDSA)
    EdDsa,

    /// RSA signing following the PKCS#1 standard
    Pkcs1,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using an MD-5 hash
    PssMd5,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-1 hash
    PssSha1,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-224 hash
    PssSha224,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-256 hash
    PssSha256,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-384 hash
    PssSha384,

    /// RSA signing following a "probabilistic signature scheme" (PSS) using a SHA-512 hash
    PssSha512,
}

/// The cryptographic context in which a key is used.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum CryptographicKeyContext {
    /// A key is used in an OpenPGP context
    #[serde(rename = "openpgp")]
    OpenPgp {
        /// List of OpenPGP User IDs for the certificate.
        user_ids: OpenPgpUserIdList,

        /// OpenPGP version for the certificate.
        version: OpenPgpVersion,
    },

    /// A key is used in a raw cryptographic context
    #[serde(rename = "raw")]
    Raw,
}

impl CryptographicKeyContext {
    /// Validates the cryptographic context against a signing key setup
    ///
    /// # Errors
    ///
    /// Returns an error if the key setup can not be used for signing operations in the respective
    /// cryptographic context.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType};
    /// use signstar_crypto::openpgp::{OpenPgpUserIdList, OpenPgpVersion};
    ///
    /// # fn main() -> testresult::TestResult {
    /// CryptographicKeyContext::Raw.validate_signing_key_setup(
    ///     KeyType::Curve25519,
    ///     &[KeyMechanism::EdDsaSignature],
    ///     SignatureType::EdDsa,
    /// )?;
    ///
    /// CryptographicKeyContext::OpenPgp {
    ///     user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
    ///     version: OpenPgpVersion::V4,
    /// }
    /// .validate_signing_key_setup(
    ///     KeyType::Curve25519,
    ///     &[KeyMechanism::EdDsaSignature],
    ///     SignatureType::EdDsa,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn validate_signing_key_setup(
        &self,
        key_type: KeyType,
        key_mechanisms: &[KeyMechanism],
        signature_type: SignatureType,
    ) -> Result<(), Error> {
        match self {
            Self::Raw => match (key_type, signature_type) {
                (KeyType::Curve25519, SignatureType::EdDsa)
                    if key_mechanisms.contains(&KeyMechanism::EdDsaSignature) => {}
                (KeyType::EcP256, SignatureType::EcdsaP256)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
                (KeyType::EcP384, SignatureType::EcdsaP384)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
                (KeyType::EcP521, SignatureType::EcdsaP521)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
                (KeyType::Rsa, SignatureType::Pkcs1)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePkcs1) => {}
                (KeyType::Rsa, SignatureType::PssMd5)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePssMd5) => {}
                (KeyType::Rsa, SignatureType::PssSha1)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePssSha1) => {}
                (KeyType::Rsa, SignatureType::PssSha224)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePssSha224) => {}
                (KeyType::Rsa, SignatureType::PssSha256)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePssSha256) => {}
                (KeyType::Rsa, SignatureType::PssSha384)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePssSha384) => {}
                (KeyType::Rsa, SignatureType::PssSha512)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePssSha512) => {}
                _ => {
                    return Err(Error::InvalidRawSigningKeySetup {
                        key_type,
                        key_mechanisms: key_mechanisms.to_vec(),
                        signature_type,
                    });
                }
            },
            Self::OpenPgp {
                user_ids: _,
                version: _,
            } => match (key_type, signature_type) {
                (KeyType::Curve25519, SignatureType::EdDsa)
                    if key_mechanisms.contains(&KeyMechanism::EdDsaSignature) => {}
                (KeyType::EcP256, SignatureType::EcdsaP256)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
                (KeyType::EcP384, SignatureType::EcdsaP384)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
                (KeyType::EcP521, SignatureType::EcdsaP521)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
                (KeyType::Rsa, SignatureType::Pkcs1)
                    if key_mechanisms.contains(&KeyMechanism::RsaSignaturePkcs1) => {}
                _ => {
                    return Err(Error::InvalidOpenPgpSigningKeySetup {
                        key_type,
                        key_mechanisms: key_mechanisms.to_vec(),
                        signature_type,
                    });
                }
            },
        }
        Ok(())
    }
}

impl Display for CryptographicKeyContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenPgp { user_ids, version } => {
                write!(
                    f,
                    "OpenPGP (Version: {version}; User IDs: {})",
                    user_ids
                        .iter()
                        .map(|user_id| format!("\"{user_id}\""))
                        .collect::<Vec<String>>()
                        .join(", ")
                )
            }
            Self::Raw => {
                write!(f, "Raw")
            }
        }
    }
}

impl TryFrom<SignedPublicKey> for CryptographicKeyContext {
    type Error = crate::Error;

    /// Creates a [`CryptographicKeyContext`] from [`SignedPublicKey`].
    ///
    /// Drops any invalid OpenPGP User ID (e.g. non-UTF-8).
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - duplicate OpenPGP User IDs are encountered in `value`,
    /// - or no valid OpenPGP version can be derived from the OpenPGP primary key in `value`.
    fn try_from(value: SignedPublicKey) -> Result<Self, Self::Error> {
        let user_ids: Vec<OpenPgpUserId> = value
            .details
            .users
            .iter()
            .filter_map(|signed_user| signed_user.try_into().ok())
            .collect();

        Ok(Self::OpenPgp {
            user_ids: OpenPgpUserIdList::new(user_ids)?,
            version: value.primary_key.version().try_into()?,
        })
    }
}

/// Ensures that a [`KeyType`] is compatible with a list of [`KeyMechanism`]s
///
/// # Errors
///
/// Returns an error if any of the `mechanisms` is incompatible with the `key_type`.
///
/// # Examples
///
/// ```
/// use signstar_crypto::key::{KeyMechanism, KeyType, key_type_matches_mechanisms};
///
/// # fn main() -> testresult::TestResult {
/// key_type_matches_mechanisms(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature])?;
/// key_type_matches_mechanisms(
///     KeyType::Rsa,
///     &[
///         KeyMechanism::RsaDecryptionPkcs1,
///         KeyMechanism::RsaSignaturePkcs1,
///     ],
/// )?;
/// key_type_matches_mechanisms(
///     KeyType::Generic,
///     &[
///         KeyMechanism::AesDecryptionCbc,
///         KeyMechanism::AesEncryptionCbc,
///     ],
/// )?;
///
/// // this fails because Curve25519 is not compatible with the Elliptic Curve Digital Signature Algorithm (ECDSA),
/// // but instead requires the use of the Edwards-curve Digital Signature Algorithm (EdDSA)
/// assert!(
///     key_type_matches_mechanisms(KeyType::Curve25519, &[KeyMechanism::EcdsaSignature]).is_err()
/// );
///
/// // this fails because RSA key mechanisms are not compatible with block ciphers
/// assert!(key_type_matches_mechanisms(
///     KeyType::Generic,
///     &[
///         KeyMechanism::RsaDecryptionPkcs1,
///         KeyMechanism::RsaSignaturePkcs1,
///     ]
/// )
/// .is_err());
///
/// // this fails because RSA keys do not support Curve25519's Edwards-curve Digital Signature Algorithm (EdDSA)
/// assert!(key_type_matches_mechanisms(
///     KeyType::Rsa,
///     &[
///         KeyMechanism::AesDecryptionCbc,
///         KeyMechanism::AesEncryptionCbc,
///         KeyMechanism::EcdsaSignature
///     ]
/// )
/// .is_err());
/// # Ok(())
/// # }
/// ```
pub fn key_type_matches_mechanisms(
    key_type: KeyType,
    mechanisms: &[KeyMechanism],
) -> Result<(), Error> {
    let valid_mechanisms: &[KeyMechanism] = match key_type {
        KeyType::Curve25519 => &KeyMechanism::curve25519_mechanisms(),
        KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
            &KeyMechanism::elliptic_curve_mechanisms()
        }
        KeyType::Generic => &KeyMechanism::generic_mechanisms(),
        KeyType::Rsa => &KeyMechanism::rsa_mechanisms(),
    };

    let invalid_mechanisms = mechanisms
        .iter()
        .filter(|mechanism| !valid_mechanisms.contains(mechanism))
        .cloned()
        .collect::<Vec<KeyMechanism>>();

    if invalid_mechanisms.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidKeyMechanism {
            key_type,
            invalid_mechanisms,
        })
    }
}

/// Ensures that a [`KeyType`] and a list of [`KeyMechanism`]s is compatible with a
/// [`SignatureType`]
///
/// # Errors
///
/// Returns an error if the provided `signature_type` is incompatible with the `key_type` or
/// `mechanisms`.
///
/// # Examples
///
/// ```
/// use signstar_crypto::key::{KeyMechanism, KeyType, SignatureType, key_type_and_mechanisms_match_signature_type};
///
/// # fn main() -> testresult::TestResult {
/// key_type_and_mechanisms_match_signature_type(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature], SignatureType::EdDsa)?;
/// key_type_and_mechanisms_match_signature_type(KeyType::EcP256, &[KeyMechanism::EcdsaSignature], SignatureType::EcdsaP256)?;
/// key_type_and_mechanisms_match_signature_type(KeyType::Rsa, &[KeyMechanism::RsaSignaturePkcs1],SignatureType::Pkcs1)?;
///
/// // this fails because Curve25519 is not compatible with the Elliptic Curve Digital Signature Algorithm (ECDSA),
/// // but instead requires the use of the Edwards-curve Digital Signature Algorithm (EdDSA)
/// assert!(
///     key_type_and_mechanisms_match_signature_type(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature], SignatureType::EcdsaP256).is_err()
/// );
/// # Ok(())
/// # }
/// ```
pub fn key_type_and_mechanisms_match_signature_type(
    key_type: KeyType,
    mechanisms: &[KeyMechanism],
    signature_type: SignatureType,
) -> Result<(), Error> {
    match signature_type {
        SignatureType::EcdsaP256 => {
            if key_type != KeyType::EcP256 {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::EcdsaSignature) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::EcdsaSignature,
                    signature_type,
                });
            }
        }
        SignatureType::EcdsaP384 => {
            if key_type != KeyType::EcP384 {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::EcdsaSignature) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::EcdsaSignature,
                    signature_type,
                });
            }
        }
        SignatureType::EcdsaP521 => {
            if key_type != KeyType::EcP521 {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::EcdsaSignature) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::EcdsaSignature,
                    signature_type,
                });
            }
        }
        SignatureType::EdDsa => {
            if key_type != KeyType::Curve25519 {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::EdDsaSignature) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::EdDsaSignature,
                    signature_type,
                });
            }
        }
        SignatureType::Pkcs1 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePkcs1) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePkcs1,
                    signature_type,
                });
            }
        }
        SignatureType::PssMd5 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePssMd5) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePssMd5,
                    signature_type,
                });
            }
        }
        SignatureType::PssSha1 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePssSha1) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePssSha1,
                    signature_type,
                });
            }
        }
        SignatureType::PssSha224 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePssSha224) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePssSha224,
                    signature_type,
                });
            }
        }
        SignatureType::PssSha256 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePssSha256) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePssSha256,
                    signature_type,
                });
            }
        }
        SignatureType::PssSha384 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePssSha384) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePssSha384,
                    signature_type,
                });
            }
        }
        SignatureType::PssSha512 => {
            if key_type != KeyType::Rsa {
                return Err(Error::InvalidKeyTypeForSignatureType {
                    key_type,
                    signature_type,
                });
            } else if !mechanisms.contains(&KeyMechanism::RsaSignaturePssSha512) {
                return Err(Error::InvalidKeyMechanismsForSignatureType {
                    required_key_mechanism: KeyMechanism::RsaSignaturePssSha512,
                    signature_type,
                });
            }
        }
    }
    Ok(())
}

/// Ensures that a [`KeyType`] is compatible with an optional key length
///
/// # Errors
///
/// Returns an error if
/// * `key_type` is one of [`KeyType::Curve25519`], [`KeyType::EcP256`], [`KeyType::EcP384`] or
///   [`KeyType::EcP521`] and `length` is [`Some`].
/// * `key_type` is [`KeyType::Generic`] or [`KeyType::Rsa`] and `length` is [`None`].
/// * `key_type` is [`KeyType::Generic`] and `length` is not [`Some`] value of `128`, `192` or
///   `256`.
/// * `key_type` is [`KeyType::Rsa`] and `length` is not [`Some`] value equal to or greater than
///   [`MIN_RSA_BIT_LENGTH`].
///
/// # Examples
///
/// ```
/// use signstar_crypto::key::{KeyType, key_type_matches_length};
///
/// # fn main() -> testresult::TestResult {
/// key_type_matches_length(KeyType::Curve25519, None)?;
/// key_type_matches_length(KeyType::EcP256, None)?;
/// key_type_matches_length(KeyType::Rsa, Some(2048))?;
/// key_type_matches_length(KeyType::Generic, Some(256))?;
///
/// // this fails because elliptic curve keys have their length set intrinsically
/// assert!(key_type_matches_length(KeyType::Curve25519, Some(2048)).is_err());
/// // this fails because a bit length of 2048 is not defined for AES block ciphers
/// assert!(key_type_matches_length(KeyType::Generic, Some(2048)).is_err());
/// // this fails because a bit length of 1024 is unsafe to use for RSA keys
/// assert!(key_type_matches_length(KeyType::Rsa, Some(1024)).is_err());
/// # Ok(())
/// # }
/// ```
pub fn key_type_matches_length(key_type: KeyType, length: Option<u32>) -> Result<(), Error> {
    match key_type {
        KeyType::Curve25519 | KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
            if length.is_some() {
                Err(Error::KeyLengthUnsupported { key_type })
            } else {
                Ok(())
            }
        }
        KeyType::Generic => match length {
            None => Err(Error::KeyLengthRequired { key_type }),
            Some(length) => {
                if ![128, 192, 256].contains(&length) {
                    Err(Error::InvalidKeyLengthAes { key_length: length })
                } else {
                    Ok(())
                }
            }
        },
        KeyType::Rsa => match length {
            None => Err(Error::KeyLengthRequired { key_type }),
            Some(length) => {
                if length < MIN_RSA_BIT_LENGTH {
                    Err(Error::InvalidKeyLengthRsa { key_length: length })
                } else {
                    Ok(())
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    #[case(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature], SignatureType::EdDsa, None)]
    #[case(KeyType::EcP256, &[KeyMechanism::EcdsaSignature], SignatureType::EcdsaP256, None)]
    #[case(KeyType::EcP384, &[KeyMechanism::EcdsaSignature], SignatureType::EcdsaP384, None)]
    #[case(KeyType::EcP521, &[KeyMechanism::EcdsaSignature], SignatureType::EcdsaP521, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePkcs1], SignatureType::Pkcs1, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePssMd5], SignatureType::PssMd5, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePssSha1], SignatureType::PssSha1, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePssSha224], SignatureType::PssSha224, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePssSha256], SignatureType::PssSha256, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePssSha384], SignatureType::PssSha384, None)]
    #[case(KeyType::Rsa, &[KeyMechanism::RsaSignaturePssSha512], SignatureType::PssSha512, None)]
    #[case(
        KeyType::Curve25519,
        &[KeyMechanism::EdDsaSignature],
        SignatureType::EcdsaP256,
        Some(Box::new(Error::InvalidKeyTypeForSignatureType {
            key_type: KeyType::Curve25519,
            signature_type: SignatureType::EcdsaP256
        })
    ))]
    #[case(
        KeyType::Curve25519,
        &[KeyMechanism::EcdsaSignature],
        SignatureType::EdDsa,
        Some(Box::new(Error::InvalidKeyMechanismsForSignatureType {
            signature_type: SignatureType::EdDsa,
            required_key_mechanism: KeyMechanism::EdDsaSignature,
        })
    ))]
    #[case(
        KeyType::EcP256,
        &[KeyMechanism::EcdsaSignature],
        SignatureType::EdDsa,
        Some(Box::new(Error::InvalidKeyTypeForSignatureType {
            key_type: KeyType::EcP256,
            signature_type: SignatureType::EdDsa,
        })
    ))]
    #[case(
        KeyType::EcP256,
        &[KeyMechanism::EdDsaSignature],
        SignatureType::EcdsaP256,
        Some(Box::new(Error::InvalidKeyMechanismsForSignatureType {
            signature_type: SignatureType::EcdsaP256,
            required_key_mechanism: KeyMechanism::EcdsaSignature,
        })
    ))]
    #[case(
        KeyType::EcP384,
        &[KeyMechanism::EcdsaSignature],
        SignatureType::EdDsa,
        Some(Box::new(Error::InvalidKeyTypeForSignatureType {
            key_type: KeyType::EcP384,
            signature_type: SignatureType::EdDsa,
        })
    ))]
    #[case(
        KeyType::EcP384,
        &[KeyMechanism::EdDsaSignature],
        SignatureType::EcdsaP384,
        Some(Box::new(Error::InvalidKeyMechanismsForSignatureType {
            signature_type: SignatureType::EcdsaP384,
            required_key_mechanism: KeyMechanism::EcdsaSignature,
        })
    ))]
    #[case(
        KeyType::EcP521,
        &[KeyMechanism::EcdsaSignature],
        SignatureType::EdDsa,
        Some(Box::new(Error::InvalidKeyTypeForSignatureType {
            key_type: KeyType::EcP521,
            signature_type: SignatureType::EdDsa,
        })
    ))]
    #[case(
        KeyType::EcP521,
        &[KeyMechanism::EdDsaSignature],
        SignatureType::EcdsaP521,
        Some(Box::new(Error::InvalidKeyMechanismsForSignatureType {
            signature_type: SignatureType::EcdsaP521,
            required_key_mechanism: KeyMechanism::EcdsaSignature,
        })
    ))]
    #[case(
        KeyType::Rsa,
        &[KeyMechanism::RsaSignaturePkcs1],
        SignatureType::EdDsa,
        Some(Box::new(Error::InvalidKeyTypeForSignatureType {
            key_type: KeyType::Rsa,
            signature_type: SignatureType::EdDsa,
        })
    ))]
    #[case(
        KeyType::Rsa,
        &[KeyMechanism::RsaDecryptionOaepMd5],
        SignatureType::PssMd5,
        Some(Box::new(Error::InvalidKeyMechanismsForSignatureType {
            signature_type: SignatureType::PssMd5,
            required_key_mechanism: KeyMechanism::RsaSignaturePssMd5,
        })
    ))]
    fn test_key_type_and_mechanisms_match_signature_type(
        #[case] key_type: KeyType,
        #[case] key_mechanisms: &[KeyMechanism],
        #[case] signature_type: SignatureType,
        #[case] result: Option<Box<Error>>,
    ) -> TestResult {
        if let Some(error) = result {
            if let Err(fn_error) = key_type_and_mechanisms_match_signature_type(
                key_type,
                key_mechanisms,
                signature_type,
            ) {
                assert_eq!(fn_error.to_string(), error.to_string());
            } else {
                panic!("Did not return an Error!");
            }
        } else {
            key_type_and_mechanisms_match_signature_type(key_type, key_mechanisms, signature_type)?;
        }

        Ok(())
    }

    #[rstest]
    #[case("raw", Some(DecryptMode::Raw))]
    #[case("pkcs1", Some(DecryptMode::Pkcs1))]
    #[case("oaepmd5", Some(DecryptMode::OaepMd5))]
    #[case("oaepsha1", Some(DecryptMode::OaepSha1))]
    #[case("oaepsha224", Some(DecryptMode::OaepSha224))]
    #[case("oaepsha256", Some(DecryptMode::OaepSha256))]
    #[case("oaepsha384", Some(DecryptMode::OaepSha384))]
    #[case("oaepsha512", Some(DecryptMode::OaepSha512))]
    #[case("aescbc", Some(DecryptMode::AesCbc))]
    #[case("foo", None)]
    fn decryptmode_fromstr(
        #[case] input: &str,
        #[case] expected: Option<DecryptMode>,
    ) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(DecryptMode::from_str(input)?, expected);
        } else {
            assert!(DecryptMode::from_str(input).is_err());
        }
        Ok(())
    }

    #[rstest]
    #[case("aescbc", Some(EncryptMode::AesCbc))]
    #[case("foo", None)]
    fn encryptmode_fromstr(
        #[case] input: &str,
        #[case] expected: Option<EncryptMode>,
    ) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(EncryptMode::from_str(input)?, expected);
        } else {
            assert!(EncryptMode::from_str(input).is_err());
        }
        Ok(())
    }

    #[rstest]
    #[case("rsadecryptionraw", Some(KeyMechanism::RsaDecryptionRaw))]
    #[case("rsadecryptionpkcs1", Some(KeyMechanism::RsaDecryptionPkcs1))]
    #[case("rsadecryptionoaepmd5", Some(KeyMechanism::RsaDecryptionOaepMd5))]
    #[case("rsadecryptionoaepsha1", Some(KeyMechanism::RsaDecryptionOaepSha1))]
    #[case("rsadecryptionoaepsha224", Some(KeyMechanism::RsaDecryptionOaepSha224))]
    #[case("rsadecryptionoaepsha256", Some(KeyMechanism::RsaDecryptionOaepSha256))]
    #[case("rsadecryptionoaepsha384", Some(KeyMechanism::RsaDecryptionOaepSha384))]
    #[case("rsadecryptionoaepsha512", Some(KeyMechanism::RsaDecryptionOaepSha512))]
    #[case("rsadecryptionoaepsha512", Some(KeyMechanism::RsaDecryptionOaepSha512))]
    #[case("rsasignaturepkcs1", Some(KeyMechanism::RsaSignaturePkcs1))]
    #[case("rsasignaturepssmd5", Some(KeyMechanism::RsaSignaturePssMd5))]
    #[case("rsasignaturepsssha1", Some(KeyMechanism::RsaSignaturePssSha1))]
    #[case("rsasignaturepsssha224", Some(KeyMechanism::RsaSignaturePssSha224))]
    #[case("rsasignaturepsssha256", Some(KeyMechanism::RsaSignaturePssSha256))]
    #[case("rsasignaturepsssha384", Some(KeyMechanism::RsaSignaturePssSha384))]
    #[case("rsasignaturepsssha512", Some(KeyMechanism::RsaSignaturePssSha512))]
    #[case("eddsasignature", Some(KeyMechanism::EdDsaSignature))]
    #[case("ecdsasignature", Some(KeyMechanism::EcdsaSignature))]
    #[case("aesencryptioncbc", Some(KeyMechanism::AesEncryptionCbc))]
    #[case("aesdecryptioncbc", Some(KeyMechanism::AesDecryptionCbc))]
    #[case("foo", None)]
    fn keymechanism_fromstr(
        #[case] input: &str,
        #[case] expected: Option<KeyMechanism>,
    ) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(KeyMechanism::from_str(input)?, expected);
        } else {
            assert!(KeyMechanism::from_str(input).is_err());
        }
        Ok(())
    }

    #[rstest]
    #[case("rsa", Some(KeyType::Rsa))]
    #[case("curve25519", Some(KeyType::Curve25519))]
    #[case("ecp256", Some(KeyType::EcP256))]
    #[case("ecp384", Some(KeyType::EcP384))]
    #[case("ecp521", Some(KeyType::EcP521))]
    #[case("generic", Some(KeyType::Generic))]
    #[case("foo", None)]
    fn keytype_fromstr(#[case] input: &str, #[case] expected: Option<KeyType>) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(KeyType::from_str(input)?, expected);
        } else {
            assert!(KeyType::from_str(input).is_err());
        }
        Ok(())
    }

    #[rstest]
    #[case("ecdsap256", Some(SignatureType::EcdsaP256))]
    #[case("ecdsap384", Some(SignatureType::EcdsaP384))]
    #[case("ecdsap521", Some(SignatureType::EcdsaP521))]
    #[case("eddsa", Some(SignatureType::EdDsa))]
    #[case("pkcs1", Some(SignatureType::Pkcs1))]
    #[case("pssmd5", Some(SignatureType::PssMd5))]
    #[case("psssha1", Some(SignatureType::PssSha1))]
    #[case("psssha224", Some(SignatureType::PssSha224))]
    #[case("psssha256", Some(SignatureType::PssSha256))]
    #[case("psssha384", Some(SignatureType::PssSha384))]
    #[case("psssha512", Some(SignatureType::PssSha512))]
    #[case("foo", None)]
    fn signaturetype_fromstr(
        #[case] input: &str,
        #[case] expected: Option<SignatureType>,
    ) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(SignatureType::from_str(input)?, expected);
        } else {
            assert!(SignatureType::from_str(input).is_err());
        }
        Ok(())
    }
}
