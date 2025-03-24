use std::{fmt::Display, str::FromStr};

use base64ct::{Base64, Encoding};
use nethsm_sdk_rs::models::KeyPrivateData;
use rsa::{
    RsaPrivateKey,
    pkcs8::DecodePrivateKey,
    traits::PrivateKeyParts,
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};

use crate::{KeyMechanism, KeyType, OpenPgpUserIdList, OpenPgpVersion, SignatureType, TlsKeyType};

/// The minimum bit length for an RSA key
///
/// This follows recommendations from [NIST Special Publication 800-57 Part 3 Revision 1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf) (January 2015).
pub const MIN_RSA_BIT_LENGTH: u32 = 2048;

/// A unique key identifier for a private key on a NetHSM.
///
/// A [`KeyId`]s must be in the character set `[a-z0-9]`.
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
            return Err(Error::InvalidKeyId(key_id));
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Importing from PKCS#8 DER or PEM failed
    #[error("PKCS#8 error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),

    /// No primes found when importing an RSA key
    #[error("No primes found")]
    NoPrimes,

    /// The [`KeyType`] is not supported
    #[error("The {0} key type is not supported")]
    UnsupportedKeyType(KeyType),

    /// The key mechanisms provided for a key type are not valid
    #[error(
        "The key type {key_type} does not support the following key mechanisms: {invalid_mechanisms:?}"
    )]
    InvalidKeyMechanism {
        key_type: KeyType,
        invalid_mechanisms: Vec<KeyMechanism>,
    },

    /// Elliptic curve keys do not support providing a length
    #[error("Elliptic curve key ({key_type}) does not support setting length")]
    KeyLengthUnsupported { key_type: KeyType },

    /// Key type requires setting a length
    #[error("Generating a key of type {key_type} requires setting a length")]
    KeyLengthRequired { key_type: KeyType },

    /// AES key is generated with unsupported key length (not 128, 192 or 256)
    #[error(
        "AES only defines key lengths of 128, 192 and 256. A key length of {key_length} is unsupported!"
    )]
    InvalidKeyLengthAes { key_length: u32 },

    /// RSA key is generated with unsafe key length (smaller than 2048)
    #[error(
        "RSA keys shorter than {MIN_RSA_BIT_LENGTH} are not supported. A key length of {key_length} is unsafe!"
    )]
    InvalidKeyLengthRsa { key_length: u32 },

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

    /// Invalid Key ID
    #[error("Invalid Key ID: {0}")]
    InvalidKeyId(String),

    /// The signature type provided for a key type is not valid
    #[error("The key type {key_type} is not compatible with signature type: {signature_type}")]
    InvalidKeyTypeForSignatureType {
        key_type: KeyType,
        signature_type: SignatureType,
    },

    /// The key mechanisms provided for a signature type are not valid
    #[error(
        "The key mechanism {required_key_mechanism} must be used with signature type {signature_type}"
    )]
    InvalidKeyMechanismsForSignatureType {
        required_key_mechanism: KeyMechanism,
        signature_type: SignatureType,
    },

    /// A valid cryptographic key use can not be derived from a String
    #[error("Unable to derive a valid cryptography key use from string: {0}")]
    InvalidCryptograhicKeyUse(String),

    /// A signing key setup is not compatible with raw cryptographic signing
    #[error(
        "The key type {key_type}, key mechanisms {key_mechanisms:?} and signature type {signature_type} are incompatible with raw cryptographic signing"
    )]
    InvalidRawSigningKeySetup {
        key_type: KeyType,
        key_mechanisms: Vec<KeyMechanism>,
        signature_type: SignatureType,
    },

    /// A signing key setup is not compatible with OpenPGP signing
    #[error(
        "The key type {key_type}, key mechanisms {key_mechanisms:?} and signature type {signature_type} are incompatible with OpenPGP signing"
    )]
    InvalidOpenPgpSigningKeySetup {
        key_type: KeyType,
        key_mechanisms: Vec<KeyMechanism>,
        signature_type: SignatureType,
    },
}

/// The cryptographic context in which a key is used
///
/// Each key can only be used in one cryptographic context.
/// This is because the NetHSM offers only a single certificate slot per key, which can be used to
/// attach certificates for a specific cryptographic use.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
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
    /// Returns an [`Error::Key`][`crate::Error::Key`] if the key setup can not be used for signing
    /// operations in the respective cryptographic context.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{
    ///     CryptographicKeyContext,
    ///     KeyMechanism,
    ///     KeyType,
    ///     OpenPgpUserIdList,
    ///     OpenPgpVersion,
    ///     SignatureType,
    /// };
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
    ///
    /// // OpenPGP does not support ECDSA P224
    /// assert!(
    ///     CryptographicKeyContext::OpenPgp {
    ///         user_ids: OpenPgpUserIdList::new(vec![
    ///             "Foobar McFooface <foobar@mcfooface.org>".parse()?
    ///         ])?,
    ///         version: OpenPgpVersion::V4,
    ///     }
    ///     .validate_signing_key_setup(
    ///         KeyType::EcP224,
    ///         &[KeyMechanism::EcdsaSignature],
    ///         SignatureType::EcdsaP224,
    ///     )
    ///     .is_err()
    /// );
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
                (KeyType::EcP224, SignatureType::EcdsaP224)
                    if key_mechanisms.contains(&KeyMechanism::EcdsaSignature) => {}
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

/// The validated setup for a cryptographic signing key
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
pub struct SigningKeySetup {
    key_id: KeyId,
    key_type: KeyType,
    key_mechanisms: Vec<KeyMechanism>,
    key_length: Option<u32>,
    signature_type: SignatureType,
    key_context: CryptographicKeyContext,
}

impl SigningKeySetup {
    /// Creates a new [`SigningKeySetup`]
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Key`][`crate::Error::Key`] if the key setup is not valid in itself or
    /// can not be used for signing operations in the respective cryptographic context.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{
    ///     CryptographicKeyContext,
    ///     KeyMechanism,
    ///     KeyType,
    ///     OpenPgpUserIdList,
    ///     SignatureType,
    ///     SigningKeySetup,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// SigningKeySetup::new(
    ///     "key1".parse()?,
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     SignatureType::EdDsa,
    ///     CryptographicKeyContext::Raw,
    /// )?;
    ///
    /// SigningKeySetup::new(
    ///     "key1".parse()?,
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     SignatureType::EdDsa,
    ///     CryptographicKeyContext::OpenPgp {
    ///         user_ids: OpenPgpUserIdList::new(vec![
    ///             "Foobar McFooface <foobar@mcfooface.org>".parse()?,
    ///         ])?,
    ///         version: "v4".parse()?,
    ///     },
    /// )?;
    ///
    /// // this fails because Curve25519 does not support the ECDSA key mechanism
    /// assert!(
    ///     SigningKeySetup::new(
    ///         "key1".parse()?,
    ///         KeyType::Curve25519,
    ///         vec![KeyMechanism::EcdsaSignature],
    ///         None,
    ///         SignatureType::EdDsa,
    ///         CryptographicKeyContext::OpenPgp {
    ///             user_ids: OpenPgpUserIdList::new(vec![
    ///                 "Foobar McFooface <foobar@mcfooface.org>".parse()?
    ///             ])?,
    ///             version: "v4".parse()?,
    ///         },
    ///     )
    ///     .is_err()
    /// );
    ///
    /// // this fails because OpenPGP does not support the ECDSA P224 key type
    /// assert!(
    ///     SigningKeySetup::new(
    ///         "key1".parse()?,
    ///         KeyType::EcP224,
    ///         vec![KeyMechanism::EcdsaSignature],
    ///         None,
    ///         SignatureType::EcdsaP224,
    ///         CryptographicKeyContext::OpenPgp {
    ///             user_ids: OpenPgpUserIdList::new(vec![
    ///                 "Foobar McFooface <foobar@mcfooface.org>".parse()?
    ///             ])?,
    ///             version: "v4".parse()?,
    ///         },
    ///     )
    ///     .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        key_id: KeyId,
        key_type: KeyType,
        key_mechanisms: Vec<KeyMechanism>,
        key_length: Option<u32>,
        signature_type: SignatureType,
        cryptographic_key_context: CryptographicKeyContext,
    ) -> Result<Self, Error> {
        key_type_matches_mechanisms(key_type, &key_mechanisms)?;
        key_type_matches_length(key_type, key_length)?;
        key_type_and_mechanisms_match_signature_type(key_type, &key_mechanisms, signature_type)?;
        cryptographic_key_context.validate_signing_key_setup(
            key_type,
            &key_mechanisms,
            signature_type,
        )?;

        Ok(Self {
            key_id,
            key_type,
            key_mechanisms,
            key_length,
            signature_type,
            key_context: cryptographic_key_context,
        })
    }

    /// Returns the [`KeyId`]
    pub fn get_key_id(&self) -> KeyId {
        self.key_id.clone()
    }

    /// Returns the [`KeyType`]
    pub fn get_key_type(&self) -> KeyType {
        self.key_type
    }

    /// Returns the list of [`KeyMechanism`]s
    pub fn get_key_mechanisms(&self) -> Vec<KeyMechanism> {
        self.key_mechanisms.clone()
    }

    /// Returns the optional key length
    pub fn get_key_length(&self) -> Option<u32> {
        self.key_length
    }

    /// Returns the [`SignatureType`]
    pub fn get_signature_type(&self) -> SignatureType {
        self.signature_type
    }

    /// Returns the [`CryptographicKeyContext`]
    pub fn get_key_context(&self) -> CryptographicKeyContext {
        self.key_context.clone()
    }
}

/// The data for private key import
enum PrivateKeyData {
    /// Data for [`KeyType::Curve25519`]
    Curve25519(Vec<u8>),
    /// Data for [`KeyType::EcP224`]
    EcP224(Vec<u8>),
    /// Data for [`KeyType::EcP256`]
    EcP256(Vec<u8>),
    /// Data for [`KeyType::EcP384`]
    EcP384(Vec<u8>),
    /// Data for [`KeyType::EcP521`]
    EcP521(Vec<u8>),
    /// Data for [`KeyType::Rsa`]
    Rsa {
        prime_p: Vec<u8>,
        prime_q: Vec<u8>,
        public_exponent: Vec<u8>,
    },
}

/// The key data required when importing a secret key
pub struct PrivateKeyImport {
    key_data: PrivateKeyData,
}

/// Creates a new vector with bytes in `buf`, left-padded with zeros so
/// that the result is exactly `len` big.
///
/// # Errors
///
/// Returns an [`crate::Error::Default`], if the input buffer `buf` is
/// longer than the targeted `len`.
///
/// # Examples
///
/// ```no_compile
/// let input = vec![1, 2, 3];
/// let output = pad(&input, 4)?;
/// assert_eq!(output, vec![0, 1, 2, 3]);
/// ```
fn pad(buf: &[u8], len: usize) -> Result<Vec<u8>, crate::Error> {
    if len < buf.len() {
        return Err(crate::Error::Default(format!(
            "Input buffer should be upmost {len} bytes long but has {} bytes.",
            buf.len()
        )));
    }
    let mut v = vec![0; len];
    v[len - buf.len()..].copy_from_slice(buf);
    Ok(v)
}

impl PrivateKeyImport {
    /// Creates a new [`PrivateKeyImport`]
    ///
    /// Accepts a [`KeyType`] (all except [`KeyType::Generic`]) and a bytes array representing a
    /// matching PKCS#8 private key in ASN.1 DER-encoded format.
    ///
    /// # Errors
    ///
    /// Returns an [`crate::Error::Key`] if
    /// * `key_data` can not be deserialized to a respective private key format.
    /// * an RSA private key does not have prime P or prime Q.
    /// * an RSA private key is shorter than [`MIN_RSA_BIT_LENGTH`].
    /// * `key_type` is the unsupported [`KeyType::Generic`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    /// use nethsm::{KeyType, PrivateKeyImport};
    /// use rand::rngs::OsRng;
    /// # fn main() -> TestResult {
    ///
    /// let key_data = {
    ///     let mut csprng = OsRng;
    ///     let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    ///     signing_key.to_pkcs8_der()?.as_bytes().to_vec()
    /// };
    ///
    /// assert!(PrivateKeyImport::new(KeyType::Curve25519, &key_data).is_ok());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(key_type: KeyType, key_data: &[u8]) -> Result<Self, Error> {
        Ok(match key_type {
            KeyType::Curve25519 => {
                let key_pair = ed25519_dalek::pkcs8::KeypairBytes::from_pkcs8_der(key_data)?;
                Self {
                    key_data: PrivateKeyData::Curve25519(key_pair.secret_key.to_vec()),
                }
            }
            KeyType::EcP224 => {
                let private_key = p224::SecretKey::from_pkcs8_der(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP224(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP256 => {
                let private_key = p256::SecretKey::from_pkcs8_der(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP384 => {
                let private_key = p384::SecretKey::from_pkcs8_der(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP384(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP521 => {
                let private_key = p521::SecretKey::from_pkcs8_der(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP521(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::Generic => return Err(Error::UnsupportedKeyType(KeyType::Generic)),
            KeyType::Rsa => {
                let private_key = RsaPrivateKey::from_pkcs8_der(key_data)?;
                // ensure, that we have sufficient bit length
                key_type_matches_length(key_type, Some(private_key.size() as u32 * 8))?;
                Self {
                    key_data: PrivateKeyData::Rsa {
                        prime_p: private_key
                            .primes()
                            .first()
                            .ok_or(Error::NoPrimes)?
                            .to_bytes_be(),
                        prime_q: private_key
                            .primes()
                            .get(1)
                            .ok_or(Error::NoPrimes)?
                            .to_bytes_be(),
                        public_exponent: private_key.e().to_bytes_be(),
                    },
                }
            }
        })
    }

    /// Creates a new [`PrivateKeyImport`]
    ///
    /// Accepts a [`KeyType`] (all except [`KeyType::Generic`]) and a string slice representing a
    /// matching PKCS#8 private key in PEM-encoded format.
    ///
    /// # Errors
    ///
    /// Returns an [`crate::Error::Key`] if
    /// * `key_data` can not be deserialized to a respective private key format.
    /// * an RSA private key does not have prime P or prime Q.
    /// * an RSA private key is shorter than [`MIN_RSA_BIT_LENGTH`].
    /// * `key_type` is the unsupported [`KeyType::Generic`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use std::ops::Deref;
    ///
    /// use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey, pkcs8::spki::der::pem::LineEnding};
    /// use nethsm::{KeyType, PrivateKeyImport};
    /// use rand::rngs::OsRng;
    /// # fn main() -> TestResult {
    ///
    /// let key_data = {
    ///     let mut csprng = OsRng;
    ///     let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    ///     signing_key.to_pkcs8_pem(LineEnding::default())?
    /// };
    ///
    /// assert!(PrivateKeyImport::from_pkcs8_pem(KeyType::Curve25519, key_data.deref()).is_ok());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_pkcs8_pem(key_type: KeyType, key_data: &str) -> Result<Self, Error> {
        Ok(match key_type {
            KeyType::Curve25519 => {
                let key_pair = ed25519_dalek::pkcs8::KeypairBytes::from_pkcs8_pem(key_data)?;
                Self {
                    key_data: PrivateKeyData::Curve25519(key_pair.secret_key.to_vec()),
                }
            }
            KeyType::EcP224 => {
                let private_key = p224::SecretKey::from_pkcs8_pem(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP224(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP256 => {
                let private_key = p256::SecretKey::from_pkcs8_pem(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP384 => {
                let private_key = p384::SecretKey::from_pkcs8_pem(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP384(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP521 => {
                let private_key = p521::SecretKey::from_pkcs8_pem(key_data)?;
                Self {
                    key_data: PrivateKeyData::EcP521(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::Generic => return Err(Error::UnsupportedKeyType(KeyType::Generic)),
            KeyType::Rsa => {
                let private_key = RsaPrivateKey::from_pkcs8_pem(key_data)?;
                // ensure, that we have sufficient bit length
                key_type_matches_length(key_type, Some(private_key.size() as u32 * 8))?;
                Self {
                    key_data: PrivateKeyData::Rsa {
                        prime_p: private_key
                            .primes()
                            .first()
                            .ok_or(Error::NoPrimes)?
                            .to_bytes_be(),
                        prime_q: private_key
                            .primes()
                            .get(1)
                            .ok_or(Error::NoPrimes)?
                            .to_bytes_be(),
                        public_exponent: private_key.e().to_bytes_be(),
                    },
                }
            }
        })
    }

    /// Create [`PrivateKeyImport`] object from raw, private RSA key parts.
    ///
    /// The function takes two primes (*p* and *q*) and the public exponent,
    /// which usually is 65537 (`[0x01, 0x00, 0x01]`).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nethsm::PrivateKeyImport;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let prime_p = vec![7];
    /// let prime_q = vec![11];
    /// let public_exponent = vec![1, 0, 1];
    ///
    /// let _import = PrivateKeyImport::from_rsa(prime_p, prime_q, public_exponent);
    /// # Ok(()) }
    /// ```
    pub fn from_rsa(prime_p: Vec<u8>, prime_q: Vec<u8>, public_exponent: Vec<u8>) -> Self {
        Self {
            key_data: PrivateKeyData::Rsa {
                prime_p,
                prime_q,
                public_exponent,
            },
        }
    }

    /// Create [`PrivateKeyImport`] object from raw, private Elliptic Curve bytes.
    ///
    /// The function takes two parameters:
    /// - the type of elliptic curve,
    /// - raw bytes in a curve-specific encoding
    ///
    /// Elliptic curve keys require the `bytes` to be zero-padded to be of correct size.
    /// This function automatically applies padding accordingly.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nethsm::{KeyType, PrivateKeyImport};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let bytes = vec![0x00; 32];
    ///
    /// let _import = PrivateKeyImport::from_raw_bytes(KeyType::Curve25519, bytes)?;
    /// # Ok(()) }
    /// ```
    pub fn from_raw_bytes(ec: KeyType, bytes: impl AsRef<[u8]>) -> Result<Self, crate::Error> {
        let bytes = bytes.as_ref();
        Ok(Self {
            key_data: match ec {
                KeyType::EcP224 => PrivateKeyData::EcP224(pad(bytes, 28)?),
                KeyType::EcP256 => PrivateKeyData::EcP256(pad(bytes, 32)?),
                KeyType::EcP384 => PrivateKeyData::EcP384(pad(bytes, 48)?),
                KeyType::EcP521 => PrivateKeyData::EcP521(pad(bytes, 66)?),
                KeyType::Curve25519 => PrivateKeyData::Curve25519(pad(bytes, 32)?),
                ec => return Err(crate::Error::Default(format!("Unsupported key type: {ec}"))),
            },
        })
    }

    /// Get the matching [`KeyType`] for the data contained in the [`PrivateKeyImport`]
    pub fn key_type(&self) -> KeyType {
        match &self.key_data {
            PrivateKeyData::Curve25519(_) => KeyType::Curve25519,
            PrivateKeyData::EcP224(_) => KeyType::EcP224,
            PrivateKeyData::EcP256(_) => KeyType::EcP256,
            PrivateKeyData::EcP384(_) => KeyType::EcP384,
            PrivateKeyData::EcP521(_) => KeyType::EcP521,
            PrivateKeyData::Rsa {
                prime_p: _,
                prime_q: _,
                public_exponent: _,
            } => KeyType::Rsa,
        }
    }
}

impl From<PrivateKeyImport> for KeyPrivateData {
    fn from(value: PrivateKeyImport) -> Self {
        match value.key_data {
            PrivateKeyData::Rsa {
                prime_p,
                prime_q,
                public_exponent,
            } => KeyPrivateData {
                prime_p: Some(Base64::encode_string(&prime_p)),
                prime_q: Some(Base64::encode_string(&prime_q)),
                public_exponent: Some(Base64::encode_string(&public_exponent)),
                data: None,
            },
            PrivateKeyData::EcP224(data)
            | PrivateKeyData::EcP256(data)
            | PrivateKeyData::EcP384(data)
            | PrivateKeyData::EcP521(data)
            | PrivateKeyData::Curve25519(data) => KeyPrivateData {
                prime_p: None,
                prime_q: None,
                public_exponent: None,
                data: Some(Base64::encode_string(&data)),
            },
        }
    }
}

/// Ensures that a [`KeyType`] is compatible with a list of [`KeyMechanism`]s
///
/// # Errors
///
/// Returns an [`Error::Key`][`crate::Error::Key`] if any of the [`KeyMechanism`]s is incompatible
/// with the [`KeyType`]
///
/// # Examples
///
/// ```
/// use nethsm::{KeyMechanism, KeyType, key_type_matches_mechanisms};
///
/// # fn main() -> testresult::TestResult {
/// key_type_matches_mechanisms(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature])?;
/// key_type_matches_mechanisms(KeyType::EcP224, &[KeyMechanism::EcdsaSignature])?;
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
        KeyType::EcP224 | KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
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
/// Returns an [`Error::Key`][`crate::Error::Key`] if the provided [`SignatureType`] is incompatible
/// with the [`KeyType`] or [`KeyMechanism`]s.
///
/// # Examples
///
/// ```
/// use nethsm::{KeyMechanism, KeyType, SignatureType, key_type_and_mechanisms_match_signature_type};
///
/// # fn main() -> testresult::TestResult {
/// key_type_and_mechanisms_match_signature_type(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature], SignatureType::EdDsa)?;
/// key_type_and_mechanisms_match_signature_type(KeyType::EcP224, &[KeyMechanism::EcdsaSignature], SignatureType::EcdsaP224)?;
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
        SignatureType::EcdsaP224 => {
            if key_type != KeyType::EcP224 {
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
/// Returns an [`Error::Key`][`crate::Error::Key`] if
/// * `key_type` is one of [`KeyType::Curve25519`], [`KeyType::EcP224`], [`KeyType::EcP256`],
///   [`KeyType::EcP384`] or [`KeyType::EcP521`] and `length` is [`Some`].
/// * `key_type` is [`KeyType::Generic`] or [`KeyType::Rsa`] and `length` is [`None`].
/// * `key_type` is [`KeyType::Generic`] and `length` is not [`Some`] value of `128`, `192` or
///   `256`.
/// * `key_type` is [`KeyType::Rsa`] and `length` is not [`Some`] value equal to or greater than
///   [`MIN_RSA_BIT_LENGTH`].
///
/// # Examples
///
/// ```
/// use nethsm::{KeyType, key_type_matches_length};
///
/// # fn main() -> testresult::TestResult {
/// key_type_matches_length(KeyType::Curve25519, None)?;
/// key_type_matches_length(KeyType::EcP224, None)?;
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
        KeyType::Curve25519
        | KeyType::EcP224
        | KeyType::EcP256
        | KeyType::EcP384
        | KeyType::EcP521 => {
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

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rstest::{fixture, rstest};
    use testresult::TestResult;

    use super::*;

    #[fixture]
    fn ed25519_private_key() -> TestResult<Vec<u8>> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Ok(signing_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[fixture]
    fn p224_private_key() -> TestResult<Vec<u8>> {
        use p224::elliptic_curve::rand_core::OsRng;
        let private_key = p224::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[fixture]
    fn p256_private_key() -> TestResult<Vec<u8>> {
        use p256::elliptic_curve::rand_core::OsRng;
        let private_key = p256::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[fixture]
    fn p384_private_key() -> TestResult<Vec<u8>> {
        use p384::elliptic_curve::rand_core::OsRng;
        let private_key = p384::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[fixture]
    fn p521_private_key() -> TestResult<Vec<u8>> {
        use p521::elliptic_curve::rand_core::OsRng;
        let private_key = p521::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[fixture]
    fn rsa_private_key() -> TestResult<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048.try_into()?)?;
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[rstest]
    fn key_data(
        ed25519_private_key: TestResult<Vec<u8>>,
        p224_private_key: TestResult<Vec<u8>>,
        p256_private_key: TestResult<Vec<u8>>,
        p384_private_key: TestResult<Vec<u8>>,
        p521_private_key: TestResult<Vec<u8>>,
        rsa_private_key: TestResult<Vec<u8>>,
    ) -> TestResult {
        let ed25519_private_key = ed25519_private_key?;
        let p224_private_key = p224_private_key?;
        let p256_private_key = p256_private_key?;
        let p384_private_key = p384_private_key?;
        let p521_private_key = p521_private_key?;
        let rsa_private_key = rsa_private_key?;

        assert!(PrivateKeyImport::new(KeyType::Curve25519, &ed25519_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p224_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP224, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP224, &p224_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP224, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP224, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP224, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP224, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP256, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p224_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p256_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP384, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p224_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p384_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP521, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p224_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p521_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::Rsa, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p224_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &rsa_private_key).is_ok());

        assert!(PrivateKeyImport::new(KeyType::Generic, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p224_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &rsa_private_key).is_err());
        Ok(())
    }

    #[rstest]
    #[case(KeyType::Curve25519, &[KeyMechanism::EdDsaSignature], SignatureType::EdDsa, None)]
    #[case(KeyType::EcP224, &[KeyMechanism::EcdsaSignature], SignatureType::EcdsaP224, None)]
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
        KeyType::EcP224,
        &[KeyMechanism::EcdsaSignature],
        SignatureType::EdDsa,
        Some(Box::new(Error::InvalidKeyTypeForSignatureType {
            key_type: KeyType::EcP224,
            signature_type: SignatureType::EdDsa,
        })
    ))]
    #[case(
        KeyType::EcP224,
        &[KeyMechanism::EdDsaSignature],
        SignatureType::EcdsaP224,
        Some(Box::new(Error::InvalidKeyMechanismsForSignatureType {
            signature_type: SignatureType::EcdsaP224,
            required_key_mechanism: KeyMechanism::EcdsaSignature,
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
}
