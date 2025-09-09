//! Functionality for importing of cryptographic key material.

#[cfg(feature = "nethsm")]
pub mod nethsm;

use std::fmt::Debug;

use rsa::{
    RsaPrivateKey,
    pkcs8::DecodePrivateKey,
    traits::PrivateKeyParts,
    traits::PublicKeyParts,
};

#[cfg(doc)]
use crate::key::MIN_RSA_BIT_LENGTH;
use crate::key::{Error, KeyType, key_type_matches_length};

/// The data for private key import
// Allow dead code here, as the variants of `PrivateKeyData` are only used with a backend, which
// requires enabling a feature.
pub enum PrivateKeyData {
    /// Data for [`KeyType::Curve25519`]
    Curve25519(Vec<u8>),
    /// Data for [`KeyType::EcP256`]
    EcP256(Vec<u8>),
    /// Data for [`KeyType::EcP384`]
    EcP384(Vec<u8>),
    /// Data for [`KeyType::EcP521`]
    EcP521(Vec<u8>),
    /// Data for [`KeyType::Rsa`]
    Rsa {
        /// The prime number `p`.
        prime_p: Vec<u8>,
        /// The prime number `q`.
        prime_q: Vec<u8>,
        /// The public exponent `e`.
        public_exponent: Vec<u8>,
    },
}

impl Debug for PrivateKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &&str = &"[REDACTED]";
        match self {
            Self::Curve25519(_) => f.debug_tuple("Curve25519").field(REDACTED).finish(),
            Self::EcP256(_) => f.debug_tuple("EcP256").field(REDACTED).finish(),
            Self::EcP384(_) => f.debug_tuple("EcP384").field(REDACTED).finish(),
            Self::EcP521(_) => f.debug_tuple("EcP521").field(REDACTED).finish(),
            Self::Rsa {
                public_exponent, ..
            } => f
                .debug_struct("Rsa")
                .field("prime_p", REDACTED)
                .field("prime_q", REDACTED)
                .field("public_exponent", public_exponent)
                .finish(),
        }
    }
}

/// The key data required when importing a secret key
#[derive(Debug)]
pub struct PrivateKeyImport {
    key_data: PrivateKeyData,
}

/// Creates a new vector with bytes in `buf`, left-padded with zeros so
/// that the result is exactly `len` big.
///
/// # Errors
///
/// Returns an an error, if the input buffer `buf` is longer than the targeted `len`.
///
/// # Examples
///
/// ```no_compile
/// let input = vec![1, 2, 3];
/// let output = pad(&input, 4)?;
/// assert_eq!(output, vec![0, 1, 2, 3]);
/// ```
fn pad(buf: &[u8], len: usize) -> Result<Vec<u8>, Error> {
    let buffer_len = buf.len();
    if len < buf.len() {
        return Err(Error::PaddingInputTooLong {
            buffer_len,
            pad_len: len,
        });
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
    /// Returns an error if
    ///
    /// - `key_data` can not be deserialized to a respective private key format.
    /// - an RSA private key does not have prime P or prime Q.
    /// - an RSA private key is shorter than [`MIN_RSA_BIT_LENGTH`].
    /// - `key_type` is the unsupported [`KeyType::Generic`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    /// use rand::rngs::OsRng;
    /// use signstar_crypto::key::{KeyType, PrivateKeyImport};
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
    /// Returns an error if
    ///
    /// - `key_data` can not be deserialized to a respective private key format.
    /// - an RSA private key does not have prime P or prime Q.
    /// - an RSA private key is shorter than [`MIN_RSA_BIT_LENGTH`].
    /// - `key_type` is the unsupported [`KeyType::Generic`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use std::ops::Deref;
    ///
    /// use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey, pkcs8::spki::der::pem::LineEnding};
    /// use rand::rngs::OsRng;
    /// use signstar_crypto::key::{KeyType, PrivateKeyImport};
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
    /// use signstar_crypto::key::PrivateKeyImport;
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
    /// use signstar_crypto::key::{KeyType, PrivateKeyImport};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let bytes = vec![0x00; 32];
    ///
    /// let _import = PrivateKeyImport::from_raw_bytes(KeyType::Curve25519, bytes)?;
    /// # Ok(()) }
    /// ```
    pub fn from_raw_bytes(ec: KeyType, bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        let bytes = bytes.as_ref();
        Ok(Self {
            key_data: match ec {
                KeyType::EcP256 => PrivateKeyData::EcP256(pad(bytes, 32)?),
                KeyType::EcP384 => PrivateKeyData::EcP384(pad(bytes, 48)?),
                KeyType::EcP521 => PrivateKeyData::EcP521(pad(bytes, 66)?),
                KeyType::Curve25519 => PrivateKeyData::Curve25519(pad(bytes, 32)?),
                key_type => return Err(Error::UnsupportedKeyType(key_type)),
            },
        })
    }

    /// Get the matching [`KeyType`] for the data contained in the [`PrivateKeyImport`]
    pub fn key_type(&self) -> KeyType {
        match &self.key_data {
            PrivateKeyData::Curve25519(_) => KeyType::Curve25519,
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
        p256_private_key: TestResult<Vec<u8>>,
        p384_private_key: TestResult<Vec<u8>>,
        p521_private_key: TestResult<Vec<u8>>,
        rsa_private_key: TestResult<Vec<u8>>,
    ) -> TestResult {
        let ed25519_private_key = ed25519_private_key?;
        let p256_private_key = p256_private_key?;
        let p384_private_key = p384_private_key?;
        let p521_private_key = p521_private_key?;
        let rsa_private_key = rsa_private_key?;

        assert!(PrivateKeyImport::new(KeyType::Curve25519, &ed25519_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Curve25519, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP256, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p256_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP256, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP384, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p384_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP384, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::EcP521, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &p521_private_key).is_ok());
        assert!(PrivateKeyImport::new(KeyType::EcP521, &rsa_private_key).is_err());

        assert!(PrivateKeyImport::new(KeyType::Rsa, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Rsa, &rsa_private_key).is_ok());

        assert!(PrivateKeyImport::new(KeyType::Generic, &ed25519_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p256_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p384_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &p521_private_key).is_err());
        assert!(PrivateKeyImport::new(KeyType::Generic, &rsa_private_key).is_err());
        Ok(())
    }
}
