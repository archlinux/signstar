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
    /// Data for [`KeyType::EcBp256`]
    EcBp256(Vec<u8>),
    /// Data for [`KeyType::EcBp384`]
    EcBp384(Vec<u8>),
    /// Data for [`KeyType::EcK256`]
    EcK256(Vec<u8>),
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
            Self::EcBp256(_) => f.debug_tuple("EcBp256").field(REDACTED).finish(),
            Self::EcBp384(_) => f.debug_tuple("EcBp384").field(REDACTED).finish(),
            Self::EcK256(_) => f.debug_tuple("EcK256").field(REDACTED).finish(),
            Self::EcP224(_) => f.debug_tuple("EcP224").field(REDACTED).finish(),
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

impl From<&PrivateKeyData> for KeyType {
    fn from(value: &PrivateKeyData) -> Self {
        match value {
            PrivateKeyData::Curve25519(_) => Self::Curve25519,
            PrivateKeyData::EcBp256(_) => Self::EcBp256,
            PrivateKeyData::EcBp384(_) => Self::EcBp384,
            PrivateKeyData::EcK256(_) => Self::EcK256,
            PrivateKeyData::EcP224(_) => Self::EcP224,
            PrivateKeyData::EcP256(_) => Self::EcP256,
            PrivateKeyData::EcP384(_) => Self::EcP384,
            PrivateKeyData::EcP521(_) => Self::EcP521,
            PrivateKeyData::Rsa { .. } => Self::Rsa,
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
    /// - `key_type` is the unsupported [`KeyType::Generic`] or [`KeyType::EcBp512`].
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
    pub fn new(key_type: KeyType, key_data: &[u8]) -> Result<Self, crate::Error> {
        Ok(match key_type {
            KeyType::Curve25519 => {
                let key_pair = ed25519_dalek::pkcs8::KeypairBytes::from_pkcs8_der(key_data)
                    .map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::Curve25519(key_pair.secret_key.to_vec()),
                }
            }
            KeyType::EcBp256 => {
                let private_key =
                    bp256::r1::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcBp256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcBp384 => {
                let private_key =
                    bp384::r1::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcBp384(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcBp512 => return Err(Error::UnsupportedKeyType(key_type).into()),
            KeyType::EcK256 => {
                let private_key =
                    k256::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcK256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP224 => {
                let private_key =
                    p224::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP224(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP256 => {
                let private_key =
                    p256::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP384 => {
                let private_key =
                    p384::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP384(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP521 => {
                let private_key =
                    p521::SecretKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP521(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::Generic => return Err(Error::UnsupportedKeyType(KeyType::Generic).into()),
            KeyType::Rsa => {
                let private_key = RsaPrivateKey::from_pkcs8_der(key_data).map_err(Error::Pkcs8)?;
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
    /// - `key_type` is the unsupported [`KeyType::Generic`] or [`KeyType::EcBp512`].
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
    pub fn from_pkcs8_pem(key_type: KeyType, key_data: &str) -> Result<Self, crate::Error> {
        Ok(match key_type {
            KeyType::Curve25519 => {
                let key_pair = ed25519_dalek::pkcs8::KeypairBytes::from_pkcs8_pem(key_data)
                    .map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::Curve25519(key_pair.secret_key.to_vec()),
                }
            }
            KeyType::EcBp256 => {
                let private_key =
                    bp256::r1::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcBp256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcBp384 => {
                let private_key =
                    bp384::r1::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcBp384(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcBp512 => return Err(Error::UnsupportedKeyType(key_type).into()),
            KeyType::EcK256 => {
                let private_key =
                    k256::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcK256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP224 => {
                let private_key =
                    p224::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP224(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP256 => {
                let private_key =
                    p256::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP256(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP384 => {
                let private_key =
                    p384::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP384(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::EcP521 => {
                let private_key =
                    p521::SecretKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
                Self {
                    key_data: PrivateKeyData::EcP521(private_key.to_bytes().as_slice().to_owned()),
                }
            }
            KeyType::Generic => return Err(Error::UnsupportedKeyType(KeyType::Generic).into()),
            KeyType::Rsa => {
                let private_key = RsaPrivateKey::from_pkcs8_pem(key_data).map_err(Error::Pkcs8)?;
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
    pub fn from_raw_bytes(ec: KeyType, bytes: impl AsRef<[u8]>) -> Result<Self, crate::Error> {
        let bytes = bytes.as_ref();
        Ok(Self {
            key_data: match ec {
                KeyType::EcP256 => PrivateKeyData::EcP256(pad(bytes, 32)?),
                KeyType::EcP384 => PrivateKeyData::EcP384(pad(bytes, 48)?),
                KeyType::EcP521 => PrivateKeyData::EcP521(pad(bytes, 66)?),
                KeyType::Curve25519 => PrivateKeyData::Curve25519(pad(bytes, 32)?),
                key_type => return Err(Error::UnsupportedKeyType(key_type).into()),
            },
        })
    }

    /// Get the matching [`KeyType`] for the data contained in the [`PrivateKeyImport`]
    pub fn key_type(&self) -> KeyType {
        KeyType::from(&self.key_data)
    }
}

#[cfg(test)]
mod tests {
    use rsa::RsaPrivateKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    fn ed25519_private_key() -> TestResult<Vec<u8>> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;
        let mut csprng = OsRng;
        let signing_key: SigningKey = SigningKey::generate(&mut csprng);
        Ok(signing_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn bp256_private_key() -> TestResult<Vec<u8>> {
        use bp256::elliptic_curve::rand_core::OsRng;
        let private_key = bp256::r1::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn bp384_private_key() -> TestResult<Vec<u8>> {
        use bp384::elliptic_curve::rand_core::OsRng;
        let private_key = bp384::r1::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn k256_private_key() -> TestResult<Vec<u8>> {
        use k256::elliptic_curve::rand_core::OsRng;
        let private_key = k256::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn p224_private_key() -> TestResult<Vec<u8>> {
        use p224::elliptic_curve::rand_core::OsRng;
        let private_key = p224::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn p256_private_key() -> TestResult<Vec<u8>> {
        use p256::elliptic_curve::rand_core::OsRng;
        let private_key = p256::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn p384_private_key() -> TestResult<Vec<u8>> {
        use p384::elliptic_curve::rand_core::OsRng;
        let private_key = p384::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn p521_private_key() -> TestResult<Vec<u8>> {
        use p521::elliptic_curve::rand_core::OsRng;
        let private_key = p521::SecretKey::random(&mut OsRng);
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    fn rsa_private_key() -> TestResult<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048.try_into()?)?;
        Ok(private_key.to_pkcs8_der()?.as_bytes().to_vec())
    }

    #[rstest]
    #[case::curve25519(KeyType::Curve25519)]
    #[case::ecbp256(KeyType::EcBp256)]
    #[case::ecbp384(KeyType::EcBp384)]
    #[case::eck256(KeyType::EcK256)]
    #[case::ecp224(KeyType::EcP224)]
    #[case::ecp256(KeyType::EcP256)]
    #[case::ecp384(KeyType::EcP384)]
    #[case::ecp521(KeyType::EcP521)]
    #[case::rsa(KeyType::Rsa)]
    fn key_data(#[case] key_type: KeyType) -> TestResult {
        let bp256_private_key = bp256_private_key()?;
        let bp384_private_key = bp384_private_key()?;
        let ed25519_private_key = ed25519_private_key()?;
        let k256_private_key = k256_private_key()?;
        let p224_private_key = p224_private_key()?;
        let p256_private_key = p256_private_key()?;
        let p384_private_key = p384_private_key()?;
        let p521_private_key = p521_private_key()?;
        let rsa_private_key = rsa_private_key()?;

        let (ok_cases, error_cases) = match key_type {
            KeyType::Curve25519 => (
                [&ed25519_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcBp256 => (
                [&bp256_private_key],
                [
                    &bp384_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcBp384 => (
                [&bp384_private_key],
                [
                    &bp256_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcK256 => (
                [&k256_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &ed25519_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcP224 => (
                [&p224_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcP256 => (
                [&p256_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p384_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcP384 => (
                [&p384_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p521_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::EcP521 => (
                [&p521_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &rsa_private_key,
                ],
            ),
            KeyType::Rsa => (
                [&rsa_private_key],
                [
                    &bp256_private_key,
                    &bp384_private_key,
                    &ed25519_private_key,
                    &k256_private_key,
                    &p224_private_key,
                    &p256_private_key,
                    &p384_private_key,
                    &p521_private_key,
                ],
            ),
            KeyType::Generic => unimplemented!("generic key types are not supported"),
            KeyType::EcBp512 => unimplemented!("there is currently no rustcrypto support"),
        };

        for ok_case in ok_cases.iter() {
            assert!(PrivateKeyImport::new(key_type, ok_case).is_ok());
        }

        for error_case in error_cases.iter() {
            assert!(PrivateKeyImport::new(key_type, error_case).is_err());
        }

        Ok(())
    }

    #[rstest]
    #[case::curve_25519(PrivateKeyImport::new(KeyType::Curve25519, ed25519_private_key()?.as_slice())?, KeyType::Curve25519)]
    #[case::ecbp256(PrivateKeyImport::new(KeyType::EcBp256, bp256_private_key()?.as_slice())?, KeyType::EcBp256)]
    #[case::ecbp384(PrivateKeyImport::new(KeyType::EcBp384, bp384_private_key()?.as_slice())?, KeyType::EcBp384)]
    #[case::eck256(PrivateKeyImport::new(KeyType::EcK256, k256_private_key()?.as_slice())?, KeyType::EcK256)]
    #[case::ecp224(PrivateKeyImport::new(KeyType::EcP224, p224_private_key()?.as_slice())?, KeyType::EcP224)]
    #[case::ecp256(PrivateKeyImport::new(KeyType::EcP256, p256_private_key()?.as_slice())?, KeyType::EcP256)]
    #[case::ecp384(PrivateKeyImport::new(KeyType::EcP384, p384_private_key()?.as_slice())?, KeyType::EcP384)]
    #[case::ecp521(PrivateKeyImport::new(KeyType::EcP521, p521_private_key()?.as_slice())?, KeyType::EcP521)]
    #[case::rsa(PrivateKeyImport::new(KeyType::Rsa, rsa_private_key()?.as_slice())?, KeyType::Rsa)]
    fn private_key_import_key_data_matches(
        #[case] private_key_data: PrivateKeyImport,
        #[case] key_type: KeyType,
    ) -> TestResult {
        assert_eq!(private_key_data.key_type(), key_type);

        Ok(())
    }
}
