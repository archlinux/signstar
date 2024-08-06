use base64ct::{Base64, Encoding};
use nethsm_sdk_rs::models::KeyPrivateData;
use rsa::{
    pkcs8::DecodePrivateKey,
    traits::PrivateKeyParts,
    traits::PublicKeyParts,
    RsaPrivateKey,
};

use crate::KeyType;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("PKCS#8 error: {0}")]
    Pkcs8(#[from] rsa::pkcs8::Error),
    #[error("No primes found")]
    NoPrimes,
    #[error("The {0} key type is not supported")]
    UnsupportedKeyType(KeyType),
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

impl PrivateKeyImport {
    /// Creates a new [`PrivateKeyImport`]
    ///
    /// Accepts a [`KeyType`] (all except [`KeyType::Generic`]) and a bytes array representing a
    /// matching PKCS#8 private key in ASN.1 DER-encoded format.
    ///
    /// # Errors
    ///
    /// Returns an [`crate::Error::KeyData`] if `key_data` can not be deserialized to a respective
    /// private key format, an RSA private key does not have prime P or prime Q, or if an
    /// unsupported [`KeyType`] is provided.
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
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
    /// Returns an [`crate::Error::KeyData`] if `key_data` can not be deserialized to a respective
    /// private key format, an RSA private key does not have prime P or prime Q, or if an
    /// unsupported [`KeyType`] is provided.
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use std::ops::Deref;
    ///
    /// use ed25519_dalek::{pkcs8::spki::der::pem::LineEnding, pkcs8::EncodePrivateKey, SigningKey};
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
    /// # Examples
    ///
    /// ```rust
    /// use nethsm::{KeyType, PrivateKeyImport};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let bytes = vec![0x00; 40];
    ///
    /// let _import = PrivateKeyImport::from_raw_bytes(KeyType::Curve25519, bytes);
    /// # Ok(()) }
    /// ```
    pub fn from_raw_bytes(ec: KeyType, bytes: Vec<u8>) -> Self {
        Self {
            key_data: match ec {
                KeyType::EcP224 => PrivateKeyData::EcP224(bytes),
                KeyType::EcP256 => PrivateKeyData::EcP256(bytes),
                KeyType::EcP384 => PrivateKeyData::EcP384(bytes),
                KeyType::EcP521 => PrivateKeyData::EcP521(bytes),
                KeyType::Curve25519 => PrivateKeyData::Curve25519(bytes),
                _ => unimplemented!(),
            },
        }
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

#[cfg(test)]
mod tests {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::RsaPrivateKey;
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
}
