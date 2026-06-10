//! YubiHSM2 specific integration for cryptographic keys.

use yubihsm::{
    Algorithm,
    asymmetric::Algorithm as AsymmetricAlgorithm,
    authentication::Algorithm as AuthenticationAlgorithm,
    ecdh::Algorithm as EcdhAlgorithm,
    ecdsa::Algorithm as EcdsaAlgorithm,
    hmac::Algorithm as HmacAlgorithm,
    opaque::Algorithm as OpaqueAlgorithm,
    otp::Algorithm as OtpAlgorithm,
    rsa::Algorithm as RsaAlgorithm,
    rsa::mgf::Algorithm as RsaMgfAlgorithm,
    template::Algorithm as TemplateAlgorithm,
    wrap::Algorithm as WrapAlgorithm,
};

use crate::key::{Error, KeyType};

impl TryFrom<Algorithm> for KeyType {
    type Error = crate::Error;

    /// Creates a new [`KeyType`] from an [`Algorithm`].
    ///
    /// # Note
    ///
    /// The semantic abstraction for types of keys and their inherent capabilities differs in
    /// [`yubihsm`] and [`signstar_crypto`][`crate`]. Hence, this conversion is only an
    /// approximation and other abstractions (e.g. [`KeyMechanism`][`crate::key::KeyMechanism`]
    /// and [`SignatureType`][`crate::key::SignatureType`]) may need to be considered in
    /// addition.
    ///
    /// # Errors
    ///
    /// Returns an error, if an [`Algorithm`] is encountered, that either does not map directly to a
    /// [`KeyType`] or describes other functionality (e.g. a hash function).
    fn try_from(value: Algorithm) -> Result<Self, Self::Error> {
        Ok(match value {
            Algorithm::Asymmetric(algorithm) => match algorithm {
                AsymmetricAlgorithm::Rsa2048
                | AsymmetricAlgorithm::Rsa3072
                | AsymmetricAlgorithm::Rsa4096 => KeyType::Rsa,
                AsymmetricAlgorithm::Ed25519 => KeyType::Curve25519,
                AsymmetricAlgorithm::EcP224 => KeyType::EcP224,
                AsymmetricAlgorithm::EcP256 => KeyType::EcP256,
                AsymmetricAlgorithm::EcP384 => KeyType::EcP384,
                AsymmetricAlgorithm::EcP521 => KeyType::EcP521,
                AsymmetricAlgorithm::EcK256 => KeyType::EcK256,
                AsymmetricAlgorithm::EcBp256 => KeyType::EcBp256,
                AsymmetricAlgorithm::EcBp384 => KeyType::EcBp384,
                AsymmetricAlgorithm::EcBp512 => KeyType::EcBp512,
            },
            Algorithm::Authentication(AuthenticationAlgorithm::YubicoAes) => KeyType::Generic,
            Algorithm::Ecdh(EcdhAlgorithm::Ecdh) => {
                return Err(Error::YubiHsm2AlgorithmNotAKeyType {
                    algorithm: value,
                    context: "it is an Elliptic-curve Diffie-Hellman (ECDH) protocol",
                }
                .into());
            }
            Algorithm::Ecdsa(algorithm) => match algorithm {
                EcdsaAlgorithm::Sha1
                | EcdsaAlgorithm::Sha256
                | EcdsaAlgorithm::Sha384
                | EcdsaAlgorithm::Sha512 => {
                    return Err(Error::YubiHsm2AlgorithmNotAKeyType {
                        algorithm: value,
                        context: "it is a hash function",
                    }
                    .into());
                }
            },

            Algorithm::Hmac(algorithm) => match algorithm {
                HmacAlgorithm::Sha1
                | HmacAlgorithm::Sha256
                | HmacAlgorithm::Sha384
                | HmacAlgorithm::Sha512 => {
                    return Err(Error::YubiHsm2AlgorithmNotAKeyType {
                        algorithm: value,
                        context: "it is a hash-based message authentication code (HMAC)",
                    }
                    .into());
                }
            },
            Algorithm::Mgf(algorithm) => match algorithm {
                RsaMgfAlgorithm::Sha1
                | RsaMgfAlgorithm::Sha256
                | RsaMgfAlgorithm::Sha384
                | RsaMgfAlgorithm::Sha512 => KeyType::Rsa,
            },
            Algorithm::Opaque(algorithm) => match algorithm {
                OpaqueAlgorithm::Data | OpaqueAlgorithm::X509Certificate => {
                    return Err(Error::YubiHsm2AlgorithmNotAKeyType {
                        algorithm: value,
                        context: "it is data",
                    }
                    .into());
                }
            },
            Algorithm::Rsa(algorithm) => match algorithm {
                RsaAlgorithm::Oaep(_) => KeyType::Rsa,
                RsaAlgorithm::Pkcs1(_) => KeyType::Rsa,
                RsaAlgorithm::Pss(_) => KeyType::Rsa,
            },
            Algorithm::Template(TemplateAlgorithm::Ssh) => {
                return Err(Error::YubiHsm2AlgorithmNotAKeyType {
                    algorithm: value,
                    context: "it is an SSH template",
                }
                .into());
            }
            Algorithm::Wrap(algorithm) => match algorithm {
                WrapAlgorithm::Aes128Ccm | WrapAlgorithm::Aes192Ccm | WrapAlgorithm::Aes256Ccm => {
                    KeyType::Generic
                }
            },
            Algorithm::YubicoOtp(algorithm) => match algorithm {
                OtpAlgorithm::Aes128 | OtpAlgorithm::Aes192 | OtpAlgorithm::Aes256 => {
                    KeyType::Generic
                }
            },
        })
    }
}
