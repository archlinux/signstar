//! NetHSM specific integration for cryptographic keys.

use nethsm_sdk_rs::models::SignMode;

use crate::key::base::{DecryptMode, EncryptMode, KeyMechanism, KeyType, SignatureType};

impl From<KeyType> for nethsm_sdk_rs::models::KeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Curve25519 => Self::Curve25519,
            KeyType::EcP256 => Self::EcP256,
            KeyType::EcP384 => Self::EcP384,
            KeyType::EcP521 => Self::EcP521,
            KeyType::Generic => Self::Generic,
            KeyType::Rsa => Self::Rsa,
        }
    }
}

impl TryFrom<nethsm_sdk_rs::models::KeyType> for KeyType {
    type Error = crate::key::Error;
    /// Creates a [`KeyType`] from a [`nethsm_sdk_rs::models::KeyType`].
    ///
    /// # Panics
    ///
    /// Panics if `value` is [`nethsm_sdk_rs::models::KeyType::EcP224`].
    /// This variant is about to be removed from [`nethsm_sdk_rs::models::KeyType`] and [`KeyType`]
    /// does not support it.
    fn try_from(value: nethsm_sdk_rs::models::KeyType) -> Result<Self, Self::Error> {
        Ok(match value {
            nethsm_sdk_rs::models::KeyType::Curve25519 => Self::Curve25519,
            nethsm_sdk_rs::models::KeyType::EcP224 => {
                unimplemented!(
                    "Elliptic Curve P224 is not implemented and the nethsm-sdk-rs crate will drop it in the future"
                )
            }
            nethsm_sdk_rs::models::KeyType::EcP256 => Self::EcP256,
            nethsm_sdk_rs::models::KeyType::EcP384 => Self::EcP384,
            nethsm_sdk_rs::models::KeyType::EcP521 => Self::EcP521,
            nethsm_sdk_rs::models::KeyType::Generic => Self::Generic,
            nethsm_sdk_rs::models::KeyType::Rsa => Self::Rsa,
        })
    }
}

impl From<&nethsm_sdk_rs::models::KeyMechanism> for KeyMechanism {
    fn from(value: &nethsm_sdk_rs::models::KeyMechanism) -> Self {
        match value {
            nethsm_sdk_rs::models::KeyMechanism::AesDecryptionCbc => Self::AesDecryptionCbc,
            nethsm_sdk_rs::models::KeyMechanism::AesEncryptionCbc => Self::AesEncryptionCbc,
            nethsm_sdk_rs::models::KeyMechanism::EcdsaSignature => Self::EcdsaSignature,
            nethsm_sdk_rs::models::KeyMechanism::EdDsaSignature => Self::EdDsaSignature,
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionOaepMd5 => Self::RsaDecryptionOaepMd5,
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionOaepSha1 => {
                Self::RsaDecryptionOaepSha1
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionOaepSha224 => {
                Self::RsaDecryptionOaepSha224
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionOaepSha256 => {
                Self::RsaDecryptionOaepSha256
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionOaepSha384 => {
                Self::RsaDecryptionOaepSha384
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionOaepSha512 => {
                Self::RsaDecryptionOaepSha512
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionPkcs1 => Self::RsaDecryptionPkcs1,
            nethsm_sdk_rs::models::KeyMechanism::RsaDecryptionRaw => Self::RsaDecryptionRaw,
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePkcs1 => Self::RsaSignaturePkcs1,
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePssMd5 => Self::RsaSignaturePssMd5,
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePssSha1 => Self::RsaSignaturePssSha1,
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePssSha224 => {
                Self::RsaSignaturePssSha224
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePssSha256 => {
                Self::RsaSignaturePssSha256
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePssSha384 => {
                Self::RsaSignaturePssSha384
            }
            nethsm_sdk_rs::models::KeyMechanism::RsaSignaturePssSha512 => {
                Self::RsaSignaturePssSha512
            }
        }
    }
}

impl From<KeyMechanism> for nethsm_sdk_rs::models::KeyMechanism {
    fn from(value: KeyMechanism) -> Self {
        match value {
            KeyMechanism::AesDecryptionCbc => Self::AesDecryptionCbc,
            KeyMechanism::AesEncryptionCbc => Self::AesEncryptionCbc,
            KeyMechanism::EcdsaSignature => Self::EcdsaSignature,
            KeyMechanism::EdDsaSignature => Self::EdDsaSignature,
            KeyMechanism::RsaDecryptionOaepMd5 => Self::RsaDecryptionOaepMd5,
            KeyMechanism::RsaDecryptionOaepSha1 => Self::RsaDecryptionOaepSha1,
            KeyMechanism::RsaDecryptionOaepSha224 => Self::RsaDecryptionOaepSha224,
            KeyMechanism::RsaDecryptionOaepSha256 => Self::RsaDecryptionOaepSha256,
            KeyMechanism::RsaDecryptionOaepSha384 => Self::RsaDecryptionOaepSha384,
            KeyMechanism::RsaDecryptionOaepSha512 => Self::RsaDecryptionOaepSha512,
            KeyMechanism::RsaDecryptionPkcs1 => Self::RsaDecryptionPkcs1,
            KeyMechanism::RsaDecryptionRaw => Self::RsaDecryptionRaw,
            KeyMechanism::RsaSignaturePkcs1 => Self::RsaSignaturePkcs1,
            KeyMechanism::RsaSignaturePssMd5 => Self::RsaSignaturePssMd5,
            KeyMechanism::RsaSignaturePssSha1 => Self::RsaSignaturePssSha1,
            KeyMechanism::RsaSignaturePssSha224 => Self::RsaSignaturePssSha224,
            KeyMechanism::RsaSignaturePssSha256 => Self::RsaSignaturePssSha256,
            KeyMechanism::RsaSignaturePssSha384 => Self::RsaSignaturePssSha384,
            KeyMechanism::RsaSignaturePssSha512 => Self::RsaSignaturePssSha512,
        }
    }
}

impl From<SignatureType> for SignMode {
    /// Creates a [`SignMode`] from a [`SignatureType`].
    ///
    /// # Note
    ///
    /// The more specific [`SignatureType::EcdsaP256`], [`SignatureType::EcdsaP384`] and
    /// [`SignatureType::EcdsaP521`] are returned as [`SignMode::Ecdsa`].
    fn from(value: SignatureType) -> Self {
        match value {
            SignatureType::Pkcs1 => SignMode::Pkcs1,
            SignatureType::PssMd5 => SignMode::PssMd5,
            SignatureType::PssSha1 => SignMode::PssSha1,
            SignatureType::PssSha224 => SignMode::PssSha224,
            SignatureType::PssSha256 => SignMode::PssSha256,
            SignatureType::PssSha384 => SignMode::PssSha384,
            SignatureType::PssSha512 => SignMode::PssSha512,
            SignatureType::EdDsa => SignMode::EdDsa,
            SignatureType::EcdsaP256 | SignatureType::EcdsaP384 | SignatureType::EcdsaP521 => {
                SignMode::Ecdsa
            }
        }
    }
}

impl From<EncryptMode> for nethsm_sdk_rs::models::EncryptMode {
    fn from(value: EncryptMode) -> Self {
        match value {
            EncryptMode::AesCbc => Self::AesCbc,
        }
    }
}

impl From<DecryptMode> for nethsm_sdk_rs::models::DecryptMode {
    fn from(value: DecryptMode) -> Self {
        match value {
            DecryptMode::AesCbc => Self::AesCbc,
            DecryptMode::OaepMd5 => Self::OaepMd5,
            DecryptMode::OaepSha1 => Self::OaepSha1,
            DecryptMode::OaepSha224 => Self::OaepSha224,
            DecryptMode::OaepSha256 => Self::OaepSha256,
            DecryptMode::OaepSha384 => Self::OaepSha384,
            DecryptMode::OaepSha512 => Self::OaepSha512,
            DecryptMode::Pkcs1 => Self::Pkcs1,
            DecryptMode::Raw => Self::Raw,
        }
    }
}
