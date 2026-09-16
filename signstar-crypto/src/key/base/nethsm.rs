//! NetHSM specific integration for cryptographic keys.

use nethsm_sdk_rs::models::{
    KeyMechanism as NetHsmRsKeyMechanism,
    KeyType as NetHsmSdkRsKeyType,
    SignMode,
};

use crate::key::{
    Error,
    base::{DecryptMode, EncryptMode, KeyMechanism, KeyType, SignatureType},
};

impl TryFrom<KeyType> for NetHsmSdkRsKeyType {
    type Error = crate::Error;

    fn try_from(value: KeyType) -> Result<Self, Self::Error> {
        Ok(match value {
            KeyType::Curve25519 => Self::Curve25519,
            KeyType::EcBp256 => Self::BrainpoolP256,
            KeyType::EcBp384 => Self::BrainpoolP384,
            KeyType::EcBp512 => Self::BrainpoolP512,
            KeyType::EcK256 => Self::EcP256K1,
            KeyType::EcP224 => return Err(Error::UnsupportedKeyType(value).into()),
            KeyType::EcP256 => Self::EcP256,
            KeyType::EcP384 => Self::EcP384,
            KeyType::EcP521 => Self::EcP521,
            KeyType::Generic => Self::Generic,
            KeyType::Rsa => Self::Rsa,
        })
    }
}

impl TryFrom<NetHsmSdkRsKeyType> for KeyType {
    type Error = crate::Error;

    /// Creates a [`KeyType`] from a [`nethsm_sdk_rs::models::KeyType`].
    ///
    /// # Errors
    ///
    /// Returns an error, if an unsupported [`nethsm_sdk_rs::models::KeyType`] is used.
    fn try_from(value: NetHsmSdkRsKeyType) -> Result<Self, Self::Error> {
        Ok(match value {
            NetHsmSdkRsKeyType::BrainpoolP256 => Self::EcBp256,
            NetHsmSdkRsKeyType::BrainpoolP384 => Self::EcBp384,
            NetHsmSdkRsKeyType::BrainpoolP512 => Self::EcBp512,
            NetHsmSdkRsKeyType::Curve25519 => Self::Curve25519,
            NetHsmSdkRsKeyType::EcP256 => Self::EcP256,
            NetHsmSdkRsKeyType::EcP256K1 => Self::EcK256,
            NetHsmSdkRsKeyType::EcP384 => Self::EcP384,
            NetHsmSdkRsKeyType::EcP521 => Self::EcP521,
            NetHsmSdkRsKeyType::Generic => Self::Generic,
            NetHsmSdkRsKeyType::Rsa => Self::Rsa,
            // NOTE: Upstream has marked all of their models non-exhaustive.
            // Thus, comment the below on every update to nethsm-sdk-rs to check if there are new
            // variants that should be supported... :(
            key_type => return Err(Error::UnsupportedNetHsmSdkRsKeyType { key_type }.into()),
        })
    }
}

impl TryFrom<NetHsmRsKeyMechanism> for KeyMechanism {
    type Error = crate::Error;
    fn try_from(value: NetHsmRsKeyMechanism) -> Result<Self, Self::Error> {
        Ok(match value {
            NetHsmRsKeyMechanism::AesDecryptionCbc => Self::AesDecryptionCbc,
            NetHsmRsKeyMechanism::AesEncryptionCbc => Self::AesEncryptionCbc,
            NetHsmRsKeyMechanism::EcdsaSignature => Self::EcdsaSignature,
            NetHsmRsKeyMechanism::EdDsaSignature => Self::EdDsaSignature,
            NetHsmRsKeyMechanism::RsaDecryptionOaepMd5 => Self::RsaDecryptionOaepMd5,
            NetHsmRsKeyMechanism::RsaDecryptionOaepSha1 => Self::RsaDecryptionOaepSha1,
            NetHsmRsKeyMechanism::RsaDecryptionOaepSha224 => Self::RsaDecryptionOaepSha224,
            NetHsmRsKeyMechanism::RsaDecryptionOaepSha256 => Self::RsaDecryptionOaepSha256,
            NetHsmRsKeyMechanism::RsaDecryptionOaepSha384 => Self::RsaDecryptionOaepSha384,
            NetHsmRsKeyMechanism::RsaDecryptionOaepSha512 => Self::RsaDecryptionOaepSha512,
            NetHsmRsKeyMechanism::RsaDecryptionPkcs1 => Self::RsaDecryptionPkcs1,
            NetHsmRsKeyMechanism::RsaDecryptionRaw => Self::RsaDecryptionRaw,
            NetHsmRsKeyMechanism::RsaSignaturePkcs1 => Self::RsaSignaturePkcs1,
            NetHsmRsKeyMechanism::RsaSignaturePssSha1 => Self::RsaSignaturePssSha1,
            NetHsmRsKeyMechanism::RsaSignaturePssSha224 => Self::RsaSignaturePssSha224,
            NetHsmRsKeyMechanism::RsaSignaturePssSha256 => Self::RsaSignaturePssSha256,
            NetHsmRsKeyMechanism::RsaSignaturePssSha384 => Self::RsaSignaturePssSha384,
            NetHsmRsKeyMechanism::RsaSignaturePssSha512 => Self::RsaSignaturePssSha512,
            NetHsmRsKeyMechanism::RsaSignaturePssMd5 => {
                return Err(Error::UnsupportedNetHsmSdkRsKeyMechanism {
                    key_mechanism: value,
                }
                .into());
            }
            // NOTE: Upstream has marked all of their models non-exhaustive.
            // Thus, comment the below on every update to nethsm-sdk-rs to check if there are new
            // variants that should be supported... :(
            key_mechanism => {
                return Err(Error::UnsupportedNetHsmSdkRsKeyMechanism { key_mechanism }.into());
            }
        })
    }
}

impl From<KeyMechanism> for NetHsmRsKeyMechanism {
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
            KeyMechanism::RsaSignaturePssSha1 => Self::RsaSignaturePssSha1,
            KeyMechanism::RsaSignaturePssSha224 => Self::RsaSignaturePssSha224,
            KeyMechanism::RsaSignaturePssSha256 => Self::RsaSignaturePssSha256,
            KeyMechanism::RsaSignaturePssSha384 => Self::RsaSignaturePssSha384,
            KeyMechanism::RsaSignaturePssSha512 => Self::RsaSignaturePssSha512,
        }
    }
}

impl TryFrom<SignatureType> for SignMode {
    type Error = crate::Error;

    /// Creates a [`SignMode`] from a [`SignatureType`].
    ///
    /// # Note
    ///
    /// The more specific [`SignatureType::EcdsaP256`], [`SignatureType::EcdsaP384`] and
    /// [`SignatureType::EcdsaP521`] are returned as [`SignMode::Ecdsa`].
    ///
    /// # Errors
    ///
    /// Returns an error if an unsupported SignatureType is encountered
    fn try_from(value: SignatureType) -> Result<Self, Self::Error> {
        Ok(match value {
            SignatureType::Pkcs1 => SignMode::Pkcs1,
            SignatureType::PssSha1 => SignMode::PssSha1,
            SignatureType::PssSha224 => SignMode::PssSha224,
            SignatureType::PssSha256 => SignMode::PssSha256,
            SignatureType::PssSha384 => SignMode::PssSha384,
            SignatureType::PssSha512 => SignMode::PssSha512,
            SignatureType::EdDsa => SignMode::EdDsa,
            SignatureType::EcdsaP224
            | SignatureType::EcdsaP256
            | SignatureType::EcdsaP384
            | SignatureType::EcdsaP521 => SignMode::Ecdsa,
            SignatureType::EcdsaK256 => {
                return Err(Error::UnsupportedSignatureType {
                    signature_type: SignatureType::EcdsaK256,
                    context: "the NetHSM backend does not support it",
                }
                .into());
            }
        })
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
