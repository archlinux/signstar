// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::fmt::Display;

use base64ct::{Base64, Encoding};
use nethsm_sdk_rs::models::{
    KeyMechanism,
    KeyPrivateData,
    KeyType,
    SignMode,
    Switch,
    UnattendedBootConfig,
};
use ureq::Response;

use crate::Error;

/// A representation of a message body in an HTTP response
///
/// This type allows us to deserialize the message body when the NetHSM API triggers the return of a
/// [`nethsm_sdk_rs::models::Error::Ureq`].
#[derive(Debug, serde::Deserialize)]
pub struct Message {
    message: String,
}

impl From<Response> for Message {
    fn from(value: Response) -> Self {
        if let Ok(message) = value.into_json() {
            message
        } else {
            Message {
                message: "Deseralization error (no message in body)".to_string(),
            }
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

#[derive(Debug)]
pub struct ApiErrorMessage {
    pub status_code: u16,
    pub message: Message,
}

impl From<(u16, Message)> for ApiErrorMessage {
    fn from(value: (u16, Message)) -> Self {
        Self {
            status_code: value.0,
            message: value.1,
        }
    }
}

impl Display for ApiErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{} (status code {})",
            self.message, self.status_code
        ))
    }
}

/// A helper Error for more readable output for [`nethsm_sdk_rs::apis::Error`]
///
/// This type allows us to create more readable output for [`nethsm_sdk_rs::apis::Error::Ureq`] and
/// reuse the upstream handling otherwise.
pub struct NetHsmApiError<T> {
    error: Option<nethsm_sdk_rs::apis::Error<T>>,
    message: Option<String>,
}

impl<T> From<nethsm_sdk_rs::apis::Error<T>> for NetHsmApiError<T> {
    fn from(value: nethsm_sdk_rs::apis::Error<T>) -> Self {
        match value {
            nethsm_sdk_rs::apis::Error::Ureq(error) => match error {
                nethsm_sdk_rs::ureq::Error::Status(code, response) => Self {
                    error: None,
                    message: Some(ApiErrorMessage::from((code, response.into())).to_string()),
                },
                nethsm_sdk_rs::ureq::Error::Transport(transport) => Self {
                    error: None,
                    message: Some(format!("{}", transport)),
                },
            },
            _ => Self {
                error: Some(value),
                message: None,
            },
        }
    }
}

impl<T> Display for NetHsmApiError<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(message) = self.message.as_ref() {
            write!(f, "{}", message)?;
        } else if let Some(error) = self.error.as_ref() {
            write!(f, "{}", error)?;
        }
        Ok(())
    }
}

/// The key data required when importing a secret key
///
/// The `prime_p`, `prime_q` and `public_exponent` fields must be [`Option::Some`] for keys
/// of type [`KeyType::Rsa`]. The `data` field must be  [`Option::Some`] for keys
/// of type [`KeyType::Curve25519`], [`KeyType::EcP224`], [`KeyType::EcP256`], [`KeyType::EcP384`]
/// and [`KeyType::EcP521`].
pub struct KeyImportData {
    pub prime_p: Option<Vec<u8>>,
    pub prime_q: Option<Vec<u8>>,
    pub public_exponent: Option<Vec<u8>>,
    pub data: Option<Vec<u8>>,
}

impl KeyImportData {
    /// Ensures the provided [`KeyType`] is compatible with the data
    ///
    /// Checks whether all needed data for a [`KeyType`] is present to be able to import it.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::KeyImport`] if:
    /// * `key_type` is [`KeyType::Rsa`] and [`KeyImportData::prime_p`], [`KeyImportData::prime_q`],
    /// [`KeyImportData::public_exponent`] is [`None`]
    /// * `key_type` is [`KeyType::Curve25519`], [`KeyType::EcP224`], [`KeyType::EcP256`],
    ///   [`KeyType::EcP384`], or
    /// [`KeyType::EcP521`] and [`KeyImportData::data`] is [`None`]
    pub fn validate_key_type(&self, key_type: KeyType) -> Result<(), Error> {
        match key_type {
            KeyType::Rsa => {
                if self.prime_p.is_none()
                    || self.prime_q.is_none()
                    || self.public_exponent.is_none()
                {
                    return Err(Error::KeyImport(format!(
                        "prime p, prime q and public exponent must be set for {:?}",
                        key_type
                    )));
                }

                if self.data.is_some() {
                    return Err(Error::KeyImport(format!(
                        "data must not be provided for {:?}",
                        key_type
                    )));
                }
            }
            KeyType::Curve25519
            | KeyType::EcP224
            | KeyType::EcP256
            | KeyType::EcP384
            | KeyType::EcP521 => {
                if self.data.is_none() {
                    return Err(Error::KeyImport(format!(
                        "data must be provided for {:?}",
                        key_type
                    )));
                }

                if self.prime_p.is_some()
                    || self.prime_q.is_some()
                    || self.public_exponent.is_some()
                {
                    return Err(Error::KeyImport(format!(
                        "prime p, prime q and public exponent must not be set for {:?}",
                        key_type
                    )));
                }
            }
            // TODO: figure out what checks to do for KeyType::Generic
            _ => {}
        }
        Ok(())
    }
}

impl From<Box<KeyImportData>> for Box<KeyPrivateData> {
    fn from(value: Box<KeyImportData>) -> Self {
        // all KeyPrivateData fields need to be base64 encoded
        Box::new(KeyPrivateData {
            prime_p: value.prime_p.map(|x| Base64::encode_string(&x)),
            prime_q: value.prime_q.map(|x| Base64::encode_string(&x)),
            public_exponent: value.public_exponent.map(|x| Base64::encode_string(&x)),
            data: value.data.map(|x| Base64::encode_string(&x)),
        })
    }
}

/// Ensures that the [`KeyType`] and [`KeyMechanism`] combinations are valid
pub fn match_key_type_and_mechanisms(
    key_type: KeyType,
    mechanisms: &[KeyMechanism],
) -> Result<(), Error> {
    let valid_mechanisms = match key_type {
        KeyType::Rsa => vec![
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
        ],
        KeyType::Curve25519 => vec![KeyMechanism::EdDsaSignature],
        KeyType::EcP224 | KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
            vec![KeyMechanism::EcdsaSignature]
        }
        KeyType::Generic => vec![
            KeyMechanism::AesDecryptionCbc,
            KeyMechanism::AesEncryptionCbc,
        ],
    };

    let invalid_mechanisms = mechanisms
        .iter()
        .filter(|mechanism| !valid_mechanisms.contains(mechanism))
        .collect::<Vec<&KeyMechanism>>();

    if invalid_mechanisms.is_empty() {
        Ok(())
    } else {
        Err(Error::KeyData(format!(
            "{:?} is incompatible with {}",
            key_type,
            invalid_mechanisms
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )))
    }
}

/// The type of a signature
///
/// This enum covers all variants of [`nethsm_sdk_rs::models::SignMode`], but instead of
/// [`nethsm_sdk_rs::models::SignMode::Ecdsa`] covers hash-specific ECDSA modes.
#[derive(
    Debug, strum_macros::Display, strum_macros::EnumString, Eq, PartialEq, Ord, PartialOrd, Hash,
)]
pub enum SignatureType {
    #[strum(to_string = "PKCS1")]
    Pkcs1,
    #[strum(to_string = "PSS_MD5")]
    PssMd5,
    #[strum(to_string = "PSS_SHA1")]
    PssSha1,
    #[strum(to_string = "PSS_SHA224")]
    PssSha224,
    #[strum(to_string = "PSS_SHA256")]
    PssSha256,
    #[strum(to_string = "PSS_SHA384")]
    PssSha384,
    #[strum(to_string = "PSS_SHA512")]
    PssSha512,
    #[strum(to_string = "EdDSA")]
    EdDsa,
    #[strum(to_string = "ECDSA_P224")]
    EcdsaP224,
    #[strum(to_string = "ECDSA_P256")]
    EcdsaP256,
    #[strum(to_string = "ECDSA_P384")]
    EcdsaP384,
    #[strum(to_string = "ECDSA_P521")]
    EcdsaP521,
}

impl From<SignatureType> for SignMode {
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
            SignatureType::EcdsaP224
            | SignatureType::EcdsaP256
            | SignatureType::EcdsaP384
            | SignatureType::EcdsaP521 => SignMode::Ecdsa,
        }
    }
}

/// The NetHSM boot mode
///
/// Defines in which state the NetHSM is in during boot after provisioning (see
/// [`crate::NetHsm::provision`]) and whether an unlock passphrase has to be provided for it to be
/// of state [`crate::SystemState::Operational`].
#[derive(Clone, Debug, strum::Display, strum::EnumString, Eq, PartialEq)]
#[strum(ascii_case_insensitive)]
pub enum BootMode {
    /// The device boots into state [`crate::SystemState::Locked`] and an unlock passphrase has to
    /// be provided
    Attended,
    /// The device boots into state [`crate::SystemState::Operational`] and no unlock passphrase
    /// has to be provided
    Unattended,
}

impl From<UnattendedBootConfig> for BootMode {
    fn from(value: UnattendedBootConfig) -> Self {
        match value.status {
            Switch::On => BootMode::Unattended,
            Switch::Off => BootMode::Attended,
        }
    }
}

impl From<BootMode> for UnattendedBootConfig {
    fn from(value: BootMode) -> Self {
        match value {
            BootMode::Unattended => UnattendedBootConfig { status: Switch::On },
            BootMode::Attended => UnattendedBootConfig {
                status: Switch::Off,
            },
        }
    }
}
