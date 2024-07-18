use std::fmt::Display;

use nethsm_sdk_rs::models::{SignMode, Switch, UnattendedBootConfig};
use serde::{Deserialize, Serialize};
use ureq::Response;

use crate::Error;

/// A representation of a message body in an HTTP response
///
/// This type allows us to deserialize the message body when the NetHSM API triggers the return of a
/// [`nethsm_sdk_rs::models::Error::Ureq`].
#[derive(Debug, Deserialize)]
pub struct Message {
    message: String,
}

impl From<Response> for Message {
    fn from(value: Response) -> Self {
        if let Ok(message) = value.into_json() {
            message
        } else {
            Message {
                message: "Deserialization error (no message in body)".to_string(),
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

/// The type of a signature
///
/// This enum covers all variants of [`nethsm_sdk_rs::models::SignMode`], but instead of
/// [`nethsm_sdk_rs::models::SignMode::Ecdsa`] covers prime size specific ECDSA modes.
#[derive(
    Clone,
    Debug,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
)]
#[strum(ascii_case_insensitive)]
pub enum SignatureType {
    /// Elliptic Curve Digital Signature Algorithm (ECDSA) signing using a key over a prime field
    /// for a prime of size 224 bit
    EcdsaP224,

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
#[derive(
    Clone,
    Debug,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    PartialEq,
)]
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

impl From<EncryptMode> for nethsm_sdk_rs::models::EncryptMode {
    fn from(value: EncryptMode) -> Self {
        match value {
            EncryptMode::AesCbc => Self::AesCbc,
        }
    }
}

/// A mechanism which can be used with a key
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

/// The algorithm type of a key
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
pub enum KeyType {
    /// A Montgomery curve key over a prime field for the prime number 2^255-19
    #[default]
    Curve25519,

    /// An elliptic-curve key over a prime field for a prime of size 224 bit
    EcP224,

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

impl KeyType {
    /// Ensures that the [`KeyType`] is compatible with a list of [`KeyMechanism`]s
    ///
    /// # Errors
    ///
    /// Returns an error if the [`KeyMechanism`] is incompatible with the [`KeyType`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use nethsm::{KeyMechanism, KeyType};
    ///
    /// assert!(KeyType::Curve25519
    ///     .matches_mechanisms(&[KeyMechanism::EdDsaSignature])
    ///     .is_ok());
    ///
    /// assert!(KeyType::Curve25519
    ///     .matches_mechanisms(&[KeyMechanism::EcdsaSignature])
    ///     .is_err());
    ///
    /// assert!(KeyType::EcP224
    ///     .matches_mechanisms(&[KeyMechanism::EcdsaSignature])
    ///     .is_ok());
    ///
    /// assert!(KeyType::Generic
    ///     .matches_mechanisms(&[
    ///         KeyMechanism::AesDecryptionCbc,
    ///         KeyMechanism::AesEncryptionCbc,
    ///     ])
    ///     .is_ok());
    ///
    /// assert!(KeyType::Generic
    ///     .matches_mechanisms(&[
    ///         KeyMechanism::RsaDecryptionPkcs1,
    ///         KeyMechanism::RsaSignaturePkcs1,
    ///     ])
    ///     .is_err());
    ///
    /// assert!(KeyType::Rsa
    ///     .matches_mechanisms(&[
    ///         KeyMechanism::RsaDecryptionPkcs1,
    ///         KeyMechanism::RsaSignaturePkcs1,
    ///     ])
    ///     .is_ok());
    ///
    /// assert!(KeyType::Rsa
    ///     .matches_mechanisms(&[
    ///         KeyMechanism::AesDecryptionCbc,
    ///         KeyMechanism::AesEncryptionCbc,
    ///         KeyMechanism::EcdsaSignature
    ///     ])
    ///     .is_err());
    /// ```
    pub fn matches_mechanisms(&self, mechanisms: &[KeyMechanism]) -> Result<(), Error> {
        let valid_mechanisms: &[KeyMechanism] = match self {
            KeyType::Curve25519 => &KeyMechanism::curve25519_mechanisms(),
            KeyType::EcP224 | KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521 => {
                &KeyMechanism::elliptic_curve_mechanisms()
            }
            KeyType::Generic => &KeyMechanism::generic_mechanisms(),
            KeyType::Rsa => &KeyMechanism::rsa_mechanisms(),
        };

        let mut invalid_mechanisms = mechanisms
            .iter()
            .filter(|mechanism| !valid_mechanisms.contains(mechanism))
            .peekable();

        if invalid_mechanisms.peek().is_none() {
            Ok(())
        } else {
            Err(Error::KeyData(format!(
                "{:?} is incompatible with {}",
                self,
                invalid_mechanisms
                    .map(Into::into)
                    .collect::<Vec<&'static str>>()
                    .join(",")
            )))
        }
    }
}

impl From<KeyType> for nethsm_sdk_rs::models::KeyType {
    fn from(value: KeyType) -> Self {
        match value {
            KeyType::Curve25519 => Self::Curve25519,
            KeyType::EcP224 => Self::EcP224,
            KeyType::EcP256 => Self::EcP256,
            KeyType::EcP384 => Self::EcP384,
            KeyType::EcP521 => Self::EcP521,
            KeyType::Generic => Self::Generic,
            KeyType::Rsa => Self::Rsa,
        }
    }
}

impl From<nethsm_sdk_rs::models::KeyType> for KeyType {
    fn from(value: nethsm_sdk_rs::models::KeyType) -> Self {
        use nethsm_sdk_rs::models::KeyType;
        match value {
            KeyType::Curve25519 => Self::Curve25519,
            KeyType::EcP224 => Self::EcP224,
            KeyType::EcP256 => Self::EcP256,
            KeyType::EcP384 => Self::EcP384,
            KeyType::EcP521 => Self::EcP521,
            KeyType::Generic => Self::Generic,
            KeyType::Rsa => Self::Rsa,
        }
    }
}

/// The format of a key
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
pub enum KeyFormat {
    /// Privacy-Enhanced Mail (PEM) format.
    Pem,

    /// ASN.1 DER binary format.
    #[default]
    Der,
}

/// A device log level
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
pub enum LogLevel {
    /// Show debug, error, warning and info messages
    Debug,

    /// Show error, warning and info messages
    Error,

    /// Show info messages
    #[default]
    Info,

    /// Show warning and info messages
    Warning,
}

impl From<LogLevel> for nethsm_sdk_rs::models::LogLevel {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Debug => Self::Debug,
            LogLevel::Error => Self::Error,
            LogLevel::Info => Self::Info,
            LogLevel::Warning => Self::Warning,
        }
    }
}

/// The algorithm type of a key used for TLS
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
pub enum TlsKeyType {
    /// A Montgomery curve key over a prime field for the prime number 2^255-19
    Curve25519,

    /// An elliptic-curve key over a prime field for a prime of size 224 bit
    EcP224,

    /// An elliptic-curve key over a prime field for a prime of size 256 bit
    EcP256,

    /// An elliptic-curve key over a prime field for a prime of size 384 bit
    EcP384,

    /// An elliptic-curve key over a prime field for a prime of size 521 bit
    EcP521,

    /// An RSA key
    #[default]
    Rsa,
}

impl From<TlsKeyType> for nethsm_sdk_rs::models::TlsKeyType {
    fn from(value: TlsKeyType) -> Self {
        match value {
            TlsKeyType::Curve25519 => Self::Curve25519,
            TlsKeyType::EcP224 => Self::EcP224,
            TlsKeyType::EcP256 => Self::EcP256,
            TlsKeyType::EcP384 => Self::EcP384,
            TlsKeyType::EcP521 => Self::EcP521,
            TlsKeyType::Rsa => Self::Rsa,
        }
    }
}

/// The role of a user on a NetHSM device
#[derive(
    Clone,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
)]
#[strum(ascii_case_insensitive)]
pub enum UserRole {
    /// A role for administrating a device, its users and keys
    Administrator,
    /// A role for creating backups of a device
    Backup,
    /// A role for reading metrics of a device
    Metrics,
    /// A role for using one or more keys of a device
    #[default]
    Operator,
}

impl From<UserRole> for nethsm_sdk_rs::models::UserRole {
    fn from(value: UserRole) -> Self {
        match value {
            UserRole::Administrator => Self::Administrator,
            UserRole::Backup => Self::Backup,
            UserRole::Metrics => Self::Metrics,
            UserRole::Operator => Self::Operator,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

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
    #[case("ecp224", Some(KeyType::EcP224))]
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
    #[case("ecdsap224", Some(SignatureType::EcdsaP224))]
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

    #[rstest]
    #[case("rsa", Some(TlsKeyType::Rsa))]
    #[case("curve25519", Some(TlsKeyType::Curve25519))]
    #[case("ecp224", Some(TlsKeyType::EcP224))]
    #[case("ecp256", Some(TlsKeyType::EcP256))]
    #[case("ecp384", Some(TlsKeyType::EcP384))]
    #[case("ecp521", Some(TlsKeyType::EcP521))]
    #[case("foo", None)]
    fn tlskeytype_fromstr(#[case] input: &str, #[case] expected: Option<TlsKeyType>) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(TlsKeyType::from_str(input)?, expected);
        } else {
            assert!(TlsKeyType::from_str(input).is_err());
        }
        Ok(())
    }

    #[rstest]
    #[case("administrator", Some(UserRole::Administrator))]
    #[case("backup", Some(UserRole::Backup))]
    #[case("metrics", Some(UserRole::Metrics))]
    #[case("operator", Some(UserRole::Operator))]
    #[case("foo", None)]
    fn userrole_fromstr(#[case] input: &str, #[case] expected: Option<UserRole>) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(UserRole::from_str(input)?, expected);
        } else {
            assert!(UserRole::from_str(input).is_err());
        }
        Ok(())
    }
}
