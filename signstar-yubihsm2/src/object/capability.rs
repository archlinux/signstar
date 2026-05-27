//! YubiHSM2 object capabilities.

use std::{collections::BTreeSet, hash::Hash};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumIter, EnumString, IntoEnumIterator, IntoStaticStr};

/// A capability of an object stored on a YubiHSM2.
#[derive(
    AsRefStr,
    Clone,
    Copy,
    Debug,
    Display,
    EnumIter,
    EnumString,
    Eq,
    Hash,
    IntoStaticStr,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[strum(serialize_all = "kebab-case")]
pub enum Capability {
    /// Replace authentication key objects.
    ///
    /// Applicable for authentication key objects.
    ChangeAuthenticationKey,

    /// Create OTP AEAD.
    ///
    /// Applicable for authentication and OTP AEAD key objects.
    CreateOtpAead,

    /// Decrypt data using AES CBC mode.
    ///
    /// Applicable for authentication and symmetric key objects.
    DecryptCbc,

    /// Decrypt data using AES ECB mode.
    ///
    /// Applicable for authentication and symmetric key objects.
    DecryptEcb,

    /// Decrypt data using RSA-OAEP.
    ///
    /// Applicable for authentication and asymmetric key objects.
    DecryptOaep,

    /// Decrypt OTP.
    ///
    /// Applicable for authentication and OTP AEAD key objects.
    DecryptOtp,

    /// Decrypt data using RSA-PKCS1v1.5.
    ///
    /// Applicable for authentication and asymmetric key objects.
    DecryptPkcs,

    /// Delete asymmetric key objects.
    ///
    /// Applicable for authentication key objects.
    DeleteAsymmetricKey,

    /// Delete authentication key objects.
    ///
    /// Applicable for authentication key objects.
    DeleteAuthenticationKey,

    /// Delete HMAC key objects.
    ///
    /// Applicable for authentication key objects.
    DeleteHmacKey,

    /// Delete opaque objects.
    ///
    /// Applicable for authentication key objects.
    DeleteOpaque,

    /// Delete OTP AEAD key objects.
    ///
    /// Applicable for authentication key objects.
    DeleteOtpAeadKey,

    /// Delete RSA public wrap key.
    ///
    /// Applicable for authentication and wrap key objects.
    DeletePublicWrapKey,

    /// Delete AES key.
    ///
    /// Applicable for authentication key objects.
    DeleteSymmetricKey,

    /// Delete template objects.
    ///
    /// Applicable for authentication key objects.
    DeleteTemplate,

    /// Delete wrap key objects.
    ///
    /// Applicable for authentication key objects.
    DeleteWrapKey,

    /// Perform ECDH.
    ///
    /// Applicable for authentication and asymmetric key objects.
    DeriveEcdh,

    /// Encrypt data using AES CBC mode.
    ///
    /// Applicable for authentication and symmetric key objects.
    EncryptCbc,

    /// Encrypt data using AES ECB mode.
    ///
    /// Applicable for authentication and symmetric key objects.
    EncryptEcb,

    /// The object can be exported under wrap (encrypted).
    ///
    /// Applicable for all objects.
    ExportableUnderWrap,

    /// Export other objects under wrap.
    ///
    /// Applicable for authentication and wrap key objects.
    ///
    /// # Note
    ///
    /// Both the authentication key used for export *and* the wrapping key need to be capable of
    /// export.
    ExportWrapped,

    /// Generate asymmetric key objects.
    ///
    /// Applicable for authentication key objects.
    GenerateAsymmetricKey,

    /// Generate HMAC key objects.
    ///
    /// Applicable for authentication key objects.
    GenerateHmacKey,

    /// Generate OTP AEAD key objects.
    ///
    /// Applicable for authentication key objects.
    GenerateOtpAeadKey,

    /// Generate AES key.
    ///
    /// Applicable for authentication key objects.
    GenerateSymmetricKey,

    /// Generate wrap key objects.
    ///
    /// Applicable for authentication key objects.
    GenerateWrapKey,

    /// Read the log store.
    ///
    /// Applicable for authentication key objects.
    GetLogEntries,

    /// Read opaque objects.
    ///
    /// Applicable for authentication key objects.
    GetOpaque,

    /// Read device-global options.
    ///
    /// Applicable for authentication key objects.
    GetOption,

    /// Extract random bytes.
    ///
    /// Applicable for authentication key objects.
    GetPseudoRandom,

    /// Read template objects.
    ///
    /// Applicable for authentication key objects.
    GetTemplate,

    /// Import wrapped objects.
    ///
    /// Applicable for authentication and wrap key objects.
    ///
    /// # Note
    ///
    /// Both the authentication key used for import *and* the wrapping key need to be capable of
    /// import.
    ImportWrapped,

    /// Write asymmetric key objects.
    ///
    /// Applicable for authentication key objects.
    PutAsymmetricKey,

    /// Write authentications key objects.
    ///
    /// Applicable for authentication key objects.
    PutAuthenticationKey,

    /// Write HMAC key objects.
    ///
    /// Applicable for authentication key objects.
    PutHmacKey,

    /// Write opaque objects.
    ///
    /// Applicable for authentication key objects.
    PutOpaque,

    /// Write OTP AEAD key objects.
    ///
    /// Applicable for authentication key objects.
    PutOtpAeadKey,

    /// Write RSA public wrap key.
    ///
    /// Applicable for authentication and wrap key objects.
    PutPublicWrapKey,

    /// Import AES key.
    ///
    /// Applicable for authentication key objects.
    PutSymmetricKey,

    /// Write template objects.
    ///
    /// Applicable for authentication key objects.
    PutTemplate,

    /// Write wrap key objects.
    ///
    /// Applicable for authentication key objects.
    PutWrapKey,

    /// Create OTP AEAD from random data.
    ///
    /// Applicable for authentication and OTP AEAD key objects.
    RandomizeOtpAead,

    /// Perform a factory reset on the device.
    ///
    /// Applicable for authentication key objects.
    ResetDevice,

    /// Rewrap AEADs from one OTP AEAD key to another.
    ///
    /// Applicable for authentication and OTP AEAD key objects.
    RewrapFromOtpAeadKey,

    /// Rewrap AEADs to one OTP AEAD key from another.
    ///
    /// Applicable for authentication and OTP AEAD key objects.
    RewrapToOtpAeadKey,

    /// Write device-global options.
    ///
    /// Applicable for authentication key objects.
    SetOption,

    /// Attest properties of asymmetric key objects.
    ///
    /// Applicable for authentication and asymmetric key objects.
    SignAttestationCertificate,

    /// Compute digital signatures using ECDSA.
    ///
    /// Applicable for authentication and asymmetric key objects.
    SignEcdsa,

    /// Compute digital signatures using [EdDSA].
    ///
    /// Applicable for authentication and asymmetric key objects.
    ///
    /// [EdDSA]: https://en.wikipedia.org/wiki/EdDSA
    SignEddsa,

    /// Compute HMAC of data.
    ///
    /// Applicable for authentication and HMAC key objects.
    SignHmac,

    /// Compute digital signatures using RSA-PKCS1v1.5.
    ///
    /// Applicable for authentication and asymmetric key objects.
    SignPkcs,

    /// Compute digital signatures using RSA-PSS.
    ///
    /// Applicable for authentication and asymmetric key objects.
    SignPss,

    /// Sign SSH certificates.
    ///
    /// Applicable for authentication and asymmetric key objects.
    SignSshCertificate,

    /// Unwrap user-provided data.
    ///
    /// Applicable for authentication and wrap key objects.
    UnwrapData,

    /// Verify HMAC of data.
    ///
    /// Applicable for authentication and HMAC key objects.
    VerifyHmac,

    /// Wrap user-provided data.
    ///
    /// Applicable for authentication and wrap key objects.
    WrapData,
}

impl From<&Capability> for yubihsm::Capability {
    fn from(value: &Capability) -> Self {
        match *value {
            Capability::ChangeAuthenticationKey => yubihsm::Capability::CHANGE_AUTHENTICATION_KEY,
            Capability::CreateOtpAead => yubihsm::Capability::CREATE_OTP_AEAD,
            Capability::DecryptCbc => yubihsm::Capability::UNKNOWN_CAPABILITY_52,
            Capability::DecryptEcb => yubihsm::Capability::UNKNOWN_CAPABILITY_50,
            Capability::DecryptOaep => yubihsm::Capability::DECRYPT_OAEP,
            Capability::DecryptOtp => yubihsm::Capability::DECRYPT_OTP,
            Capability::DecryptPkcs => yubihsm::Capability::DECRYPT_PKCS,
            Capability::DeleteAsymmetricKey => yubihsm::Capability::DELETE_ASYMMETRIC_KEY,
            Capability::DeleteAuthenticationKey => yubihsm::Capability::DELETE_AUTHENTICATION_KEY,
            Capability::DeleteHmacKey => yubihsm::Capability::DELETE_HMAC_KEY,
            Capability::DeleteOpaque => yubihsm::Capability::DELETE_OPAQUE,
            Capability::DeleteOtpAeadKey => yubihsm::Capability::DELETE_OTP_AEAD_KEY,
            Capability::DeletePublicWrapKey => yubihsm::Capability::UNKNOWN_CAPABILITY_55,
            Capability::DeleteSymmetricKey => yubihsm::Capability::UNKNOWN_CAPABILITY_49,
            Capability::DeleteTemplate => yubihsm::Capability::DELETE_TEMPLATE,
            Capability::DeleteWrapKey => yubihsm::Capability::DELETE_WRAP_KEY,
            Capability::DeriveEcdh => yubihsm::Capability::DERIVE_ECDH,
            Capability::EncryptCbc => yubihsm::Capability::UNKNOWN_CAPABILITY_53,
            Capability::EncryptEcb => yubihsm::Capability::UNKNOWN_CAPABILITY_51,
            Capability::ExportableUnderWrap => yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            Capability::ExportWrapped => yubihsm::Capability::EXPORT_WRAPPED,
            Capability::GenerateAsymmetricKey => yubihsm::Capability::GENERATE_ASYMMETRIC_KEY,
            Capability::GenerateHmacKey => yubihsm::Capability::GENERATE_HMAC_KEY,
            Capability::GenerateOtpAeadKey => yubihsm::Capability::GENERATE_OTP_AEAD_KEY,
            Capability::GenerateSymmetricKey => yubihsm::Capability::UNKNOWN_CAPABILITY_48,
            Capability::GenerateWrapKey => yubihsm::Capability::GENERATE_WRAP_KEY,
            Capability::GetOpaque => yubihsm::Capability::GET_OPAQUE,
            Capability::GetOption => yubihsm::Capability::GET_OPTION,
            Capability::GetPseudoRandom => yubihsm::Capability::GET_PSEUDO_RANDOM,
            Capability::GetLogEntries => yubihsm::Capability::GET_LOG_ENTRIES,
            Capability::GetTemplate => yubihsm::Capability::GET_TEMPLATE,
            Capability::ImportWrapped => yubihsm::Capability::IMPORT_WRAPPED,
            Capability::PutAsymmetricKey => yubihsm::Capability::PUT_ASYMMETRIC_KEY,
            Capability::PutAuthenticationKey => yubihsm::Capability::PUT_AUTHENTICATION_KEY,
            Capability::PutHmacKey => yubihsm::Capability::PUT_HMAC_KEY,
            Capability::PutOpaque => yubihsm::Capability::PUT_OPAQUE,
            Capability::PutOtpAeadKey => yubihsm::Capability::PUT_OTP_AEAD_KEY,
            Capability::PutPublicWrapKey => yubihsm::Capability::UNKNOWN_CAPABILITY_51,
            Capability::PutSymmetricKey => yubihsm::Capability::UNKNOWN_CAPABILITY_47,
            Capability::PutTemplate => yubihsm::Capability::PUT_TEMPLATE,
            Capability::PutWrapKey => yubihsm::Capability::PUT_WRAP_KEY,
            Capability::RandomizeOtpAead => yubihsm::Capability::RANDOMIZE_OTP_AEAD,
            Capability::RewrapFromOtpAeadKey => yubihsm::Capability::REWRAP_FROM_OTP_AEAD_KEY,
            Capability::RewrapToOtpAeadKey => yubihsm::Capability::REWRAP_TO_OTP_AEAD_KEY,
            Capability::ResetDevice => yubihsm::Capability::RESET_DEVICE,
            Capability::SetOption => yubihsm::Capability::PUT_OPTION,
            Capability::SignAttestationCertificate => {
                yubihsm::Capability::SIGN_ATTESTATION_CERTIFICATE
            }
            Capability::SignEcdsa => yubihsm::Capability::SIGN_ECDSA,
            Capability::SignEddsa => yubihsm::Capability::SIGN_EDDSA,
            Capability::SignHmac => yubihsm::Capability::SIGN_HMAC,
            Capability::SignPkcs => yubihsm::Capability::SIGN_PKCS,
            Capability::SignPss => yubihsm::Capability::SIGN_PSS,
            Capability::SignSshCertificate => yubihsm::Capability::SIGN_SSH_CERTIFICATE,
            Capability::UnwrapData => yubihsm::Capability::UNWRAP_DATA,
            Capability::VerifyHmac => yubihsm::Capability::VERIFY_HMAC,
            Capability::WrapData => yubihsm::Capability::WRAP_DATA,
        }
    }
}

/// A set of capabilities of an object on a YubiHSM2.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Capabilities(BTreeSet<Capability>);

impl From<[u8; 8]> for Capabilities {
    fn from(bytes: [u8; 8]) -> Self {
        let numeric = u64::from_be_bytes(bytes);
        let value = yubihsm::Capability::from_bits_retain(numeric);
        Self(
            Capability::iter()
                .filter(|capability| value.contains(capability.into()))
                .collect(),
        )
    }
}

impl From<&Capabilities> for [u8; 8] {
    fn from(value: &Capabilities) -> Self {
        yubihsm::Capability::from(value).bits().to_be_bytes()
    }
}

impl From<&Capabilities> for yubihsm::Capability {
    fn from(value: &Capabilities) -> Self {
        value
            .0
            .iter()
            .map(yubihsm::Capability::from)
            .fold(yubihsm::Capability::empty(), |acc, c| acc | c)
    }
}

impl From<&[Capability]> for Capabilities {
    fn from(value: &[Capability]) -> Self {
        Self(value.iter().copied().collect())
    }
}
