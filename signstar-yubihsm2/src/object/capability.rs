//! YubiHSM2 object capabilities.

use std::{collections::BTreeSet, fmt::Display, hash::Hash};

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

impl Display for Capabilities {
    /// Formats a [`Capabilities`] as a string.
    ///
    /// Here, the capabilities in `self` are represented as a comma-separated list (e.g.
    /// `change-authentication-key, create-otp-aead, decrypt-cbc` or
    /// `change-authentication-key`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|capability| capability.as_ref())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

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

impl From<yubihsm::Capability> for Capabilities {
    fn from(value: yubihsm::Capability) -> Self {
        let lookup = [
            (
                yubihsm::Capability::CHANGE_AUTHENTICATION_KEY,
                Capability::ChangeAuthenticationKey,
            ),
            (
                yubihsm::Capability::CREATE_OTP_AEAD,
                Capability::CreateOtpAead,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_52,
                Capability::DecryptCbc,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_50,
                Capability::DecryptEcb,
            ),
            (yubihsm::Capability::DECRYPT_OAEP, Capability::DecryptOaep),
            (yubihsm::Capability::DECRYPT_OTP, Capability::DecryptOtp),
            (yubihsm::Capability::DECRYPT_PKCS, Capability::DecryptPkcs),
            (
                yubihsm::Capability::DELETE_ASYMMETRIC_KEY,
                Capability::DeleteAsymmetricKey,
            ),
            (
                yubihsm::Capability::DELETE_AUTHENTICATION_KEY,
                Capability::DeleteAuthenticationKey,
            ),
            (
                yubihsm::Capability::DELETE_HMAC_KEY,
                Capability::DeleteHmacKey,
            ),
            (yubihsm::Capability::DELETE_OPAQUE, Capability::DeleteOpaque),
            (
                yubihsm::Capability::DELETE_OTP_AEAD_KEY,
                Capability::DeleteOtpAeadKey,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_55,
                Capability::DeletePublicWrapKey,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_49,
                Capability::DeleteSymmetricKey,
            ),
            (
                yubihsm::Capability::DELETE_TEMPLATE,
                Capability::DeleteTemplate,
            ),
            (
                yubihsm::Capability::DELETE_WRAP_KEY,
                Capability::DeleteWrapKey,
            ),
            (yubihsm::Capability::DERIVE_ECDH, Capability::DeriveEcdh),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_53,
                Capability::EncryptCbc,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_51,
                Capability::EncryptEcb,
            ),
            (
                yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
                Capability::ExportableUnderWrap,
            ),
            (
                yubihsm::Capability::EXPORT_WRAPPED,
                Capability::ExportWrapped,
            ),
            (
                yubihsm::Capability::GENERATE_ASYMMETRIC_KEY,
                Capability::GenerateAsymmetricKey,
            ),
            (
                yubihsm::Capability::GENERATE_HMAC_KEY,
                Capability::GenerateHmacKey,
            ),
            (
                yubihsm::Capability::GENERATE_OTP_AEAD_KEY,
                Capability::GenerateOtpAeadKey,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_48,
                Capability::GenerateSymmetricKey,
            ),
            (
                yubihsm::Capability::GENERATE_WRAP_KEY,
                Capability::GenerateWrapKey,
            ),
            (yubihsm::Capability::GET_OPAQUE, Capability::GetOpaque),
            (yubihsm::Capability::GET_OPTION, Capability::GetOption),
            (
                yubihsm::Capability::GET_PSEUDO_RANDOM,
                Capability::GetPseudoRandom,
            ),
            (
                yubihsm::Capability::GET_LOG_ENTRIES,
                Capability::GetLogEntries,
            ),
            (yubihsm::Capability::GET_TEMPLATE, Capability::GetTemplate),
            (
                yubihsm::Capability::IMPORT_WRAPPED,
                Capability::ImportWrapped,
            ),
            (
                yubihsm::Capability::PUT_ASYMMETRIC_KEY,
                Capability::PutAsymmetricKey,
            ),
            (
                yubihsm::Capability::PUT_AUTHENTICATION_KEY,
                Capability::PutAuthenticationKey,
            ),
            (yubihsm::Capability::PUT_HMAC_KEY, Capability::PutHmacKey),
            (yubihsm::Capability::PUT_OPAQUE, Capability::PutOpaque),
            (
                yubihsm::Capability::PUT_OTP_AEAD_KEY,
                Capability::PutOtpAeadKey,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_54,
                Capability::PutPublicWrapKey,
            ),
            // NOTE: This capability is not yet understood by the underlying library.
            (
                yubihsm::Capability::UNKNOWN_CAPABILITY_47,
                Capability::PutSymmetricKey,
            ),
            (yubihsm::Capability::PUT_TEMPLATE, Capability::PutTemplate),
            (yubihsm::Capability::PUT_WRAP_KEY, Capability::PutWrapKey),
            (
                yubihsm::Capability::RANDOMIZE_OTP_AEAD,
                Capability::RandomizeOtpAead,
            ),
            (
                yubihsm::Capability::REWRAP_FROM_OTP_AEAD_KEY,
                Capability::RewrapFromOtpAeadKey,
            ),
            (
                yubihsm::Capability::REWRAP_TO_OTP_AEAD_KEY,
                Capability::RewrapToOtpAeadKey,
            ),
            (yubihsm::Capability::RESET_DEVICE, Capability::ResetDevice),
            (yubihsm::Capability::PUT_OPTION, Capability::SetOption),
            (
                yubihsm::Capability::SIGN_ATTESTATION_CERTIFICATE,
                Capability::SignAttestationCertificate,
            ),
            (yubihsm::Capability::SIGN_ECDSA, Capability::SignEcdsa),
            (yubihsm::Capability::SIGN_EDDSA, Capability::SignEddsa),
            (yubihsm::Capability::SIGN_HMAC, Capability::SignHmac),
            (yubihsm::Capability::SIGN_PKCS, Capability::SignPkcs),
            (yubihsm::Capability::SIGN_PSS, Capability::SignPss),
            (
                yubihsm::Capability::SIGN_SSH_CERTIFICATE,
                Capability::SignSshCertificate,
            ),
            (yubihsm::Capability::UNWRAP_DATA, Capability::UnwrapData),
            (yubihsm::Capability::VERIFY_HMAC, Capability::VerifyHmac),
            (yubihsm::Capability::WRAP_DATA, Capability::WrapData),
        ];

        Self(BTreeSet::from_iter(lookup.iter().filter_map(
            |(yubi_cap, cap)| {
                if value.contains(*yubi_cap) {
                    Some(*cap)
                } else {
                    None
                }
            },
        )))
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    /// Ensures that [`Capabilities::to_string`] works as expected.
    #[test]
    fn capabilities_to_string() {
        let capability_list = vec![Capability::ChangeAuthenticationKey];
        let capabilities = Capabilities::from(capability_list.as_slice());
        assert_eq!("change-authentication-key", capabilities.to_string());

        let capability_list = vec![
            Capability::ChangeAuthenticationKey,
            Capability::CreateOtpAead,
        ];
        let capabilities = Capabilities::from(capability_list.as_slice());
        assert_eq!(
            "change-authentication-key, create-otp-aead",
            capabilities.to_string()
        );
    }

    /// Ensures that [`Capabilities`] are created correctly from [`yubihsm::Capabilities`].
    #[rstest]
    #[case::change_authentication_key(
        yubihsm::Capability::CHANGE_AUTHENTICATION_KEY,
        Capabilities(BTreeSet::from_iter([Capability::ChangeAuthenticationKey])),
    )]
    #[case::create_otp_aead(
        yubihsm::Capability::CREATE_OTP_AEAD,
        Capabilities(BTreeSet::from_iter([Capability::CreateOtpAead])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::decrypt_cbc(
        yubihsm::Capability::UNKNOWN_CAPABILITY_52,
        Capabilities(BTreeSet::from_iter([Capability::DecryptCbc])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::decrypt_ecb(
        yubihsm::Capability::UNKNOWN_CAPABILITY_50,
        Capabilities(BTreeSet::from_iter([Capability::DecryptEcb])),
    )]
    #[case::decrypt_oaep(
        yubihsm::Capability::DECRYPT_OAEP,
        Capabilities(BTreeSet::from_iter([Capability::DecryptOaep])),
    )]
    #[case::decrypt_otp(
        yubihsm::Capability::DECRYPT_OTP,
        Capabilities(BTreeSet::from_iter([Capability::DecryptOtp])),
    )]
    #[case::decrypt_pkcs(
        yubihsm::Capability::DECRYPT_PKCS,
        Capabilities(BTreeSet::from_iter([Capability::DecryptPkcs])),
    )]
    #[case::delete_asymmetric_key(
        yubihsm::Capability::DELETE_ASYMMETRIC_KEY,
        Capabilities(BTreeSet::from_iter([Capability::DeleteAsymmetricKey])),
    )]
    #[case::delete_authentication_key(
        yubihsm::Capability::DELETE_AUTHENTICATION_KEY,
        Capabilities(BTreeSet::from_iter([Capability::DeleteAuthenticationKey])),
    )]
    #[case::delete_hmac_key(
        yubihsm::Capability::DELETE_HMAC_KEY,
        Capabilities(BTreeSet::from_iter([Capability::DeleteHmacKey])),
    )]
    #[case::delete_opaque(
        yubihsm::Capability::DELETE_OPAQUE,
        Capabilities(BTreeSet::from_iter([Capability::DeleteOpaque])),
    )]
    #[case::delete_otp_aead_key(
        yubihsm::Capability::DELETE_OTP_AEAD_KEY,
        Capabilities(BTreeSet::from_iter([Capability::DeleteOtpAeadKey])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::delete_public_wrap_key(
        yubihsm::Capability::UNKNOWN_CAPABILITY_55,
        Capabilities(BTreeSet::from_iter([Capability::DeletePublicWrapKey])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::delete_symmetric_key(
        yubihsm::Capability::UNKNOWN_CAPABILITY_49,
        Capabilities(BTreeSet::from_iter([Capability::DeleteSymmetricKey])),
    )]
    #[case::delete_template(
        yubihsm::Capability::DELETE_TEMPLATE,
        Capabilities(BTreeSet::from_iter([Capability::DeleteTemplate])),
    )]
    #[case::delete_wrap_key(
        yubihsm::Capability::DELETE_WRAP_KEY,
        Capabilities(BTreeSet::from_iter([Capability::DeleteWrapKey])),
    )]
    #[case::derive_ecdh(
        yubihsm::Capability::DERIVE_ECDH,
        Capabilities(BTreeSet::from_iter([Capability::DeriveEcdh])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::encrypt_cbc(
        yubihsm::Capability::UNKNOWN_CAPABILITY_53,
        Capabilities(BTreeSet::from_iter([Capability::EncryptCbc])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::encrypt_ecb(
        yubihsm::Capability::UNKNOWN_CAPABILITY_51,
        Capabilities(BTreeSet::from_iter([Capability::EncryptEcb])),
    )]
    #[case::exportable_under_wrap(
        yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
        Capabilities(BTreeSet::from_iter([Capability::ExportableUnderWrap])),
    )]
    #[case::export_wrapped(
        yubihsm::Capability::EXPORT_WRAPPED,
        Capabilities(BTreeSet::from_iter([Capability::ExportWrapped])),
    )]
    #[case::generate_asymmetric_key(
        yubihsm::Capability::GENERATE_ASYMMETRIC_KEY,
        Capabilities(BTreeSet::from_iter([Capability::GenerateAsymmetricKey])),
    )]
    #[case::generate_hmac_key(
        yubihsm::Capability::GENERATE_HMAC_KEY,
        Capabilities(BTreeSet::from_iter([Capability::GenerateHmacKey])),
    )]
    #[case::generate_otp_aead_key(
        yubihsm::Capability::GENERATE_OTP_AEAD_KEY,
        Capabilities(BTreeSet::from_iter([Capability::GenerateOtpAeadKey])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::generate_symmetric_key(
        yubihsm::Capability::UNKNOWN_CAPABILITY_48,
        Capabilities(BTreeSet::from_iter([Capability::GenerateSymmetricKey])),
    )]
    #[case::generate_wrap_key(
        yubihsm::Capability::GENERATE_WRAP_KEY,
        Capabilities(BTreeSet::from_iter([Capability::GenerateWrapKey])),
    )]
    #[case::get_opaque(
        yubihsm::Capability::GET_OPAQUE,
        Capabilities(BTreeSet::from_iter([Capability::GetOpaque])),
    )]
    #[case::get_option(
        yubihsm::Capability::GET_OPTION,
        Capabilities(BTreeSet::from_iter([Capability::GetOption])),
    )]
    #[case::get_pseudo_random(
        yubihsm::Capability::GET_PSEUDO_RANDOM,
        Capabilities(BTreeSet::from_iter([Capability::GetPseudoRandom])),
    )]
    #[case::get_log_entries(
        yubihsm::Capability::GET_LOG_ENTRIES,
        Capabilities(BTreeSet::from_iter([Capability::GetLogEntries])),
    )]
    #[case::get_template(
        yubihsm::Capability::GET_TEMPLATE,
        Capabilities(BTreeSet::from_iter([Capability::GetTemplate])),
    )]
    #[case::import_wrapped(
        yubihsm::Capability::IMPORT_WRAPPED,
        Capabilities(BTreeSet::from_iter([Capability::ImportWrapped])),
    )]
    #[case::put_asymmetric_key(
        yubihsm::Capability::PUT_ASYMMETRIC_KEY,
        Capabilities(BTreeSet::from_iter([Capability::PutAsymmetricKey])),
    )]
    #[case::put_authentication_key(
        yubihsm::Capability::PUT_AUTHENTICATION_KEY,
        Capabilities(BTreeSet::from_iter([Capability::PutAuthenticationKey])),
    )]
    #[case::put_hmac_key(
        yubihsm::Capability::PUT_HMAC_KEY,
        Capabilities(BTreeSet::from_iter([Capability::PutHmacKey])),
    )]
    #[case::put_opaque(
        yubihsm::Capability::PUT_OPAQUE,
        Capabilities(BTreeSet::from_iter([Capability::PutOpaque])),
    )]
    #[case::put_otp_aead_key(
        yubihsm::Capability::PUT_OTP_AEAD_KEY,
        Capabilities(BTreeSet::from_iter([Capability::PutOtpAeadKey])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::put_public_wrap_key(
        yubihsm::Capability::UNKNOWN_CAPABILITY_54,
        Capabilities(BTreeSet::from_iter([Capability::PutPublicWrapKey])),
    )]
    // NOTE: This capability is not yet understood by the underlying library.
    #[case::put_symmetric_key(
        yubihsm::Capability::UNKNOWN_CAPABILITY_47,
        Capabilities(BTreeSet::from_iter([Capability::PutSymmetricKey])),
    )]
    #[case::put_template(
        yubihsm::Capability::PUT_TEMPLATE,
        Capabilities(BTreeSet::from_iter([Capability::PutTemplate])),
    )]
    #[case::put_wrap_key(
        yubihsm::Capability::PUT_WRAP_KEY,
        Capabilities(BTreeSet::from_iter([Capability::PutWrapKey])),
    )]
    #[case::randomize_otp_aead(
        yubihsm::Capability::RANDOMIZE_OTP_AEAD,
        Capabilities(BTreeSet::from_iter([Capability::RandomizeOtpAead])),
    )]
    #[case::rewrap_from_otp_aead_key(
        yubihsm::Capability::REWRAP_FROM_OTP_AEAD_KEY,
        Capabilities(BTreeSet::from_iter([Capability::RewrapFromOtpAeadKey])),
    )]
    #[case::rewrap_to_otp_aead_key(
        yubihsm::Capability::REWRAP_TO_OTP_AEAD_KEY,
        Capabilities(BTreeSet::from_iter([Capability::RewrapToOtpAeadKey])),
    )]
    #[case::reset_device(
        yubihsm::Capability::RESET_DEVICE,
        Capabilities(BTreeSet::from_iter([Capability::ResetDevice])),
    )]
    #[case::put_option(
        yubihsm::Capability::PUT_OPTION,
        Capabilities(BTreeSet::from_iter([Capability::SetOption])),
    )]
    #[case::sign_attestation_certificate(
        yubihsm::Capability::SIGN_ATTESTATION_CERTIFICATE,
        Capabilities(BTreeSet::from_iter([Capability::SignAttestationCertificate])),
    )]
    #[case::sign_ecdsa(
        yubihsm::Capability::SIGN_ECDSA,
        Capabilities(BTreeSet::from_iter([Capability::SignEcdsa])),
    )]
    #[case::sign_eddsa(
        yubihsm::Capability::SIGN_EDDSA,
        Capabilities(BTreeSet::from_iter([Capability::SignEddsa])),
    )]
    #[case::sign_hmac(
        yubihsm::Capability::SIGN_HMAC,
        Capabilities(BTreeSet::from_iter([Capability::SignHmac])),
    )]
    #[case::sign_pkcs(
        yubihsm::Capability::SIGN_PKCS,
        Capabilities(BTreeSet::from_iter([Capability::SignPkcs])),
    )]
    #[case::sign_pss(
        yubihsm::Capability::SIGN_PSS,
        Capabilities(BTreeSet::from_iter([Capability::SignPss])),
    )]
    #[case::sign_ssh_certificate(
        yubihsm::Capability::SIGN_SSH_CERTIFICATE,
        Capabilities(BTreeSet::from_iter([Capability::SignSshCertificate])),
    )]
    #[case::unwrap_data(
        yubihsm::Capability::UNWRAP_DATA,
        Capabilities(BTreeSet::from_iter([Capability::UnwrapData])),
    )]
    #[case::verify_hmac(
        yubihsm::Capability::VERIFY_HMAC,
        Capabilities(BTreeSet::from_iter([Capability::VerifyHmac])),
    )]
    #[case::wrap_data(
        yubihsm::Capability::WRAP_DATA,
        Capabilities(BTreeSet::from_iter([Capability::WrapData])),
    )]
    fn capabilities_from_yubihsm_capability(
        #[case] yubi_cap: yubihsm::Capability,
        #[case] cap: Capabilities,
    ) {
        assert_eq!(Capabilities::from(yubi_cap), cap);
    }
}
