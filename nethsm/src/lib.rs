#![doc = include_str!("../README.md")]

mod base;
pub mod connection;
mod error;
mod key;
mod nethsm_sdk;
pub mod signer;
#[cfg(feature = "test-helpers")]
pub mod test;
mod tls;
mod user;

pub use base::NetHsm;
// Publicly re-export chrono facilities used in the API of NetHsm.
pub use chrono::{DateTime, Utc};
pub use connection::{Connection, Url};
pub use error::Error;
pub use key::{KeyId, SigningKeySetup, tls_key_type_matches_length};
pub use nethsm_sdk::{BootMode, LogLevel, TlsKeyType, UserRole};
// Publicly re-export nethsm_sdk_rs types that are used in return values of the NetHsm API.
pub use nethsm_sdk_rs::models::{
    DistinguishedName,
    InfoData,
    LoggingConfig,
    NetworkConfig,
    PublicKey,
    SystemInfo,
    SystemState,
    SystemUpdateData,
    UserData,
};
// Publicly re-export signstar_crypto types that are used in the NetHsm API.
pub use signstar_crypto::{
    key::{
        CryptographicKeyContext,
        DecryptMode,
        EncryptMode,
        KeyFormat,
        KeyMechanism,
        KeyType,
        PrivateKeyImport,
        SignatureType,
        key_type_and_mechanisms_match_signature_type,
        key_type_matches_length,
        key_type_matches_mechanisms,
    },
    openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId, OpenPgpUserIdList, OpenPgpVersion},
    passphrase::Passphrase,
};
pub use tls::{
    ConnectionSecurity,
    DEFAULT_MAX_IDLE_CONNECTIONS,
    DEFAULT_TIMEOUT_SECONDS,
    HostCertificateFingerprints,
};
pub use user::{Credentials, Error as UserError, FullCredentials, NamespaceId, UserId};

/// Extracts certificate (public key) from an OpenPGP TSK.
///
/// # Errors
///
/// Returns an error if
///
/// - a secret key cannot be decoded from `key_data`,
/// - or writing a serialized certificate into a vector fails.
pub fn extract_openpgp_certificate(key_data: &[u8]) -> Result<Vec<u8>, Error> {
    signstar_crypto::signer::extract_certificate(key_data).map_err(Error::SignstarCryptoSigner)
}

/// Converts an OpenPGP Transferable Secret Key into [`PrivateKeyImport`] object.
///
/// # Errors
///
/// Returns an [`Error::SignstarCryptoSigner`] if creating a [`PrivateKeyImport`] from `key_data` is
/// not possible.
///
/// Returns an [`crate::Error::Key`] if `key_data` is an RSA public key and is shorter than
/// [`signstar_crypto::key::MIN_RSA_BIT_LENGTH`].
pub fn tsk_to_private_key_import(
    key_data: &[u8],
) -> Result<(PrivateKeyImport, KeyMechanism), Error> {
    signstar_crypto::signer::tsk_to_private_key_import(key_data)
        .map_err(Error::SignstarCryptoSigner)
}
