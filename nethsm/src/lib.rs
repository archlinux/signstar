#![doc = include_str!("../README.md")]

mod backup;
mod base;
pub mod connection;
mod error;
mod key;
mod nethsm_sdk;
pub mod openpgp;
#[cfg(feature = "test-helpers")]
pub mod test;
mod tls;
mod user;

pub use backup::validate_backup;
pub use base::NetHsm;
// Publicly re-export chrono facilities used in the API of NetHsm.
pub use chrono::{DateTime, Utc};
pub use connection::{Connection, Url};
pub use error::Error;
pub use key::{
    CryptographicKeyContext,
    KeyId,
    MIN_RSA_BIT_LENGTH,
    PrivateKeyImport,
    SigningKeySetup,
    key_type_and_mechanisms_match_signature_type,
    key_type_matches_length,
    key_type_matches_mechanisms,
    tls_key_type_matches_length,
};
pub use nethsm_sdk::{
    BootMode,
    DecryptMode,
    EncryptMode,
    KeyFormat,
    KeyMechanism,
    KeyType,
    LogLevel,
    SignatureType,
    TlsKeyType,
    UserRole,
};
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
pub use openpgp::{
    KeyUsageFlags as OpenPgpKeyUsageFlags,
    OpenPgpUserId,
    OpenPgpUserIdList,
    OpenPgpVersion,
    extract_certificate as extract_openpgp_certificate,
    tsk_to_private_key_import,
};
pub use tls::{
    ConnectionSecurity,
    DEFAULT_MAX_IDLE_CONNECTIONS,
    DEFAULT_TIMEOUT_SECONDS,
    HostCertificateFingerprints,
};
pub use user::{Credentials, Error as UserError, FullCredentials, NamespaceId, Passphrase, UserId};
