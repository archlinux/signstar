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
pub use base::impl_openpgp::{extract_openpgp_certificate, tsk_to_private_key_import};
// Publicly re-export chrono facilities used in the API of NetHsm.
pub use chrono::{DateTime, Utc};
pub use connection::{Connection, Url};
pub use error::Error;
pub use key::{KeyId, tls_key_type_matches_length};
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
pub use user::{
    Credentials,
    Error as UserError,
    FullCredentials,
    NamespaceId,
    SystemWideUserId,
    UserId,
};
