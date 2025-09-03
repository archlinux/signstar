//! A high-level library to interact with the API of a [Nitrokey NetHSM].
//!
//! Provides high-level integration with a [Nitrokey NetHSM] and the official container.
//! As this crate is a wrapper around [`nethsm_sdk_rs`] it covers all available actions from
//! provisioning, over key and user management to backup and restore.
//!
//! The NetHSM provides dedicated [user management] based on a [role] system (see [`UserRole`])
//! which can be used to separate concerns.
//! Each user has exactly one [role].
//!
//! With the help of a [namespace] concept, it is possible to segregate users and their keys into
//! secluded groups.
//! Notably, this introduces *R-Administrators* (system-wide users in the
//! [`Administrator`][`UserRole::Administrator`] [role]), which have access to all system-wide
//! actions, but can *not* modify users and keys in a [namespace] and *N-Administrators*
//! ([namespace] users in the [`Administrator`][`UserRole::Administrator`] [role]), which have
//! access only to actions towards users and keys in their own [namespace].
//! [Namespace] users in the [`Operator`][`UserRole::Operator`] [role] only have access to keys in
//! their own [namespace], while system-wide users only have access to system-wide keys.
//!
//! The cryptographic key material on the NetHSM can be assigned to one or several [tags].
//! Users in the [`Operator`][`UserRole::Operator`] [role] can be assigned to the same [tags]
//! to gain access to the respective keys.
//!
//! Using the central [`NetHsm`] struct it is possible to establish a TLS connection for multiple
//! users and all available operations.
//! TLS validation can be configured based on a variant of the [`ConnectionSecurity`] enum:
//! - [`ConnectionSecurity::Unsafe`]: The host certificate is not validated.
//! - [`ConnectionSecurity::Fingerprints`]: The host certificate is validated based on configurable
//!   fingerprints.
//! - [`ConnectionSecurity::Native`]: The host certificate is validated using the native Operating
//!   System trust store.
//!
//! Apart from the crate specific documentation it is very recommended to read the canonical
//! upstream documentation as well: <https://docs.nitrokey.com/nethsm/>
//!
//! ## Reexports
//!
//! This crate re-exports the following types, so that the respective crates do not have to be
//! relied upon directly:
//!
//! * [`chrono::DateTime`]
//! * [`chrono::Utc`]
//! * [`nethsm_sdk_rs::models::DistinguishedName`]
//! * [`nethsm_sdk_rs::models::InfoData`]
//! * [`nethsm_sdk_rs::models::LoggingConfig`]
//! * [`nethsm_sdk_rs::models::NetworkConfig`]
//! * [`nethsm_sdk_rs::models::PublicKey`]
//! * [`nethsm_sdk_rs::models::SystemInfo`]
//! * [`nethsm_sdk_rs::models::SystemState`]
//! * [`nethsm_sdk_rs::models::SystemUpdateData`]
//! * [`nethsm_sdk_rs::models::UserData`]
//!
//! # Examples
//!
//! ```
//! use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};
//!
//! # fn main() -> testresult::TestResult {
//! // Create a new connection to a NetHSM at "https://example.org" using admin credentials
//! let nethsm = NetHsm::new(
//!     Connection::new(
//!         "https://example.org/api/v1".try_into()?,
//!         ConnectionSecurity::Unsafe,
//!     ),
//!     Some(Credentials::new("admin".parse()?, Some(Passphrase::new("passphrase".to_string())))),
//!     None,
//!     None,
//! )?;
//!
//! // Connections can be initialized without any credentials and more than one can be provided later on
//! let nethsm = NetHsm::new(
//!     Connection::new(
//!         "https://example.org/api/v1".try_into()?,
//!         ConnectionSecurity::Unsafe,
//!     ),
//!     None,
//!     None,
//!     None,
//! )?;
//!
//! nethsm.add_credentials(Credentials::new("admin".parse()?, Some(Passphrase::new("passphrase".to_string()))));
//! nethsm.add_credentials(Credentials::new("user1".parse()?, Some(Passphrase::new("other_passphrase".to_string()))));
//!
//! // A set of credentials must be used before establishing a connection with the configured NetHSM
//! nethsm.use_credentials(&"user1".parse()?)?;
//! # Ok(())
//! # }
//! ```
//! [Nitrokey NetHSM]: https://docs.nitrokey.com/nethsm/
//! [user management]: https://docs.nitrokey.com/nethsm/administration#user-management
//! [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
//! [tags]: https://docs.nitrokey.com/nethsm/operation#tags-for-keys
//! [role]: https://docs.nitrokey.com/nethsm/administration#roles

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
