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
//! This crate re-exports the following [`nethsm_sdk_rs`] types, so that the crate does not have to
//! be relied upon directly:
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
//! use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
//!
//! # fn main() -> testresult::TestResult {
//! // Create a new connection to a NetHSM at "https://example.org" using admin credentials
//! let nethsm = NetHsm::new(
//!     "https://example.org/api/v1".try_into()?,
//!     ConnectionSecurity::Unsafe,
//!     Some(Credentials::new("admin".parse()?, Some(Passphrase::new("passphrase".to_string())))),
//!     None,
//!     None,
//! )?;
//!
//! // Connections can be initialized without any credentials and more than one can be provided later on
//! let nethsm = NetHsm::new(
//!     "https://example.org/api/v1".try_into()?,
//!     ConnectionSecurity::Unsafe,
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
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use log::{debug, error, info};
use md5::Md5;
use nethsm_sdk_rs::apis::configuration::Configuration;
use nethsm_sdk_rs::apis::default_api::{
    config_backup_passphrase_put,
    config_logging_get,
    config_logging_put,
    config_network_get,
    config_network_put,
    config_time_get,
    config_time_put,
    config_tls_cert_pem_get,
    config_tls_cert_pem_put,
    config_tls_csr_pem_post,
    config_tls_generate_post,
    config_tls_public_pem_get,
    config_unattended_boot_get,
    config_unattended_boot_put,
    config_unlock_passphrase_put,
    health_alive_get,
    health_ready_get,
    health_state_get,
    info_get,
    keys_generate_post,
    keys_get,
    keys_key_id_cert_delete,
    keys_key_id_cert_get,
    keys_key_id_cert_put,
    keys_key_id_csr_pem_post,
    keys_key_id_decrypt_post,
    keys_key_id_delete,
    keys_key_id_encrypt_post,
    keys_key_id_get,
    keys_key_id_public_pem_get,
    keys_key_id_put,
    keys_key_id_restrictions_tags_tag_delete,
    keys_key_id_restrictions_tags_tag_put,
    keys_key_id_sign_post,
    keys_post,
    lock_post,
    metrics_get,
    namespaces_get,
    namespaces_namespace_id_delete,
    namespaces_namespace_id_put,
    provision_post,
    random_post,
    system_backup_post,
    system_cancel_update_post,
    system_commit_update_post,
    system_factory_reset_post,
    system_info_get,
    system_reboot_post,
    system_restore_post,
    system_shutdown_post,
    system_update_post,
    unlock_post,
    users_get,
    users_post,
    users_user_id_delete,
    users_user_id_get,
    users_user_id_passphrase_post,
    users_user_id_put,
    users_user_id_tags_get,
    users_user_id_tags_tag_delete,
    users_user_id_tags_tag_put,
    KeysPostBody,
};
use nethsm_sdk_rs::models::{
    BackupPassphraseConfig,
    DecryptRequestData,
    EncryptRequestData,
    KeyGenerateRequestData,
    KeyRestrictions,
    PrivateKey,
    ProvisionRequestData,
    RandomRequestData,
    SignRequestData,
    TimeConfig,
    TlsKeyGenerateRequestData,
    UnlockPassphraseConfig,
    UnlockRequestData,
    UserPassphrasePostData,
    UserPostData,
};
// Re-export some useful types so that users do not have to use nethsm-sdk-rs directly
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
use nethsm_sdk_rs::ureq::{Agent, AgentBuilder};
use rustls::client::ClientConfig;
use rustls::crypto::{ring as tls_provider, CryptoProvider};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};

mod key;
pub use key::{key_type_matches_mechanisms, PrivateKeyImport};

mod nethsm_sdk;
use nethsm_sdk::NetHsmApiError;
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
mod openpgp;
pub use openpgp::extract_certificate as extract_openpgp_certificate;
pub use openpgp::tsk_to_private_key_import;
pub use openpgp::KeyUsageFlags as OpenPgpKeyUsageFlags;

mod tls;
pub use tls::{ConnectionSecurity, HostCertificateFingerprints};
use tls::{DangerIgnoreVerifier, FingerprintVerifier};

mod user;
pub use user::Error as UserError;
use user::NamespaceSupport;
pub use user::{Credentials, NamespaceId, Passphrase, UserId};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Wraps a [`rustls::Error`] for issues with rustls based TLS setups
    #[error("TLS error: {0}")]
    Rustls(#[from] rustls::Error),

    /// A Base64 encoded string can not be decode
    #[error("Decoding Base64 string failed: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// A generic error with a custom message
    #[error("NetHSM error: {0}")]
    Default(String),

    /// The loading of TLS root certificates from the platform's native certificate store failed
    #[error("Loading system TLS certs failed: {0:?}")]
    CertLoading(Vec<rustls_native_certs::Error>),

    /// No TLS root certificates from the platform's native certificate store could be added
    ///
    /// Provides the number certificates that failed to be added
    #[error("Unable to load any system TLS certs ({failed} failed)")]
    NoSystemCertsAdded { failed: usize },

    /// A call to the NetHSM API failed
    #[error("NetHSM API error: {0}")]
    Api(String),

    /// An error with a key occurred
    #[error("Key error: {0}")]
    Key(#[from] key::Error),

    /// URL is invalid
    #[error("URL invalid: {0}")]
    Url(String),

    /// User data error
    #[error("User data error: {0}")]
    User(#[from] user::Error),

    /// OpenPGP error
    #[error("OpenPGP error: {0}")]
    OpenPgp(#[from] openpgp::Error),
}

/// The URL used for connecting to a NetHSM instance.
///
/// Wraps [`url::Url`] but offers stricter constraints. The URL
///
/// * must use https
/// * must have a host
/// * must not contain a password, user or query
#[derive(Clone, Debug, Serialize)]
pub struct Url(url::Url);

impl Url {
    /// Creates a new Url.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::Url;
    ///
    /// Url::new("https://example.org/api/v1").is_ok();
    /// Url::new("https://127.0.0.1:8443/api/v1").is_ok();
    ///
    /// // errors when not using https
    /// Url::new("http://example.org/api/v1").is_err();
    ///
    /// // errors when using query, user or password
    /// Url::new("https://example.org/api/v1?something").is_err();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// * https is not used
    /// * a host is not defined
    /// * the URL contains a password, user or query
    pub fn new(url: &str) -> Result<Self, Error> {
        let url = url::Url::parse(url).map_err(|error| Error::Url(error.to_string()))?;
        if !url.scheme().eq("https") {
            Err(Error::Url("Must use https".to_string()))
        } else if !url.has_host() {
            Err(Error::Url("Must have a host".to_string()))
        } else if url.password().is_some() {
            Err(Error::Url("Must not contain password".to_string()))
        } else if !url.username().is_empty() {
            Err(Error::Url("Must not contain user".to_string()))
        } else if url.query().is_some() {
            Err(Error::Url("Must not contain query".to_string()))
        } else {
            Ok(Self(url))
        }
    }
}

impl<'de> Deserialize<'de> for Url {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Unexpected, Visitor};

        struct UrlVisitor;

        impl<'de> Visitor<'de> for UrlVisitor {
            type Value = Url;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a string representing an URL")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                Url::new(s).map_err(|err| {
                    let err_s = format!("{}", err);
                    Error::invalid_value(Unexpected::Str(s), &err_s.as_str())
                })
            }
        }

        deserializer.deserialize_str(UrlVisitor)
    }
}

impl Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&str> for Url {
    type Error = Error;
    fn try_from(value: &str) -> Result<Self, Error> {
        Self::new(value)
    }
}

impl TryFrom<String> for Url {
    type Error = Error;
    fn try_from(value: String) -> Result<Self, Error> {
        Self::new(&value)
    }
}

impl FromStr for Url {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

/// A network connection to a NetHSM.
///
/// Defines a network configuration for the connection and a list of user [`Credentials`] that can
/// be used over this connection.
pub struct NetHsm {
    /// The agent for the requests
    agent: RefCell<Agent>,
    /// The URL path for the target API
    url: RefCell<Url>,
    /// The default [`Credentials`] to use for requests
    current_credentials: RefCell<Option<UserId>>,
    /// The list of all available credentials
    credentials: RefCell<HashMap<UserId, Credentials>>,
}

impl NetHsm {
    /// Creates a new NetHSM connection.
    ///
    /// Creates a new NetHSM connection based on the `url` of the API and a chosen
    /// `connection_security` for TLS (see [`ConnectionSecurity`]).
    ///
    /// Optionally initial `credentials` (used when communicating with the NetHSM),
    /// `max_idle_connections` to set the size of the connection pool (defaults to `100`) and
    /// `timeout_seconds` to set the timeout for a successful socket connection (defaults to `10`)
    /// can be provided.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the rustls based [`ClientConfig`] can not be created.
    pub fn new(
        url: Url,
        connection_security: ConnectionSecurity,
        credentials: Option<Credentials>,
        max_idle_connections: Option<usize>,
        timeout_seconds: Option<u64>,
    ) -> Result<Self, Error> {
        let tls_conf = {
            let tls_conf = ClientConfig::builder_with_provider(Arc::new(CryptoProvider {
                cipher_suites: tls_provider::ALL_CIPHER_SUITES.into(),
                ..tls_provider::default_provider()
            }))
            .with_protocol_versions(rustls::DEFAULT_VERSIONS)?;

            match connection_security {
                ConnectionSecurity::Unsafe => {
                    let dangerous = tls_conf.dangerous();
                    dangerous
                        .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier(
                            tls_provider::default_provider(),
                        )))
                        .with_no_client_auth()
                }
                ConnectionSecurity::Native => {
                    let native_certs = rustls_native_certs::load_native_certs();
                    if !native_certs.errors.is_empty() {
                        return Err(Error::CertLoading(native_certs.errors));
                    }
                    let native_certs = native_certs.certs;

                    let roots = {
                        let mut roots = rustls::RootCertStore::empty();
                        let (added, failed) = roots.add_parsable_certificates(native_certs);
                        debug!(
                            "Added {added} certificates and failed to parse {failed} certificates"
                        );
                        if added == 0 {
                            error!("Added no native certificates");
                            return Err(Error::NoSystemCertsAdded { failed });
                        }
                        roots
                    };

                    tls_conf.with_root_certificates(roots).with_no_client_auth()
                }
                ConnectionSecurity::Fingerprints(fingerprints) => {
                    let dangerous = tls_conf.dangerous();
                    dangerous
                        .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
                            fingerprints,
                            provider: tls_provider::default_provider(),
                        }))
                        .with_no_client_auth()
                }
            }
        };

        let agent = {
            let max_idle_connections = max_idle_connections
                .or_else(|| available_parallelism().ok().map(Into::into))
                .unwrap_or(100);
            let timeout_seconds = timeout_seconds.unwrap_or(10);
            info!(
                "NetHSM connection configured with \"max_idle_connection\" {} and \"timeout_seconds\" {}.",
                max_idle_connections, timeout_seconds
            );

            RefCell::new(
                AgentBuilder::new()
                    .tls_config(Arc::new(tls_conf))
                    .max_idle_connections(max_idle_connections)
                    .max_idle_connections_per_host(max_idle_connections)
                    .timeout_connect(Duration::from_secs(timeout_seconds))
                    .build(),
            )
        };

        let (current_credentials, credentials) = if let Some(credentials) = credentials {
            (
                RefCell::new(Some(credentials.user_id.clone())),
                RefCell::new(HashMap::from([(credentials.user_id.clone(), credentials)])),
            )
        } else {
            (Default::default(), Default::default())
        };

        Ok(Self {
            agent,
            url: RefCell::new(url),
            current_credentials,
            credentials,
        })
    }

    /// Validates the potential [namespace] access of a context.
    ///
    /// Validates, that [`current_credentials`][`NetHsm::current_credentials`] can be used in a
    /// defined context. This function relies on [`UserId::validate_namespace_access`] and should be
    /// used for validating the context of [`NetHsm`] methods.
    ///
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    fn validate_namespace_access(
        &self,
        support: NamespaceSupport,
        target: Option<&UserId>,
        role: Option<&UserRole>,
    ) -> Result<(), Error> {
        if let Some(current_user_id) = self.current_credentials.borrow().to_owned() {
            current_user_id.validate_namespace_access(support, target, role)?
        }
        Ok(())
    }

    /// Creates a connection configuration.
    ///
    /// Uses the [`Agent`] configured during creation of the [`NetHsm`], the current [`Url`] and
    /// [`Credentials`] to create a [`Configuration`] for a connection to the API of a NetHSM.
    fn create_connection_config(&self) -> Configuration {
        let current_credentials = self.current_credentials.borrow().to_owned();
        Configuration {
            client: self.agent.borrow().to_owned(),
            base_path: self.url.borrow().to_string(),
            basic_auth: if let Some(current_credentials) = current_credentials {
                self.credentials
                    .borrow()
                    .get(&current_credentials)
                    .map(Into::into)
            } else {
                None
            },
            user_agent: Some(format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )),
            ..Default::default()
        }
    }

    /// Sets the URL for the NetHSM connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{ConnectionSecurity, NetHsm, Url};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // Create a new connection for a NetHSM at "https://example.org"
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // change the url to something else
    /// nethsm.set_url(Url::new("https://other.org/api/v1")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_url(&self, url: Url) {
        *self.url.borrow_mut() = url;
    }

    /// Adds [`Credentials`] to the list of available ones.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add credentials
    /// nethsm.add_credentials(Credentials::new(
    ///     "admin".parse()?,
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// ));
    /// nethsm.add_credentials(Credentials::new(
    ///     "user1".parse()?,
    ///     Some(Passphrase::new("other_passphrase".to_string())),
    /// ));
    /// nethsm.add_credentials(Credentials::new("user2".parse()?, None));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_credentials(&self, credentials: Credentials) {
        // remove any previously existing credentials (User IDs are unique)
        self.remove_credentials(&credentials.user_id);
        self.credentials
            .borrow_mut()
            .insert(credentials.user_id.clone(), credentials);
    }

    /// Removes [`Credentials`] from the list of available and currently used ones.
    ///
    /// Removes [`Credentials`] from the list of available ones and if identical unsets the
    /// ones used for further authentication as well.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // remove credentials
    /// nethsm.remove_credentials(&"admin".parse()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_credentials(&self, user_id: &UserId) {
        self.credentials.borrow_mut().remove(user_id);
        if self
            .current_credentials
            .borrow()
            .as_ref()
            .is_some_and(|id| id == user_id)
        {
            *self.current_credentials.borrow_mut() = None
        }
    }

    /// Sets [`Credentials`] to use for the next connection.
    ///
    /// # Errors
    ///
    /// An [`Error`] is returned if no [`Credentials`] with the [`UserId`] `user_id` can be found.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add credentials
    /// nethsm.add_credentials(Credentials::new(
    ///     "admin".parse()?,
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// ));
    /// nethsm.add_credentials(Credentials::new(
    ///     "user1".parse()?,
    ///     Some(Passphrase::new("other_passphrase".to_string())),
    /// ));
    ///
    /// // use admin credentials
    /// nethsm.use_credentials(&"admin".parse()?)?;
    ///
    /// // use operator credentials
    /// nethsm.use_credentials(&"user1".parse()?)?;
    ///
    /// // this fails, because the user has not been added yet
    /// assert!(nethsm.use_credentials(&"user2".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn use_credentials(&self, user_id: &UserId) -> Result<(), Error> {
        if self.credentials.borrow().contains_key(user_id) {
            if self.current_credentials.borrow().as_ref().is_none()
                || self
                    .current_credentials
                    .borrow()
                    .as_ref()
                    .is_some_and(|id| id != user_id)
            {
                *self.current_credentials.borrow_mut() = Some(user_id.to_owned());
            }
        } else {
            return Err(Error::Default(format!(
                "The credentials for User ID \"{}\" need to be added before they can be used!",
                user_id
            )));
        }
        Ok(())
    }

    /// Provisions a NetHSM.
    ///
    /// [Provisioning] is the initial setup step for a NetHSM.
    /// It sets the `unlock_passphrase`, which is used to [`unlock`][`NetHsm::unlock`] a device in
    /// [`Locked`][`SystemState::Locked`] [state], the initial `admin_passphrase` for the
    /// default [`Administrator`][`UserRole::Administrator`] account ("admin") and the
    /// `system_time`. The unlock passphrase can later on be changed using
    /// [`set_unlock_passphrase`][`NetHsm::set_unlock_passphrase`] and the admin passphrase using
    /// [`set_user_passphrase`][`NetHsm::set_user_passphrase`].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if provisioning fails:
    /// * the NetHSM is not in [`Unprovisioned`][`SystemState::Unprovisioned`] [state]
    /// * the provided data is malformed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::Utc;
    /// use nethsm::{ConnectionSecurity, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // provision the NetHSM
    /// nethsm.provision(
    ///     Passphrase::new("unlock-the-device".to_string()),
    ///     Passphrase::new("admin-passphrase".to_string()),
    ///     Utc::now(),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Provisioning]: https://docs.nitrokey.com/nethsm/getting-started#provisioning
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn provision(
        &self,
        unlock_passphrase: Passphrase,
        admin_passphrase: Passphrase,
        system_time: DateTime<Utc>,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        provision_post(
            &self.create_connection_config(),
            ProvisionRequestData::new(
                unlock_passphrase.expose_owned(),
                admin_passphrase.expose_owned(),
                system_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Provisioning failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns whether the NetHSM is in [`Unprovisioned`][`SystemState::Unprovisioned`] or
    /// [`Locked`][`SystemState::Locked`] [state].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the information can not be retrieved or the NetHSM is in
    /// [`Operational`][`SystemState::Operational`] [state].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // check whether the NetHSM is locked or unprovisioned
    /// assert!(nethsm.alive().is_ok());
    /// # Ok(())
    /// # }
    /// ```
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn alive(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        health_alive_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving alive status failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns whether the NetHSM is in [`Operational`][`SystemState::Operational`] [state].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the information can not be retrieved or the NetHSM is in
    /// [`Unprovisioned`][`SystemState::Unprovisioned`] or [`Locked`][`SystemState::Locked`]
    /// [state].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // check whether the NetHSM is operational
    /// assert!(nethsm.ready().is_ok());
    /// # Ok(())
    /// # }
    /// ```
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn ready(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        health_ready_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving ready status failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns the system [state] of the NetHSM.
    ///
    /// Returns a variant of [`SystemState`], which describes the [state] a NetHSM is currently in.
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the [state] information can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the state
    /// println!("{:?}", nethsm.state()?);
    /// # Ok(())
    /// # }
    /// ```
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn state(&self) -> Result<SystemState, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let health_state = health_state_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving state failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(health_state.entity.state)
    }

    /// Returns [device information] for the NetHSM.
    ///
    /// Returns an [`InfoData`], which provides the [device information].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM [device information] can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the NetHSM info
    /// println!("{:?}", nethsm.info()?);
    /// # Ok(())
    /// # }
    /// ```
    /// [device information]: https://docs.nitrokey.com/nethsm/administration#device-information
    pub fn info(&self) -> Result<InfoData, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let info = info_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving device information failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(info.entity)
    }

    /// Returns metrics for the NetHSM.
    ///
    /// Returns a [`Value`][`serde_json::Value`] which provides [metrics] for the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a user in the [`Metrics`][`UserRole::Metrics`]
    /// [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM [metrics] can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Metrics`][`UserRole::Metrics`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Metrics role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "metrics".parse()?,
    ///         Some(Passphrase::new("metrics-passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the metrics
    /// println!("{:?}", nethsm.metrics()?);
    /// # Ok(())
    /// # }
    /// ```
    /// [metrics]: https://docs.nitrokey.com/nethsm/administration#metrics
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn metrics(&self) -> Result<Value, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let metrics = metrics_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving metrics failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(metrics.entity)
    }

    /// Sets the [unlock passphrase].
    ///
    /// Changes the [unlock passphrase] from `current_passphrase` to `new_passphrase`.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the [unlock passphrase] can not be changed:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `current_passphrase` is not correct
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the unlock passphrase
    /// nethsm.set_unlock_passphrase(
    ///     Passphrase::new("current-unlock-passphrase".to_string()),
    ///     Passphrase::new("new-unlock-passphrase".to_string()),
    /// )?;
    ///
    /// // N-Administrators can not set the unlock passphrase
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm
    ///     .set_unlock_passphrase(
    ///         Passphrase::new("current-unlock-passphrase".to_string()),
    ///         Passphrase::new("new-unlock-passphrase".to_string()),
    ///     )
    ///     .is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [unlock passphrase]: https://docs.nitrokey.com/nethsm/administration#unlock-passphrase
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_unlock_passphrase(
        &self,
        current_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_unlock_passphrase_put(
            &self.create_connection_config(),
            UnlockPassphraseConfig::new(
                new_passphrase.expose_owned(),
                current_passphrase.expose_owned(),
            ),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Changing unlock passphrase failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns the [boot mode].
    ///
    /// Returns a variant of [`BootMode`] which represents the NetHSM's [boot mode].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the boot mode can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can retrieve the boot mode
    /// println!("{:?}", nethsm.get_boot_mode()?);
    ///
    /// // N-Administrators can not retrieve the boot mode
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_boot_mode().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [boot mode]: https://docs.nitrokey.com/nethsm/administration#boot-mode
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_boot_mode(&self) -> Result<BootMode, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(BootMode::from(
            config_unattended_boot_get(&self.create_connection_config())
                .map_err(|error| {
                    Error::Api(format!(
                        "Retrieving boot mode failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        ))
    }

    /// Sets the [boot mode].
    ///
    /// Sets the NetHSM's [boot mode] based on a [`BootMode`] variant.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the boot mode can not be set:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{BootMode, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the boot mode
    /// // set the boot mode to unattended
    /// nethsm.set_boot_mode(BootMode::Unattended)?;
    /// // set the boot mode to attended
    /// nethsm.set_boot_mode(BootMode::Attended)?;
    ///
    /// // N-Administrators can not set the boot mode
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_boot_mode(BootMode::Attended).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [boot mode]: https://docs.nitrokey.com/nethsm/administration#boot-mode
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_boot_mode(&self, boot_mode: BootMode) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_unattended_boot_put(&self.create_connection_config(), boot_mode.into()).map_err(
            |error| {
                Error::Api(format!(
                    "Setting boot mode failed: {}",
                    NetHsmApiError::from(error)
                ))
            },
        )?;
        Ok(())
    }

    /// Returns the TLS public key of the API.
    ///
    /// Returns the NetHSM's public key part of its [TLS certificate] which is used for
    /// communication with the API.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM's TLS public key can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the TLS public key
    /// println!("{}", nethsm.get_tls_public_key()?);
    ///
    /// // N-Administrators can not get the TLS public key
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_tls_public_key().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_tls_public_key(&self) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_tls_public_pem_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Retrieving API TLS public key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Returns the TLS certificate of the API.
    ///
    /// Returns the NetHSM's [TLS certificate] which is used for communication with the API.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM's TLS certificate can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the TLS certificate
    /// println!("{}", nethsm.get_tls_cert()?);
    ///
    /// // N-Administrators can not get the TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_tls_cert().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_tls_cert(&self) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_tls_cert_pem_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Retrieving API TLS certificate failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Returns a Certificate Signing Request ([CSR]) for the API's [TLS certificate].
    ///
    /// Based on [`DistinguishedName`] data returns a [CSR] in [PKCS#10] format for the NetHSM's
    /// [TLS certificate].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the [CSR] can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     DistinguishedName,
    ///     NetHsm,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get a CSR for the TLS certificate
    /// println!(
    ///     "{}",
    ///     nethsm.get_tls_csr(DistinguishedName {
    ///         country_name: Some("DE".to_string()),
    ///         state_or_province_name: Some("Berlin".to_string()),
    ///         locality_name: Some("Berlin".to_string()),
    ///         organization_name: Some("Foobar Inc".to_string()),
    ///         organizational_unit_name: Some("Department of Foo".to_string()),
    ///         common_name: "Foobar Inc".to_string(),
    ///         email_address: Some("foobar@mcfooface.com".to_string()),
    ///     })?
    /// );
    ///
    /// // N-Administrators can not get a CSR for the TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm
    ///     .get_tls_csr(DistinguishedName {
    ///         country_name: Some("DE".to_string()),
    ///         state_or_province_name: Some("Berlin".to_string()),
    ///         locality_name: Some("Berlin".to_string()),
    ///         organization_name: Some("Foobar Inc".to_string()),
    ///         organizational_unit_name: Some("Department of Foo".to_string()),
    ///         common_name: "Foobar Inc".to_string(),
    ///         email_address: Some("foobar@mcfooface.com".to_string()),
    ///     })
    ///     .is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
    /// [PKCS#10]: https://en.wikipedia.org/wiki/Certificate_signing_request#Structure_of_a_PKCS_#10_CSR
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_tls_csr(&self, distinguished_name: DistinguishedName) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(
            config_tls_csr_pem_post(&self.create_connection_config(), distinguished_name)
                .map_err(|error| {
                    Error::Api(format!(
                        "Retrieving CSR for TLS certificate failed: {}",
                        NetHsmApiError::from(error),
                    ))
                })?
                .entity,
        )
    }

    /// Generates a new [TLS certificate] for the API.
    ///
    /// Generates a new [TLS certificate] (used for communication with the API) based on
    /// `tls_key_type` and `length`.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the new [TLS certificate] can not be generated:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the `tls_key_type` and `length` combination is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, TlsKeyType, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can generate a new TLS certificate
    /// nethsm.generate_tls_cert(TlsKeyType::Rsa, Some(4096))?;
    ///
    /// // N-Administrators can not generate a new TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm
    ///     .generate_tls_cert(TlsKeyType::Rsa, Some(4096))
    ///     .is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn generate_tls_cert(
        &self,
        tls_key_type: TlsKeyType,
        length: Option<u32>,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_tls_generate_post(
            &self.create_connection_config(),
            TlsKeyGenerateRequestData {
                r#type: tls_key_type.into(),
                length: length.map(|length| length as i32),
            },
        )
        .map_err(|error| {
            Error::Api(format!(
                "Generating API TLS certificate failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Sets a new [TLS certificate] for the API.
    ///
    /// Accepts a Base64 encoded [DER] certificate provided using `certificate` which is added as
    /// new [TLS certificate] for communication with the API.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting a new TLS certificate fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `certificate` is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// let cert = r#"-----BEGIN CERTIFICATE-----
    /// MIIBHjCBxKADAgECAghDngCv6xWIXDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlr
    /// ZXlmZW5kZXIwIBcNNzAwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMBQxEjAQ
    /// BgNVBAMMCWtleWZlbmRlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJsHIrsZ
    /// 6fJzrk12GK7nW6bGyTIIZiQUq0uaKbn21dgPiDCO5+iYVXAqnWu4IMVZQnkFJmte
    /// PRUUuM3119f8ffkwCgYIKoZIzj0EAwIDSQAwRgIhALH4fDYJ21tRecXp9IipBlil
    /// p+hJCj77zBvFmGYy/UnPAiEA8csj7U6BfzvK4EiQyUZa7/as+nXwj3XHU/i8LyLm
    /// Chw=
    /// -----END CERTIFICATE-----"#;
    ///
    /// // R-Administrators can set a new TLS certificate
    /// nethsm.set_tls_cert(cert)?;
    ///
    /// // N-Administrators can not set a new TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_tls_cert(cert).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [DER]: https://en.wikipedia.org/wiki/X.690#DER_encoding
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_tls_cert(&self, certificate: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_tls_cert_pem_put(&self.create_connection_config(), certificate).map_err(
            |error| {
                Error::Api(format!(
                    "Setting API TLS certificate failed: {}",
                    NetHsmApiError::from(error)
                ))
            },
        )?;
        Ok(())
    }

    /// Gets the [network configuration].
    ///
    /// Retrieves the [network configuration] of the NetHSM as [`NetworkConfig`].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving network configuration fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the network configuration
    /// println!("{:?}", nethsm.get_network()?);
    ///
    /// // N-Administrators can not get the network configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_network().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [network configuration]: https://docs.nitrokey.com/nethsm/administration#network
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_network(&self) -> Result<NetworkConfig, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_network_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting network config failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Sets the [network configuration].
    ///
    /// Sets the [network configuration] of the NetHSM on the basis of a [`NetworkConfig`].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the network configuration fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `network_config` is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, NetworkConfig, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// let network_config = NetworkConfig::new(
    ///     "192.168.1.1".to_string(),
    ///     "255.255.255.0".to_string(),
    ///     "0.0.0.0".to_string(),
    /// );
    ///
    /// // R-Administrators can set the network configuration
    /// nethsm.set_network(network_config.clone())?;
    ///
    /// // N-Administrators can not set the network configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_network(network_config).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [network configuration]: https://docs.nitrokey.com/nethsm/administration#network
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_network(&self, network_config: NetworkConfig) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_network_put(&self.create_connection_config(), network_config).map_err(|error| {
            Error::Api(format!(
                "Setting network config failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets the current [time].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving [time] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the time
    /// println!("{:?}", nethsm.get_time()?);
    ///
    /// // N-Administrators can not get the time
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_time().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [time]: https://docs.nitrokey.com/nethsm/administration#time
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_time(&self) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_time_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting NetHSM system time failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .time)
    }

    /// Sets the current [time].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting [time] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `time` is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::Utc;
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the time
    /// nethsm.set_time(Utc::now())?;
    ///
    /// // N-Administrators can not set the time
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_time(Utc::now()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [time]: https://docs.nitrokey.com/nethsm/administration#time
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_time(&self, time: DateTime<Utc>) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_time_put(
            &self.create_connection_config(),
            TimeConfig::new(time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting NetHSM system time failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets the [logging configuration].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the [logging configuration] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get logging configuration
    /// println!("{:?}", nethsm.get_logging()?);
    ///
    /// // N-Administrators can not get logging configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_logging().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [logging configuration]: https://docs.nitrokey.com/nethsm/administration#logging
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_logging(&self) -> Result<LoggingConfig, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_logging_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting logging config failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Sets the [logging configuration].
    ///
    /// Sets the NetHSM's [logging configuration] by providing `ip_address` and `port` of a host to
    /// send logs to. The log level is configured using `log_level`.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the logging configuration fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `ip_address`, `port` or `log_level` are not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::Ipv4Addr;
    ///
    /// use nethsm::{ConnectionSecurity, Credentials, LogLevel, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set logging configuration
    /// nethsm.set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)?;
    ///
    /// // N-Administrators can not set logging configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm
    ///     .set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)
    ///     .is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [logging configuration]: https://docs.nitrokey.com/nethsm/administration#logging
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_logging(
        &self,
        ip_address: Ipv4Addr,
        port: u32,
        log_level: LogLevel,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        let ip_address = ip_address.to_string();
        config_logging_put(
            &self.create_connection_config(),
            LoggingConfig::new(ip_address, port as i32, log_level.into()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting logging config failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Sets the [backup] passphrase.
    ///
    /// Sets `current_passphrase` to `new_passphrase`, which changes the [backup] passphrase for the
    /// NetHSM.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the backup passphrase fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `current_passphrase` is not correct
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the backup passphrase
    /// nethsm.set_backup_passphrase(
    ///     Passphrase::new("current-backup-passphrase".to_string()),
    ///     Passphrase::new("new-backup-passphrase".to_string()),
    /// )?;
    ///
    /// // N-Administrators can not set logging configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm
    ///     .set_backup_passphrase(
    ///         Passphrase::new("new-backup-passphrase".to_string()),
    ///         Passphrase::new("current-backup-passphrase".to_string()),
    ///     )
    ///     .is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_backup_passphrase(
        &self,
        current_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_backup_passphrase_put(
            &self.create_connection_config(),
            BackupPassphraseConfig::new(
                new_passphrase.expose_owned(),
                current_passphrase.expose_owned(),
            ),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting backup passphrase failed: {}",
                NetHsmApiError::from(error),
            ))
        })?;
        Ok(())
    }

    /// Creates a [backup].
    ///
    /// Triggers the creation and download of a [backup] of the NetHSM.
    /// **NOTE**: Before creating the first [backup], the [backup] passphrase must be set using
    /// [`set_backup_passphrase`][`NetHsm::set_backup_passphrase`].
    ///
    /// This call requires using [`Credentials`] of a user in the [`Backup`][`UserRole::Backup`]
    /// [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating a [backup] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Backup`][`UserRole::Backup`]
    ///   [role]
    /// * the [backup] passphrase has not yet been set
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a user in the Backup role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "backup1".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // create a backup and write it to file
    /// std::fs::write("nethsm.bkp", nethsm.backup()?)?;
    /// # Ok(())
    /// # }
    /// ```
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn backup(&self) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(system_backup_post(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting backup failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Triggers a [factory reset].
    ///
    /// Triggers a [factory reset] of the NetHSM.
    /// **WARNING**: This action deletes all user and system data! Make sure to create a [backup]
    /// using [`backup`][`NetHsm::backup`] first!
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if resetting the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, SystemState, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not trigger factory reset
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.factory_reset().is_err());
    ///
    /// // R-Administrators are able to trigger a factory reset
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.factory_reset()?;
    /// assert_eq!(nethsm.state()?, SystemState::Unprovisioned);
    /// # Ok(())
    /// # }
    /// ```
    /// [factory reset]: https://docs.nitrokey.com/nethsm/administration#reset-to-factory-defaults
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn factory_reset(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_factory_reset_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Factory reset failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Restores NetHSM from [backup].
    ///
    /// [Restores] a NetHSM from a [backup], by providing a `backup_passphrase` (see
    /// [`set_backup_passphrase`][`NetHsm::set_backup_passphrase`]) a new `system_time` for the
    /// NetHSM and a backup file (created using [`backup`][`NetHsm::backup`]).
    ///
    /// The NetHSM must be in [`Operational`][`SystemState::Operational`] or
    /// [`Unprovisioned`][`SystemState::Unprovisioned`] [state].
    ///
    /// Any existing user data is safely removed and replaced by that of the [backup], after which
    /// the NetHSM ends up in [`Locked`][`SystemState::Locked`] [state].
    /// If the NetHSM is in [`Unprovisioned`][`SystemState::Unprovisioned`] [state], additionally
    /// the system configuration from the backup is applied and leads to a
    /// [`reboot`][`NetHsm::reboot`] of the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if restoring the NetHSM from [backup] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] or
    ///   [`Unprovisioned`][`SystemState::Unprovisioned`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::Utc;
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// #
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not restore from backup
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm
    ///     .restore(
    ///         Passphrase::new("backup-passphrase".to_string()),
    ///         Utc::now(),
    ///         std::fs::read("nethsm.bkp")?,
    ///     )
    ///     .is_err());
    ///
    /// // R-Administrators can restore from backup
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.restore(
    ///     Passphrase::new("backup-passphrase".to_string()),
    ///     Utc::now(),
    ///     std::fs::read("nethsm.bkp")?,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Restores]: https://docs.nitrokey.com/nethsm/administration#restore
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn restore(
        &self,
        backup_passphrase: Passphrase,
        system_time: DateTime<Utc>,
        backup: Vec<u8>,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_restore_post(
            &self.create_connection_config(),
            Some(nethsm_sdk_rs::models::RestoreRequestArguments {
                backup_passphrase: Some(backup_passphrase.expose_owned()),
                system_time: Some(system_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            }),
            Some(backup),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Restoring backup failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Locks the NetHSM.
    ///
    /// Locks the NetHSM and sets its [state] to [`Locked`][`SystemState::Locked`].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if locking the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, SystemState, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    ///
    /// // N-Administrators can not lock the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.lock().is_err());
    ///
    /// // R-Administrators can lock the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.lock()?;
    /// assert_eq!(nethsm.state()?, SystemState::Locked);
    /// # Ok(())
    /// # }
    /// ```
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn lock(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        lock_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Locking NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Unlocks the NetHSM.
    ///
    /// Unlocks the NetHSM if it is in [`Locked`][`SystemState::Locked`] [state] by providing
    /// `unlock_passphrase` and sets its [state] to [`Operational`][`SystemState::Operational`].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if unlocking the NetHSM fails:
    /// * the NetHSM is not in [`Locked`][`SystemState::Locked`] [state]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial [`Credentials`] are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Locked);
    /// // unlock the NetHSM
    /// nethsm.unlock(Passphrase::new("unlock-passphrase".to_string()))?;
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// # Ok(())
    /// # }
    /// ```
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn unlock(&self, unlock_passphrase: Passphrase) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        unlock_post(
            &self.create_connection_config(),
            UnlockRequestData::new(unlock_passphrase.expose_owned()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Unlocking NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Retrieves [system information].
    ///
    /// Returns [system information] in the form of a [`SystemInfo`], which contains various pieces
    /// of information such as software version, software build, firmware version, hardware
    /// version, device ID and information on TPM related components such as attestation key and
    /// relevant PCR values.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving the system information fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can retrieve system information
    /// println!("{:?}", nethsm.system_info()?);
    ///
    /// // N-Administrators can not retrieve system information
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.system_info().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [system information]: https://docs.nitrokey.com/nethsm/administration#system-information
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn system_info(&self) -> Result<SystemInfo, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(system_info_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Retrieving system information failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// [Reboots] the NetHSM.
    ///
    /// [Reboots] the NetHSM, if it is in [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if rebooting the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not reboot the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.reboot().is_err());
    ///
    /// // R-Administrators can reboot the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.reboot()?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Reboots]: https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn reboot(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_reboot_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Rebooting NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// [Shuts down] the NetHSM.
    ///
    /// [Shuts down] the NetHSM, if it is in [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if shutting down the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not shut down the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.shutdown().is_err());
    ///
    /// // R-Administrators can shut down the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.shutdown()?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Shuts down]: https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn shutdown(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_shutdown_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Shutting down NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Uploads a software update.
    ///
    /// WARNING: This function has shown flaky behavior during tests with the official container!
    /// Upload may have to be repeated!
    ///
    /// Uploads a [software update] to the NetHSM, if it is in
    /// [`Operational`][`SystemState::Operational`] [state] and returns information about the
    /// software update as [`SystemUpdateData`].
    /// Software updates can successively be installed ([`commit_update`][`NetHsm::commit_update`])
    /// or canceled ([`cancel_update`][`NetHsm::cancel_update`]).
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if uploading the software update fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not upload software updates to the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.upload_update(std::fs::read("update.bin")?).is_err());
    ///
    /// // R-Administrators can upload software updates to the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// println!("{:?}", nethsm.upload_update(std::fs::read("update.bin")?)?);
    /// # Ok(())
    /// # }
    /// ```
    /// [software update]: https://docs.nitrokey.com/nethsm/administration#software-update
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn upload_update(&self, update: Vec<u8>) -> Result<SystemUpdateData, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(system_update_post(&self.create_connection_config(), update)
            .map_err(|error| {
                println!("error during upload");
                Error::Api(format!(
                    "Uploading update failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Commits an already uploaded [software update].
    ///
    /// Commits a [software update] previously uploaded to the NetHSM (using
    /// [`upload_update`][`NetHsm::upload_update`]), if the NetHSM is in
    /// [`Operational`][`SystemState::Operational`] [state].
    /// Successfully committing a [software update] leads to the [reboot] of the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if committing the software update fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * there is no software update to commit
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// println!("{:?}", nethsm.upload_update(std::fs::read("update.bin")?)?);
    ///
    /// // N-Administrators can not commit software updates on a NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.commit_update().is_err());
    ///
    /// // R-Administrators can commit software updates on a NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.commit_update()?;
    /// # Ok(())
    /// # }
    /// ```
    /// [software update]: https://docs.nitrokey.com/nethsm/administration#software-update
    /// [reboot]: https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn commit_update(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_commit_update_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Committing update failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Cancels an already uploaded [software update].
    ///
    /// Cancels a [software update] previously uploaded to the NetHSM (using
    /// [`upload_update`][`NetHsm::upload_update`]), if the NetHSM is in
    /// [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if canceling the software update fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * there is no software update to cancel
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, SystemState, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// println!("{:?}", nethsm.upload_update(std::fs::read("update.bin")?)?);
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    ///
    /// // N-Administrators can not cancel software updates on a NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.cancel_update().is_err());
    ///
    /// // R-Administrators can cancel software updates on a NetHSM
    /// nethsm.cancel_update()?;
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// # Ok(())
    /// # }
    /// ```
    /// [software update]: https://docs.nitrokey.com/nethsm/administration#software-update
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn cancel_update(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_cancel_update_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Cancelling update failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Adds a new namespace.
    ///
    /// Adds a new [namespace] with the ID `namespace_id`.
    ///
    /// **WARNING**: A user in the [`Administrator`][`UserRole::Administrator`] [role] must be added
    /// for the [namespace] using [`add_user`][`NetHsm::add_user`] **before** creating the
    /// [namespace]! Otherwise there is no user to administrate the new [namespace]!
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the namespace fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the namespace identified by `namespace_id` exists already
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrator can not create namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.add_namespace(&"namespace2".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_namespace(&self, namespace_id: &NamespaceId) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        namespaces_namespace_id_put(&self.create_connection_config(), &namespace_id.to_string())
            .map_err(|error| {
                Error::Api(format!(
                    "Adding namespace failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// Gets all available [namespaces].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the namespaces fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // print list of all namespaces
    /// println!("{:?}", nethsm.get_namespaces()?);
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrator can not get namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_namespaces().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [namespaces]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_namespaces(&self) -> Result<Vec<String>, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(namespaces_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting namespaces failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .iter()
            .map(|x| &x.id)
            .cloned()
            .collect())
    }

    /// Deletes an existing [namespace].
    ///
    /// Deletes the [namespace] identified by `namespace_id`.
    ///
    /// **WARNING**: This call deletes the [namespace] and all keys in it! Make sure to create a
    /// [`backup`][`NetHsm::backup`]!
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the namespace fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the [namespace] identified by `namespace_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not delete namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.delete_namespace(&"namespace1".parse()?).is_err());
    ///
    /// // R-Administrators can delete namespaces
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.delete_namespace(&"namespace1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_namespace(&self, namespace_id: &NamespaceId) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        namespaces_namespace_id_delete(&self.create_connection_config(), &namespace_id.to_string())
            .map_err(|error| {
                Error::Api(format!(
                    "Deleting namespace failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// [Adds a user] and returns its User ID.
    ///
    /// A new user is created by providing a `real_name` from which a User ID is derived (optionally
    /// a User ID can be provided with `user_id`), a `role` which describes the user's access rights
    /// on the NetHSM (see [`UserRole`]) and a `passphrase`.
    ///
    /// Internally, this function also calls [`add_credentials`][`NetHsm::add_credentials`] to
    /// add the new user to the list of available credentials.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    /// When adding a user to a [namespace], that does not yet exist, the caller must
    /// be a system-wide [`Administrator`][`UserRole::Administrator`] (*R-Administrator*).
    /// When adding a user to an already existing [namespace], the caller must be an
    /// [`Administrator`][`UserRole::Administrator`] in that [namespace]
    /// (*N-Administrator*).
    ///
    /// ## Namespaces
    ///
    /// New users *implicitly* inherit the [namespace] of the caller.
    /// A [namespace] can be provided *explicitly* by prefixing the User ID with the ID of a
    /// [namespace] and the `~` character (e.g. `namespace1~user1`).
    /// When specifying a namespace as part of the User ID and the [namespace] exists already, the
    /// caller must be an [`Administrator`][`UserRole::Administrator`] of that [namespace]
    /// (*N-Administrator*).
    /// When specifying a [namespace] as part of the User ID and the [namespace] does not yet exist,
    /// the caller must be a system-wide [`Administrator`][`UserRole::Administrator`]
    /// (*R-Administrator*).
    ///
    /// **NOTE**: Users in the [`Backup`][`UserRole::Backup`] and [`Metrics`][`UserRole::Metrics`]
    /// [role] can not be created for a [namespace], as their underlying functionality can only be
    /// used in a system-wide context!
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `real_name`, `passphrase` or `user_id` are not valid
    /// * the provided `user_id` exists already
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide
    ///   [`Administrator`][`UserRole::Administrator`], when adding a user to a not yet existing
    ///   [namespace]
    /// * the used [`Credentials`] are not that of an [`Administrator`][`UserRole::Administrator`]
    ///   in the [namespace] the user is about to be added to
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    ///
    /// // this fails because the user exists already
    /// assert!(nethsm
    ///     .add_user(
    ///         "Operator One".to_string(),
    ///         UserRole::Operator,
    ///         Passphrase::new("operator1-passphrase".to_string()),
    ///         Some("user1".parse()?),
    ///     )
    ///     .is_err());
    ///
    /// // add a user in the Administrator role (N-Administrator) for a not yet existing namespace "namespace1"
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    /// [Adds a user]: https://docs.nitrokey.com/nethsm/administration#add-user
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_user(
        &self,
        real_name: String,
        role: UserRole,
        passphrase: Passphrase,
        user_id: Option<UserId>,
    ) -> Result<UserId, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, user_id.as_ref(), Some(&role))?;
        let user_id = if let Some(user_id) = user_id {
            users_user_id_put(
                &self.create_connection_config(),
                &user_id.to_string(),
                UserPostData::new(real_name, role.into(), passphrase.expose_owned()),
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Adding user failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
            user_id
        } else {
            UserId::new(
                users_post(
                    &self.create_connection_config(),
                    UserPostData::new(real_name, role.into(), passphrase.expose_owned()),
                )
                .map_err(|error| {
                    Error::Api(format!(
                        "Adding user failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity
                .id,
            )?
        };

        // add to list of users
        self.add_credentials(Credentials::new(user_id.clone(), Some(passphrase)));

        Ok(user_id)
    }

    /// Deletes an existing user.
    ///
    /// [Deletes a user] identified by `user_id`.
    ///
    /// Internally, this function also calls [`remove_credentials`][`NetHsm::remove_credentials`] to
    /// remove the user from the list of available credentials.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) can only delete users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) can
    ///   only delete system-wide users, but not those in a [namespace]. To allow *R-Administrators*
    ///   to delete users in a [namespace], the given [namespace] has to be deleted first using
    ///   [`delete_namespace`][`NetHsm::delete_namespace`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting a user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] role
    /// * the targeted user is in an existing [namespace], but the caller is an *R-Administrator* or
    ///   an *N-Administrator* in a different [namespace]
    /// * the targeted user is a system-wide user, but the caller is not an *R-Administrator*
    /// * the user attempts to delete itself
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can not delete N-Administrators, as long as their namespace exists
    /// assert!(nethsm.delete_user(&"namespace1~admin1".parse()?).is_err());
    /// // however, after deleting the namespace, this becomes possible
    /// nethsm.delete_namespace(&"namespace1".parse()?)?;
    /// nethsm.delete_user(&"namespace1~admin1".parse()?)?;
    ///
    /// // R-Administrators can delete system-wide users
    /// nethsm.delete_user(&"user1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Deletes a user]: https://docs.nitrokey.com/nethsm/administration#delete-user
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_user(&self, user_id: &UserId) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        users_user_id_delete(&self.create_connection_config(), &user_id.to_string()).map_err(
            |error| {
                Error::Api(format!(
                    "Deleting user failed: {}",
                    NetHsmApiError::from(error)
                ))
            },
        )?;

        // remove from list of credentials
        self.remove_credentials(user_id);

        Ok(())
    }

    /// Gets a [list of all User IDs].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) can only list users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) can
    ///   list all users on the system.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving the list of all User IDs fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// // the N-Administrator only sees itself
    /// assert_eq!(nethsm.get_users()?.len(), 1);
    ///
    /// // use the credentials of the R-Administrator
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// // the R-Administrator sees at least itself and the previously created N-Administrator
    /// assert!(nethsm.get_users()?.len() >= 2);
    /// # Ok(())
    /// # }
    /// ```
    /// [list of all User IDs]: https://docs.nitrokey.com/nethsm/administration#list-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_users(&self) -> Result<Vec<String>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        Ok(users_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting users failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .iter()
            .map(|x| x.user.clone())
            .collect())
    }

    /// Gets [information of a user].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) can only access information about users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) can
    ///   access information about all users on the system.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving information of the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] role
    /// * the used [`Credentials`] do not provide access to information about a user in the targeted
    ///   [namespace] (*N-Administrator* of a different [namespace])
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// // the N-Administrator sees itself
    /// println!("{:?}", nethsm.get_user(&"namespace1~admin1".parse()?)?);
    /// // the N-Administrator can not see the R-Administrator
    /// assert!(nethsm.get_user(&"admin".parse()?).is_err());
    ///
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// // the R-Administrator sees itself
    /// println!("{:?}", nethsm.get_user(&"admin".parse()?)?);
    /// // the R-Administrator sees the N-Administrator
    /// println!("{:?}", nethsm.get_user(&"namespace1~admin1".parse()?)?);
    /// // this fails if the user does not exist
    /// assert!(nethsm.get_user(&"user1".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [information of a user]: https://docs.nitrokey.com/nethsm/administration#list-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_user(&self, user_id: &UserId) -> Result<UserData, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        Ok(
            users_user_id_get(&self.create_connection_config(), &user_id.to_string())
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting user failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }

    /// Sets the [passphrase for a user] on the NetHSM.
    ///
    /// ## Namespaces
    ///
    /// *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    /// [namespace]) are only able to set the passphrases for users in their own [namespace].
    /// *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are only
    /// able to set the passphrases for system-wide users.
    ///
    /// Internally, this function also calls [`add_credentials`][`NetHsm::add_credentials`] to add
    /// the updated user [`Credentials`] to the list of available ones.
    /// If the calling user is in the [`Administrator`][`UserRole::Administrator`] [role] and
    /// changes their own passphrase, additionally
    /// [`use_credentials`][`NetHsm::use_credentials`] is called to use the updated passphrase
    /// after changing it.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the passphrase for the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the targeted user is in a [namespace], but the caller is not an
    ///   [`Administrator`][`UserRole::Administrator`] of that [namespace] (*N-Administrator*)
    /// * the targeted user is a system-wide user, but the caller is not a system-wide
    ///   [`Administrator`][`UserRole::Administrator`] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // the R-Administrator can set its own passphrase
    /// nethsm.set_user_passphrase(
    ///     "admin".parse()?,
    ///     Passphrase::new("new-admin-passphrase".to_string()),
    /// )?;
    /// // the R-Administrator can not set the N-Administrator's passphrase
    /// assert!(nethsm
    ///     .set_user_passphrase(
    ///         "namespace1~admin".parse()?,
    ///         Passphrase::new("new-admin-passphrase".to_string()),
    ///     )
    ///     .is_err());
    ///
    /// // the N-Administrator can set its own passphrase
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// nethsm.set_user_passphrase(
    ///     "namespace1~admin1".parse()?,
    ///     Passphrase::new("new-admin-passphrase".to_string()),
    /// )?;
    /// // the N-Administrator can not set the R-Administrator's passphrase
    /// assert!(nethsm
    ///     .set_user_passphrase(
    ///         "admin".parse()?,
    ///         Passphrase::new("new-admin-passphrase".to_string())
    ///     )
    ///     .is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [passphrase for a user]: https://docs.nitrokey.com/nethsm/administration#user-passphrase
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_user_passphrase(
        &self,
        user_id: UserId,
        passphrase: Passphrase,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, Some(&user_id), None)?;
        users_user_id_passphrase_post(
            &self.create_connection_config(),
            &user_id.to_string(),
            UserPassphrasePostData::new(passphrase.expose_owned()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting user passphrase failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;

        // add to list of available credentials
        self.add_credentials(Credentials::new(user_id, Some(passphrase)));

        Ok(())
    }

    /// [Adds a tag] to a user in the [`Operator`][`UserRole::Operator`] [role].
    ///
    /// A `tag` provides the user identified by `user_id` with access to keys in their [namespace],
    /// that are tagged with that same `tag`.
    ///
    /// **NOTE**: The tag for the key in the same [namespace] must be added beforehand, by calling
    /// [`add_key_tag`][`NetHsm::add_key_tag`].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to add tags for users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to add tags for system-wide users.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the tag for the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the [`Operator`][`UserRole::Operator`] [role]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the caller does not have access to the target user's [namespace]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add a user in the Operator role for a namespace
    /// nethsm.add_user(
    ///     "Namespace1 Operator".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("namespce1-operator-passphrase".to_string()),
    ///     Some("namespace1~operator1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    ///
    /// // R-Administrators can add tags for system-wide users
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    /// // R-Administrators can not add tags for namespace users
    /// assert!(nethsm
    ///     .add_user_tag(&"namespace1~user1".parse()?, "tag1")
    ///     .is_err());
    ///
    /// // user tags in namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// // generate key in namespace1 with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing2".to_string()),
    ///     Some(vec!["tag2".to_string()]),
    /// )?;
    /// // N-Administrators can not add tags to system-wide users
    /// assert!(nethsm.add_user_tag(&"user1".parse()?, "tag2").is_err());
    /// // N-Administrators can add tags to users in their own namespace
    /// nethsm.add_user_tag(&"namespace1~user1".parse()?, "tag2")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Adds a tag]: https://docs.nitrokey.com/nethsm/administration#tags-for-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_user_tag(&self, user_id: &UserId, tag: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        users_user_id_tags_tag_put(&self.create_connection_config(), &user_id.to_string(), tag)
            .map_err(|error| {
                Error::Api(format!(
                    "Adding tag for user failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// [Deletes a tag] from a user in the [`Operator`][`UserRole::Operator`] [role].
    ///
    /// Removes a `tag` from a target user identified by `user_id`, which removes its access to any
    /// key in their [namespace], that carries the same `tag`.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to delete tags for users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to delete tags for system-wide users.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the tag from the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the [`Operator`][`UserRole::Operator`] [role]
    /// * the `tag` is not added to user identified by `user_id`
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the caller does not have access to the target user's [namespace]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add a user in the Operator role for a namespace
    /// nethsm.add_user(
    ///     "Namespace1 Operator".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("namespce1-operator-passphrase".to_string()),
    ///     Some("namespace1~operator1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // add tag for system-wide user
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    ///
    /// // N-Administrators can not delete tags from system-wide Operator users
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.delete_user_tag(&"user1".parse()?, "tag2").is_err());
    ///
    /// // R-Administrators can delete tags from system-wide Operator users
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.delete_user_tag(&"user1".parse()?, "tag1")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Deletes a tag]: https://docs.nitrokey.com/nethsm/administration#tags-for-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_user_tag(&self, user_id: &UserId, tag: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        users_user_id_tags_tag_delete(&self.create_connection_config(), &user_id.to_string(), tag)
            .map_err(|error| {
                Error::Api(format!(
                    "Deleting tag for user failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// [Gets all tags] of a user in the [`Operator`][`UserRole::Operator`] [role].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to get tags of users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   able to get tags of system-wide and all [namespace] users.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the tags for the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the [`Operator`][`UserRole::Operator`] [role]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the caller does not have access to the target user's [namespace]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    ///
    /// // R-Administrators can access tags of all users
    /// assert!(nethsm.get_user_tags(&"user1".parse()?)?.is_empty());
    /// // add a tag for the user
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    /// assert_eq!(nethsm.get_user_tags(&"user1".parse()?)?.len(), 1);
    ///
    /// // N-Administrators can not access tags of system-wide users
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_user_tags(&"user1".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [Gets all tags]: https://docs.nitrokey.com/nethsm/administration#tags-for-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_user_tags(&self, user_id: &UserId) -> Result<Vec<String>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        Ok(
            users_user_id_tags_get(&self.create_connection_config(), &user_id.to_string())
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting tags of user failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }

    /// [Generates a new key] on the NetHSM.
    ///
    /// [Generates a new key] with customizable features on the NetHSM.
    /// The provided [`KeyType`] and list of [`KeyMechanism`]s have to match:
    /// * [`KeyType::Rsa`] requires one of [`KeyMechanism::RsaDecryptionRaw`],
    ///   [`KeyMechanism::RsaDecryptionPkcs1`], [`KeyMechanism::RsaDecryptionOaepMd5`],
    ///   [`KeyMechanism::RsaDecryptionOaepSha1`], [`KeyMechanism::RsaDecryptionOaepSha224`],
    ///   [`KeyMechanism::RsaDecryptionOaepSha256`], [`KeyMechanism::RsaDecryptionOaepSha384`],
    ///   [`KeyMechanism::RsaDecryptionOaepSha512`], [`KeyMechanism::RsaSignaturePkcs1`],
    ///   [`KeyMechanism::RsaSignaturePssMd5`], [`KeyMechanism::RsaSignaturePssSha1`],
    ///   [`KeyMechanism::RsaSignaturePssSha224`], [`KeyMechanism::RsaSignaturePssSha256`],
    ///   [`KeyMechanism::RsaSignaturePssSha384`] or [`KeyMechanism::RsaSignaturePssSha512`]
    /// * [`KeyType::Curve25519`] requires [`KeyMechanism::EdDsaSignature`]
    /// * [`KeyType::EcP224`], [`KeyType::EcP256`], [`KeyType::EcP384`] and [`KeyType::EcP521`]
    ///   require [`KeyMechanism::EcdsaSignature`]
    /// * [`KeyType::Generic`] requires one of [`KeyMechanism::AesDecryptionCbc`] or
    ///   [`KeyMechanism::AesEncryptionCbc`]
    ///
    /// Optionally the key bit-length using `length`, a custom key ID using `key_id`
    /// and a list of `tags` to be attached to the new key can be provided.
    /// If no `key_id` is provided, a unique one is generated automatically.
    ///
    /// **WARNING**: If no `tags` are provided, the generated key is usable by all users in the
    /// [`Operator`][`UserRole::Operator`] [role] in the same scope (e.g. same [namespace]) by
    /// default!
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * Keys generated by *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users
    ///   in a given [namespace]) are only visible to users in their [namespace]. Only users in the
    ///   [`Operator`][`UserRole::Operator`] [role] in that same [namespace] can be granted access
    ///   to them.
    /// * Keys generated by *R-Administrators* (system-wide
    ///   [`Administrator`][`UserRole::Administrator`] users) are only visible to system-wide users.
    ///   Only system-wide users in the [`Operator`][`UserRole::Operator`] [role] (not in any
    ///   [namespace]) can be granted access to them.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if generating the key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * a key identified by ` key_id` exists already
    /// * the chosen `length` or `tags` options are not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// Returns an [`Error::Key`] if the provided combination of `key_type` and `mechanisms` is not
    /// valid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, KeyMechanism, KeyType, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // generate a Curve25519 key for signing with custom Key ID and tags
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["sign_tag1".to_string(), "sign_tag2".to_string()]),
    /// )?;
    ///
    /// // generate a generic key for symmetric encryption and decryption
    /// nethsm.generate_key(
    ///     KeyType::Generic,
    ///     vec![
    ///         KeyMechanism::AesEncryptionCbc,
    ///         KeyMechanism::AesDecryptionCbc,
    ///     ],
    ///     Some(128),
    ///     Some("encryption1".to_string()),
    ///     Some(vec!["encryption_tag1".to_string()]),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Generates a new key]: https://docs.nitrokey.com/nethsm/operation#generate-key
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn generate_key(
        &self,
        key_type: KeyType,
        mechanisms: Vec<KeyMechanism>,
        length: Option<u32>,
        key_id: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        // ensure the key_type - mechanisms combinations are valid
        key_type_matches_mechanisms(key_type, &mechanisms)?;

        Ok(keys_generate_post(
            &self.create_connection_config(),
            KeyGenerateRequestData {
                mechanisms: mechanisms
                    .into_iter()
                    .map(|mechanism| mechanism.into())
                    .collect(),
                r#type: key_type.into(),
                length: length.map(|length| length as i32),
                id: key_id,
                restrictions: tags.map(|tags| Box::new(KeyRestrictions { tags: Some(tags) })),
            },
        )
        .map_err(|error| {
            Error::Api(format!(
                "Creating key failed: {}",
                NetHsmApiError::from(error)
            ))
        })?
        .entity
        .id)
    }

    /// Imports an existing private key.
    ///
    /// [Imports an existing key] with custom features into the NetHSM.
    /// The [`KeyType`] implied by the provided [`PrivateKeyImport`] and the list of
    /// [`KeyMechanism`]s have to match:
    /// * [`KeyType::Rsa`] must be used with [`KeyMechanism::RsaDecryptionRaw`],
    ///   [`KeyMechanism::RsaDecryptionPkcs1`], [`KeyMechanism::RsaDecryptionOaepMd5`],
    ///   [`KeyMechanism::RsaDecryptionOaepSha1`], [`KeyMechanism::RsaDecryptionOaepSha224`],
    ///   [`KeyMechanism::RsaDecryptionOaepSha256`], [`KeyMechanism::RsaDecryptionOaepSha384`],
    ///   [`KeyMechanism::RsaDecryptionOaepSha512`], [`KeyMechanism::RsaSignaturePkcs1`],
    ///   [`KeyMechanism::RsaSignaturePssMd5`], [`KeyMechanism::RsaSignaturePssSha1`],
    ///   [`KeyMechanism::RsaSignaturePssSha224`], [`KeyMechanism::RsaSignaturePssSha256`],
    ///   [`KeyMechanism::RsaSignaturePssSha384`] or [`KeyMechanism::RsaSignaturePssSha512`]
    /// * [`KeyType::Curve25519`] must be used with [`KeyMechanism::EdDsaSignature`]
    /// * [`KeyType::EcP224`], [`KeyType::EcP256`], [`KeyType::EcP384`] and [`KeyType::EcP521`] must
    ///   be used with [`KeyMechanism::EcdsaSignature`]
    /// * [`KeyType::Generic`] must be used with [`KeyMechanism::AesDecryptionCbc`] or
    ///   [`KeyMechanism::AesEncryptionCbc`]
    ///
    /// Optionally a custom Key ID using `key_id` and a list of `tags` to be attached to the new key
    /// can be provided.
    /// If no `key_id` is provided, a unique one is generated automatically.
    ///
    /// **WARNING**: If no `tags` are provided, the imported key is usable by all users in the
    /// [`Operator`][`UserRole::Operator`] [role] in the same scope (e.g. same [namespace]) by
    /// default!
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * Keys imported by *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in
    ///   a given [namespace]) are only visible to users in their [namespace]. Only users in the
    ///   [`Operator`][`UserRole::Operator`] [role] in that same [namespace] can be granted access
    ///   to them.
    /// * Keys imported by *R-Administrators* (system-wide
    ///   [`Administrator`][`UserRole::Administrator`] users) are only visible to system-wide users.
    ///   Only system-wide users in the [`Operator`][`UserRole::Operator`] [role] (not in any
    ///   [namespace]) can be granted access to them.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if importing the key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * a key identified by ` key_id` exists already
    /// * the chosen `tags` option is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// Returns an [`Error::Key`] if the provided combination of `key_data` and `mechanisms` is not
    /// valid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, PrivateKeyImport, KeyMechanism, KeyType, NetHsm, Passphrase};
    /// use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    /// use rsa::RsaPrivateKey;
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // create a 4096 bit RSA private key and return it as PKCS#8 private key in ASN.1 DER-encoded format
    /// let private_key = {
    ///     let mut rng = rand::thread_rng();
    ///     let private_key = RsaPrivateKey::new(&mut rng, 4096)?;
    ///     private_key.to_pkcs8_der()?
    /// };
    ///
    /// // import an RSA key for PKCS1 signatures
    /// nethsm.import_key(
    ///     vec![KeyMechanism::RsaSignaturePkcs1],
    ///     PrivateKeyImport::new(KeyType::Rsa, private_key.as_bytes())?,
    ///     Some("signing2".to_string()),
    ///     Some(vec!["signing_tag3".to_string()]),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Imports an existing key]: https://docs.nitrokey.com/nethsm/operation#import-key
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn import_key(
        &self,
        mechanisms: Vec<KeyMechanism>,
        key_data: PrivateKeyImport,
        key_id: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        // ensure the key_type - mechanisms combinations are valid
        let key_type = key_data.key_type();
        key_type_matches_mechanisms(key_type, &mechanisms)?;

        let restrictions = tags.map(|tags| Box::new(KeyRestrictions { tags: Some(tags) }));
        let private = Box::new(key_data.into());
        let mechanisms = mechanisms
            .into_iter()
            .map(|mechanism| mechanism.into())
            .collect();

        if let Some(key_id) = key_id {
            keys_key_id_put(
                &self.create_connection_config(),
                &key_id,
                nethsm_sdk_rs::apis::default_api::KeysKeyIdPutBody::ApplicationJson(PrivateKey {
                    mechanisms,
                    r#type: key_type.into(),
                    private,
                    restrictions,
                }),
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Importing key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
            Ok(key_id)
        } else {
            Ok(keys_post(
                &self.create_connection_config(),
                KeysPostBody::ApplicationJson(PrivateKey {
                    mechanisms,
                    r#type: key_type.into(),
                    private,
                    restrictions,
                }),
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Importing key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .id)
        }
    }

    /// [Deletes a key] from the NetHSM.
    ///
    /// [Deletes a key] identified by `key_id` from the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * Keys in a [namespace] can only be deleted by *N-Administrators*
    ///   ([`Administrator`][`UserRole::Administrator`] users in a given [namespace]) of that
    ///   [namespace] (*R-Administrators* have no access to keys in a [namespace]). **NOTE**:
    ///   Calling [`delete_namespace`][`NetHsm::delete_namespace`] deletes **all keys** in a
    ///   [namespace]!
    /// * System-wide keys can only be deleted by *R-Administrators* (system-wide
    ///   [`Administrator`][`UserRole::Administrator`] users).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // delete a key with the Key ID "signing1"
    /// nethsm.delete_key("signing1")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Deletes a key]: https://docs.nitrokey.com/nethsm/operation#delete-key
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_key(&self, key_id: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        keys_key_id_delete(&self.create_connection_config(), key_id).map_err(|error| {
            Error::Api(format!(
                "Deleting key failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets [details about a key].
    ///
    /// Gets [details about a key] identified by `key_id`.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] or [`Operator`][`UserRole::Operator`]
    /// [role].
    ///
    /// ## Namespaces
    ///
    /// * Users in a [namespace] can only get details about keys in their own [namespace].
    /// * System-wide users (not in a [namespace]) can only get details about system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the key details fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] or [`Operator`][`UserRole::Operator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // get details on a key with the Key ID "signing1"
    /// println!("{:?}", nethsm.get_key("signing1")?);
    /// # Ok(())
    /// # }
    /// ```
    /// [details about a key]: https://docs.nitrokey.com/nethsm/operation#show-key-details
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_key(&self, key_id: &str) -> Result<PublicKey, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        Ok(keys_key_id_get(&self.create_connection_config(), key_id)
            .map_err(|error| {
                Error::Api(format!(
                    "Getting key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Gets a [list of Key IDs] on the NetHSM.
    ///
    /// Optionally `filter` can be provided for matching against Key IDs.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] or [`Operator`][`UserRole::Operator`]
    /// [role].
    ///
    /// ## Namespaces
    ///
    /// * Users in a [namespace] can only list key IDs of keys in their own [namespace].
    /// * System-wide users (not in a [namespace]) can only list key IDs of system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the list of Key IDs fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] or [`Operator`][`UserRole::Operator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // get all Key IDs
    /// println!("{:?}", nethsm.get_keys(None)?);
    ///
    /// // get all Key IDs that begin with "signing"
    /// println!("{:?}", nethsm.get_keys(Some("signing"))?);
    /// # Ok(())
    /// # }
    /// ```
    /// [list of Key IDs]: https://docs.nitrokey.com/nethsm/operation#list-keys
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_keys(&self, filter: Option<&str>) -> Result<Vec<String>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        Ok(keys_get(&self.create_connection_config(), filter)
            .map_err(|error| {
                Error::Api(format!(
                    "Getting keys failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .iter()
            .map(|x| x.id.clone())
            .collect())
    }

    /// Gets the [public key of a key] on the NetHSM.
    ///
    /// Gets the [public key of a key] on the NetHSM, identified by `key_id`.
    /// The public key is returned in [X.509] Privacy-Enhanced Mail ([PEM]) format.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] or [`Operator`][`UserRole::Operator`]
    /// [role].
    ///
    /// ## Namespaces
    ///
    /// * Users in a [namespace] can only get public keys of keys in their own [namespace].
    /// * System-wide users (not in a [namespace]) can only get public keys of system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the public key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] or [`Operator`][`UserRole::Operator`] [role]
    /// * the targeted key is a symmetric key (i.e. [`KeyType::Generic`]) and therefore can not
    ///   provide a public key
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, KeyMechanism, KeyType, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    ///
    /// // get public key for a key with Key ID "signing1"
    /// println!("{:?}", nethsm.get_public_key("signing1")?);
    /// # Ok(())
    /// # }
    /// ```
    /// [public key of a key]: https://docs.nitrokey.com/nethsm/operation#show-key-details
    /// [X.509]: https://en.wikipedia.org/wiki/X.509
    /// [PEM]: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_public_key(&self, key_id: &str) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        Ok(
            keys_key_id_public_pem_get(&self.create_connection_config(), key_id)
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting public key failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }

    /// Adds a [tag for a key].
    ///
    /// Adds `tag` for a key, identified by `key_id`.
    ///
    /// A [tag for a key] is prerequisite to adding the same tag to a user in the
    /// [`Operator`][`UserRole::Operator`] [role] and thus granting it access to the key.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to tag keys in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to tag system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * `tag` is already associated with the key
    /// * `tag` is invalid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * a key in a [namespace] is attempted to be tagged by an *R-Administrator*
    /// * a system-wide key is attempted to be tagged by an *N-Administrator*
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, KeyMechanism, KeyType, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    ///
    /// // add the tag "important" to a key with Key ID "signing1"
    /// nethsm.add_key_tag("signing1", "important")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [tag for a key]: https://docs.nitrokey.com/nethsm/operation#tags-for-keys
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_key_tag(&self, key_id: &str, tag: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        keys_key_id_restrictions_tags_tag_put(&self.create_connection_config(), tag, key_id)
            .map_err(|error| {
                Error::Api(format!(
                    "Adding tag for key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// Deletes a [tag from a key].
    ///
    /// Deletes `tag` from a key, identified by `key_id` on the NetHSM.
    ///
    /// Deleting a [tag from a key] removes access to it for any user in the
    /// [`Operator`][`UserRole::Operator`] [role], that carries the same tag.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to delete tags from keys in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to delete tags from system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * `tag` is not associated with the key
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the tag for a key in a [namespace] is attempted to be removed by an *R-Administrator*
    /// * the tag for a system-wide key is attempted to be removed by an *N-Administrator*
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, KeyMechanism, KeyType, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string(), "important".to_string()]),
    /// )?;
    ///
    /// // remove the tag "important" from a key with Key ID "signing1"
    /// nethsm.delete_key_tag("signing1", "important")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [tag from a key]: https://docs.nitrokey.com/nethsm/operation#tags-for-keys
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_key_tag(&self, key_id: &str, tag: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        keys_key_id_restrictions_tags_tag_delete(&self.create_connection_config(), tag, key_id)
            .map_err(|error| {
                Error::Api(format!(
                    "Deleting tag for key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// Imports a [certificate for a key].
    ///
    /// Imports a [certificate for a key] identified by `key_id`.
    /// Certificates up to 1 MiB in size are supported.
    /// **NOTE**: The imported bytes are not validated!
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to import certificates for keys in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to import certificates for system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if importing a [certificate for a key] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * the `data` is invalid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    /// // use the Operator credentials to create an OpenPGP certificate for a key
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let openpgp_cert = nethsm.create_openpgp_cert(
    ///     "signing1",
    ///     OpenPgpKeyUsageFlags::default(),
    ///     "Test <test@example.org>",
    ///     SystemTime::now().into(),
    /// )?;
    ///
    /// // use the Administrator credentials to import the OpenPGP certificate as certificate for the key
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// assert!(nethsm.get_key_certificate("signing1").is_err());
    /// nethsm.import_key_certificate("signing1", openpgp_cert)?;
    /// assert!(nethsm.get_key_certificate("signing1").is_ok());
    /// # Ok(())
    /// # }
    /// ```
    /// [certificate for a key]: https://docs.nitrokey.com/nethsm/operation#key-certificates
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn import_key_certificate(&self, key_id: &str, data: Vec<u8>) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        keys_key_id_cert_put(&self.create_connection_config(), key_id, data).map_err(|error| {
            Error::Api(format!(
                "Importing certificate for key failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets the [certificate for a key].
    ///
    /// Gets the [certificate for a key] identified by `key_id`.
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// or [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to get certificates for keys in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to get certificates for system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the [certificate for a key] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * no certificate is associated with the key
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   or [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    /// // use the Operator credentials to create an OpenPGP certificate for a key
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let openpgp_cert = nethsm.create_openpgp_cert(
    ///     "signing1",
    ///     OpenPgpKeyUsageFlags::default(),
    ///     "Test <test@example.org>",
    ///     SystemTime::now().into(),
    /// )?;
    /// // use the Administrator credentials to import the OpenPGP certificate as certificate for the key
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.import_key_certificate("signing1", openpgp_cert)?;
    ///
    /// // get the certificate associated with a key
    /// println!("{:?}", nethsm.get_key_certificate("signing1")?);
    /// # Ok(())
    /// # }
    /// ```
    /// [key certificate]: https://docs.nitrokey.com/nethsm/operation#key-certificates
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_key_certificate(&self, key_id: &str) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        Ok(
            keys_key_id_cert_get(&self.create_connection_config(), key_id)
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting certificate for key failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }

    /// Deletes the [certificate for a key].
    ///
    /// Deletes the [certificate for a key] identified by `key_id`.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to delete certificates for keys in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to delete certificates for system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the [certificate for a key] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * no certificate is associated with the key
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    /// // use the Operator credentials to create an OpenPGP certificate for a key
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let openpgp_cert = nethsm.create_openpgp_cert(
    ///     "signing1",
    ///     OpenPgpKeyUsageFlags::default(),
    ///     "Test <test@example.org>",
    ///     SystemTime::now().into(),
    /// )?;
    /// // use the Administrator credentials to import the OpenPGP certificate as certificate for the key
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.import_key_certificate("signing1", openpgp_cert)?;
    ///
    /// // delete a certificate for a key with Key ID "signing1"
    /// assert!(nethsm.delete_key_certificate("signing1").is_ok());
    /// nethsm.delete_key_certificate("signing1")?;
    /// assert!(nethsm.delete_key_certificate("signing1").is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [certificate for a key]: https://docs.nitrokey.com/nethsm/operation#key-certificates
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_key_certificate(&self, key_id: &str) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        keys_key_id_cert_delete(&self.create_connection_config(), key_id).map_err(|error| {
            Error::Api(format!(
                "Deleting certificate for key failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets a [Certificate Signing Request for a key].
    ///
    /// Returns a Certificate Signing Request ([CSR]) for a key, identified by `key_id` in [PKCS#10]
    /// format based on a provided [`DistinguishedName`].
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// or [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * Users in a [namespace] only have access to keys in their own [namespace]
    /// * System-wide users only have access to system-wide keys (not in a [namespace]).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting a CSR for a key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   or [`Administrator`][`UserRole::Administrator`] [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     DistinguishedName,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     Passphrase,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    ///
    /// // get a CSR for a key
    /// println!(
    ///     "{}",
    ///     nethsm.get_key_csr(
    ///         "signing1",
    ///         DistinguishedName {
    ///             country_name: Some("DE".to_string()),
    ///             state_or_province_name: Some("Berlin".to_string()),
    ///             locality_name: Some("Berlin".to_string()),
    ///             organization_name: Some("Foobar Inc".to_string()),
    ///             organizational_unit_name: Some("Department of Foo".to_string()),
    ///             common_name: "Foobar Inc".to_string(),
    ///             email_address: Some("foobar@mcfooface.com".to_string()),
    ///         }
    ///     )?
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [Certificate Signing Request for a key]: https://docs.nitrokey.com/nethsm/operation#key-certificate-signing-requests
    /// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
    /// [PKCS#10]: https://en.wikipedia.org/wiki/Certificate_signing_request#Structure_of_a_PKCS_#10_CSR
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_key_csr(
        &self,
        key_id: &str,
        distinguished_name: DistinguishedName,
    ) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        Ok(
            keys_key_id_csr_pem_post(&self.create_connection_config(), key_id, distinguished_name)
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting CSR for key failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }

    /// [Signs] a digest using a key.
    ///
    /// [Signs] a `digest` using a key identified by `key_id`.
    ///
    /// **NOTE**: This function offers low-level access for signing [digests]. Use
    /// [`sign`][`NetHsm::sign`] for signing a message.
    ///
    /// The `digest` must be of appropriate type depending on `signature_type`:
    /// * [`SignatureType::Pkcs1`], [`SignatureType::PssSha256`] and [`SignatureType::EcdsaP256`]
    ///   require a [SHA-256] digest
    /// * [`SignatureType::PssMd5`] requires an [MD5] digest
    /// * [`SignatureType::PssSha1`] requires a [SHA-1] digest
    /// * [`SignatureType::PssSha224`] and [`SignatureType::EcdsaP224`] require a [SHA-224] digest
    /// * [`SignatureType::PssSha384`] and [`SignatureType::EcdsaP384`] require a [SHA-384] digest
    /// * [`SignatureType::PssSha512`] and [`SignatureType::EcdsaP521`] require a [SHA-521] digest
    /// * [`SignatureType::EdDsa`] requires no digest (`digest` is the message)
    ///
    /// The returned data depends on the chosen [`SignatureType`]:
    ///
    /// * [`SignatureType::Pkcs1`] returns the [PKCS 1] padded signature (no signature algorithm OID
    ///   prepended, since the used hash is not known).
    /// * [`SignatureType::PssMd5`], [`SignatureType::PssSha1`], [`SignatureType::PssSha224`],
    ///   [`SignatureType::PssSha256`], [`SignatureType::PssSha384`] and
    ///   [`SignatureType::PssSha512`] return the [EMSA-PSS] encoded signature.
    /// * [`SignatureType::EdDsa`] returns the encoding as specified in [RFC 8032 (5.1.6)] (`r`
    ///   appended with `s` (each 32 bytes), in total 64 bytes).
    /// * [`SignatureType::EcdsaP224`], [`SignatureType::EcdsaP256`], [`SignatureType::EcdsaP384`]
    ///   and [`SignatureType::EcdsaP521`] return the [ASN.1] [DER] encoded signature (a sequence of
    ///   integer `r` and integer `s`).
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// [role], which carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one
    /// of the tags of the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if signing the `digest` fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the chosen [`SignatureType`] is incompatible with the targeted key
    /// * the chosen `digest` is incompatible with the [`SignatureType`]
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     Passphrase,
    ///     SignatureType,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    ///
    /// // create an ed25519 signature
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// println!(
    ///     "{:?}",
    ///     nethsm.sign_digest("signing1", SignatureType::EdDsa, &[0, 1, 2])?
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [Signs]: https://docs.nitrokey.com/nethsm/operation#sign
    /// [digests]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
    /// [SHA-256]: https://en.wikipedia.org/wiki/SHA-2
    /// [MD5]: https://en.wikipedia.org/wiki/MD5
    /// [SHA-1]: https://en.wikipedia.org/wiki/SHA-1
    /// [SHA-224]: https://en.wikipedia.org/wiki/SHA-2
    /// [SHA-384]: https://en.wikipedia.org/wiki/SHA-2
    /// [SHA-521]: https://en.wikipedia.org/wiki/SHA-2
    /// [PKCS 1]: https://en.wikipedia.org/wiki/PKCS_1
    /// [EMSA-PSS]: https://en.wikipedia.org/wiki/PKCS_1
    /// [RFC 8032 (5.1.6)]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6
    /// [ASN.1]: https://en.wikipedia.org/wiki/ASN.1
    /// [DER]: https://en.wikipedia.org/wiki/X.690#DER_encoding
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn sign_digest(
        &self,
        key_id: &str,
        signature_type: SignatureType,
        digest: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        // decode base64 encoded data from the API
        Base64::decode_vec(
            &keys_key_id_sign_post(
                &self.create_connection_config(),
                key_id,
                SignRequestData::new(signature_type.into(), Base64::encode_string(digest)),
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Signing message failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .signature,
        )
        .map_err(Error::Base64Decode)
    }

    /// [Signs] a message using a key.
    ///
    /// [Signs] a `message` using a key identified by `key_id` based on a specific `signature_type`.
    ///
    /// The `message` should not be [hashed], as this function takes care of it based on the
    /// provided [`SignatureType`]. For lower level access, see
    /// [`sign_digest`][`NetHsm::sign_digest`].
    ///
    /// The returned data depends on the chosen [`SignatureType`]:
    ///
    /// * [`SignatureType::Pkcs1`] returns the [PKCS 1] padded signature (no signature algorithm OID
    ///   prepended, since the used hash is not known).
    /// * [`SignatureType::PssMd5`], [`SignatureType::PssSha1`], [`SignatureType::PssSha224`],
    ///   [`SignatureType::PssSha256`], [`SignatureType::PssSha384`] and
    ///   [`SignatureType::PssSha512`] return the [EMSA-PSS] encoded signature.
    /// * [`SignatureType::EdDsa`] returns the encoding as specified in [RFC 8032 (5.1.6)] (`r`
    ///   appended with `s` (each 32 bytes), in total 64 bytes).
    /// * [`SignatureType::EcdsaP224`], [`SignatureType::EcdsaP256`], [`SignatureType::EcdsaP384`]
    ///   and [`SignatureType::EcdsaP521`] return the [ASN.1] [DER] encoded signature (a sequence of
    ///   integer `r` and integer `s`).
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// [role], which carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one
    /// of the tags of the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if signing the `message` fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the chosen [`SignatureType`] is incompatible with the targeted key
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     Passphrase,
    ///     SignatureType,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    ///
    /// // create an ed25519 signature
    /// println!(
    ///     "{:?}",
    ///     nethsm.sign("signing1", SignatureType::EdDsa, b"message")?
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [Signs]: https://docs.nitrokey.com/nethsm/operation#sign
    /// [hashed]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
    /// [PKCS 1]: https://en.wikipedia.org/wiki/PKCS_1
    /// [EMSA-PSS]: https://en.wikipedia.org/wiki/PKCS_1
    /// [RFC 8032 (5.1.6)]: https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6
    /// [ASN.1]: https://en.wikipedia.org/wiki/ASN.1
    /// [DER]: https://en.wikipedia.org/wiki/X.690#DER_encoding
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn sign(
        &self,
        key_id: &str,
        signature_type: SignatureType,
        message: &[u8],
    ) -> Result<Vec<u8>, Error> {
        // Some algorithms require the data to be hashed first
        // The API requires data to be base64 encoded
        let message = match signature_type {
            SignatureType::Pkcs1 | SignatureType::PssSha256 | SignatureType::EcdsaP256 => {
                let mut hasher = Sha256::new();
                hasher.update(message);
                &hasher.finalize()[..]
            }
            SignatureType::PssMd5 => {
                let mut hasher = Md5::new();
                hasher.update(message);
                &hasher.finalize()[..]
            }
            SignatureType::PssSha1 => {
                let mut hasher = Sha1::new();
                hasher.update(message);
                &hasher.finalize()[..]
            }
            SignatureType::PssSha224 | SignatureType::EcdsaP224 => {
                let mut hasher = Sha224::new();
                hasher.update(message);
                &hasher.finalize()[..]
            }
            SignatureType::PssSha384 | SignatureType::EcdsaP384 => {
                let mut hasher = Sha384::new();
                hasher.update(message);
                &hasher.finalize()[..]
            }
            SignatureType::PssSha512 | SignatureType::EcdsaP521 => {
                let mut hasher = Sha512::new();
                hasher.update(message);
                &hasher.finalize()[..]
            }
            SignatureType::EdDsa => message,
        };

        self.sign_digest(key_id, signature_type, message)
    }

    /// [Encrypts] a message using a [symmetric key].
    ///
    /// [Encrypts] a `message` using a [symmetric key] identified by `key_id`, a specific
    /// [`EncryptMode`] `mode` and initialization vector `iv`.
    ///
    /// The targeted key must be of type [`KeyType::Generic`] and feature the mechanisms
    /// [`KeyMechanism::AesDecryptionCbc`] and [`KeyMechanism::AesEncryptionCbc`].
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// [role], which carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one
    /// of the tags of the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if encrypting the `message` fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the chosen `mode` is incompatible with the targeted key
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, EncryptMode, KeyMechanism, KeyType, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Generic,
    ///     vec![KeyMechanism::AesDecryptionCbc, KeyMechanism::AesEncryptionCbc],
    ///     Some(128),
    ///     Some("encryption1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    ///
    /// // assuming we have an AES128 encryption key, the message must be a multiple of 32 bytes long
    /// let message = b"Hello World! This is a message!!";
    /// // we have an AES128 encryption key. the initialization vector must be a multiple of 16 bytes long
    /// let iv = b"This is unsafe!!";
    ///
    /// // encrypt message using
    /// println!(
    ///     "{:?}",
    ///     nethsm.encrypt("encryption1", EncryptMode::AesCbc, message, Some(iv))?
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [Encrypts]: https://docs.nitrokey.com/nethsm/operation#encrypt
    /// [symmetric key]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn encrypt(
        &self,
        key_id: &str,
        mode: EncryptMode,
        message: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        // the API requires data to be base64 encoded
        let message = Base64::encode_string(message);
        let iv = iv.map(Base64::encode_string);

        // decode base64 encoded data from the API
        Base64::decode_vec(
            &keys_key_id_encrypt_post(
                &self.create_connection_config(),
                key_id,
                EncryptRequestData {
                    mode: mode.into(),
                    message,
                    iv,
                },
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Encrypting message failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .encrypted,
        )
        .map_err(Error::Base64Decode)
    }

    /// [Decrypts] a message using a key.
    ///
    /// [Decrypts] a `message` using a key identified by `key_id`, a specific [`DecryptMode`] `mode`
    /// and initialization vector `iv`.
    ///
    /// This function can be used to decrypt messages encrypted using a [symmetric key] (e.g. using
    /// [`encrypt`][`NetHsm::encrypt`]) by providing [`DecryptMode::AesCbc`] as `mode`. The targeted
    /// key must be of type [`KeyType::Generic`] and feature the mechanisms
    /// [`KeyMechanism::AesDecryptionCbc`] and [`KeyMechanism::AesEncryptionCbc`].
    ///
    /// Decryption for messages encrypted using an [asymmetric key] is also possible. Foreign
    /// entities can use the public key of an [asymmetric key] (see
    /// [`get_public_key`][`NetHsm::get_public_key`]) to encrypt a message and the private key
    /// on the NetHSM is used for decryption.
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// [role], which carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one
    /// of the tags of the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if decrypting the `message` fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the chosen `mode` is incompatible with the targeted key
    /// * the encrypted message can not be decrypted
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, DecryptMode, EncryptMode, KeyMechanism, KeyType, NetHsm, Passphrase, UserRole};
    /// use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide keys with the same tag
    /// nethsm.generate_key(
    ///     KeyType::Generic,
    ///     vec![KeyMechanism::AesDecryptionCbc, KeyMechanism::AesEncryptionCbc],
    ///     Some(128),
    ///     Some("encryption1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// nethsm.generate_key(
    ///     KeyType::Rsa,
    ///     vec![KeyMechanism::RsaDecryptionPkcs1],
    ///     None,
    ///     Some("encryption2".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    ///
    /// // assuming we have an AES128 encryption key, the message must be a multiple of 32 bytes long
    /// let message = "Hello World! This is a message!!".to_string();
    /// // we have an AES128 encryption key. the initialization vector must be a multiple of 16 bytes long
    /// let iv = "This is unsafe!!".to_string();
    ///
    /// // encrypt message using a symmetric key
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let encrypted_message = nethsm.encrypt("encryption1", EncryptMode::AesCbc, message.as_bytes(), Some(iv.as_bytes()))?;
    ///
    /// // decrypt message using the same symmetric key and the same initialization vector
    /// assert_eq!(
    ///     message.as_bytes(),
    ///     &nethsm.decrypt("encryption1", DecryptMode::AesCbc, &encrypted_message, Some(iv.as_bytes()))?
    /// );
    ///
    /// // get the public key of an asymmetric key and encrypt the message with it
    /// let pubkey = RsaPublicKey::from_public_key_pem(&nethsm.get_public_key("encryption2")?)?;
    /// let mut rng = rand::thread_rng();
    /// let encrypted_message = pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, message.as_bytes())?;
    /// println!("raw encrypted message: {:?}", encrypted_message);
    ///
    /// let decrypted_message =
    ///     nethsm.decrypt("encryption2", DecryptMode::Pkcs1, &encrypted_message, None)?;
    /// println!("raw decrypted message: {:?}", decrypted_message);
    ///
    /// assert_eq!(&decrypted_message, message.as_bytes());
    /// # Ok(())
    /// # }
    /// ```
    /// [Decrypts]: https://docs.nitrokey.com/nethsm/operation#decrypt
    /// [symmetric key]: https://en.wikipedia.org/wiki/Symmetric-key_algorithm
    /// [asymmetric key]: https://en.wikipedia.org/wiki/Public-key_cryptography
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn decrypt(
        &self,
        key_id: &str,
        mode: DecryptMode,
        message: &[u8],
        iv: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        // the API requires data to be base64 encoded
        let encrypted = Base64::encode_string(message);
        let iv = iv.map(Base64::encode_string);

        // decode base64 encoded data from the API
        Base64::decode_vec(
            &keys_key_id_decrypt_post(
                &self.create_connection_config(),
                key_id,
                DecryptRequestData {
                    mode: mode.into(),
                    encrypted,
                    iv,
                },
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Decrypting message failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .decrypted,
        )
        .map_err(Error::Base64Decode)
    }

    /// Generates [random] bytes.
    ///
    /// Retrieves `length` [random] bytes from the NetHSM, if it is in
    /// [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving random bytes fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    ///
    /// // get 10 random bytes
    /// println!("{:#?}", nethsm.random(10)?);
    /// # Ok(())
    /// # }
    /// ```
    /// [random]: https://docs.nitrokey.com/nethsm/operation#random
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn random(&self, length: u32) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let base64_bytes = random_post(
            &self.create_connection_config(),
            RandomRequestData::new(length as i32),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Getting random bytes failed: {}",
                NetHsmApiError::from(error)
            ))
        })?
        .entity
        .random;
        Base64::decode_vec(&base64_bytes).map_err(Error::Base64Decode)
    }

    /// Creates an [OpenPGP certificate] for an existing key.
    ///
    /// The NetHSM key identified by `key_id` is used to issue required [binding signatures] (e.g.
    /// those for the [User ID] defined by `user_id`).
    /// Using `flags` it is possible to define the key's [capabilities] and with `created_at` to
    /// provide the certificate's creation time.
    /// The resulting [OpenPGP certificate] is returned as vector of bytes.
    ///
    /// To make use of the [OpenPGP certificate] (e.g. with
    /// [`openpgp_sign`][`NetHsm::openpgp_sign`]), it should be added as certificate for the key
    /// using [`import_key_certificate`][`NetHsm::import_key_certificate`].
    ///
    /// This call requires using a user in the [`Operator`][`UserRole::Operator`] [role], which
    /// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
    /// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating an [OpenPGP certificate] for a key fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    ///
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    ///
    /// // create an OpenPGP certificate for the key with ID "signing1"
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// assert!(!nethsm
    ///     .create_openpgp_cert(
    ///         "signing1",
    ///         OpenPgpKeyUsageFlags::default(),
    ///         "Test <test@example.org>",
    ///         SystemTime::now().into()
    ///     )?
    ///     .is_empty());
    /// # Ok(())
    /// # }
    /// ```
    /// [OpenPGP certificate]: https://openpgp.dev/book/certificates.html
    /// [binding signatures]: https://openpgp.dev/book/signing_components.html#binding-signatures
    /// [User ID]: https://openpgp.dev/book/glossary.html#term-User-ID
    /// [key certificate]: https://docs.nitrokey.com/nethsm/operation#key-certificates
    /// [capabilities]: https://openpgp.dev/book/glossary.html#term-Capability
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn create_openpgp_cert(
        &self,
        key_id: &str,
        flags: OpenPgpKeyUsageFlags,
        user_id: &str,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, Error> {
        openpgp::add_certificate(self, flags, key_id.into(), user_id, created_at)
    }

    /// Creates an [OpenPGP signature] for a message.
    ///
    /// Signs the `message` using the key identified by `key_id` and returns a binary [OpenPGP data
    /// signature].
    ///
    /// This call requires using a user in the [`Operator`][`UserRole::Operator`] [role], which
    /// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
    /// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
    ///
    /// ## Namespaces
    ///
    /// * [`Operator`][`UserRole::Operator`] users in a [namespace] only have access to keys in
    ///   their own [namespace].
    /// * System-wide [`Operator`][`UserRole::Operator`] users only have access to system-wide keys.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating an [OpenPGP signature] for the `message` fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * no key identified by `key_id` exists on the NetHSM
    /// * the [`Operator`][`UserRole::Operator`] user does not have access to the key (e.g.
    ///   different [namespace])
    /// * the [`Operator`][`UserRole::Operator`] user does not carry a tag matching one of the key
    ///   tags
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not those of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::time::SystemTime;
    ///
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     OpenPgpKeyUsageFlags,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".to_string()),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // tag system-wide user in Operator role for access to signing key
    /// nethsm.add_user_tag(&"operator1".parse()?, "tag1")?;
    /// // create an OpenPGP certificate for the key with ID "signing1"
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// let openpgp_cert = nethsm.create_openpgp_cert(
    ///     "signing1",
    ///     OpenPgpKeyUsageFlags::default(),
    ///     "Test <test@example.org>",
    ///     SystemTime::now().into(),
    /// )?;
    /// // import the OpenPGP certificate as key certificate
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.import_key_certificate("signing1", openpgp_cert)?;
    ///
    /// // create OpenPGP signature
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    /// assert!(!nethsm
    ///     .openpgp_sign("signing1", b"sample message")?
    ///     .is_empty());
    /// # Ok(()) }
    /// ```
    /// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
    /// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn openpgp_sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        openpgp::sign(self, key_id.into(), message)
    }
}
