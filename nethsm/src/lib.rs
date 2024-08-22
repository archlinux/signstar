//! A high-level library to interact with the API of a [Nitrokey NetHSM](https://docs.nitrokey.com/nethsm/)
//!
//! Provides high-level integration with a Nitrokey NetHSM and official container.
//! As this crate is a wrapper around [`nethsm_sdk_rs`] it covers all available actions from
//! provisioning, over key and user management to backup and restore.
//!
//! The NetHSM provides dedicated [user management](https://docs.nitrokey.com/nethsm/administration#user-management)
//! based on several roles (see [`UserRole`]) which can be used to separate concerns.
//!
//! The cryptographic key material on the device can be assigned to one or several [tags](https://docs.nitrokey.com/nethsm/operation#tags-for-keys).
//! Users in the "operator" role can be assigned to the same [tags](https://docs.nitrokey.com/nethsm/administration#tags-for-users)
//! to gain access to the keys.
//!
//! Apart from the crate specific documentation it is very recommended to read the canonical
//! upstream documentation as well: <https://docs.nitrokey.com/nethsm/>
//!
//! This crate re-exports the following [`nethsm_sdk_rs`] types so that the crate does not have to
//! be relied on directly:
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
//! Using the [`NetHsm`] struct it is possible to establish a TLS connection for multiple users.
//! TLS validation can be configured based on a variant of the [`ConnectionSecurity`] enum:
//! - [`ConnectionSecurity::Unsafe`]: The host certificate is not validated.
//! - [`ConnectionSecurity::Fingerprints`]: The host certificate is validated based on configurable
//!   fingerprints.
//! - [`ConnectionSecurity::Native`]: The host certificate is validated using the native Operating
//!   System trust store.
//!
//! # Examples
//!
//! ```
//! # use testresult::TestResult;
//! use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
//!
//! # fn main() -> TestResult {
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
pub use key::PrivateKeyImport;

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
    #[error("Loading system TLS certs failed")]
    CertLoading,

    /// A call to the NetHSM API failed
    #[error("NetHSM API error: {0}")]
    Api(String),

    /// Provided key data is invalid
    #[error("Key data invalid: {0}")]
    KeyData(String),

    /// Importing a key failed because of malformed data
    #[error("Key data is invalid: {0}")]
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

/// The URL used for connecting to a NetHSM instance
///
/// Wraps [`url::Url`] but offers stricter constraints. The URL
///
/// * must use https
/// * must have a host
/// * must not contain a password, user or query
#[derive(Clone, Debug, Serialize)]
pub struct Url(url::Url);

impl Url {
    /// Creates a new Url
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

/// A network connection to a NetHSM
///
/// Defines a network configuration for the connection and a list of user credentials that can be
/// used over this connection.
pub struct NetHsm {
    /// The agent for the requests
    agent: RefCell<Agent>,
    /// The URL path for the target API
    url: RefCell<Url>,
    /// The default credentials to use for requests
    current_credentials: RefCell<Option<UserId>>,
    /// The list of all available credentials
    credentials: RefCell<HashMap<UserId, Credentials>>,
}

impl NetHsm {
    /// Creates a new NetHSM connection
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
                    let mut roots = rustls::RootCertStore::empty();
                    let native_certs = rustls_native_certs::load_native_certs().map_err(|err| {
                        error!("Failed to load certificates: {err}");
                        Error::CertLoading
                    })?;

                    let (added, failed) = roots.add_parsable_certificates(native_certs);
                    debug!("Added {added} certificates and failed to parse {failed} certificates");

                    if added == 0 {
                        error!("Added no native certificates");
                        return Err(Error::CertLoading);
                    }

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

    /// Validates the potential [namespace] access of a context
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

    /// Creates a connection configuration
    ///
    /// Uses the [`Agent`] configured during creation of the [`NetHsm`], the current [`Url`] and
    /// [`Credentials`] to create a [`Configuration`] for a connection to the API of a NetHSM
    /// device.
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

    /// Sets the URL for the NetHSM connection
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Error, NetHsm, Url};
    ///
    /// # fn main() -> TestResult {
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

    /// Adds credentials to the list of available credentials
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
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

    /// Removes credentials from the list of available and currently used ones
    ///
    /// Removes credentials from the list of available credentials and if identical unsets the
    /// credentials for current authentication as well.
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
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

    /// Sets credentials to use for the next connection
    ///
    /// # Errors
    ///
    /// An [`Error`] is returned if no credentials with the User ID `user_id` can be found.
    ///
    /// # Examples
    ///
    /// ```
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
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

    /// Provisions a NetHSM
    ///
    /// [Provisioning](https://docs.nitrokey.com/nethsm/getting-started#provisioning) is the initial setup step for a device.
    /// It sets the `unlock_passphrase` which is used for unlocking a device that is using attended
    /// boot (see [`BootMode::Attended`]), the initial `admin_passphrase` for the default
    /// administrator account ("admin") and the `system_time`.
    /// The unlock passphrase can later on be changed using [`NetHsm::set_unlock_passphrase`] and
    /// the admin passphrase using [`NetHsm::set_user_passphrase`].
    ///
    /// For this call no credentials are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if provisioning fails:
    /// * the device is not in state [`SystemState::Unprovisioned`]
    /// * the provided data is malformed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use chrono::Utc;
    /// use nethsm::{ConnectionSecurity, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // provision the device
    /// nethsm.provision(
    ///     Passphrase::new("unlock-the-device".to_string()),
    ///     Passphrase::new("admin-passphrase".to_string()),
    ///     Utc::now(),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns whether the NetHSM is in [`SystemState::Unprovisioned`] or [`SystemState::Locked`]
    ///
    /// For this call no credentials are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the information can not be retrieved or the device is in
    /// [`SystemState::Operational`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Error, NetHsm};
    ///
    /// # fn main() -> TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // check whether the device is locked or unprovisioned
    /// assert!(nethsm.alive().is_ok());
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns whether the NetHSM is in [`SystemState::Operational`]
    ///
    /// For this call no credentials are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the information can not be retrieved or the device is in
    /// [`SystemState::Unprovisioned`] or [`SystemState::Locked`].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Error, NetHsm};
    ///
    /// # fn main() -> TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // check whether the device is operational
    /// assert!(nethsm.ready().is_ok());
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns the system state of the NetHSM instance
    ///
    /// Returns a variant of [`SystemState`], which describes the [state](https://docs.nitrokey.com/nethsm/administration#state) a device is currently in.
    ///
    /// For this call no credentials are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the state information can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Error, NetHsm};
    ///
    /// # fn main() -> TestResult {
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

    /// Returns device information for the NetHSM instance
    ///
    /// Returns an [`InfoData`], which provides the [device information](https://docs.nitrokey.com/nethsm/administration#device-information).
    ///
    /// For this call no credentials are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the device information can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Error, NetHsm};
    ///
    /// # fn main() -> TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the device info
    /// println!("{:?}", nethsm.info()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns metrics for the NetHSM instance
    ///
    /// Returns a [`serde_json::Value`] which provides [metrics](https://docs.nitrokey.com/nethsm/administration#metrics) for the device.
    ///
    /// This call requires using credentials of a user in the "metrics" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the device metrics can not be retrieved:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "metrics" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "metrics" role
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

    /// Sets the unlock passphrase for the NetHSM instance
    ///
    /// Sets `current_passphrase` to `new_passphrase`, which changes the [unlock passphrase](https://docs.nitrokey.com/nethsm/administration#unlock-passphrase) for the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the unlock passphrase can not be changed:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `current_passphrase` is not correct
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // set the unlock passphrase
    /// nethsm.set_unlock_passphrase(
    ///     Passphrase::new("current-unlock-passphrase".to_string()),
    ///     Passphrase::new("new-unlock-passphrase".to_string()),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns the boot mode
    ///
    /// Returns a variant of [`BootMode`] which represents the device's [boot mode](https://docs.nitrokey.com/nethsm/administration#boot-mode).
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the boot mode can not be retrieved:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // retrieve the boot mode
    /// println!("{:?}", nethsm.get_boot_mode()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Sets the boot mode
    ///
    /// Sets the device's [boot mode](https://docs.nitrokey.com/nethsm/administration#boot-mode) based on a [`BootMode`] variant.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the boot mode can not be set:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{BootMode, ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // set the boot mode to unattended
    /// nethsm.set_boot_mode(BootMode::Unattended)?;
    ///
    /// // set the boot mode to attended
    /// nethsm.set_boot_mode(BootMode::Attended)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns the TLS public key of the API
    ///
    /// Returns the device's public key part of its [TLS certificate](https://docs.nitrokey.com/nethsm/administration#tls-certificate)
    /// which is used for communication with the API.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the device's TLS public key can not be retrieved:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get the TLS public key
    /// println!("{}", nethsm.get_tls_public_key()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns the TLS certificate of the API
    ///
    /// Returns the device's [TLS certificate](https://docs.nitrokey.com/nethsm/administration#tls-certificate) which is used for communication with the API.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the device's TLS certificate can not be retrieved:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get the TLS certificate
    /// println!("{}", nethsm.get_tls_cert()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Returns a Certificate Signing Request (CSR) for the API's TLS certificate
    ///
    /// Based on data from an instance of [`nethsm_sdk_rs::models::DistinguishedName`] returns a
    /// [Certificate Signing Request (CSR)](https://en.wikipedia.org/wiki/Certificate_signing_request)
    /// in [PKCS#10](https://en.wikipedia.org/wiki/Certificate_signing_request#Structure_of_a_PKCS_#10_CSR) format
    /// for the device's [TLS certificate](https://docs.nitrokey.com/nethsm/administration#tls-certificate)
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the CSR can not be retrieved:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, DistinguishedName, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get the CSR for TLS certificate
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
    /// # Ok(())
    /// # }
    /// ```
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

    /// Generates a new TLS certificate for the API
    ///
    /// Based on `tls_key_type` and `length` generates a new
    /// [TLS certificate](https://docs.nitrokey.com/nethsm/administration#tls-certificate)
    /// (used for communication with the API).
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the new TLS certificate can not be generated:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the `tls_key_type` and `length` combination is not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, TlsKeyType};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // generate a new TLS certificate
    /// nethsm.generate_tls_cert(TlsKeyType::Rsa, Some(4096))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_tls_cert(
        &self,
        tls_key_type: TlsKeyType,
        length: Option<i32>,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_tls_generate_post(
            &self.create_connection_config(),
            TlsKeyGenerateRequestData {
                r#type: tls_key_type.into(),
                length,
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

    /// Sets a new TLS certificate for the API
    ///
    /// Accepts a Base64 encoded [DER](https://en.wikipedia.org/wiki/X.690#DER_encoding) certificate via `certificate`
    /// which is added as new [TLS certificate](https://docs.nitrokey.com/nethsm/administration#tls-certificate) for
    /// communication with the API.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting a new TLS certificate fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `certificate` is not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // set a new TLS certificate
    /// nethsm.set_tls_cert(cert)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets the network configuration
    ///
    /// Retrieves the [network configuration](https://docs.nitrokey.com/nethsm/administration#network) of the device in
    /// the form of a [`nethsm_sdk_rs::models::NetworkConfig`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving network configuration fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get the network configuration
    /// println!("{:?}", nethsm.get_network()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Sets the network configuration
    ///
    /// Sets the [network configuration](https://docs.nitrokey.com/nethsm/administration#network) of the device based on
    /// a [`nethsm_sdk_rs::models::NetworkConfig`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the network configuration fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `network_config` is not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, NetworkConfig, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// let network_config = NetworkConfig::new(
    ///     "192.168.1.1".to_string(),
    ///     "255.255.255.0".to_string(),
    ///     "0.0.0.0".to_string(),
    /// );
    ///
    /// // set the network configuration
    /// nethsm.set_network(network_config)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets the device's time
    ///
    /// Retrieves the current [time](https://docs.nitrokey.com/nethsm/administration#time) of the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving time fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get the time
    /// println!("{:?}", nethsm.get_time()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_time(&self) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_time_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting device time failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .time)
    }

    /// Sets the device's time
    ///
    /// Sets the [time](https://docs.nitrokey.com/nethsm/administration#time) for the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting time fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `time` is not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use chrono::Utc;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// let time = Utc::now();
    /// // set the time
    /// nethsm.set_time(time)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_time(&self, time: DateTime<Utc>) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_time_put(
            &self.create_connection_config(),
            TimeConfig::new(time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting device time failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets the logging configuration
    ///
    /// Retrieves the current [logging configuration](https://docs.nitrokey.com/nethsm/administration#logging) of the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting logging configuration fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get logging configuration
    /// println!("{:?}", nethsm.get_logging()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Sets the logging configuration
    ///
    /// Sets the device's [logging configuration](https://docs.nitrokey.com/nethsm/administration#logging).
    /// A host to send logs to is defined with `ip_address` and `port`. The log level is configured
    /// using `log_level`.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the logging configuration fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `ip_address`, `port` or `log_level` are not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use std::net::Ipv4Addr;
    ///
    /// use nethsm::{ConnectionSecurity, Credentials, Error, LogLevel, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // set logging configuration
    /// println!(
    ///     "{:?}",
    ///     nethsm.set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)?
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_logging(
        &self,
        ip_address: Ipv4Addr,
        port: i32,
        log_level: LogLevel,
    ) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        let ip_address = ip_address.to_string();
        config_logging_put(
            &self.create_connection_config(),
            LoggingConfig::new(ip_address, port, log_level.into()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting logging config failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Sets the backup passphrase
    ///
    /// Sets `current_passphrase` to `new_passphrase`, which changes the [backup](https://docs.nitrokey.com/nethsm/administration#backup) passphrase for the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the backup passphrase fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `current_passphrase` is not correct
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // set the backup passphrase
    /// nethsm.set_backup_passphrase(
    ///     Passphrase::new("current-backup-passphrase".to_string()),
    ///     Passphrase::new("new-backup-passphrase".to_string()),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Creates a backup
    ///
    /// Triggers the creation and download of a [backup](https://docs.nitrokey.com/nethsm/administration#backup) of the device.
    /// Before creating a backup, [`NetHsm::set_backup_passphrase`] has to be called once to set a
    /// passphrase for the backup.
    ///
    /// This call requires using credentials of a user in the "backup" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating a backup fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "backup" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use std::path::PathBuf;
    ///
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // create a backup and write it to file
    /// let backup_file = PathBuf::from("nethsm.bkp");
    /// std::fs::write(backup_file, nethsm.backup()?)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Triggers a factory reset
    ///
    /// Triggers a [factory reset](https://docs.nitrokey.com/nethsm/administration#reset-to-factory-defaults) for the device.
    /// This action deletes all user and system data! Make sure to create a backup using
    /// [`NetHsm::backup`] first!
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if resetting the device fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // trigger a factory reset
    /// nethsm.factory_reset()?;
    /// assert_eq!(nethsm.state()?, SystemState::Unprovisioned);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Restores device from backup
    ///
    /// WARNING: This function has known issues and may in fact not work! <https://github.com/Nitrokey/nethsm/issues/5>
    ///
    /// [Restores](https://docs.nitrokey.com/nethsm/administration#restore) a device from a
    /// [backup](https://docs.nitrokey.com/nethsm/administration#backup), by providing a
    /// `backup_passphrase` (set using [`NetHsm::set_backup_passphrase`]) a new `system_time` for
    /// the device and a backup (created using [`NetHsm::backup`]).
    /// The device may be in state [`SystemState::Operational`] or [`SystemState::Unprovisioned`].
    /// Any existing user data is safely removed and replaced by that of the backup. If the
    /// device is in state [`SystemState::Unprovisioned`] the system configuration from the
    /// backup is also used and the device is rebooted.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if restoring the device from backup fails:
    /// * the device is not in state [`SystemState::Operational`] or [`SystemState::Unprovisioned`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use std::path::PathBuf;
    ///
    /// use chrono::Utc;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// #
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // restore from backup
    /// let backup_file = PathBuf::from("nethsm.bkp");
    /// let backup = std::fs::read(backup_file)?;
    /// nethsm.restore(
    ///     Passphrase::new("backup-passphrase".to_string()),
    ///     Utc::now(),
    ///     backup,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Locks the device
    ///
    /// Locks the device and sets its [state](https://docs.nitrokey.com/nethsm/administration#state) to [`SystemState::Locked`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if locking the device fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // lock the device
    /// nethsm.lock()?;
    /// assert_eq!(nethsm.state()?, SystemState::Locked);
    /// # Ok(())
    /// # }
    /// ```
    pub fn lock(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        lock_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Locking device failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Unlocks the device
    ///
    /// If the device is in state [`SystemState::Locked`] unlocks the device using
    /// `unlock_passphrase` and sets its [state](https://docs.nitrokey.com/nethsm/administration#state) to [`SystemState::Operational`].
    ///
    /// For this call no credentials are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if unlocking the device fails:
    /// * the device is not in state [`SystemState::Locked`]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Locked);
    /// // unlock the device
    /// nethsm.unlock(Passphrase::new("unlock-passphrase".to_string()))?;
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// # Ok(())
    /// # }
    /// ```
    pub fn unlock(&self, unlock_passphrase: Passphrase) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        unlock_post(
            &self.create_connection_config(),
            UnlockRequestData::new(unlock_passphrase.expose_owned()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Unlocking device failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Retrieves system information of a device
    ///
    /// Returns a [`SystemInfo`] which contains various pieces of information such as software
    /// version, software build, firmware version, hardware version, device ID and information on
    /// TPM related components such as attestation key and relevant PCR values.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving the system information fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // retrieve system information of the device
    /// println!("{:?}", nethsm.system_info()?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Reboots the device
    ///
    /// [Reboots](https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown) the device,
    /// if it is in state [`SystemState::Operational`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if rebooting the device fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // reboot the device
    /// nethsm.reboot()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn reboot(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_reboot_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Rebooting device failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Shuts down the device
    ///
    /// [Shuts down](https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown) the device,
    /// if it is in state [`SystemState::Operational`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if shutting down the device fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // shut down the device
    /// nethsm.shutdown()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn shutdown(&self) -> Result<(), Error> {
        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_shutdown_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Shutting down device failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Uploads a software update
    ///
    /// WARNING: This function has shown flaky behavior during tests with the official container!
    /// Upload may have to be repeated!
    ///
    /// Uploads a [software update](https://docs.nitrokey.com/nethsm/administration#software-update) to the device,
    /// if it is in state [`SystemState::Operational`] and returns information about the software
    /// update ([`nethsm_sdk_rs::models::SystemUpdateData`]).
    /// Software updates can successively be installed ([`NetHsm::commit_update`]) or canceled
    /// ([`NetHsm::cancel_update`]).
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if uploading the software update fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// let update_file = std::path::PathBuf::from("update.bin");
    /// let update = std::fs::read(update_file)?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // upload software update to device
    /// println!("{:?}", nethsm.upload_update(update)?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Commits an uploaded software update
    ///
    /// Commits a [software update](https://docs.nitrokey.com/nethsm/administration#software-update)
    /// previously uploaded to the device (e.g. using [`NetHsm::upload_update`]), if the device is
    /// in state [`SystemState::Operational`].
    /// Successfully committing a software update leads to the reboot of the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if committing the software update fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * there is no software update to commit
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// let update_file = std::path::PathBuf::from("update.bin");
    /// let update = std::fs::read(update_file)?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // upload software update to device
    /// println!("{:?}", nethsm.upload_update(update)?);
    /// // commit software update
    /// nethsm.commit_update()?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Cancels an uploaded software update
    ///
    /// Cancels a [software update](https://docs.nitrokey.com/nethsm/administration#software-update)
    /// previously uploaded to the device (e.g. using [`NetHsm::upload_update`]), if the device is
    /// in state [`SystemState::Operational`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if canceling the software update fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * there is no software update to cancel
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// let update_file = std::path::PathBuf::from("update.bin");
    /// let update = std::fs::read(update_file)?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // upload software update to device
    /// println!("{:?}", nethsm.upload_update(update)?);
    /// // cancel software update
    /// nethsm.cancel_update()?;
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Adds a new namespace
    ///
    /// Adds a new [namespace] with the ID `namespace_id`.
    ///
    /// **WARNING**: A user in the [`Administrator`][`UserRole::Administrator`] [role] must be added
    /// for the [namespace] using [`add_user`][`NetHsm::add_user`] **before** creating the
    /// [namespace]! Otherwise there is no user to administrate the new [namespace]!
    ///
    /// This call requires using credentials of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the namespace fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the namespace identified by `namespace_id` exists already
    /// * the used credentials are not correct
    /// * the used credentials are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> TestResult {
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

    /// Gets all available [namespaces]
    ///
    /// This call requires using credentials of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the namespaces fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> TestResult {
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

    /// Deletes an existing [namespace]
    ///
    /// Deletes the [namespace] identified by `namespace_id`.
    ///
    /// **WARNING**: This call deletes the [namespace] and all keys in it! Make sure to create a
    /// [`backup`][`NetHsm::backup`]!
    ///
    /// This call requires using credentials of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the namespace fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the [namespace] identified by `namespace_id` does not exist
    /// * the used credentials are not correct
    /// * the used credentials are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> TestResult {
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

    /// Adds a new user on the device
    ///
    /// [Adds a user](https://docs.nitrokey.com/nethsm/administration#add-user)
    /// on the device, if the device is in state [`SystemState::Operational`] and returns the User
    /// ID of the created user.
    /// A new user is created by providing a `real_name` from which a User ID is derived (optionally
    /// a User ID can be provided with `user_id`), a `role` which describes the user's access rights
    /// on the device (see [`UserRole`]) and a `passphrase`.
    ///
    /// Internally, this function also calls [`NetHsm::add_credentials`] to add the new user to the
    /// list of available credentials.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided `real_name`, `passphrase` or `user_id` are not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserId, UserRole};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // add a user in the operator role
    /// assert_eq!(
    ///     UserId::new("user1".to_string())?,
    ///     nethsm.add_user(
    ///         "Operator One".to_string(),
    ///         UserRole::Operator,
    ///         Passphrase::new("operator1-passphrase".to_string()),
    ///         Some("user1".parse()?),
    ///     )?
    /// );
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
    /// # Ok(())
    /// # }
    /// ```
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

    /// Deletes a user from the device
    ///
    /// [Deletes a user](https://docs.nitrokey.com/nethsm/administration#delete-user)
    /// from the device based on `user_id`.
    ///
    /// Internally, this function also calls [`NetHsm::remove_credentials`] to remove the user from
    /// the list of available credentials.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting a user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the user identified by `user_id` does not exist
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserId, UserRole};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // add a user in the operator role
    /// assert_eq!(
    ///     UserId::new("user1".to_string())?,
    ///     nethsm.add_user(
    ///         "Operator One".to_string(),
    ///         UserRole::Operator,
    ///         Passphrase::new("operator1-passphrase".to_string()),
    ///         Some("user1".parse()?),
    ///     )?
    /// );
    ///
    /// // delete the user again
    /// nethsm.delete_user(&"user1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets a list of all User IDs on the device
    ///
    /// Gets a [list of all User IDs](https://docs.nitrokey.com/nethsm/administration#list-users)
    /// on the device.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving the list of all User IDs fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get all User IDs... at a minimum the "admin" user should be there!
    /// assert!(nethsm.get_users()?.contains(&"admin".to_string()));
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets information of a user on the device
    ///
    /// Gets [information of a user](https://docs.nitrokey.com/nethsm/administration#list-users)
    /// on the device and returns it as a [`UserData`].
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving information of the user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the user identified by `user_id` does not exist
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get user information
    /// println!("{:?}", nethsm.get_user(&"admin".parse()?)?);
    ///
    /// // this fails as the user does not exist
    /// assert!(nethsm.get_user(&"user1".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
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

    /// Sets the passphrase for a user on the device
    ///
    /// Sets the [passphrase for a user](https://docs.nitrokey.com/nethsm/administration#user-passphrase)
    /// on the device.
    ///
    /// Internally, this function also calls [`NetHsm::add_credentials`] to add the updated user
    /// credentials to the list of available credentials.
    /// If the calling user in the "admin" role changes their own passphrase, additionally
    /// [`NetHsm::use_credentials`] is called to use the updated passphrase.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the passphrase for the user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the user identified by `user_id` does not exist
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // set the admin user's passphrase
    /// nethsm.set_user_passphrase(
    ///     "admin".parse()?,
    ///     Passphrase::new("new-admin-passphrase".to_string()),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Adds a tag to a user in the operator role
    ///
    /// [Adds a tag](https://docs.nitrokey.com/nethsm/administration#tags-for-users)
    /// to a user in the "operator" role. A tag provides a user in the "operator" role with access
    /// to keys on the device associated with that same tag. The tag must have been set for a
    /// key on the device beforehand (e.g. using [`NetHsm::add_key_tag`]).
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the tag for the user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the "operator" role
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserId, UserRole};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // add a user in the operator role
    /// assert_eq!(
    ///     UserId::new("user1".to_string())?,
    ///     nethsm.add_user(
    ///         "Operator One".to_string(),
    ///         UserRole::Operator,
    ///         Passphrase::new("operator1-passphrase".to_string()),
    ///         Some("user1".parse()?),
    ///     )?
    /// );
    ///
    /// // add a tag for the user
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Deletes a tag from a user in the operator role
    ///
    /// [Deletes a tag](https://docs.nitrokey.com/nethsm/administration#tags-for-users)
    /// from a user in the "operator" role. Removing a tag from a user in the "operator" role
    /// removes its access to any key on the device that has the same tag.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the tag from the user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the "operator" role
    /// * the user identified by `user_id` does not have `tag`
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // add a tag for the user
    /// nethsm.delete_user_tag(&"user1".parse()?, "tag1")?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets all tags on a user in the operator role
    ///
    /// [Gets all tags](https://docs.nitrokey.com/nethsm/administration#tags-for-users)
    /// of a user in the operator role.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the tags for the user fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the "operator" role
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, UserId, UserRole};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // add a user in the operator role
    /// assert_eq!(
    ///     UserId::new("user1".to_string())?,
    ///     nethsm.add_user(
    ///         "Operator One".to_string(),
    ///         UserRole::Operator,
    ///         Passphrase::new("operator1-passphrase".to_string()),
    ///         Some("user1".parse()?),
    ///     )?
    /// );
    ///
    /// assert!(nethsm.get_user_tags(&"user1".parse()?)?.is_empty());
    ///
    /// // add a tag for the user
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    ///
    /// assert!(nethsm
    ///     .get_user_tags(&"user1".parse()?)?
    ///     .contains(&"tag1".to_string()));
    /// # Ok(())
    /// # }
    /// ```
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

    /// Generates a new key on the device
    ///
    /// [Generates a new key](https://docs.nitrokey.com/nethsm/operation#generate-key)
    /// with custom features on the device.
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
    /// Optionally the key bit-length (using `length`), a custom key ID using `key_id`
    /// and a list of tags to be attached to the new key (using `tags`) can be provided.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if generating the key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided combination of `key_type` and `mechanisms` is not valid
    /// * a key identified by ` key_id` exists already
    /// * the chosen `length` or `tags` options are not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     Error,
    ///     KeyMechanism,
    ///     KeyType,
    ///     NetHsm,
    ///     Passphrase,
    /// };
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    ///     Some(4096),
    ///     Some("encryption1".to_string()),
    ///     Some(vec!["encryption_tag1".to_string()]),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn generate_key(
        &self,
        key_type: KeyType,
        mechanisms: Vec<KeyMechanism>,
        length: Option<i32>,
        key_id: Option<String>,
        tags: Option<Vec<String>>,
    ) -> Result<String, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        // ensure the key_type - mechanisms combinations are valid
        key_type.matches_mechanisms(&mechanisms)?;

        Ok(keys_generate_post(
            &self.create_connection_config(),
            KeyGenerateRequestData {
                mechanisms: mechanisms
                    .into_iter()
                    .map(|mechanism| mechanism.into())
                    .collect(),
                r#type: key_type.into(),
                length,
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

    /// Imports an existing private key
    ///
    /// [Imports an existing key](https://docs.nitrokey.com/nethsm/operation#import-key)
    /// with custom features into the device.
    /// The [`KeyType`] implied by the provided [`PrivateKeyImport`] and list of [`KeyMechanism`]s
    /// have to match:
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
    /// Optionally a custom Key ID using `key_id` and a list of tags to be attached to the new key
    /// (using `tags`) can be provided.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if importing the key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the provided combination of `key_type` and `mechanisms` is not valid
    /// * the provided combination of `key_type` and `key_data` is not valid
    /// * a key identified by ` key_id` exists already
    /// * the chosen `tags` option is not valid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, PrivateKeyImport, KeyMechanism, KeyType, NetHsm, Passphrase};
    /// use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
    /// use rsa::RsaPrivateKey;
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
        key_type.matches_mechanisms(&mechanisms)?;

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

    /// Deletes a key from the device
    ///
    /// [Deletes a key](https://docs.nitrokey.com/nethsm/operation#delete-key)
    /// from the device based on a Key ID provided using `key_id`.
    ///
    /// This call requires using credentials of a user in the "admin" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// assert!(nethsm.delete_key("signing1").is_ok());
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets details of a key
    ///
    /// [Gets details of a key](https://docs.nitrokey.com/nethsm/operation#show-key-details)
    /// from the device based on a Key ID provided using `key_id`.
    ///
    /// This call requires using credentials of a user in the "admin" or "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the key details fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * the used credentials are not correct
    /// * the used credentials are not those of a user in the "admin" or "operator" role
    /// * a user in the "operator" role lacks access to the key
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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

    /// Gets a list of Key IDs on the device
    ///
    /// [Gets a list of Key IDs](https://docs.nitrokey.com/nethsm/operation#list-keys)
    /// from the device.
    /// Optionally `filter` can be provided for matching against Key IDs.
    ///
    /// This call requires using credentials of a user in the "admin" or "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the list of Key IDs fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not those of a user in the "admin" or "operator" role
    /// * a user in the "operator" role lacks access to the key
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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

    /// Gets the public key of a key on the device
    ///
    /// [Gets the public key of a key](https://docs.nitrokey.com/nethsm/operation#show-key-details)
    /// on the device specified by `key_id`.
    /// The public key is returned in [X.509] Privacy-Enhanced Mail ([PEM]) format.
    ///
    /// This call requires using credentials of a user in the "admin" or "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the public key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" or "operator" role
    /// * a user in the "operator" role lacks access to the key
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get public key for a key with Key ID "signing1"
    /// println!("{:?}", nethsm.get_public_key("signing1")?);
    /// # Ok(())
    /// # }
    /// ```
    /// [X.509]: https://en.wikipedia.org/wiki/X.509
    /// [PEM]: https://en.wikipedia.org/wiki/Privacy-Enhanced_Mail
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

    /// Adds a tag to a key on the device
    ///
    /// [Adds a tag to a key](https://docs.nitrokey.com/nethsm/operation#tags-for-keys)
    /// on the device.
    /// The key is specified by `key_id` and the tag using `tag`.
    ///
    /// Afterwards the same `tag` can be associated with a user in the "operator" role, using
    /// [`NetHsm::add_user_tag`] to provide the user access to the respective key(s).
    ///
    /// This call requires using credentials of a user in the "admin"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * `tag` is already associated with the key
    /// * `tag` is invalid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" or "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // add the tag "important" to a key with Key ID "signing1"
    /// nethsm.add_key_tag("signing1", "important")?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Deletes a tag from a key on the device
    ///
    /// [Deletes a tag from a key](https://docs.nitrokey.com/nethsm/operation#tags-for-keys)
    /// on the device. Any user in the "operator" role that has the same tag will lose access to the
    /// affected key.
    ///
    /// This call requires using credentials of a user in the "admin"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * `tag` is not associated with the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" or "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // remove the tag "important" from a key with Key ID "signing1"
    /// nethsm.delete_key_tag("signing1", "important")?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Imports a certificate for a key
    ///
    /// [Imports a certificate](https://docs.nitrokey.com/nethsm/operation#key-certificates)
    /// and associates it with a key on the device.
    /// Certificates are supported as the following MIME types:
    /// * *application/x-pem-file*
    /// * *application/x-x509-ca-cert*
    /// * *application/pgp-keys*
    ///
    /// This call requires using credentials of a user in the "admin"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * the `data` is invalid
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// let cert_data = r#"
    /// -----BEGIN CERTIFICATE-----
    /// MIICeTCCAWECFCbuzdkAvc3Zx3W53IoSnmhUen42MA0GCSqGSIb3DQEBCwUAMHsx
    /// CzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjER
    /// MA8GA1UECgwITml0cm9rZXkxFTATBgNVBAMMDG5pdHJva2V5LmNvbTEgMB4GCSqG
    /// SIb3DQEJARYRaW5mb0BuaXRyb2tleS5jb20wHhcNMjIwODMwMjAxMzA2WhcNMjMw
    /// ODMwMjAxMzA2WjBxMW8wCQYDVQQGEwJERTANBgNVBAcMBkJlcmxpbjANBgNVBAgM
    /// BkJlcmxpbjAPBgNVBAoMCE5pdHJva2V5MBMGA1UEAwwMbml0cm9rZXkuY29tMB4G
    /// CSqGSIb3DQEJARYRaW5mb0BuaXRyb2tleS5jb20wKjAFBgMrZXADIQDc58LGDY9B
    /// wbJFdXTiDalNXrDC60Sxu3eHcpnh1MSoCjANBgkqhkiG9w0BAQsFAAOCAQEAGip8
    /// aU5nJnzm3eic3t1ihUA3VJ0mAPyfrb1Rn8tEKOZo3vg0jpRd9CSESlBsKqhvxsdQ
    /// A3eomM+W7R37TL5+ISm5QrbijLHz3OHoPM68c1Krz3bXTkJetf4YAxpLOPYfXXHv
    /// weRzwVJb4y3E0lJGhZxI3sUE8Yn/T1UvTbu/o/O5P/XTA8vfFrSNQkQxWBgYh4gC
    /// KjFFALqUPFrctSFIi34aqpdihNJWnjSS2Y7INm3oxwkR3NMKP8x4wBGfZK22nHnu
    /// PPzXuMGJTmQM8GHTzltNvLx5Iv2sXoSHClXSpdIT5IBIcR1GmZ78fmcr75OAU0+z
    /// 3XbJq/1ij3tKsjV6WA==
    /// -----END CERTIFICATE-----
    /// "#
    /// .to_string();
    ///
    /// // import a certificate for a key with Key ID "signing1"
    /// nethsm.import_key_certificate("signing1", cert_data.into_bytes())?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets the certificate associated with a key
    ///
    /// [Gets the certificate](https://docs.nitrokey.com/nethsm/operation#key-certificates)
    /// associated with a key on the device.
    ///
    /// This call requires using credentials of a user in the "admin" or "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * no certificate is associated with the key
    /// * the user lacks access to the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" or "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get the certificate associated with a key
    /// println!("{:?}", nethsm.get_key_certificate("signing1")?);
    /// # Ok(())
    /// # }
    /// ```
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

    /// Deletes the certificate associated with a key
    ///
    /// [Deletes a certificate](https://docs.nitrokey.com/nethsm/operation#key-certificates)
    /// associated with a key on the device.
    ///
    /// This call requires using credentials of a user in the "admin"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * no certificate is associated with the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // delete a certificate for a key with Key ID "signing1"
    /// nethsm.delete_key_certificate("signing1")?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets a Certificate Signing Request (CSR) for a key
    ///
    /// Based on data from an instance of [`nethsm_sdk_rs::models::DistinguishedName`] returns a
    /// [Certificate Signing Request (CSR)](https://en.wikipedia.org/wiki/Certificate_signing_request)
    /// in [PKCS#10](https://en.wikipedia.org/wiki/Certificate_signing_request#Structure_of_a_PKCS_#10_CSR) format
    /// for [a certificate](https://docs.nitrokey.com/nethsm/operation#key-certificate-signing-requests)
    /// associated with a key on the device.
    ///
    /// This call requires using credentials of a user in the "admin" or "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding a tag to a key fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists
    /// * no certificate is associated with the key
    /// * the user lacks access to the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "admin" or "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, DistinguishedName, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "admin" role
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
    /// // get a CSR for a certificate associated with a key
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

    /// Signs a digest using a key
    ///
    /// [Signs](https://docs.nitrokey.com/nethsm/operation#sign) a `digest` using a key
    /// identified by `key_id`.
    ///
    /// The digest must be of appropriate type depending on the type of the signature.
    ///
    /// The returned data depends on the chosen [`SignatureType`]:
    ///
    /// * [`SignatureType::Pkcs1`] returns the PKCS1 padded signature (no signature algorithm OID
    ///   prepended, since the used hash is not known).
    /// * [`SignatureType::PssMd5`], [`SignatureType::PssSha1`], [`SignatureType::PssSha224`],
    ///   [`SignatureType::PssSha256`], [`SignatureType::PssSha384`] and
    ///   [`SignatureType::PssSha512`] return the [EMSA-PSS](https://en.wikipedia.org/wiki/PKCS_1) encoded signature.
    /// * [`SignatureType::EdDsa`] returns the encoding as specified in [RFC 8032 (5.1.6)](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6)
    ///   (`r` appended with `s` (each 32 bytes), in total 64 bytes).
    /// * [`SignatureType::EcdsaP224`], [`SignatureType::EcdsaP256`], [`SignatureType::EcdsaP384`]
    ///   and [`SignatureType::EcdsaP521`] return the [ASN.1](https://en.wikipedia.org/wiki/ASN.1) DER encoded signature (a sequence of
    ///   integer `r` and integer `s`).
    ///
    /// This call requires using credentials of a user in the "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if signing the message fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists on the device
    /// * the chosen [`SignatureType`] is incompatible with the targeted key
    /// * the user lacks access to the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SignatureType};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "operator" role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "operator".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // create an ed25519 signature
    /// // this assumes the key with Key ID "signing1" is of type KeyType::Curve25519
    /// println!(
    ///     "{:?}",
    ///     nethsm.sign_digest("signing1", SignatureType::EdDsa, &[0, 1, 2])?
    /// );
    /// # Ok(())
    /// # }
    /// ```
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

    /// Signs a message using a key
    ///
    /// [Signs](https://docs.nitrokey.com/nethsm/operation#sign) a `message` using a key
    /// identified by `key_id` and a specific `signature_type`.
    ///
    /// The `message` does not have to be hashed, as this function takes care of this based on the
    /// provided [`SignatureType`].
    ///
    /// The returned data depends on the chosen [`SignatureType`]:
    ///
    /// * [`SignatureType::Pkcs1`] returns the PKCS1 padded signature (no signature algorithm OID
    ///   prepended, since the used hash is not known).
    /// * [`SignatureType::PssMd5`], [`SignatureType::PssSha1`], [`SignatureType::PssSha224`],
    ///   [`SignatureType::PssSha256`], [`SignatureType::PssSha384`] and
    ///   [`SignatureType::PssSha512`] return the [EMSA-PSS](https://en.wikipedia.org/wiki/PKCS_1) encoded signature.
    /// * [`SignatureType::EdDsa`] returns the encoding as specified in [RFC 8032 (5.1.6)](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.6)
    ///   (`r` appended with `s` (each 32 bytes), in total 64 bytes).
    /// * [`SignatureType::EcdsaP224`], [`SignatureType::EcdsaP256`], [`SignatureType::EcdsaP384`]
    ///   and [`SignatureType::EcdsaP521`] return the [ASN.1](https://en.wikipedia.org/wiki/ASN.1) DER encoded signature (a sequence of
    ///   integer `r` and integer `s`).
    ///
    /// This call requires using credentials of a user in the "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if signing the message fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists on the device
    /// * the chosen [`SignatureType`] is incompatible with the targeted key
    /// * the user lacks access to the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, Error, NetHsm, Passphrase, SignatureType};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "operator" role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "operator".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // create an ed25519 signature
    /// // this assumes the key with Key ID "signing1" is of type KeyType::Curve25519
    /// println!(
    ///     "{:?}",
    ///     nethsm.sign("signing1", SignatureType::EdDsa, b"message")?
    /// );
    /// # Ok(())
    /// # }
    /// ```
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

    /// Encrypts a message using a symmetric key
    ///
    /// [Encrypts](https://docs.nitrokey.com/nethsm/operation#encrypt) a `message` using a *symmetric* key
    /// identified by `key_id`, a specific [`EncryptMode`] `mode` and initialization vector `iv`.
    ///
    /// The targeted key must be of type [`KeyType::Generic`] and feature the mechanism
    /// [`KeyMechanism::AesDecryptionCbc`] and [`KeyMechanism::AesEncryptionCbc`].
    ///
    /// This call requires using credentials of a user in the "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if signing the message fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists on the device
    /// * the chosen `mode` is incompatible with the targeted key
    /// * the user lacks access to the key
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, EncryptMode, Error, NetHsm, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "operator" role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "operator".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // assuming we have an AES128 encryption key, the message must be a multiple of 32 bytes long
    /// let message = b"Hello World! This is a message!!";
    /// // we have an AES128 encryption key. the initialization vector must be a multiple of 16 bytes long
    /// let iv = b"This is unsafe!!";
    ///
    /// // encrypt message using
    /// println!(
    ///     "{:?}",
    ///     nethsm.encrypt("signing1", EncryptMode::AesCbc, message, Some(iv))?
    /// );
    /// # Ok(())
    /// # }
    /// ```
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

    /// Decrypts a message using a key
    ///
    /// [Decrypts](https://docs.nitrokey.com/nethsm/operation#decrypt) a `message` using a key
    /// identified by `key_id`, a specific [`DecryptMode`] `mode` and initialization vector `iv`.
    ///
    /// This function can be used to decrypt messages encrypted using a symmetric key (e.g. using
    /// [`NetHsm::encrypt`]) by providing [`DecryptMode::AesCbc`] as `mode`. The targeted key must
    /// be of type [`KeyType::Generic`] and feature the mechanism
    /// [`KeyMechanism::AesDecryptionCbc`] and [`KeyMechanism::AesEncryptionCbc`].
    ///
    /// Decryption for messages encrypted using asymmetric keys is also possible. Foreign entities
    /// can use the public key of an asymmetric key (see [`NetHsm::get_public_key`]) to encrypt a
    /// message and the private key on the device is used for decryption.
    ///
    /// This call requires using credentials of a user in the "operator"
    /// [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if signing the message fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * no key identified by `key_id` exists on the device
    /// * the chosen `mode` is incompatible with the targeted key
    /// * the user lacks access to the key
    /// * the encrypted message can not be decrypted
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, DecryptMode, EncryptMode, NetHsm, Passphrase};
    /// use rsa::pkcs8::DecodePublicKey;
    /// use rsa::Pkcs1v15Encrypt;
    /// use rsa::RsaPublicKey;
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "operator" role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "operator".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // assuming we have an AES128 encryption key, the message must be a multiple of 32 bytes long
    /// let message = "Hello World! This is a message!!".to_string();
    /// // we have an AES128 encryption key. the initialization vector must be a multiple of 16 bytes long
    /// let iv = "This is unsafe!!".to_string();
    ///
    /// // encrypt message using a symmetric key
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

    /// Get random bytes
    ///
    /// Retrieves `length` [random](https://docs.nitrokey.com/nethsm/operation#random) bytes
    /// from the device, if it is in state [`SystemState::Operational`].
    ///
    /// This call requires using credentials of a user in the "operator" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving random bytes fails:
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "operator" role
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "operator" role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "operator".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// // get 10 random bytes
    /// println!("{:#?}", nethsm.random(10)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn random(&self, length: i32) -> Result<Vec<u8>, Error> {
        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let base64_bytes = random_post(
            &self.create_connection_config(),
            RandomRequestData::new(length),
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

    /// Creates an OpenPGP certificate for an existing key
    ///
    /// The NetHSM key is used to sign the self-certification and the resulting [OpenPGP certificate](https://openpgp.dev/book/certificates.html) is returned.
    ///
    /// This call requires using credentials of a user in the "operator" [role](https://docs.nitrokey.com/nethsm/administration#roles).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if:
    /// * retrieving random bytes fails
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not those of a user in the "operator" role
    /// * the key does not exist
    /// * the used operator credentials do not grant access to the used key
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use testresult::TestResult;
    /// use std::time::SystemTime;
    ///
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, OpenPgpKeyUsageFlags, Passphrase};
    ///
    /// # fn main() -> TestResult {
    /// // create a connection with a user in the "operator" and "administrator" role
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
    /// nethsm.add_credentials(Credentials::new(
    ///     "operator".parse()?,
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// ));
    ///
    /// assert!(!nethsm
    ///     .create_openpgp_cert(
    ///         "key",
    ///         OpenPgpKeyUsageFlags::default(),
    ///         "Test <test@example.com>",
    ///         SystemTime::now().into()
    ///     )?
    ///     .is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn create_openpgp_cert(
        &self,
        key_id: &str,
        flags: OpenPgpKeyUsageFlags,
        user_id: &str,
        created_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, Error> {
        openpgp::add_certificate(self, flags, key_id.into(), user_id, created_at)
    }

    /// Creates an OpenPGP signature for a message
    ///
    /// Signs the `message` using the `key_id` key and returns an OpenPGP-framed signature.
    ///
    /// This call requires using credentials of a user in the "operator" [role](https://docs.nitrokey.com/nethsm/administration#roles) with access to the used key.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if:
    /// * retrieving random bytes fails
    /// * the device is not in state [`SystemState::Operational`]
    /// * the used credentials are not correct
    /// * the used credentials are not that of a user in the "operator" role
    /// * the used operator credentials do not grant access to the key
    /// * the key does not exist
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a user in the "operator" role
    /// let nethsm = NetHsm::new(
    ///     "https://example.org/api/v1".try_into()?,
    ///     ConnectionSecurity::Unsafe,
    ///     Some(Credentials::new(
    ///         "operator".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// assert!(!nethsm.openpgp_sign("key", b"sample message")?.is_empty());
    /// # Ok(()) }
    /// ```
    pub fn openpgp_sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
        openpgp::sign(self, key_id.into(), message)
    }
}
