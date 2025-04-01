use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, hash_map::Entry},
    error::Error as StdError,
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
};

use nethsm::{
    Connection,
    ConnectionSecurity,
    Credentials,
    KeyId,
    NetHsm,
    Passphrase,
    Url,
    UserId,
    UserRole,
};
use serde::{Deserialize, Serialize};

use crate::{
    ConfigCredentials,
    ExtendedUserMapping,
    PassphrasePrompt,
    SystemUserId,
    UserMapping,
    UserPrompt,
};

/// Errors related to configuration
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Issue getting the config file location
    #[error("Config file issue: {0}")]
    ConfigFileLocation(#[source] confy::ConfyError),

    /// A config loading error
    ///
    /// The variant tracks a [`ConfyError`][`confy::ConfyError`] and an optional
    /// description of an inner Error type.
    /// The description is tracked separately, as otherwise we do not get to useful error messages
    /// of wrapped Error types (e.g. those for loading TOML files).
    #[error("Config loading issue: {source}\n{description}")]
    Load {
        source: confy::ConfyError,
        description: String,
    },

    /// A config storing error
    #[error("Config storing issue: {0}")]
    Store(#[source] confy::ConfyError),

    /// Credentials exist already
    #[error("Credentials exist already: {0}")]
    CredentialsExist(UserId),

    /// Credentials do not exist
    #[error("Credentials do not exist: {0}")]
    CredentialsMissing(UserId),

    /// None of the provided users map to one of the provided roles
    #[error("None of the provided users ({names:?}) map to one of the provided roles ({roles:?})")]
    MatchingCredentialsMissing {
        names: Vec<UserId>,
        roles: Vec<UserRole>,
    },

    /// Credentials do not exist
    #[error("No user matching one of the requested roles ({0:?}) exists")]
    NoMatchingCredentials(Vec<UserRole>),

    /// There is no mapping for a provided system user name.
    #[error("No mapping found where a system user matches the name {name}")]
    NoMatchingMappingForSystemUser { name: String },

    /// Shamir's Secret Sharing (SSS) is not used for administrative secret handling, but users for
    /// handling of secret shares are defined
    #[error(
        "Shamir's Secret Sharing not used for administrative secret handling, but the following users are setup to handle shares: {share_users:?}"
    )]
    NoSssButShareUsers { share_users: Vec<SystemUserId> },

    /// Device exists already
    #[error("Device exist already: {0}")]
    DeviceExists(String),

    /// Device does not exist
    #[error("Device does not exist: {0}")]
    DeviceMissing(String),

    /// Duplicate NetHsm user names
    #[error("The NetHsm user ID {nethsm_user_id} is used more than once!")]
    DuplicateNetHsmUserId { nethsm_user_id: UserId },

    /// Duplicate system user names
    #[error("The authorized SSH key {ssh_authorized_key} is used more than once!")]
    DuplicateSshAuthorizedKey { ssh_authorized_key: String },

    /// Duplicate key ID
    #[error("The key ID {key_id} is used more than once!")]
    DuplicateKeyId { key_id: KeyId },

    /// Duplicate key ID in a namespace
    #[error("The key ID {key_id} is used more than once in namespace {namespace}!")]
    DuplicateKeyIdInNamespace { key_id: KeyId, namespace: String },

    /// Duplicate system user names
    #[error("The system user ID {system_user_id} is used more than once!")]
    DuplicateSystemUserId { system_user_id: SystemUserId },

    /// Duplicate tag
    #[error("The tag {tag} is used more than once!")]
    DuplicateTag { tag: String },

    /// Duplicate tag
    #[error("The tag {tag} is used more than once in namespace {namespace}!")]
    DuplicateTagInNamespace { tag: String, namespace: String },

    /// Missing system-wide user in the Administrator role (R-Administrator)
    #[error("No system-wide user in the Administrator role exists.")]
    MissingAdministrator,

    /// Missing user in the Administrator role for a namespace (N-Administrator)
    #[error("No user in the Administrator role exist for the namespaces {namespaces:?}")]
    MissingNamespaceAdministrators { namespaces: Vec<String> },

    /// Missing system user for downloading shares of a shared secret
    #[error("No system user for downloading shares of a shared secret exists.")]
    MissingShareDownloadUser,

    /// Missing system user for uploading shares of a shared secret
    #[error("No system user for uploading shares of a shared secret exists.")]
    MissingShareUploadUser,

    /// There is more than one device (but none has been specified)
    #[error("There is more than one device")]
    MoreThanOneDevice,

    /// There is no device
    #[error("There is no device")]
    NoDevice,

    /// The configuration can not be used interactively
    #[error("The configuration can not be used interactively")]
    NonInteractive,

    /// NetHsm connection initialization error
    #[error("NetHsm connection can not be created: {0}")]
    NetHsm(#[from] nethsm::Error),

    /// A prompt requesting user data failed
    #[error("A prompt issue")]
    Prompt(#[from] crate::prompt::Error),

    /// User data is invalid
    #[error("User data invalid: {0}")]
    User(#[from] nethsm::UserError),
}

/// The interactivity of a configuration
///
/// This enum is used by [`Config`] and [`DeviceConfig`] to define whether missing items are
/// prompted for interactively ([`ConfigInteractivity::Interactive`]) or not
/// ([`ConfigInteractivity::NonInteractive`]).
#[derive(Copy, Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum ConfigInteractivity {
    /// The configuration may spawn interactive prompts to request more data (e.g. usernames or
    /// passphrases)
    Interactive,
    /// The configuration will return an [`Error`] if interactive prompts need to be spawned to
    /// request more data (e.g. usernames or passphrases)
    #[default]
    NonInteractive,
}

/// The name of a configuration
///
/// The name defines the file name (without file suffix) used by a [`Config`] object.
/// It defaults to `"config"`, but may be set specifically when initializing a [`Config`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigName(String);

impl Default for ConfigName {
    fn default() -> Self {
        Self("config".to_string())
    }
}

impl Display for ConfigName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ConfigName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

/// The settings for a [`Config`]
///
/// Settings contain the [`ConfigName`] by which the configuration file is loaded and stored, the
/// application name which uses the configuration (and also influences the file path of the
/// configuration) and the interactivity setting, which defines whether missing items are prompted
/// for interactively or not.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigSettings {
    /// The configuration name (file name without suffix)
    config_name: ConfigName,
    /// The name of the application using a [`Config`]
    app_name: String,
    /// The interactivity setting for the [`Config`] (and any [`DeviceConfig`] used by it)
    interactivity: ConfigInteractivity,
}

impl ConfigSettings {
    /// Creates a new [`ConfigSettings`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::{ConfigInteractivity, ConfigSettings};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // settings for an application called "my_app", that uses a custom configuration file named "my_app-config" interactively
    /// let config_settings = ConfigSettings::new(
    ///     "my_app".to_string(),
    ///     ConfigInteractivity::Interactive,
    ///     Some("my_app-config".parse()?),
    /// );
    ///
    /// // settings for an application called "my_app", that uses a default config file non-interactively
    /// let config_settings = ConfigSettings::new(
    ///     "my_app".to_string(),
    ///     ConfigInteractivity::NonInteractive,
    ///     None,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        app_name: String,
        interactivity: ConfigInteractivity,
        config_name: Option<ConfigName>,
    ) -> Self {
        Self {
            app_name,
            interactivity,
            config_name: config_name.unwrap_or_default(),
        }
    }

    /// Returns the configuration name
    pub fn config_name(&self) -> ConfigName {
        self.config_name.to_owned()
    }

    /// Returns the application name
    pub fn app_name(&self) -> String {
        self.app_name.clone()
    }

    /// Returns the interactivity setting
    pub fn interactivity(&self) -> ConfigInteractivity {
        self.interactivity
    }
}

/// The configuration for a [`NetHsm`]
///
/// Tracks the [`Connection`] for a [`NetHsm`] as well as a set of [`ConfigCredentials`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceConfig {
    connection: RefCell<Connection>,
    credentials: RefCell<HashSet<ConfigCredentials>>,
    #[serde(skip)]
    interactivity: ConfigInteractivity,
}

impl DeviceConfig {
    /// Creates a new [`DeviceConfig`]
    ///
    /// Creates a new [`DeviceConfig`] by providing a `connection`, an optional set of `credentials`
    /// and the `interactivity` setting.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::CredentialsExist`] if `credentials` contains duplicates.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, DeviceConfig};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let connection = Connection::new(
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// );
    ///
    /// DeviceConfig::new(
    ///     connection.clone(),
    ///     vec![],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    ///
    /// DeviceConfig::new(
    ///     connection.clone(),
    ///     vec![ConfigCredentials::new(
    ///         UserRole::Operator,
    ///         "user1".parse()?,
    ///         Some("my-passphrase".to_string()),
    ///     )],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    ///
    /// // this fails because the provided credentials contain duplicates
    /// assert!(
    ///     DeviceConfig::new(
    ///         connection.clone(),
    ///         vec![
    ///             ConfigCredentials::new(
    ///                 UserRole::Operator,
    ///                 "user1".parse()?,
    ///                 Some("my-passphrase".to_string()),
    ///             ),
    ///             ConfigCredentials::new(
    ///                 UserRole::Operator,
    ///                 "user1".parse()?,
    ///                 Some("my-passphrase".to_string()),
    ///             ),
    ///         ],
    ///         ConfigInteractivity::NonInteractive,
    ///     )
    ///     .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        connection: Connection,
        credentials: Vec<ConfigCredentials>,
        interactivity: ConfigInteractivity,
    ) -> Result<DeviceConfig, Error> {
        let device_config = DeviceConfig {
            connection: RefCell::new(connection),
            credentials: RefCell::new(HashSet::new()),
            interactivity,
        };

        if !credentials.is_empty() {
            for creds in credentials.into_iter() {
                device_config.add_credentials(creds)?
            }
        }

        Ok(device_config)
    }

    /// Sets the interactivity setting
    ///
    /// **NOTE**: This method is not necessarily useful by itself, as one usually wants to use the
    /// same [`ConfigInteractivity`] as that of a [`Config`], which holds the [`DeviceConfig`].
    pub fn set_config_interactivity(&mut self, config_type: ConfigInteractivity) {
        self.interactivity = config_type;
    }

    /// Adds credentials to the device
    ///
    /// Adds new [`ConfigCredentials`] to the [`DeviceConfig`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::CredentialsExist`] if the `credentials` exist already.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, DeviceConfig};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let connection = Connection::new(
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// );
    ///
    /// let device_config = DeviceConfig::new(
    ///     connection.clone(),
    ///     vec![],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    ///
    /// device_config.add_credentials(ConfigCredentials::new(
    ///     UserRole::Operator,
    ///     "user1".parse()?,
    ///     Some("my-passphrase".to_string()),
    /// ))?;
    ///
    /// // this fails because the credentials exist already
    /// assert!(
    ///     device_config
    ///         .add_credentials(ConfigCredentials::new(
    ///             UserRole::Operator,
    ///             "user1".parse()?,
    ///             Some("my-passphrase".to_string()),
    ///         ))
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_credentials(&self, credentials: ConfigCredentials) -> Result<(), Error> {
        if !self
            .credentials
            .borrow()
            .iter()
            .any(|creds| creds.get_name() == credentials.get_name())
        {
            self.credentials.borrow_mut().insert(credentials);
            Ok(())
        } else {
            Err(Error::CredentialsExist(credentials.get_name()))
        }
    }

    /// Returns credentials by name
    ///
    /// Returns existing [`ConfigCredentials`] from the [`DeviceConfig`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::CredentialsMissing`] if no [`ConfigCredentials`] match the provided
    /// `name`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, DeviceConfig};
    /// # fn main() -> testresult::TestResult {
    /// let connection = Connection::new(
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// );
    ///
    /// let device_config = DeviceConfig::new(
    ///     connection.clone(),
    ///     vec![],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    ///
    /// // this fails because the credentials do not exist
    /// assert!(device_config.get_credentials(&"user1".parse()?).is_err());
    ///
    /// device_config.add_credentials(ConfigCredentials::new(
    ///     UserRole::Operator,
    ///     "user1".parse()?,
    ///     Some("my-passphrase".to_string()),
    /// ))?;
    ///
    /// device_config.get_credentials(&"user1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_credentials(&self, name: &UserId) -> Result<ConfigCredentials, Error> {
        if let Some(creds) = self
            .credentials
            .borrow()
            .iter()
            .find(|creds| &creds.get_name() == name)
        {
            Ok(creds.clone())
        } else {
            Err(Error::CredentialsMissing(name.to_owned()))
        }
    }

    /// Deletes credentials by name
    ///
    /// Deletes [`ConfigCredentials`] identified by `name`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::CredentialsMissing`] if no [`ConfigCredentials`] match the provided
    /// name.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, DeviceConfig};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let device_config = DeviceConfig::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".parse()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     vec![],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    /// device_config.add_credentials(ConfigCredentials::new(
    ///     UserRole::Operator,
    ///     "user1".parse()?,
    ///     Some("my-passphrase".to_string()),
    /// ))?;
    ///
    /// device_config.delete_credentials(&"user1".parse()?)?;
    ///
    /// // this fails because the credentials do not exist
    /// assert!(device_config.delete_credentials(&"user1".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete_credentials(&self, name: &UserId) -> Result<(), Error> {
        let before = self.credentials.borrow().len();
        self.credentials
            .borrow_mut()
            .retain(|creds| &creds.get_name() != name);
        let after = self.credentials.borrow().len();
        if before == after {
            Err(Error::CredentialsMissing(name.to_owned()))
        } else {
            Ok(())
        }
    }

    /// Returns credentials machting one or several roles and a optionally a name
    ///
    /// Returns [`ConfigCredentials`] matching a list of [`UserRole`]s and/or a list of [`UserId`]s.
    ///
    /// If `names` is empty, the [`ConfigCredentials`] first found matching one of the [`UserRole`]s
    /// provided using `roles` are returned.
    /// If `names` contains at least one entry, the first [`ConfigCredentials`] with a matching
    /// [`UserId`] that have at least one matching [`UserRole`] are returned.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::NoMatchingCredentials`] if `names` is empty and no existing credentials
    /// match any of the provided `roles`.
    /// Returns an [`Error::CredentialsMissing`] if a [`UserId`] in `names` does not exist and no
    /// [`ConfigCredentials`] have been returned yet.
    /// Returns an [`Error::MatchingCredentialsMissing`] if no [`ConfigCredentials`] matching either
    /// the provided `names` or `roles` can be found.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, DeviceConfig};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let device_config = DeviceConfig::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".parse()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     vec![ConfigCredentials::new(
    ///         UserRole::Administrator,
    ///         "admin1".parse()?,
    ///         Some("my-passphrase".to_string()),
    ///     )],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    /// device_config.add_credentials(ConfigCredentials::new(
    ///     UserRole::Operator,
    ///     "user1".parse()?,
    ///     Some("my-passphrase".to_string()),
    /// ))?;
    ///
    /// device_config.get_matching_credentials(&[UserRole::Operator], &["user1".parse()?])?;
    /// device_config.get_matching_credentials(&[UserRole::Administrator], &["admin1".parse()?])?;
    /// assert_eq!(
    ///     device_config
    ///         .get_matching_credentials(&[UserRole::Operator], &[])?
    ///         .get_name(),
    ///     "user1".parse()?
    /// );
    /// assert_eq!(
    ///     device_config
    ///         .get_matching_credentials(&[UserRole::Administrator], &[])?
    ///         .get_name(),
    ///     "admin1".parse()?
    /// );
    ///
    /// // this fails because we must provide a role to match against
    /// assert!(
    ///     device_config
    ///         .get_matching_credentials(&[], &["user1".parse()?])
    ///         .is_err()
    /// );
    ///
    /// // this fails because no user in the requested role exists
    /// assert!(
    ///     device_config
    ///         .get_matching_credentials(&[UserRole::Metrics], &[])
    ///         .is_err()
    /// );
    ///
    /// // this fails because no user with the name first provided exists
    /// assert!(
    ///     device_config
    ///         .get_matching_credentials(&[UserRole::Operator], &["user2".parse()?, "user1".parse()?])
    ///         .is_err()
    /// );
    ///
    /// // this fails because no user in the requested role with any of the provided names exists
    /// assert!(
    ///     device_config
    ///         .get_matching_credentials(&[UserRole::Metrics], &["admin1".parse()?, "user1".parse()?])
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_matching_credentials(
        &self,
        roles: &[UserRole],
        names: &[UserId],
    ) -> Result<ConfigCredentials, Error> {
        if names.is_empty() {
            let creds = self
                .credentials
                .borrow()
                .iter()
                .filter_map(|creds| {
                    if roles.contains(&creds.get_role()) {
                        Some(creds.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<ConfigCredentials>>();
            return creds
                .first()
                .ok_or_else(|| Error::NoMatchingCredentials(roles.to_vec()))
                .cloned();
        }

        for name in names {
            if let Ok(creds) = &self.get_credentials(name) {
                if roles.contains(&creds.get_role()) {
                    return Ok(creds.clone());
                }
            } else {
                return Err(Error::CredentialsMissing(name.to_owned()));
            }
        }

        Err(Error::MatchingCredentialsMissing {
            names: names.to_vec(),
            roles: roles.to_vec(),
        })
    }

    /// Returns a [`NetHsm`] based on the [`DeviceConfig`] (optionally with one set of credentials)
    ///
    /// Creates a [`NetHsm`] based on the [`DeviceConfig`].
    /// Only if `roles` is not empty, one set of [`ConfigCredentials`] based on `roles`,
    /// `names` and `passphrases` is added to the [`NetHsm`].
    ///
    /// **WARNING**: Depending on the [`ConfigInteractivity`] chosen when initializing the
    /// [`DeviceConfig`] this method behaves differently with regards to adding credentials!
    ///
    /// # [`NonInteractive`][`ConfigInteractivity::NonInteractive`]
    ///
    /// If `roles` is not empty, optionally adds one set of [`ConfigCredentials`] found by
    /// [`get_matching_credentials`][`DeviceConfig::get_matching_credentials`] to the returned
    /// [`NetHsm`], based on `roles` and `names`.
    /// If the found [`ConfigCredentials`] do not contain a passphrase, a [`Passphrase`] in
    /// `pasphrases` with the same index as that of the [`UserId`] in `names` is used.
    ///
    /// # [`Interactive`][`ConfigInteractivity::Interactive`]
    ///
    /// If `roles` is not empty, optionally attempts to add one set of [`ConfigCredentials`] with
    /// the help of [`get_matching_credentials`][`DeviceConfig::get_matching_credentials`] to the
    /// returned [`NetHsm`], based on `roles` and `names`.
    /// If no [`ConfigCredentials`] are found by
    /// [`get_matching_credentials`][`DeviceConfig::get_matching_credentials`], users are
    /// interactively prompted for providing a user name.
    /// If the found or prompted for [`UserId`] [`ConfigCredentials`] do not contain a passphrase, a
    /// [`Passphrase`] in `pasphrases` with the same index as that of the [`UserId`] in `names`
    /// is used. If [`get_matching_credentials`][`DeviceConfig::get_matching_credentials`], or
    /// those the user has been prompted for provides [`ConfigCredentials`] without a
    /// passphrase, a [`Passphrase`] in `pasphrases` with the same index as that of the
    /// [`UserId`] in `names` is used. If none is provided (at the right location) in `passphrases`,
    /// the user is prompted for a passphrase interactively.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::NoMatchingCredentials`], [`Error::CredentialsMissing`], or
    /// [`Error::MatchingCredentialsMissing`] if the [`DeviceConfig`] is initialized with
    /// [`Interactive`][`ConfigInteractivity::Interactive`] and
    /// [`get_matching_credentials`][`DeviceConfig::get_matching_credentials`] is unable to return
    /// [`ConfigCredentials`] based on `roles` and `names`.
    ///
    /// Returns an [`Error::NonInteractive`] if the [`DeviceConfig`] is initialized with
    /// [`NonInteractive`][`ConfigInteractivity::NonInteractive`], but additional data would be
    /// requested interactively.
    ///
    /// Returns an [`Error::Prompt`] if requesting additional data interactively leads to error.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, Passphrase, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, DeviceConfig};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let device_config = DeviceConfig::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".parse()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     vec![ConfigCredentials::new(
    ///         UserRole::Administrator,
    ///         "admin1".parse()?,
    ///         Some("my-passphrase".to_string()),
    ///     )],
    ///     ConfigInteractivity::NonInteractive,
    /// )?;
    /// device_config.add_credentials(ConfigCredentials::new(
    ///     UserRole::Operator,
    ///     "user1".parse()?,
    ///     None,
    /// ))?;
    ///
    /// // NetHsm with Operator credentials
    /// // this works non-interactively, although the credentials in the config provide no passphrase, because we provide the passphrase manually
    /// device_config.nethsm_with_matching_creds(
    ///     &[UserRole::Operator],
    ///     &["user1".parse()?],
    ///     &[Passphrase::new("my-passphrase".to_string())],
    /// )?;
    ///
    /// // NetHsm with Administrator credentials
    /// // this automatically selects "admin1" as it is the only user in the Administrator role
    /// // this works non-interactively, because the credentials in the config provide a passphrase!
    /// device_config.nethsm_with_matching_creds(
    ///     &[UserRole::Administrator],
    ///     &[],
    ///     &[],
    /// )?;
    ///
    /// // a NetHsm without any credentials
    /// device_config.nethsm_with_matching_creds(
    ///     &[],
    ///     &[],
    ///     &[],
    /// )?;
    ///
    /// // this fails because the config is non-interactive, the targeted credentials do not offer a passphrase and we also provide none
    /// assert!(device_config.nethsm_with_matching_creds(
    ///     &[UserRole::Operator],
    ///     &["user1".parse()?],
    ///     &[],
    /// ).is_err());
    ///
    /// // this fails because the config is non-interactive and the targeted credentials do not exist
    /// assert!(device_config.nethsm_with_matching_creds(
    ///     &[UserRole::Operator],
    ///     &["user2".parse()?],
    ///     &[],
    /// ).is_err());
    ///
    /// // this fails because the config is non-interactive and no user in the targeted role exists
    /// assert!(device_config.nethsm_with_matching_creds(
    ///     &[UserRole::Metrics],
    ///     &[],
    ///     &[],
    /// ).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn nethsm_with_matching_creds(
        &self,
        roles: &[UserRole],
        names: &[UserId],
        passphrases: &[Passphrase],
    ) -> Result<NetHsm, Error> {
        let nethsm: NetHsm = self.try_into()?;

        // do not add any users if no user roles are requested
        if !roles.is_empty() {
            // try to find a user name with a role in the requested set of credentials
            let creds = if let Ok(creds) = self.get_matching_credentials(roles, names) {
                creds
            // or request a user name in the first requested role
            } else {
                // if running non-interactively, return Error
                if self.interactivity == ConfigInteractivity::NonInteractive {
                    return Err(Error::NonInteractive);
                }

                let role = roles.first().expect("We have at least one user role");
                ConfigCredentials::new(
                    role.to_owned(),
                    UserPrompt::new(role.to_owned()).prompt()?,
                    None,
                )
            };

            // if no passphrase is set for the credentials, attempt to set it
            let credentials = if !creds.has_passphrase() {
                // get index of the found credentials name in the input names
                let name_index = names.iter().position(|name| name == &creds.get_name());
                if let Some(name_index) = name_index {
                    // if a passphrase index in passphrases matches the index of the user, use it
                    if let Some(passphrase) = passphrases.get(name_index) {
                        Credentials::new(creds.get_name(), Some(passphrase.clone()))
                        // else try to set the passphrase interactively
                    } else {
                        // if running non-interactively, return Error
                        if self.interactivity == ConfigInteractivity::NonInteractive {
                            return Err(Error::NonInteractive);
                        }
                        Credentials::new(
                            creds.get_name(),
                            Some(
                                PassphrasePrompt::User {
                                    user_id: Some(creds.get_name()),
                                    real_name: None,
                                }
                                .prompt()?,
                            ),
                        )
                    }
                    // else try to set the passphrase interactively
                } else {
                    // if running non-interactively, return Error
                    if self.interactivity == ConfigInteractivity::NonInteractive {
                        return Err(Error::NonInteractive);
                    }
                    Credentials::new(
                        creds.get_name(),
                        Some(
                            PassphrasePrompt::User {
                                user_id: Some(creds.get_name()),
                                real_name: None,
                            }
                            .prompt()?,
                        ),
                    )
                }
            } else {
                creds.into()
            };

            let user_id = credentials.user_id.clone();
            // add the found credentials
            nethsm.add_credentials(credentials);
            // use the found credentials by default
            nethsm.use_credentials(&user_id)?;
        }

        Ok(nethsm)
    }
}

impl TryFrom<DeviceConfig> for NetHsm {
    type Error = Error;
    fn try_from(value: DeviceConfig) -> Result<Self, Error> {
        let nethsm = NetHsm::new(value.connection.borrow().clone(), None, None, None)?;
        for creds in value.credentials.borrow().clone().into_iter() {
            nethsm.add_credentials(creds.into())
        }
        Ok(nethsm)
    }
}

impl TryFrom<&DeviceConfig> for NetHsm {
    type Error = Error;
    fn try_from(value: &DeviceConfig) -> Result<Self, Error> {
        let nethsm = NetHsm::new(value.connection.borrow().clone(), None, None, None)?;
        for creds in value.credentials.borrow().clone().into_iter() {
            nethsm.add_credentials(creds.into())
        }
        Ok(nethsm)
    }
}

/// A configuration for NetHSM devices
///
/// Tracks a set of [`DeviceConfig`]s hashed by label.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    devices: RefCell<HashMap<String, DeviceConfig>>,
    #[serde(skip)]
    config_settings: ConfigSettings,
}

impl Config {
    /// Loads the configuration
    ///
    /// If `path` is `Some`, the configuration is loaded from a specific file.
    /// If `path` is `None`, a default location is assumed. The default location depends on the
    /// chosen [`app_name`][`ConfigSettings::app_name`] and the OS platform. Assuming
    /// [`app_name`][`ConfigSettings::app_name`] is `"my_app"` on Linux the default location is
    /// `~/.config/my_app/config.toml`.
    ///
    /// If the targeted configuration file does not yet exist, an empty default [`Config`] is
    /// assumed.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Load`] if loading the configuration file fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let config_settings = ConfigSettings::new(
    ///     "my_app".to_string(),
    ///     ConfigInteractivity::NonInteractive,
    ///     None,
    /// );
    /// let config_from_default = Config::new(config_settings.clone(), None)?;
    ///
    /// let tmpfile = testdir::testdir!().join("my_app_new.conf");
    /// let config_from_file = Config::new(config_settings, Some(&tmpfile))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config_settings: ConfigSettings, path: Option<&Path>) -> Result<Self, Error> {
        let mut config: Config = if let Some(path) = path {
            confy::load_path(path).map_err(|error| Error::Load {
                description: if let Some(error) = error.source() {
                    error.to_string()
                } else {
                    "".to_string()
                },
                source: error,
            })?
        } else {
            confy::load(
                &config_settings.app_name,
                Some(config_settings.config_name.0.as_str()),
            )
            .map_err(|error| Error::Load {
                description: if let Some(error) = error.source() {
                    error.to_string()
                } else {
                    "".to_string()
                },
                source: error,
            })?
        };
        for (_label, device) in config.devices.borrow_mut().iter_mut() {
            device.set_config_interactivity(config_settings.interactivity);
        }
        config.set_config_settings(config_settings);

        Ok(config)
    }

    fn set_config_settings(&mut self, config_settings: ConfigSettings) {
        self.config_settings = config_settings
    }

    /// Adds a [`DeviceConfig`]
    ///
    /// A device is defined by its `label`, the `url` to connect to and the chosen `tls_security`
    /// for the connection.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::DeviceExists`] if a [`DeviceConfig`] with the same `label` exists
    /// already.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::ConnectionSecurity;
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&testdir::testdir!().join("my_app_add_device.conf")),
    /// # )?;
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// // adding the same device again leads to error
    /// assert!(
    ///     config
    ///         .add_device(
    ///             "device1".to_string(),
    ///             "https://example.org/api/v1".parse()?,
    ///             ConnectionSecurity::Unsafe,
    ///         )
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_device(
        &self,
        label: String,
        url: Url,
        tls_security: ConnectionSecurity,
    ) -> Result<(), Error> {
        if let Entry::Vacant(entry) = self.devices.borrow_mut().entry(label.clone()) {
            entry.insert(DeviceConfig::new(
                Connection::new(url, tls_security),
                vec![],
                self.config_settings.interactivity,
            )?);
            Ok(())
        } else {
            Err(Error::DeviceExists(label))
        }
    }

    /// Deletes a [`DeviceConfig`] identified by `label`
    ///
    /// # Errors
    ///
    /// Returns an [`Error::DeviceMissing`] if no [`DeviceConfig`] with a matching `label` exists.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::ConnectionSecurity;
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&testdir::testdir!().join("my_app_delete_device.conf")),
    /// # )?;
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// config.delete_device("device1")?;
    ///
    /// // deleting a non-existent device leads to error
    /// assert!(config.delete_device("device1",).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete_device(&self, label: &str) -> Result<(), Error> {
        if self.devices.borrow_mut().remove(label).is_some() {
            Ok(())
        } else {
            Err(Error::DeviceMissing(label.to_string()))
        }
    }

    /// Returns a single [`DeviceConfig`] from the [`Config`] based on an optional `label`
    ///
    /// If `label` is [`Some`], a specific [`DeviceConfig`] is retrieved.
    /// If `label` is [`None`] and only one device is defined in the config, then the
    /// [`DeviceConfig`] for that device is returned.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::DeviceMissing`] if `label` is [`Some`] but it can not be found in the
    /// [`Config`].
    /// Returns an [`Error::NoDevice`], if `label` is [`None`] but the [`Config`] has no
    /// devices.
    /// Returns an [`Error::NoDevice`], if `label` is [`None`] and the [`Config`] has more than one
    /// device.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::ConnectionSecurity;
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&testdir::testdir!().join("my_app_get_device.conf")),
    /// # )?;
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// config.get_device(Some("device1"))?;
    ///
    /// // this fails because the device does not exist
    /// assert!(config.get_device(Some("device2")).is_err());
    ///
    /// config.add_device(
    ///     "device2".to_string(),
    ///     "https://example.org/other/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    /// // this fails because there is more than one device
    /// assert!(config.get_device(None).is_err());
    ///
    /// config.delete_device("device1")?;
    /// config.delete_device("device2")?;
    /// // this fails because there is no device
    /// assert!(config.get_device(None).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_device(&self, label: Option<&str>) -> Result<DeviceConfig, Error> {
        if let Some(label) = label {
            if let Some(device_config) = self.devices.borrow().get(label) {
                Ok(device_config.clone())
            } else {
                Err(Error::DeviceMissing(label.to_string()))
            }
        } else {
            match self.devices.borrow().len() {
                0 => Err(Error::NoDevice),
                1 => Ok(self
                    .devices
                    .borrow()
                    .values()
                    .next()
                    .expect("there should be one")
                    .to_owned()),
                _ => Err(Error::MoreThanOneDevice),
            }
        }
    }

    /// Returns a single [`DeviceConfig`] label from the [`Config`]
    ///
    /// # Errors
    ///
    /// Returns an error if not exactly one [`DeviceConfig`] is present.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::ConnectionSecurity;
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&testdir::testdir!().join("my_app_get_single_device_label.conf")),
    /// # )?;
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// assert_eq!(config.get_single_device_label()?, "device1".to_string());
    ///
    /// config.add_device(
    ///     "device2".to_string(),
    ///     "https://example.org/other/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    /// // this fails because there is more than one device
    /// assert!(config.get_single_device_label().is_err());
    ///
    /// config.delete_device("device1")?;
    /// config.delete_device("device2")?;
    /// // this fails because there is no device
    /// assert!(config.get_single_device_label().is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_single_device_label(&self) -> Result<String, Error> {
        if self.devices.borrow().keys().len() == 1 {
            self.devices
                .borrow()
                .keys()
                .next()
                .map(|label| label.to_string())
                .ok_or(Error::NoDevice)
        } else {
            Err(Error::MoreThanOneDevice)
        }
    }

    /// Adds new credentials for a [`DeviceConfig`]
    ///
    /// Using a `label` that identifies a [`DeviceConfig`], new credentials tracking a [`UserRole`],
    /// a name and optionally a passphrase are added to it.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::DeviceMissing`] if the targeted [`DeviceConfig`] does not exist.
    /// Returns an [`Error::CredentialsExist`] if the [`ConfigCredentials`] identified by `name`
    /// exist already.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{Config, ConfigCredentials, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&testdir::testdir!().join("my_app_add_credentials.conf")),
    /// # )?;
    ///
    /// // this fails because the targeted device does not yet exist
    /// assert!(
    ///     config
    ///         .add_credentials(
    ///             "device1".to_string(),
    ///             ConfigCredentials::new(
    ///                 UserRole::Operator,
    ///                 "user1".parse()?,
    ///                 Some("my-passphrase".to_string()),
    ///             ),
    ///         )
    ///         .is_err()
    /// );
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// config.add_credentials(
    ///     "device1".to_string(),
    ///     ConfigCredentials::new(
    ///         UserRole::Operator,
    ///         "user1".parse()?,
    ///         Some("my-passphrase".to_string()),
    ///     ),
    /// )?;
    ///
    /// // this fails because the credentials exist already
    /// assert!(
    ///     config
    ///         .add_credentials(
    ///             "device1".to_string(),
    ///             ConfigCredentials::new(
    ///                 UserRole::Operator,
    ///                 "user1".parse()?,
    ///                 Some("my-passphrase".to_string()),
    ///             ),
    ///         )
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_credentials(
        &self,
        label: String,
        credentials: ConfigCredentials,
    ) -> Result<(), Error> {
        if let Some(device) = self.devices.borrow_mut().get_mut(&label) {
            device.add_credentials(credentials)?
        } else {
            return Err(Error::DeviceMissing(label));
        }

        Ok(())
    }

    /// Deletes credentials from a [`DeviceConfig`]
    ///
    /// The `label` identifies the [`DeviceConfig`] and the `name` the name of the credentials.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::DeviceMissing`] if the targeted [`DeviceConfig`] does not exist.
    /// Returns an [`Error::CredentialsMissing`] if the targeted [`ConfigCredentials`] do not exist.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{Config, ConfigCredentials, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&testdir::testdir!().join("my_app_delete_credentials.conf")),
    /// # )?;
    ///
    /// // this fails because the targeted device does not yet exist
    /// assert!(
    ///     config
    ///         .delete_credentials("device1", &"user1".parse()?)
    ///         .is_err()
    /// );
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// // this fails because the targeted credentials does not yet exist
    /// assert!(
    ///     config
    ///         .delete_credentials("device1", &"user1".parse()?)
    ///         .is_err()
    /// );
    ///
    /// config.add_credentials(
    ///     "device1".to_string(),
    ///     ConfigCredentials::new(
    ///         UserRole::Operator,
    ///         "user1".parse()?,
    ///         Some("my-passphrase".to_string()),
    ///     ),
    /// )?;
    ///
    /// config.delete_credentials("device1", &"user1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn delete_credentials(&self, label: &str, name: &UserId) -> Result<(), Error> {
        if let Some(device) = self.devices.borrow_mut().get_mut(label) {
            device.delete_credentials(name)?
        } else {
            return Err(Error::DeviceMissing(label.to_string()));
        }

        Ok(())
    }

    /// Returns the [`ConfigSettings`] of the [`Config`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// let config_settings = ConfigSettings::new(
    ///     "my_app".to_string(),
    ///     ConfigInteractivity::NonInteractive,
    ///     None,
    /// );
    /// let config = Config::new(
    ///     config_settings.clone(),
    ///     Some(&testdir::testdir!().join("my_app_get_config_settings.conf")),
    /// )?;
    ///
    /// println!("{:?}", config.get_config_settings());
    /// # assert_eq!(config.get_config_settings(), config_settings);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_config_settings(&self) -> ConfigSettings {
        self.config_settings.clone()
    }

    /// Returns the default config file location
    ///
    /// # Errors
    ///
    /// Returns an [`Error::ConfigFileLocation`] if the config file location can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    /// # fn main() -> testresult::TestResult {
    /// let config = Config::new(
    ///     ConfigSettings::new(
    ///         "my_app".to_string(),
    ///         ConfigInteractivity::NonInteractive,
    ///         None,
    ///     ),
    ///     Some(&testdir::testdir!().join("my_app_get_default_config_file_path.conf")),
    /// )?;
    ///
    /// println!("{:?}", config.get_default_config_file_path()?);
    /// # assert_eq!(
    /// #     config.get_default_config_file_path()?,
    /// #     dirs::config_dir()
    /// #         .ok_or("Platform does not support config dir")?
    /// #         .join(config.get_config_settings().app_name())
    /// #         .join(format!(
    /// #             "{}.toml",
    /// #             config.get_config_settings().config_name()
    /// #         ))
    /// # );
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_default_config_file_path(&self) -> Result<PathBuf, Error> {
        confy::get_configuration_file_path(
            &self.config_settings.app_name,
            Some(self.config_settings.config_name().0.as_str()),
        )
        .map_err(Error::ConfigFileLocation)
    }

    /// Writes the configuration to file
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Store`] if the configuration can not be written to file.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::ConnectionSecurity;
    /// use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let config_file = testdir::testdir!().join("my_app_store.conf");
    /// # let config = Config::new(
    /// #    ConfigSettings::new(
    /// #        "my_app".to_string(),
    /// #        ConfigInteractivity::NonInteractive,
    /// #        None,
    /// #    ),
    /// #    Some(&config_file),
    /// # )?;
    /// # config.add_device(
    /// #     "device1".to_string(),
    /// #     "https://example.org/api/v1".parse()?,
    /// #     ConnectionSecurity::Unsafe,
    /// # )?;
    /// config.store(Some(&config_file))?;
    ///
    /// // this fails because we can not write the configuration to a directory
    /// assert!(config.store(Some(&testdir::testdir!())).is_err());
    /// # // remove the config file again as we otherwise influence other tests
    /// # std::fs::remove_file(&config_file);
    /// # Ok(())
    /// # }
    /// ```
    pub fn store(&self, path: Option<&Path>) -> Result<(), Error> {
        if let Some(path) = path {
            confy::store_path(path, self).map_err(Error::Store)
        } else {
            confy::store(&self.config_settings.app_name, "config", self).map_err(Error::Store)
        }
    }
}

/// The handling of administrative secrets.
///
/// Administrative secrets may be handled in different ways (e.g. persistent or non-persistent).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdministrativeSecretHandling {
    /// The administrative secrets are handled in a plaintext file in a non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted administrative secrets on a file system.
    Plaintext,

    /// The administrative secrets are handled in a file encrypted using [systemd-creds] in a
    /// non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of (host-specific) encrypted administrative secrets on a file system, that
    /// could be extracted if the host is compromised.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    SystemdCreds,

    /// The administrative secrets are handled using [Shamir's Secret Sharing] (SSS).
    ///
    /// This variant is the default for production use, as the administrative secrets are only ever
    /// exposed on a volatile filesystem for the time of their use.
    /// The secrets are only made available to the system as shares of a shared secret, split using
    /// SSS.
    /// This way no holder of a share is aware of the administrative secrets and the system only
    /// for as long as it needs to use the administrative secrets.
    ///
    /// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
    #[default]
    ShamirsSecretSharing,
}

/// The handling of non-administrative secrets.
///
/// Non-administrative secrets represent passphrases for (non-Administrator) NetHSM users and may be
/// handled in different ways (e.g. encrypted or not encrypted).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    Eq,
    PartialEq,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum NonAdministrativeSecretHandling {
    /// Each non-administrative secret is handled in a plaintext file in a non-volatile
    /// directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted non-administrative secrets on a file system.
    Plaintext,

    /// Each non-administrative secret is encrypted for a specific system user using
    /// [systemd-creds] and the resulting files are stored in a non-volatile directory.
    ///
    /// ## Note
    ///
    /// Although secrets are stored as encrypted strings in dedicated files, they may be extracted
    /// under certain circumstances:
    ///
    /// - the root account is compromised
    ///   - decrypts and exfiltrates _all_ secrets
    ///   - the secret is not encrypted using a [TPM] and the file
    ///     `/var/lib/systemd/credential.secret` as well as _any_ encrypted secret is exfiltrated
    /// - a specific user is compromised, decrypts and exfiltrates its own ssecret
    ///
    /// It is therefore crucial to follow common best-practices:
    ///
    /// - rely on a [TPM] for encrypting secrets, so that files become host-specific
    /// - heavily guard access to all users, especially root
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    /// [TPM]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
    #[default]
    SystemdCreds,
}

/// A configuration for parallel use of connections with a set of system and NetHSM users.
///
/// This configuration type is meant to be used in a read-only fashion and does not support tracking
/// the passphrases for users.
/// As such, it is useful for tools, that create system users, as well as NetHSM users and keys
/// according to it.
///
/// Various mappings of system and [`NetHsm`] users exist, that are defined by the variants of
/// [`UserMapping`].
///
/// Some system users require providing SSH authorized key(s), while others do not allow that at
/// all.
/// NetHSM users can be added in namespaces, or system-wide, depending on their use-case.
/// System and NetHSM users must be unique.
///
/// Key IDs must be unique per namespace or system-wide (depending on where they are used).
/// Tags, used to provide access to keys for NetHSM users must be unique per namespace or
/// system-wide (depending on in which scope the user and key are used)
///
/// # Examples
///
/// The below example provides a fully functional TOML configuration, outlining all available
/// functionalities.
///
/// ```
/// # use std::io::Write;
/// #
/// # use nethsm_config::{ConfigInteractivity, ConfigName, ConfigSettings, HermeticParallelConfig};
/// #
/// # fn main() -> testresult::TestResult {
/// # let config_file = testdir::testdir!().join("basic_parallel_config_example.conf");
/// # {
/// let config_string = r#"
/// ## A non-negative integer, that describes the iteration of the configuration.
/// ## The iteration should only ever be increased between changes to the config and only under the circumstance,
/// ## that user mappings are removed and should also be removed from the state of the system making use of this
/// ## configuration.
/// ## Applications reading the configuration are thereby enabled to compare existing state on the system with the
/// ## current iteration and remove user mappings and accompanying data accordingly.
/// iteration = 1
///
/// ## The handling of administrative secrets on the system.
/// ## One of:
/// ## - "shamirs-secret-sharing": Administrative secrets are never persisted on the system and only provided as shares of a shared secret.
/// ## - "systemd-creds": Administrative secrets are persisted on the system as host-specific files, encrypted using systemd-creds (only for testing).
/// ## - "plaintext": Administrative secrets are persisted on the system in unencrypted plaintext files (only for testing).
/// admin_secret_handling = "shamirs-secret-sharing"
///
/// ## The handling of non-administrative secrets on the system.
/// ## One of:
/// ## - "systemd-creds": Non-administrative secrets are persisted on the system as host-specific files, encrypted using systemd-creds (the default).
/// ## - "plaintext": Non-administrative secrets are persisted on the system in unencrypted plaintext files (only for testing).
/// non_admin_secret_handling = "systemd-creds"
///
/// [[connections]]
/// url = "https://localhost:8443/api/v1/"
/// tls_security = "Unsafe"
///
/// ## The NetHSM user "admin" is a system-wide Administrator
/// [[users]]
/// nethsm_only_admin = "admin"
///
/// ## The SSH-accessible system user "ssh-backup1" is used in conjunction with
/// ## the NetHSM user "backup1" (system-wide Backup)
/// [[users]]
///
/// [users.system_nethsm_backup]
/// nethsm_user = "backup1"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host"
/// system_user = "ssh-backup1"
///
/// ## The SSH-accessible system user "ssh-metrics1" is used with several NetHSM users:
/// ## - "metrics1" (system-wide Metrics)
/// ## - "keymetrics1" (system-wide Operator)
/// ## - "ns1~keymetrics1" (namespace Operator)
/// [[users]]
///
/// [users.system_nethsm_metrics]
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host"
/// system_user = "ssh-metrics1"
///
/// [users.system_nethsm_metrics.nethsm_users]
/// metrics_user = "metrics1"
/// operator_users = ["keymetrics1", "ns1~keymetrics1"]
///
/// ## The SSH-accessible system user "ssh-operator1" is used in conjunction with
/// ## the NetHSM user "operator1" (system-wide Operator).
/// ## User "operator1" shares tag "tag1" with key "key1" and can therefore use it
/// ## (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "operator1"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host"
/// system_user = "ssh-operator1"
/// tag = "tag1"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key1"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The SSH-accessible system user "ssh-operator2" is used in conjunction with
/// ## the NetHSM user "operator2" (system-wide Operator).
/// ## User "operator2" shares tag "tag2" with key "key2" and can therefore use it
/// ## (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "operator2"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host"
/// system_user = "ssh-operator2"
/// tag = "tag2"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key2"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The NetHSM user "ns1~admin" is a namespace Administrator
/// [[users]]
/// nethsm_only_admin = "ns1~admin"
///
/// ## The SSH-accessible system user "ns1-ssh-operator1" is used in conjunction with
/// ## the NetHSM user "ns1~operator1" (namespace Operator).
/// ## User "ns1~operator1" shares tag "tag1" with key "key1" and can therefore use it
/// ## in its namespace (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "ns1~operator1"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host"
/// system_user = "ns1-ssh-operator1"
/// tag = "tag1"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key1"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The SSH-accessible system user "ns1-ssh-operator2" is used in conjunction with
/// ## the NetHSM user "ns2~operator1" (namespace Operator).
/// ## User "ns1~operator2" shares tag "tag2" with key "key1" and can therefore use it
/// ## in its namespace (for OpenPGP signing).
/// [[users]]
///
/// [users.system_nethsm_operator_signing]
/// nethsm_user = "ns1~operator2"
/// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host"
/// system_user = "ns1-ssh-operator2"
/// tag = "tag2"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup]
/// key_id = "key2"
/// key_type = "Curve25519"
/// key_mechanisms = ["EdDsaSignature"]
/// signature_type = "EdDsa"
///
/// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
/// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
/// version = "4"
///
/// ## The hermetic system user "local-metrics1" is used with several NetHSM users:
/// ## - "metrics2" (system-wide Metrics)
/// ## - "keymetrics2" (system-wide Operator)
/// ## - "ns1~keymetrics2" (namespace Operator)
/// [[users]]
///
/// [users.hermetic_system_nethsm_metrics]
/// system_user = "local-metrics1"
///
/// [users.hermetic_system_nethsm_metrics.nethsm_users]
/// metrics_user = "metrics2"
/// operator_users = ["keymetrics2", "ns1~keymetrics2"]
///
/// ## The SSH-accessible system user "ssh-share-down" is used for the
/// ## download of shares of a shared secret (divided by Shamir's Secret Sharing).
/// [[users]]
///
/// [users.system_only_share_download]
/// ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"]
/// system_user = "ssh-share-down"
///
/// ## The SSH-accessible system user "ssh-share-up" is used for the
/// ## upload of shares of a shared secret (divided by Shamir's Secret Sharing).
/// [[users]]
///
/// [users.system_only_share_upload]
/// ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"]
/// system_user = "ssh-share-up"
///
/// ## The SSH-accessible system user "ssh-wireguard-down" is used for the
/// ## download of WireGuard configuration, used on the host.
/// [[users]]
///
/// [users.system_only_wireguard_download]
/// ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host"]
/// system_user = "ssh-wireguard-down"
/// "#;
/// #
/// #    let mut buffer = std::fs::File::create(&config_file)?;
/// #    buffer.write_all(config_string.as_bytes())?;
/// # }
/// # HermeticParallelConfig::new_from_file(
/// #    ConfigSettings::new(
/// #        "my_app".to_string(),
/// #        ConfigInteractivity::NonInteractive,
/// #        None,
/// #    ),
/// #    Some(&config_file),
/// # )?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct HermeticParallelConfig {
    iteration: u32,
    admin_secret_handling: AdministrativeSecretHandling,
    non_admin_secret_handling: NonAdministrativeSecretHandling,
    connections: HashSet<Connection>,
    users: HashSet<UserMapping>,
    #[serde(skip)]
    settings: ConfigSettings,
}

impl HermeticParallelConfig {
    /// Creates a new [`HermeticParallelConfig`] from a configuration file.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file can not be loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::io::Write;
    ///
    /// use nethsm_config::{ConfigInteractivity, ConfigName, ConfigSettings, HermeticParallelConfig};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let config_file = testdir::testdir!().join("basic_parallel_config_new.conf");
    /// {
    ///     #[rustfmt::skip]
    ///     let config_string = r#"
    /// iteration = 1
    /// admin_secret_handling = "shamirs-secret-sharing"
    /// non_admin_secret_handling = "systemd-creds"
    /// [[connections]]
    /// url = "https://localhost:8443/api/v1/"
    /// tls_security = "Unsafe"
    ///
    /// [[users]]
    /// nethsm_only_admin = "admin"
    ///
    /// [[users]]
    /// [users.system_nethsm_backup]
    /// nethsm_user = "backup1"
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host"
    /// system_user = "ssh-backup1"
    ///
    /// [[users]]
    ///
    /// [users.system_nethsm_metrics]
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host"
    /// system_user = "ssh-metrics1"
    ///
    /// [users.system_nethsm_metrics.nethsm_users]
    /// metrics_user = "metrics1"
    /// operator_users = ["operator1metrics1"]
    ///
    /// [[users]]
    /// [users.system_nethsm_operator_signing]
    /// nethsm_user = "operator1"
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host"
    /// system_user = "ssh-operator1"
    /// tag = "tag1"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup]
    /// key_id = "key1"
    /// key_type = "Curve25519"
    /// key_mechanisms = ["EdDsaSignature"]
    /// signature_type = "EdDsa"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
    /// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
    /// version = "4"
    ///
    /// [[users]]
    /// [users.system_nethsm_operator_signing]
    /// nethsm_user = "operator2"
    /// ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host"
    /// system_user = "ssh-operator2"
    /// tag = "tag2"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup]
    /// key_id = "key2"
    /// key_type = "Curve25519"
    /// key_mechanisms = ["EdDsaSignature"]
    /// signature_type = "EdDsa"
    ///
    /// [users.system_nethsm_operator_signing.nethsm_key_setup.key_context.openpgp]
    /// user_ids = ["Foobar McFooface <foobar@mcfooface.org>"]
    /// version = "4"
    ///
    /// [[users]]
    ///
    /// [users.hermetic_system_nethsm_metrics]
    /// system_user = "local-metrics1"
    ///
    /// [users.hermetic_system_nethsm_metrics.nethsm_users]
    /// metrics_user = "metrics2"
    /// operator_users = ["operator2metrics1"]
    ///
    /// [[users]]
    /// [users.system_only_share_download]
    /// ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"]
    /// system_user = "ssh-share-down"
    ///
    /// [[users]]
    /// [users.system_only_share_upload]
    /// ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host"]
    /// system_user = "ssh-share-up"
    ///
    /// [[users]]
    /// [users.system_only_wireguard_download]
    /// ssh_authorized_keys = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host"]
    /// system_user = "ssh-wireguard-down"
    /// "#;
    ///     let mut buffer = std::fs::File::create(&config_file)?;
    ///     buffer.write_all(config_string.as_bytes())?;
    /// }
    /// HermeticParallelConfig::new_from_file(
    ///     ConfigSettings::new(
    ///         "my_app".to_string(),
    ///         ConfigInteractivity::NonInteractive,
    ///         None,
    ///     ),
    ///     Some(&config_file),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new_from_file(
        config_settings: ConfigSettings,
        path: Option<&Path>,
    ) -> Result<Self, Error> {
        let mut config: HermeticParallelConfig = if let Some(path) = path {
            confy::load_path(path).map_err(|error| Error::Load {
                description: if let Some(error) = error.source() {
                    error.to_string()
                } else {
                    "".to_string()
                },
                source: error,
            })?
        } else {
            confy::load(
                &config_settings.app_name,
                Some(config_settings.config_name.0.as_str()),
            )
            .map_err(|error| Error::Load {
                description: if let Some(error) = error.source() {
                    error.to_string()
                } else {
                    "".to_string()
                },
                source: error,
            })?
        };
        config.settings = config_settings;
        config.validate()?;

        Ok(config)
    }

    /// Creates a new [`HermeticParallelConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file can not be loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    ///
    /// use nethsm::{Connection, UserRole};
    /// use nethsm_config::{
    ///     AdministrativeSecretHandling,
    ///     AuthorizedKeyEntryList,
    ///     ConfigCredentials,
    ///     ConfigInteractivity,
    ///     ConfigName,
    ///     ConfigSettings,
    ///     HermeticParallelConfig,
    ///     NonAdministrativeSecretHandling,
    ///     UserMapping,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// HermeticParallelConfig::new(
    ///     ConfigSettings::new(
    ///         "my_app".to_string(),
    ///         ConfigInteractivity::NonInteractive,
    ///         None,
    ///     ),
    ///     1,
    ///     AdministrativeSecretHandling::ShamirsSecretSharing,
    ///     NonAdministrativeSecretHandling::SystemdCreds,
    ///     HashSet::from([Connection::new(
    ///         "https://localhost:8443/api/v1/".parse()?,
    ///         "Unsafe".parse()?,
    ///     )]),
    ///     HashSet::from([
    ///         UserMapping::NetHsmOnlyAdmin("admin".parse()?),
    ///         UserMapping::SystemOnlyShareDownload {
    ///             system_user: "ssh-share-down".parse()?,
    ///             ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?])?,
    ///         },
    ///         UserMapping::SystemOnlyShareUpload {
    ///             system_user: "ssh-share-up".parse()?,
    ///             ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?])?,
    ///         }]),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        config_settings: ConfigSettings,
        iteration: u32,
        admin_secret_handling: AdministrativeSecretHandling,
        non_admin_secret_handling: NonAdministrativeSecretHandling,
        connections: HashSet<Connection>,
        users: HashSet<UserMapping>,
    ) -> Result<Self, Error> {
        let config = Self {
            iteration,
            admin_secret_handling,
            non_admin_secret_handling,
            connections,
            users,
            settings: config_settings,
        };
        config.validate()?;
        Ok(config)
    }

    /// Writes a [`HermeticParallelConfig`] to file.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration file can not be written.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashSet;
    ///
    /// use nethsm::{Connection,CryptographicKeyContext, OpenPgpUserIdList, SigningKeySetup, UserRole};
    /// use nethsm_config::{
    ///     AuthorizedKeyEntryList,
    ///     AdministrativeSecretHandling,
    ///     ConfigCredentials,
    ///     ConfigInteractivity,
    ///     ConfigName,
    ///     ConfigSettings,
    ///     HermeticParallelConfig,
    ///     NetHsmMetricsUsers,
    ///     NonAdministrativeSecretHandling,
    ///     UserMapping,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// let config = HermeticParallelConfig::new(
    ///     ConfigSettings::new(
    ///         "my_app".to_string(),
    ///         ConfigInteractivity::NonInteractive,
    ///         None,
    ///     ),
    ///     1,
    ///     AdministrativeSecretHandling::ShamirsSecretSharing,
    ///     NonAdministrativeSecretHandling::SystemdCreds,
    ///     HashSet::from([Connection::new(
    ///         "https://localhost:8443/api/v1/".parse()?,
    ///         "Unsafe".parse()?,
    ///     )]),
    ///     HashSet::from([UserMapping::NetHsmOnlyAdmin("admin".parse()?),
    ///         UserMapping::SystemNetHsmBackup {
    ///             nethsm_user: "backup1".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
    ///             system_user: "ssh-backup1".parse()?,
    ///         },
    ///         UserMapping::SystemNetHsmMetrics {
    ///             nethsm_users: NetHsmMetricsUsers::new("metrics1".parse()?, vec!["operator2metrics1".parse()?])?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIioJ9uvAxUPunFh89T+ENo7OQerqHE8SQ+2v4VWbfUZ user@host".parse()?,
    ///             system_user: "ssh-metrics1".parse()?,
    ///         },
    ///         UserMapping::SystemNetHsmOperatorSigning {
    ///             nethsm_user: "operator1".parse()?,
    ///             nethsm_key_setup: SigningKeySetup::new(
    ///                 "key1".parse()?,
    ///                 "Curve25519".parse()?,
    ///                 vec!["EdDsaSignature".parse()?],
    ///                 None,
    ///                 "EdDsa".parse()?,
    ///                 CryptographicKeyContext::OpenPgp{
    ///                     user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
    ///                     version: "4".parse()?,
    ///                 })?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
    ///             system_user: "ssh-operator1".parse()?,
    ///             tag: "tag1".to_string(),
    ///         },
    ///         UserMapping::HermeticSystemNetHsmMetrics {
    ///             nethsm_users: NetHsmMetricsUsers::new("metrics2".parse()?, vec!["operator1metrics1".parse()?])?,
    ///             system_user: "local-metrics1".parse()?,
    ///         },
    ///         UserMapping::SystemOnlyShareDownload {
    ///             system_user: "ssh-share-down".parse()?,
    ///             ssh_authorized_keys: AuthorizedKeyEntryList::new(
    ///                 vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?],
    ///             )?,
    ///         },
    ///         UserMapping::SystemOnlyShareUpload {
    ///             system_user: "ssh-share-up".parse()?,
    ///             ssh_authorized_keys: AuthorizedKeyEntryList::new(
    ///                 vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?],
    ///             )?,
    ///         },
    ///         UserMapping::SystemOnlyWireGuardDownload {
    ///             system_user: "ssh-wireguard-down".parse()?,
    ///             ssh_authorized_keys: AuthorizedKeyEntryList::new(
    ///                 vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?],
    ///             )?,
    ///         },
    ///     ]),
    /// )?;
    ///
    /// let config_file = testdir::testdir!().join("basic_parallel_config_store.conf");
    /// config.store(Some(&config_file))?;
    /// # println!("{}", std::fs::read_to_string(&config_file)?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn store(&self, path: Option<&Path>) -> Result<(), Error> {
        if let Some(path) = path {
            confy::store_path(path, self).map_err(Error::Store)
        } else {
            confy::store(&self.settings.app_name, "config", self).map_err(Error::Store)
        }
    }

    /// Returns an Iterator over the available [`Connection`]s.
    pub fn iter_connections(&self) -> impl Iterator<Item = &Connection> {
        self.connections.iter()
    }

    /// Returns an Iterator over the available [`UserMapping`]s.
    pub fn iter_user_mappings(&self) -> impl Iterator<Item = &UserMapping> {
        self.users.iter()
    }

    /// Returns the [`AdministrativeSecretHandling`].
    pub fn get_administrative_secret_handling(&self) -> AdministrativeSecretHandling {
        self.admin_secret_handling
    }

    /// Returns the [`NonAdministrativeSecretHandling`].
    pub fn get_non_administrative_secret_handling(&self) -> NonAdministrativeSecretHandling {
        self.non_admin_secret_handling
    }

    /// Returns an [`ExtendedUserMapping`] for a system user of `name` if it exists.
    ///
    /// # Errors
    ///
    /// Returns an error if no [`UserMapping`] with a [`SystemUserId`] matching `name` is found.
    pub fn get_extended_mapping_for_user(&self, name: &str) -> Result<ExtendedUserMapping, Error> {
        for user_mapping in self.users.iter() {
            if user_mapping
                .get_system_user()
                .is_some_and(|system_user| system_user.as_ref() == name)
            {
                return Ok(ExtendedUserMapping::new(
                    self.admin_secret_handling,
                    self.non_admin_secret_handling,
                    self.connections.clone(),
                    user_mapping.clone(),
                ));
            }
        }
        Err(Error::NoMatchingMappingForSystemUser {
            name: name.to_string(),
        })
    }

    /// Validates the components of the [`HermeticParallelConfig`].
    fn validate(&self) -> Result<(), Error> {
        // ensure there are no duplicate system users
        {
            let mut system_users = HashSet::new();
            for system_user_id in self
                .users
                .iter()
                .filter_map(|mapping| mapping.get_system_user())
            {
                if !system_users.insert(system_user_id.clone()) {
                    return Err(Error::DuplicateSystemUserId {
                        system_user_id: system_user_id.clone(),
                    });
                }
            }
        }

        // ensure there are no duplicate NetHsm users
        {
            let mut nethsm_users = HashSet::new();
            for nethsm_user_id in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_nethsm_users())
            {
                if !nethsm_users.insert(nethsm_user_id.clone()) {
                    return Err(Error::DuplicateNetHsmUserId {
                        nethsm_user_id: nethsm_user_id.clone(),
                    });
                }
            }
        }

        // ensure that there is at least one system-wide administrator
        if self
            .users
            .iter()
            .filter_map(|mapping| {
                if let UserMapping::NetHsmOnlyAdmin(user_id) = mapping {
                    if !user_id.is_namespaced() {
                        Some(user_id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
            .is_none()
        {
            return Err(Error::MissingAdministrator);
        }

        // ensure that there is an Administrator in each used namespace
        {
            // namespaces for all users, that are not in the Administrator role
            let namespaces_users = self
                .users
                .iter()
                .filter(|mapping| !matches!(mapping, UserMapping::NetHsmOnlyAdmin(_)))
                .flat_map(|mapping| mapping.get_namespaces())
                .collect::<HashSet<String>>();
            // namespaces for all users, that are in the Administrator role
            let namespaces_admins = self
                .users
                .iter()
                .filter(|mapping| matches!(mapping, UserMapping::NetHsmOnlyAdmin(_)))
                .flat_map(|mapping| mapping.get_namespaces())
                .collect::<HashSet<String>>();

            let namespaces: Vec<String> = namespaces_users
                .difference(&namespaces_admins)
                .cloned()
                .collect();
            if !namespaces.is_empty() {
                return Err(Error::MissingNamespaceAdministrators { namespaces });
            }
        }

        if self.admin_secret_handling == AdministrativeSecretHandling::ShamirsSecretSharing {
            // ensure there is at least one system user for downloading shares of a shared
            // secret
            if !self
                .users
                .iter()
                .any(|mapping| matches!(mapping, UserMapping::SystemOnlyShareDownload { .. }))
            {
                return Err(Error::MissingShareDownloadUser);
            }

            // ensure there is at least one system user for uploading shares of a shared secret
            if !self
                .users
                .iter()
                .any(|mapping| matches!(mapping, UserMapping::SystemOnlyShareUpload { .. }))
            {
                return Err(Error::MissingShareUploadUser);
            }
        } else {
            // ensure there is no system user setup for uploading or downloading of shares of a
            // shared secret
            let share_users: Vec<SystemUserId> = self
                .users
                .iter()
                .filter_map(|mapping| match mapping {
                    UserMapping::SystemOnlyShareUpload {
                        system_user,
                        ssh_authorized_keys: _,
                    }
                    | UserMapping::SystemOnlyShareDownload {
                        system_user,
                        ssh_authorized_keys: _,
                    } => Some(system_user.clone()),
                    _ => None,
                })
                .collect();
            if !share_users.is_empty() {
                return Err(Error::NoSssButShareUsers { share_users });
            }
        }

        // ensure there are no duplicate authorized SSH keys in the set of uploading shareholders
        // and the rest (minus downloading shareholders)
        {
            let mut ssh_authorized_keys = HashSet::new();
            for ssh_authorized_key in self
                .users
                .iter()
                .filter(|mapping| {
                    !matches!(
                        mapping,
                        UserMapping::SystemOnlyShareDownload {
                            system_user: _,
                            ssh_authorized_keys: _,
                        }
                    )
                })
                .flat_map(|mapping| mapping.get_ssh_authorized_keys())
                // we know a valid Entry can be created from AuthorizedKeyEntry, because its
                // constructor ensures it, hence we discard Errors
                .filter_map(|authorized_key| {
                    ssh_key::authorized_keys::Entry::try_from(&authorized_key).ok()
                })
            {
                if !ssh_authorized_keys.insert(ssh_authorized_key.public_key().clone()) {
                    return Err(Error::DuplicateSshAuthorizedKey {
                        ssh_authorized_key: ssh_authorized_key.public_key().to_string(),
                    });
                }
            }
        }

        // ensure there are no duplicate authorized SSH keys in the set of downloading shareholders
        // and the rest (minus uploading shareholders)
        {
            let mut ssh_authorized_keys = HashSet::new();
            for ssh_authorized_key in self
                .users
                .iter()
                .filter(|mapping| {
                    !matches!(
                        mapping,
                        UserMapping::SystemOnlyShareUpload {
                            system_user: _,
                            ssh_authorized_keys: _,
                        }
                    )
                })
                .flat_map(|mapping| mapping.get_ssh_authorized_keys())
                // we know a valid Entry can be created from AuthorizedKeyEntry, because its
                // constructor ensures it, hence we discard Errors
                .filter_map(|authorized_key| {
                    ssh_key::authorized_keys::Entry::try_from(&authorized_key).ok()
                })
            {
                if !ssh_authorized_keys.insert(ssh_authorized_key.public_key().clone()) {
                    return Err(Error::DuplicateSshAuthorizedKey {
                        ssh_authorized_key: ssh_authorized_key.public_key().to_string(),
                    });
                }
            }
        }

        // ensure that only one-to-one relationships between users in the Operator role and keys
        // exist (system-wide and per-namespace)
        {
            // ensure that KeyIds are not reused system-wide
            let mut set = HashSet::new();
            for key_id in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_key_ids(None))
            {
                if !set.insert(key_id.clone()) {
                    return Err(Error::DuplicateKeyId { key_id });
                }
            }

            // ensure that KeyIds are not reused per namespace
            for namespace in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_namespaces())
            {
                let mut set = HashSet::new();
                for key_id in self
                    .users
                    .iter()
                    .flat_map(|mapping| mapping.get_key_ids(Some(&namespace)))
                {
                    if !set.insert(key_id.clone()) {
                        return Err(Error::DuplicateKeyIdInNamespace { key_id, namespace });
                    }
                }
            }
        }

        // ensure unique tags system-wide and per namespace
        {
            // ensure that tags are unique system-wide
            let mut set = HashSet::new();
            for tag in self.users.iter().flat_map(|mapping| mapping.get_tags(None)) {
                if !set.insert(tag) {
                    return Err(Error::DuplicateTag {
                        tag: tag.to_string(),
                    });
                }
            }

            // ensure that tags are unique in each namespace
            for namespace in self
                .users
                .iter()
                .flat_map(|mapping| mapping.get_namespaces())
            {
                let mut set = HashSet::new();
                for tag in self
                    .users
                    .iter()
                    .flat_map(|mapping| mapping.get_tags(Some(&namespace)))
                {
                    if !set.insert(tag) {
                        return Err(Error::DuplicateTagInNamespace {
                            tag: tag.to_string(),
                            namespace,
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::panic;
    use std::path::PathBuf;

    use rstest::rstest;
    use testdir::testdir;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    fn create_and_store_empty_config() -> TestResult {
        let config_file: PathBuf = testdir!().join("empty_config.toml");
        let config = Config::new(
            ConfigSettings::new("test".to_string(), ConfigInteractivity::Interactive, None),
            Some(&config_file),
        )?;
        println!("{:#?}", config);
        config.store(Some(&config_file))?;
        println!("config file:\n{}", std::fs::read_to_string(config_file)?);
        Ok(())
    }

    #[rstest]
    fn roundtrip_config(
        #[files("basic-config*.toml")]
        #[base_dir = "tests/fixtures/roundtrip-config/"]
        config_file: PathBuf,
    ) -> TestResult {
        let output_config_file: PathBuf = testdir!().join(
            config_file
                .file_name()
                .expect("the input config file should have a file name"),
        );
        let config = Config::new(
            ConfigSettings::new("test".to_string(), ConfigInteractivity::Interactive, None),
            Some(&config_file),
        )?;
        config.store(Some(&output_config_file))?;
        assert_eq!(
            std::fs::read_to_string(&output_config_file)?,
            std::fs::read_to_string(&config_file)?
        );

        Ok(())
    }

    #[rstest]
    fn basic_parallel_config_new_from_file(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/working/"]
        config_file: PathBuf,
    ) -> TestResult {
        HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        )?;

        Ok(())
    }

    #[rstest]
    fn basic_parallel_config_duplicate_system_user(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-system-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("{config_file:?}");
        match HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Err(Error::DuplicateSystemUserId { .. }) => Ok(()),
            Ok(_) => panic!("Did not trigger any Error!"),
            Err(error) => panic!("Did not trigger the correct Error: {:?}!", error),
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_nethsm_user(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-nethsm-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::DuplicateNetHsmUserId { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_missing_administrator(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/missing-administrator/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::MissingAdministrator) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_missing_namespace_administrators(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/missing-namespace-administrator/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::MissingNamespaceAdministrators { .. }) =
            HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_authorized_keys_share_uploader(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-authorized-keys-share-uploader/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {:?}", config_file);
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {:?}", config_file))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // uploaders
        if config_file_string.ends_with("admin-plaintext.toml")
            || config_file_string.ends_with("admin-systemd-creds.toml")
        {
            let _config = HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )?;
            Ok(())
        } else if let Err(Error::DuplicateSshAuthorizedKey { .. }) =
            HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_authorized_keys_share_downloader(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-authorized-keys-share-downloader/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {:?}", config_file);
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {:?}", config_file))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // downloaders
        if config_file_string.ends_with("admin-plaintext.toml")
            || config_file_string.ends_with("admin-systemd-creds.toml")
        {
            let _config = HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )?;
            Ok(())
        } else if let Err(Error::DuplicateSshAuthorizedKey { .. }) =
            HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )
        {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_authorized_keys_users(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-authorized-keys-users/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::DuplicateSshAuthorizedKey { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_missing_share_download_user(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/missing-share-download-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {:?}", config_file);
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {:?}", config_file))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // downloaders
        if config_file_string.ends_with("admin-plaintext.toml")
            || config_file_string.ends_with("admin-systemd-creds.toml")
        {
            let _config = HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )?;
            Ok(())
        } else if let Err(Error::MissingShareDownloadUser) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_missing_share_upload_user(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/missing-share-upload-user/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {:?}", config_file);
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {:?}", config_file))?;
        // when using plaintext or systemd-creds for administrative credentials, there are no share
        // downloaders
        if config_file_string.ends_with("admin-plaintext.toml")
            || config_file_string.ends_with("admin-systemd-creds.toml")
        {
            let _config = HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )?;
            Ok(())
        } else if let Err(Error::MissingShareUploadUser) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_no_sss_but_shares(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/no-sss-but-shares/"]
        config_file: PathBuf,
    ) -> TestResult {
        println!("Using configuration {:?}", config_file);
        let config_file_string = config_file
            .clone()
            .into_os_string()
            .into_string()
            .map_err(|_x| format!("Can't convert {:?}", config_file))?;
        // when using shamir's secret sharing for administrative credentials, there ought to be
        // share downloaders and uploaders
        if config_file_string.ends_with("admin-shamirs-secret-sharing.toml") {
            let _config = HermeticParallelConfig::new_from_file(
                ConfigSettings::new(
                    "test".to_string(),
                    ConfigInteractivity::NonInteractive,
                    None,
                ),
                Some(&config_file),
            )?;
            Ok(())
        } else if let Err(Error::NoSssButShareUsers { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_key_id(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-key-id/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::DuplicateKeyId { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_key_id_in_namespace(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-key-id-in-namespace/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::DuplicateKeyIdInNamespace { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_tag(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-tag/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::DuplicateTag { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }

    #[rstest]
    fn basic_parallel_config_duplicate_tag_in_namespace(
        #[files("basic-parallel-config-admin-*.toml")]
        #[base_dir = "tests/fixtures/duplicate-tag-in-namespace/"]
        config_file: PathBuf,
    ) -> TestResult {
        if let Err(Error::DuplicateTagInNamespace { .. }) = HermeticParallelConfig::new_from_file(
            ConfigSettings::new(
                "test".to_string(),
                ConfigInteractivity::NonInteractive,
                None,
            ),
            Some(&config_file),
        ) {
            Ok(())
        } else {
            panic!("Did not trigger the correct Error!")
        }
    }
}
