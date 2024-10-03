use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::Display,
    path::{Path, PathBuf},
    str::FromStr,
};

use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, Url, UserId, UserRole};
use serde::{Deserialize, Serialize};

use crate::credentials::ConfigCredentials;
use crate::prompt::{PassphrasePrompt, UserPrompt};

/// Errors related to configuration
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Issue getting the config file location
    #[error("Config file issue: {0}")]
    ConfigFileLocation(#[source] confy::ConfyError),

    /// A config loading error
    #[error("Config loading issue: {0}")]
    Load(#[source] confy::ConfyError),

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

    /// Device exists already
    #[error("Device exist already: {0}")]
    DeviceExists(String),

    /// Device does not exist
    #[error("Device does not exist: {0}")]
    DeviceMissing(String),

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

/// The connection of a device
///
/// Contains the [`Url`] and [`ConnectionSecurity`] for a [`NetHsm`] device.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Connection {
    url: Url,
    tls_security: ConnectionSecurity,
}

impl Connection {
    /// Creates a new [`Connection`]
    pub fn new(url: Url, tls_security: ConnectionSecurity) -> Self {
        Self { url, tls_security }
    }
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
    /// The configuration will return an [`Error`] if there
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
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, Connection, DeviceConfig};
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
    /// assert!(DeviceConfig::new(
    ///     connection.clone(),
    ///     vec![
    ///         ConfigCredentials::new(
    ///             UserRole::Operator,
    ///             "user1".parse()?,
    ///             Some("my-passphrase".to_string()),
    ///         ),
    ///         ConfigCredentials::new(
    ///             UserRole::Operator,
    ///             "user1".parse()?,
    ///             Some("my-passphrase".to_string()),
    ///         ),
    ///     ],
    ///     ConfigInteractivity::NonInteractive,
    /// )
    /// .is_err());
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
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, Connection, DeviceConfig};
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
    /// assert!(device_config
    ///     .add_credentials(ConfigCredentials::new(
    ///         UserRole::Operator,
    ///         "user1".parse()?,
    ///         Some("my-passphrase".to_string()),
    ///     ))
    ///     .is_err());
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
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, Connection, DeviceConfig};
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
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, Connection, DeviceConfig};
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
    /// use nethsm::{ConnectionSecurity, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, Connection, DeviceConfig};
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
    /// assert!(device_config
    ///     .get_matching_credentials(&[], &["user1".parse()?])
    ///     .is_err());
    ///
    /// // this fails because no user in the requested role exists
    /// assert!(device_config
    ///     .get_matching_credentials(&[UserRole::Metrics], &[])
    ///     .is_err());
    ///
    /// // this fails because no user with the name first provided exists
    /// assert!(device_config
    ///     .get_matching_credentials(&[UserRole::Operator], &["user2".parse()?, "user1".parse()?])
    ///     .is_err());
    ///
    /// // this fails because no user in the requested role with any of the provided names exists
    /// assert!(device_config
    ///     .get_matching_credentials(&[UserRole::Metrics], &["admin1".parse()?, "user1".parse()?])
    ///     .is_err());
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
    /// use nethsm::{ConnectionSecurity, Passphrase, UserRole};
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity, Connection, DeviceConfig};
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
                ConfigCredentials::new(role.clone(), UserPrompt::new(role.clone()).prompt()?, None)
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
        let nethsm = NetHsm::new(
            value.connection.borrow().url.clone(),
            value.connection.borrow().tls_security.clone(),
            None,
            None,
            None,
        )?;
        for creds in value.credentials.borrow().clone().into_iter() {
            nethsm.add_credentials(creds.into())
        }
        Ok(nethsm)
    }
}

impl TryFrom<&DeviceConfig> for NetHsm {
    type Error = Error;
    fn try_from(value: &DeviceConfig) -> Result<Self, Error> {
        let nethsm = NetHsm::new(
            value.connection.borrow().url.clone(),
            value.connection.borrow().tls_security.clone(),
            None,
            None,
            None,
        )?;
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
            confy::load_path(path).map_err(Error::Load)?
        } else {
            confy::load(&config_settings.app_name, "config").map_err(Error::Load)?
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
    /// assert!(config
    ///     .add_device(
    ///         "device1".to_string(),
    ///         "https://example.org/api/v1".parse()?,
    ///         ConnectionSecurity::Unsafe,
    ///     )
    ///     .is_err());
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
    /// assert!(config
    ///     .add_credentials(
    ///         "device1".to_string(),
    ///         ConfigCredentials::new(
    ///             UserRole::Operator,
    ///             "user1".parse()?,
    ///             Some("my-passphrase".to_string()),
    ///         ),
    ///     )
    ///     .is_err());
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
    /// assert!(config
    ///     .add_credentials(
    ///         "device1".to_string(),
    ///         ConfigCredentials::new(
    ///             UserRole::Operator,
    ///             "user1".parse()?,
    ///             Some("my-passphrase".to_string()),
    ///         ),
    ///     )
    ///     .is_err());
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
    /// assert!(config
    ///     .delete_credentials("device1", &"user1".parse()?)
    ///     .is_err());
    ///
    /// config.add_device(
    ///     "device1".to_string(),
    ///     "https://example.org/api/v1".parse()?,
    ///     ConnectionSecurity::Unsafe,
    /// )?;
    ///
    /// // this fails because the targeted credentials does not yet exist
    /// assert!(config
    ///     .delete_credentials("device1", &"user1".parse()?)
    ///     .is_err());
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

#[cfg(test)]
mod tests {
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
    fn roundtrip_config() -> TestResult {
        use std::fs::File;
        use std::io::Write;

        let config_string = r#"[devices.test.connection]
url = "https://localhost:8443/api/v1"
tls_security = "Unsafe"

[[devices.test.credentials]]
role = "Administrator"
name = "admin"
passphrase = "my-very-unsafe-admin-passphrase"
"#;
        let config_file = {
            let config_file: PathBuf = testdir!().join("prepopulated_config.toml");
            let mut buffer = File::create(&config_file)?;
            buffer.write_all(config_string.as_bytes())?;
            config_file
        };

        let config = Config::new(
            ConfigSettings::new("test".to_string(), ConfigInteractivity::Interactive, None),
            Some(&config_file),
        )?;
        config.store(Some(&config_file))?;
        assert_eq!(config_string, std::fs::read_to_string(&config_file)?);

        Ok(())
    }
}
