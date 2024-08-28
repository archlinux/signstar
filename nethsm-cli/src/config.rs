use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, HashSet},
    path::Path,
};

use nethsm::{ConnectionSecurity, Credentials, NetHsm, Passphrase, Url, UserId, UserRole};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::prompt::{PassphrasePrompt, UserPrompt};

/// Errors related to configuration
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A config loading error
    #[error("Config loading issue: {0}")]
    Load(#[source] confy::ConfyError),

    /// A config storing error
    #[error("Config storing issue: {0}")]
    Store(#[source] confy::ConfyError),

    /// Credentials exist already
    #[error("Credentials exist already: {0}")]
    CredentialsExist(String),

    /// Credentials do not exist
    #[error("Credentials do not exist: {0}")]
    CredentialsMissing(String),

    /// Credentials do not exist
    #[error("No user {0} in the role {1} exists")]
    MatchingCredentialsMissing(String, String),

    /// Credentials do not exist
    #[error("No user matches the role {0} exists")]
    NoMatchingCredentials(String),

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
/// Tracks the [`Url`] and [`ConnectionSecurity`] of a NetHsm device.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Connection {
    url: Url,
    tls_security: ConnectionSecurity,
}

/// The credentials of a user on a NetHsm device
///
/// Tracks the [`UserRole`], name and optionally the passphrase of the user.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize, Zeroize)]
pub struct ConfigCredentials {
    #[zeroize(skip)]
    role: UserRole,
    #[zeroize(skip)]
    name: UserId,
    passphrase: Option<String>,
}

impl ConfigCredentials {
    /// Creates a new [`ConfigCredentials`]
    pub fn new(role: UserRole, name: UserId, passphrase: Option<String>) -> Self {
        Self {
            role,
            name,
            passphrase,
        }
    }

    /// Returns the name of the [`ConfigCredentials`]
    pub fn get_name(&self) -> String {
        self.name.to_string()
    }

    /// Returns the User ID of the [`ConfigCredentials`]
    pub fn get_user_id(&self) -> UserId {
        self.name.clone()
    }

    /// Returns the passphrase of the [`ConfigCredentials`]
    pub fn get_passphrase(&self) -> Option<String> {
        self.passphrase.as_ref().cloned()
    }

    /// Sets the passphrase of the [`ConfigCredentials`]
    pub fn set_passphrase(&mut self, passphrase: String) {
        self.passphrase = Some(passphrase)
    }

    /// Returns whether a passphrase is set for the [`ConfigCredentials`]
    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }
}

impl From<ConfigCredentials> for Credentials {
    fn from(value: ConfigCredentials) -> Self {
        Self::new(value.name, value.passphrase.map(Passphrase::new))
    }
}

/// The configuration for a NetHsm device
///
/// Tracks the [`Connection`] for the device as well as a set of [`ConfigCredentials`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeviceConfig {
    connection: RefCell<Connection>,
    credentials: RefCell<HashSet<ConfigCredentials>>,
}

impl DeviceConfig {
    /// Adds credentials to the device
    ///
    /// Adds credentials tracking a [`UserRole`], a name and optional passphrase.
    ///
    /// # Errors
    ///
    /// Returns an error if the credentials exist already.
    pub fn add_credentials(
        &self,
        role: UserRole,
        name: UserId,
        passphrase: Option<String>,
    ) -> Result<(), crate::Error> {
        if !self
            .credentials
            .borrow()
            .iter()
            .any(|creds| creds.name == name)
        {
            self.credentials.borrow_mut().insert(ConfigCredentials {
                role,
                name: name.clone(),
                passphrase,
            });
            Ok(())
        } else {
            Err(Error::CredentialsExist(name.to_string()).into())
        }
    }

    /// Returns [`ConfigCredentials`] by name
    ///
    /// # Errors
    ///
    /// Returns an error if no [`ConfigCredentials`] matches the provided name.
    pub fn get_credentials(&self, name: &UserId) -> Result<ConfigCredentials, Error> {
        if let Some(creds) = self
            .credentials
            .borrow()
            .iter()
            .find(|creds| &creds.name == name)
        {
            Ok(creds.clone())
        } else {
            Err(Error::CredentialsMissing(name.to_string()))
        }
    }

    /// Deletes [`ConfigCredentials`] by name
    ///
    /// # Errors
    ///
    /// Returns an error if no [`ConfigCredentials`] matches the provided name.
    pub fn delete_credentials(&self, name: &str) -> Result<(), crate::Error> {
        let before = self.credentials.borrow().len();
        self.credentials
            .borrow_mut()
            .retain(|creds| creds.name.to_string() != name);
        let after = self.credentials.borrow().len();
        if before == after {
            Err(Error::CredentialsMissing(name.to_string()).into())
        } else {
            Ok(())
        }
    }

    /// Returns [`ConfigCredentials`] matching a [`UserRole`]
    ///
    /// If `name` is [`Option::Some`], credentials matching one of the provided `roles` are
    /// returned.
    /// If `name` is [`Option::None`], the credentials first found, matching one of the provided
    /// `roles` are returned.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// * the provided `name` does not match any existing credentials
    /// * credentials matching the `name` do not have any of the provided `roles`
    /// * no credentials have any of the provided `roles`
    fn get_matching_credentials(
        &self,
        roles: &[UserRole],
        name: Option<&UserId>,
    ) -> Result<ConfigCredentials, Error> {
        if let Some(name) = name {
            if let Ok(creds) = &self.get_credentials(name) {
                if roles.contains(&creds.role) {
                    Ok(creds.clone())
                } else {
                    Err(Error::MatchingCredentialsMissing(
                        name.to_string(),
                        roles
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    ))
                }
            } else {
                Err(Error::CredentialsMissing(name.to_string()))
            }
        } else {
            let creds = self
                .credentials
                .borrow()
                .iter()
                .filter_map(|creds| {
                    if roles.contains(&creds.role) {
                        Some(creds.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<ConfigCredentials>>();
            creds
                .first()
                .ok_or_else(|| {
                    Error::NoMatchingCredentials(
                        roles
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<String>>()
                            .join(","),
                    )
                })
                .cloned()
        }
    }

    /// Returns a [`NetHsm`] (optionally with credentials) based on the [`DeviceConfig`]
    ///
    /// If there is at least one [`UserRole`] in `roles` and `name` is [`Option::Some`], matching
    /// credentials are searched for. If no credentials matching one of the `roles` and the `name`
    /// are found, credentials for a user in the first user role is prompted for interactively.
    /// is [`Option::None`], temporary [`ConfigCredentials`] using the first [`UserRole`] in `roles`
    /// are created by prompting for user input.
    /// When no passphrase is set for the [`ConfigCredentials`] yet, the user is prompted for it.
    ///
    /// In all other cases no [`ConfigCredentials`] are added for the [`NetHsm`].
    pub fn nethsm_with_matching_creds(
        &self,
        roles: &[UserRole],
        name: Option<&UserId>,
        passphrase: Option<Passphrase>,
    ) -> Result<NetHsm, Error> {
        let nethsm: NetHsm = self.try_into()?;

        // do not add any users if no user roles are requested
        if !roles.is_empty() {
            // try to find a user name with a role in the requested set of credentials
            let creds = if let Ok(creds) = self.get_matching_credentials(roles, name) {
                creds
            // or request a user name in the first requested role
            } else {
                let role = roles.first().expect("We have at least one user role");
                ConfigCredentials::new(role.clone(), UserPrompt::new(role.clone()).prompt()?, None)
            };
            if !creds.has_passphrase() {
                let credentials = if let Some(passphrase) = passphrase {
                    Credentials::new(creds.get_user_id(), Some(passphrase))
                } else {
                    Credentials::new(
                        creds.get_user_id(),
                        Some(PassphrasePrompt::User(creds.get_user_id().to_string()).prompt()?),
                    )
                };
                nethsm.add_credentials(credentials);
            }

            nethsm.use_credentials(&creds.get_user_id())?;
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

/// The configuration for all devices
///
/// Tracks a set of [`DeviceConfig`]s hashed by label.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Config {
    devices: RefCell<HashMap<String, DeviceConfig>>,
}

impl Config {
    /// Loads the configuration from the default location
    ///
    /// The default location is `~/.config/nethsm/config.toml` (on Linux).
    /// A default configuration file is created if none is found.
    pub fn new(path: Option<&Path>) -> Result<Self, crate::Error> {
        if let Some(path) = path {
            confy::load_path(path).map_err(|error| Error::Load(error).into())
        } else {
            confy::load(env!("CARGO_BIN_NAME"), "config").map_err(|error| Error::Load(error).into())
        }
    }

    /// Adds a [`DeviceConfig`]
    ///
    /// # Errors
    ///
    /// Returns an error if a [`DeviceConfig`] with the same `label` exists already.
    pub fn add_device(
        &self,
        label: String,
        url: Url,
        tls_security: ConnectionSecurity,
    ) -> Result<(), Error> {
        let credentials = RefCell::new(HashSet::new());
        if let Entry::Vacant(entry) = self.devices.borrow_mut().entry(label.clone()) {
            entry.insert(DeviceConfig {
                connection: RefCell::new(Connection { url, tls_security }),
                credentials,
            });
            Ok(())
        } else {
            Err(Error::DeviceExists(label))
        }
    }

    /// Deletes a [`DeviceConfig`]
    ///
    /// # Errors
    ///
    /// Returns an error if no [`DeviceConfig`] with a matching `label` exists.
    pub fn delete_device(&self, label: &str) -> Result<(), crate::Error> {
        if self.devices.borrow_mut().remove(label).is_some() {
            Ok(())
        } else {
            Err(Error::DeviceMissing(label.to_string()).into())
        }
    }

    /// Returns a single [`DeviceConfig`] from the [`Config`] based on an optional label
    ///
    /// If `label` is [`Some`], a specific [`DeviceConfig`] is retrieved.
    /// If `label` is [`None`] and only one device is defined in the config, then the
    /// [`DeviceConfig`] for that device is returned.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// * `label` is [`Option::Some`] but it can not be found in the [`Config`]
    /// * `label` is [`Option::None`] and there is no device or more than one device defined in
    ///   [`Config`].
    pub fn get_device(&self, label: Option<&str>) -> Result<DeviceConfig, crate::Error> {
        if let Some(label) = label {
            if let Some(device_config) = self.devices.borrow().get(label) {
                Ok(device_config.clone())
            } else {
                Err(Error::DeviceMissing(label.to_string()).into())
            }
        } else {
            match self.devices.borrow().len() {
                0 => Err(Error::NoDevice.into()),
                1 => Ok(self
                    .devices
                    .borrow()
                    .values()
                    .next()
                    .expect("there should be one")
                    .to_owned()),
                _ => Err(Error::MoreThanOneDevice.into()),
            }
        }
    }

    /// Returns a single [`DeviceConfig`] label from the [`Config`]
    ///
    /// # Errors
    ///
    /// Returns an error if not exactly one [`DeviceConfig`] is present.
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
    /// Returns an error if the the credentials can not be added or if no [`DeviceConfig`] matching
    /// the label exists.
    pub fn add_credentials(
        &self,
        label: String,
        role: UserRole,
        name: UserId,
        passphrase: Option<String>,
    ) -> Result<(), crate::Error> {
        if let Some(device) = self.devices.borrow_mut().get_mut(&label) {
            device.add_credentials(role, name, passphrase)?
        } else {
            return Err(Error::DeviceMissing(label).into());
        }

        Ok(())
    }

    /// Deletes credentials from a [`DeviceConfig`]
    ///
    /// The `label` identifies the [`DeviceConfig`] and the `name` the name of the credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if no [`DeviceConfig`] matches the label or if the credentials can not be
    /// removed.
    pub fn delete_credentials(&self, label: String, name: String) -> Result<(), crate::Error> {
        if let Some(device) = self.devices.borrow_mut().get_mut(&label) {
            device.delete_credentials(&name)?
        } else {
            return Err(Error::DeviceMissing(label).into());
        }

        Ok(())
    }

    /// Writes the configuration to file
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration can not be written to file.
    pub fn store(&self, path: Option<&Path>) -> Result<(), crate::Error> {
        if let Some(path) = path {
            confy::store_path(path, self).map_err(|error| Error::Store(error).into())
        } else {
            confy::store(env!("CARGO_BIN_NAME"), "config", self)
                .map_err(|error| Error::Store(error).into())
        }
    }
}
