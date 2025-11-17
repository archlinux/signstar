//! Non-administrative credentials handling for an HSM backend.
use std::{
    fmt::{Debug, Display},
    path::PathBuf,
};

use signstar_common::common::SECRET_FILE_MODE;
use signstar_crypto::traits::UserWithPassphrase;

use crate::{
    ExtendedUserMapping,
    SignstarConfig,
    SystemUserId,
    UserMapping,
    utils::get_current_system_user,
};

/// An error that may occur when handling non-administrative credentials for an HSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There are one or more errors when loading credentials for a specific system user.
    #[error("Errors occurred when loading credentials for system user {system_user}:\n{errors}")]
    CredentialsLoading {
        /// The system user for which loading of backend user credentials led to errors.
        system_user: SystemUserId,
        /// The errors that occurred during loading of backend user credentials for `system_user`.
        errors: CredentialsLoadingErrors,
    },

    /// There are no credentials for a specific system user.
    #[error("There are no credentials for system user {system_user}")]
    CredentialsMissing {
        /// The system user for which credentials are missing.
        system_user: SystemUserId,
    },

    /// A mapping does not offer a system user.
    #[error("There is no system user in the mapping.")]
    NoSystemUser,

    /// A user is not a signing user for the HSM backend.
    #[error("The user is not an operator user in the HSM backend used for signing.")]
    NotSigningUser,

    /// A passphrase directory can not be created.
    #[error("Passphrase directory {path} for user {system_user} can not be created:\n{source}")]
    SecretsDirCreate {
        /// The path to a secrets directory that could not be created.
        path: PathBuf,
        /// The system user in whose home directory `path` could not be created.
        system_user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },

    /// A secrets file can not be created.
    #[error("The secrets file {path} can not be created for user {system_user}:\n{source}")]
    SecretsFileCreate {
        /// The path to a secrets file that could not be created.
        path: PathBuf,
        /// The system user in whose home directory `path` could not be created.
        system_user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },

    /// The file metadata of a secrets file cannot be retrieved.
    #[error("File metadata of secrets file {path} cannot be retrieved")]
    SecretsFileMetadata {
        /// The path to a secrets file for which metadata could not be retrieved.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },

    /// A secrets file does not exist.
    #[error("Secrets file not found: {path}")]
    SecretsFileMissing {
        /// The path to a secrets file that is missing.
        path: PathBuf,
    },

    /// A secrets file is not a file.
    #[error("Secrets file is not a file: {path}")]
    SecretsFileNotAFile {
        /// The path to a secrets file that is not a file.
        path: PathBuf,
    },

    /// A secrets file does not have the correct permissions.
    #[error("Secrets file {path} has permissions {mode}, but {SECRET_FILE_MODE} is required")]
    SecretsFilePermissions {
        /// The path to a secrets file for which permissions could not be set.
        path: PathBuf,
        /// The file mode that should be applied to the file at `path`.
        mode: u32,
    },

    /// A secrets file cannot be read.
    #[error("Failed reading secrets file {path}:\n{source}")]
    SecretsFileRead {
        /// The path to a secrets file that could not be read.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },

    /// A secrets file can not be written to.
    #[error("The secrets file {path} can not be written to for user {system_user}: {source}")]
    SecretsFileWrite {
        /// The path to a secrets file that could not be written to.
        path: PathBuf,
        /// The system user in whose home directory `path` resides.
        system_user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },
}

/// An error that may occur when loading credentials for a [`SystemUserId`].
///
/// Alongside an [`Error`][`crate::Error`] contains a target user name for which the error occurred.
#[derive(Debug)]
pub struct CredentialsLoadingError {
    user_id: String,
    error: crate::Error,
}

impl CredentialsLoadingError {
    /// Creates a new [`CredentialsLoadingError`].
    pub fn new(user_id: String, error: crate::Error) -> Self {
        Self { user_id, error }
    }

    /// Returns a reference to the user name.
    pub fn get_user_id(&self) -> &str {
        &self.user_id
    }

    /// Returns a reference to the [`Error`][crate::Error].
    pub fn get_error(&self) -> &crate::Error {
        &self.error
    }
}

impl Display for CredentialsLoadingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.user_id, self.error)
    }
}

/// A wrapper for a list of [`CredentialsLoadingError`]s.
#[derive(Debug)]
pub struct CredentialsLoadingErrors {
    errors: Vec<CredentialsLoadingError>,
}

impl CredentialsLoadingErrors {
    /// Creates a new [`CredentialsLoadingError`].
    pub fn new(errors: Vec<CredentialsLoadingError>) -> Self {
        Self { errors }
    }

    /// Returns a reference to the list of [`CredentialsLoadingError`]s.
    pub fn get_errors(&self) -> &[CredentialsLoadingError] {
        &self.errors
    }
}

impl Display for CredentialsLoadingErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.errors
                .iter()
                .map(|error| error.to_string())
                .collect::<Vec<String>>()
                .join("\n")
        )
    }
}

/// A collection of credentials and credential loading errors for a system user.
///
/// Tracks a [`SystemUserId`], zero or more [`UserWithPassphrase`] implementations mapped to it, as
/// well as zero or more errors related to loading the passphrase for each of those backend users.
#[derive(Debug)]
pub struct CredentialsLoading {
    mapping: ExtendedUserMapping,
    credentials: Vec<Box<dyn UserWithPassphrase>>,
    errors: CredentialsLoadingErrors,
}

impl CredentialsLoading {
    /// Creates a new [`CredentialsLoading`].
    pub fn new(
        mapping: ExtendedUserMapping,
        credentials: Vec<Box<dyn UserWithPassphrase>>,
        errors: CredentialsLoadingErrors,
    ) -> Self {
        Self {
            mapping,
            credentials,
            errors,
        }
    }

    /// Creates a [`CredentialsLoading`] for the calling system user.
    ///
    /// Uses the data of the calling system user to derive the specific mapping for it from the
    /// Signstar configuration (a [`SignstarConfig`]).
    /// Then continues to retrieve the credentials for all associated HSM users of the mapping.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - it is not possible to derive user data from the calling process,
    /// - if there is no user data for the calling process,
    /// - the Signstar configuration file does not exist,
    /// - it is not possible to load the Signstar configuration,
    /// - not exactly one user mapping exists for the calling system user,
    /// - or if credentials loading fails due to a severe error.
    pub fn from_system_user() -> Result<Self, crate::Error> {
        let user = get_current_system_user()?;

        let system_config = SignstarConfig::new_from_file(None)?;

        let Some(mapping) = system_config.get_extended_mapping_for_user(&user.name) else {
            return Err(
                crate::ConfigError::NoMatchingMappingForSystemUser { name: user.name }.into(),
            );
        };

        // get all credentials for the mapping
        let credentials_loading = mapping.load_credentials()?;

        Ok(credentials_loading)
    }

    /// Returns the [`ExtendedUserMapping`].
    pub fn get_mapping(&self) -> &ExtendedUserMapping {
        &self.mapping
    }

    /// Returns all [credentials][`UserWithPassphrase`].
    pub fn get_credentials(&self) -> &[Box<dyn UserWithPassphrase>] {
        &self.credentials
    }

    /// Returns a reference to a [`SystemUserId`].
    ///
    /// # Errors
    ///
    /// Returns an error if there is no system user in the tracked mapping.
    pub fn get_system_user_id(&self) -> Result<&SystemUserId, crate::Error> {
        match self.mapping.get_user_mapping().get_system_user() {
            Some(system_user) => Ok(system_user),
            None => Err(crate::Error::NonAdminSecretHandling(Error::NoSystemUser)),
        }
    }

    /// Indicates whether there are any errors with user names.
    ///
    /// Returns `true` if there are errors, `false` otherwise.
    pub fn has_userid_errors(&self) -> bool {
        !self.errors.get_errors().is_empty()
    }

    /// Returns the collected errors for user names.
    pub fn get_userid_errors(self) -> CredentialsLoadingErrors {
        self.errors
    }

    /// Indicates whether the contained [`ExtendedUserMapping`] is that of a signing user.
    pub fn has_signing_user(&self) -> bool {
        match self.mapping.get_user_mapping() {
            UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::SystemNetHsmBackup { .. }
            | UserMapping::SystemNetHsmMetrics { .. }
            | UserMapping::HermeticSystemNetHsmMetrics { .. }
            | UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => false,
            UserMapping::SystemNetHsmOperatorSigning { .. } => true,
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin { .. } | UserMapping::SystemYubiHsm2Backup { .. } => {
                false
            }
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsmOperatorSigning { .. } => true,
        }
    }

    /// Returns the credentials for a signing user.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the tracked user is not a signing user
    /// - errors occurred when loading the system user's credentials
    /// - or there are no credentials for the system user.
    pub fn credentials_for_signing_user(self) -> Result<Box<dyn UserWithPassphrase>, crate::Error> {
        if !self.has_signing_user() {
            return Err(crate::Error::NonAdminSecretHandling(Error::NotSigningUser));
        }

        if !self.errors.get_errors().is_empty() {
            return Err(crate::Error::NonAdminSecretHandling(
                Error::CredentialsLoading {
                    system_user: self.get_system_user_id()?.clone(),
                    errors: self.errors,
                },
            ));
        }

        let system_user = self.get_system_user_id()?.clone();
        let mut iterator = self.credentials.into_iter();

        if let Some(credentials) = iterator.next() {
            Ok(credentials)
        } else {
            Err(crate::Error::NonAdminSecretHandling(
                Error::CredentialsMissing { system_user },
            ))
        }
    }
}
