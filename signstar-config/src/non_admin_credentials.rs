//! Non-administrative credentials handling for a NetHSM backend.
use std::{
    fmt::{Debug, Display},
    fs::{File, Permissions, create_dir_all, read_to_string, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{FullCredentials, Passphrase, UserId};
#[cfg(doc)]
use nethsm_config::HermeticParallelConfig;
use nethsm_config::{ExtendedUserMapping, NonAdministrativeSecretHandling, SystemUserId};
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use signstar_common::{
    common::SECRET_FILE_MODE,
    system_user::{
        get_home_base_dir_path,
        get_plaintext_secret_file,
        get_systemd_creds_secret_file,
        get_user_secrets_dir,
    },
};

use crate::{
    config::load_config,
    utils::{
        fail_if_not_root,
        fail_if_root,
        get_command,
        get_current_system_user,
        get_system_user_pair,
        match_current_system_user,
    },
};

/// An error that may occur when handling non-administrative credentials for a NetHSM backend.
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

    /// A user is not a signing user for the NetHSM backend.
    #[error("The user is not an operator user in the NetHSM backend used for signing.")]
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
/// Alongside an [`Error`][`crate::Error`] contains a target [`UserId`] for which the error
/// occurred.
#[derive(Debug)]
pub struct CredentialsLoadingError {
    user_id: UserId,
    error: crate::Error,
}

impl CredentialsLoadingError {
    /// Creates a new [`CredentialsLoadingError`].
    pub fn new(user_id: UserId, error: crate::Error) -> Self {
        Self { user_id, error }
    }

    /// Returns a reference to the [`UserId`].
    pub fn get_user_id(&self) -> &UserId {
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
/// Tracks a [`SystemUserId`], zero or more [`FullCredentials`] mapped to it, as well as zero or
/// more errors related to loading the passphrase for a [`UserId`].
#[derive(Debug)]
pub struct CredentialsLoading {
    mapping: ExtendedUserMapping,
    credentials: Vec<FullCredentials>,
    errors: CredentialsLoadingErrors,
}

impl CredentialsLoading {
    /// Creates a new [`CredentialsLoading`].
    pub fn new(
        mapping: ExtendedUserMapping,
        credentials: Vec<FullCredentials>,
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
    /// Signstar configuration (a [`HermeticParallelConfig`]).
    /// Then continues to retrieve the credentials for all associated [`NetHsm`] users of the
    /// mapping.
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

        let system_config = load_config()?;

        let mapping = system_config
            .get_extended_mapping_for_user(&user.name)
            .map_err(|source| crate::Error::Config(crate::config::Error::NetHsmConfig(source)))?;

        // get all credentials for the mapping
        let credentials_loading = mapping.load_credentials()?;

        Ok(credentials_loading)
    }

    /// Returns the [`ExtendedUserMapping`].
    pub fn get_mapping(&self) -> &ExtendedUserMapping {
        &self.mapping
    }

    /// Returns all [`FullCredentials`].
    pub fn get_credentials(&self) -> &[FullCredentials] {
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

    /// Indicates whether there are any errors with [`UserId`]s.
    ///
    /// Returns `true` if there are errors, `false` otherwise.
    pub fn has_userid_errors(&self) -> bool {
        !self.errors.get_errors().is_empty()
    }

    /// Returns the collected errors for [`UserId`]s.
    pub fn get_userid_errors(self) -> CredentialsLoadingErrors {
        self.errors
    }

    /// Indicates whether the contained [`ExtendedUserMapping`] is that of a signing user.
    pub fn has_signing_user(&self) -> bool {
        matches!(
            self.mapping.get_user_mapping(),
            nethsm_config::UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: _,
                nethsm_key_setup: _,
                ssh_authorized_key: _,
                system_user: _,
                tag: _,
            }
        )
    }

    /// Returns the credentials for a signing user.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the tracked user is not a signing user
    /// - errors occurred when loading the system user's credentials
    /// - or there are no credentials for the system user.
    pub fn credentials_for_signing_user(self) -> Result<FullCredentials, crate::Error> {
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

        if let Some(credentials) = self.credentials.first() {
            Ok(credentials.clone())
        } else {
            return Err(crate::Error::NonAdminSecretHandling(
                Error::CredentialsMissing {
                    system_user: self.get_system_user_id()?.clone(),
                },
            ));
        }
    }
}

/// A trait to implement loading of credentials, which includes reading of secrets.
pub trait SecretsReader {
    /// Loads credentials.
    fn load_credentials(self) -> Result<CredentialsLoading, crate::Error>;
}

/// Checks the accessibility of a secrets file.
///
/// Checks whether file at `path`
/// - exists,
/// - is a file,
/// - has accessible metadata,
/// - and has the file mode [`SECRET_FILE_MODE`].
///
/// # Errors
///
/// Returns an error, if the file at `path`
/// - does not exist,
/// - is not a file,
/// - does not have accessible metadata,
/// - or has a file mode other than [`SECRET_FILE_MODE`].
fn check_secrets_file(path: &Path) -> Result<(), crate::Error> {
    // check if a path exists
    if !path.exists() {
        return Err(crate::Error::NonAdminSecretHandling(
            Error::SecretsFileMissing {
                path: path.to_path_buf(),
            },
        ));
    }

    // check if this is a file
    if !path.is_file() {
        return Err(crate::Error::NonAdminSecretHandling(
            Error::SecretsFileNotAFile {
                path: path.to_path_buf(),
            },
        ));
    }

    // check for correct permissions
    match path.metadata() {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode != SECRET_FILE_MODE {
                return Err(crate::Error::NonAdminSecretHandling(
                    Error::SecretsFilePermissions {
                        path: path.to_path_buf(),
                        mode,
                    },
                ));
            }
        }
        Err(source) => {
            return Err(crate::Error::NonAdminSecretHandling(
                Error::SecretsFileMetadata {
                    path: path.to_path_buf(),
                    source,
                },
            ));
        }
    }

    Ok(())
}

impl SecretsReader for ExtendedUserMapping {
    /// Loads credentials for each [`UserId`] associated with a [`SystemUserId`].
    ///
    /// The [`SystemUserId`] of the mapping must be equal to the current system user calling this
    /// function.
    /// Relies on [`get_plaintext_secret_file`] and [`get_systemd_creds_secret_file`] to retrieve
    /// the specific path to a secret file for each [`UserId`] mapped to a [`SystemUserId`].
    ///
    /// Returns a [`CredentialsLoading`], which may contain critical errors related to loading a
    /// passphrase for each available [`UserId`].
    /// The caller is expected to handle any errors tracked in the returned object based on context.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the [`ExtendedUserMapping`] provides no [`SystemUserId`],
    /// - no system user equal to the [`SystemUserId`] exists,
    /// - the [`SystemUserId`] is not equal to the currently calling system user,
    /// - or the [systemd-creds] command is not available when trying to decrypt secrets.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    fn load_credentials(self) -> Result<CredentialsLoading, crate::Error> {
        // Retrieve required SystemUserId and User and compare with current User.
        let (system_user, user) = get_system_user_pair(&self)?;
        let current_system_user = get_current_system_user()?;

        // fail if running as root
        fail_if_root(&current_system_user)?;
        match_current_system_user(&current_system_user, &user)?;

        let secret_handling = self.get_non_admin_secret_handling();
        let mut credentials = Vec::new();
        let mut errors = Vec::new();

        for user_id in self.get_user_mapping().get_nethsm_users() {
            let secrets_file = match secret_handling {
                NonAdministrativeSecretHandling::Plaintext => {
                    get_plaintext_secret_file(system_user.as_ref(), &user_id.to_string())
                }
                NonAdministrativeSecretHandling::SystemdCreds => {
                    get_systemd_creds_secret_file(system_user.as_ref(), &user_id.to_string())
                }
            };
            // Ensure the secrets file has correct ownership and permissions.
            if let Err(error) = check_secrets_file(secrets_file.as_path()) {
                errors.push(CredentialsLoadingError::new(user_id, error));
                continue;
            };

            match secret_handling {
                // Read from plaintext secrets file.
                NonAdministrativeSecretHandling::Plaintext => {
                    // get passphrase or error
                    match read_to_string(&secrets_file)
                        .map_err(|source| Error::SecretsFileRead {
                            path: secrets_file,
                            source,
                        })
                        .map_err(crate::Error::NonAdminSecretHandling)
                    {
                        Ok(passphrase) => credentials
                            .push(FullCredentials::new(user_id, Passphrase::new(passphrase))),
                        Err(error) => {
                            errors.push(CredentialsLoadingError::new(user_id, error));
                            continue;
                        }
                    }
                }
                // Read from systemd-creds encrypted secrets file.
                NonAdministrativeSecretHandling::SystemdCreds => {
                    // Decrypt secret using systemd-creds.
                    let creds_command = get_command("systemd-creds")?;
                    let mut command = Command::new(creds_command);
                    let command = command
                        .arg("--user")
                        .arg("decrypt")
                        .arg(&secrets_file)
                        .arg("-");
                    match command
                        .output()
                        .map_err(|source| crate::Error::CommandExec {
                            command: format!("{command:?}"),
                            source,
                        }) {
                        Ok(command_output) => {
                            // fail if decryption did not result in a successful status code
                            if !command_output.status.success() {
                                errors.push(CredentialsLoadingError::new(
                                    user_id,
                                    crate::Error::CommandNonZero {
                                        command: format!("{command:?}"),
                                        exit_status: command_output.status,
                                        stderr: String::from_utf8_lossy(&command_output.stderr)
                                            .into_owned(),
                                    },
                                ));
                                continue;
                            }

                            let creds = match String::from_utf8(command_output.stdout) {
                                Ok(creds) => creds,
                                Err(source) => {
                                    errors.push(CredentialsLoadingError::new(
                                        user_id.clone(),
                                        crate::Error::Utf8String {
                                            path: secrets_file,
                                            context: format!(
                                                "converting stdout of {command:?} to string"
                                            ),
                                            source,
                                        },
                                    ));
                                    continue;
                                }
                            };

                            credentials.push(FullCredentials::new(user_id, Passphrase::new(creds)));
                        }
                        Err(error) => {
                            errors.push(CredentialsLoadingError::new(user_id, error));
                            continue;
                        }
                    }
                }
            }
        }

        Ok(CredentialsLoading::new(
            self,
            credentials,
            CredentialsLoadingErrors { errors },
        ))
    }
}

/// A trait to create non-administrative secrets and accompanying directories.
pub trait SecretsWriter {
    /// Creates secrets directories for all non-administrative mappings.
    fn create_secrets_dir(&self) -> Result<(), crate::Error>;

    /// Creates non-administrative secrets for all mappings of system users to backend users.
    fn create_non_administrative_secrets(&self) -> Result<(), crate::Error>;
}

impl SecretsWriter for ExtendedUserMapping {
    /// Creates secrets directories for all non-administrative mappings.
    ///
    /// Matches the [`SystemUserId`] in a mapping with an actual user on the system.
    /// Creates the passphrase directory for the user and ensures correct ownership of it and all
    /// parent directories up until the user's home directory.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - no system user is available in the mapping,
    /// - the system user of the mapping is not available on the system,
    /// - the directory could not be created,
    /// - the ownership of any directory between the user's home and the passphrase directory can
    ///   not be changed.
    fn create_secrets_dir(&self) -> Result<(), crate::Error> {
        // Retrieve required SystemUserId and User and compare with current User.
        let (system_user, user) = get_system_user_pair(self)?;

        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        // get and create the user's passphrase directory
        let secrets_dir = get_user_secrets_dir(system_user.as_ref());
        create_dir_all(&secrets_dir).map_err(|source| Error::SecretsDirCreate {
            path: secrets_dir.clone(),
            system_user: system_user.clone(),
            source,
        })?;

        // Recursively chown all directories to the user and group, until `HOME_BASE_DIR` is
        // reached.
        let home_dir = get_home_base_dir_path().join(PathBuf::from(system_user.as_ref()));
        let mut chown_dir = secrets_dir.clone();
        while chown_dir != home_dir {
            chown(&chown_dir, Some(user.uid.as_raw()), Some(user.gid.as_raw())).map_err(
                |source| crate::Error::Chown {
                    path: chown_dir.to_path_buf(),
                    user: system_user.to_string(),
                    source,
                },
            )?;
            if let Some(parent) = &chown_dir.parent() {
                chown_dir = parent.to_path_buf()
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Creates passphrases for all non-administrative mappings.
    ///
    /// Creates a random alphanumeric, 30-char long passphrase for each backend user of each
    /// non-administrative user mapping.
    ///
    /// - If `self` is configured to use [`NonAdministrativeSecretHandling::Plaintext`], the
    ///   passphrase is stored in a secrets file, defined by [`get_plaintext_secret_file`].
    /// - If `self` is configured to use [`NonAdministrativeSecretHandling::SystemdCreds`], the
    ///   passphrase is encrypted using [systemd-creds] and stored in a secrets file, defined by
    ///   [`get_systemd_creds_secret_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the targeted system user does not exist in the mapping or on the system,
    /// - the function is called using a non-root user,
    /// - the [systemd-creds] command is not available when trying to encrypt the passphrase,
    /// - the encryption of the passphrase using [systemd-creds] fails,
    /// - the secrets file can not be created,
    /// - the secrets file can not be written to,
    /// - or the ownership and permissions of the secrets file can not be changed.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    fn create_non_administrative_secrets(&self) -> Result<(), crate::Error> {
        // Retrieve required SystemUserId and User.
        let (system_user, user) = get_system_user_pair(self)?;

        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        let secret_handling = self.get_non_admin_secret_handling();

        // add a secret for each NetHSM user
        for user_id in self.get_user_mapping().get_nethsm_users() {
            let secrets_file = match secret_handling {
                NonAdministrativeSecretHandling::Plaintext => {
                    get_plaintext_secret_file(system_user.as_ref(), &user_id.to_string())
                }
                NonAdministrativeSecretHandling::SystemdCreds => {
                    get_systemd_creds_secret_file(system_user.as_ref(), &user_id.to_string())
                }
            };
            println!(
                "Create secret for system user {system_user} and backend user {user_id} in file: {secrets_file:?}"
            );
            let secret = {
                // create initial (unencrypted) secret
                let initial_secret: String = thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(30)
                    .map(char::from)
                    .collect();
                // Create credentials files depending on secret handling
                match secret_handling {
                    NonAdministrativeSecretHandling::Plaintext => {
                        initial_secret.as_bytes().to_vec()
                    }
                    NonAdministrativeSecretHandling::SystemdCreds => {
                        // Create systemd-creds encrypted secret.
                        let creds_command = get_command("systemd-creds")?;
                        let mut command = Command::new(creds_command);
                        let command = command
                            .arg("--user")
                            .arg("--name=")
                            .arg("--uid")
                            .arg(system_user.as_ref())
                            .arg("encrypt")
                            .arg("-")
                            .arg("-");
                        let mut command_child = command
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .spawn()
                            .map_err(|source| crate::Error::CommandBackground {
                                command: format!("{command:?}"),
                                source,
                            })?;
                        let Some(mut stdin) = command_child.stdin.take() else {
                            return Err(crate::Error::CommandAttachToStdin {
                                command: format!("{command:?}"),
                            })?;
                        };

                        let system_user_thread = system_user.clone();
                        let handle = std::thread::spawn(move || {
                            stdin
                                .write_all(initial_secret.as_bytes())
                                .map_err(|source| crate::Error::CommandWriteToStdin {
                                    command:
                                        format!("systemd-creds --user --name= --uid {system_user_thread} encrypt - -"),
                                    source,
                                })
                        });

                        let _handle_result = handle.join().map_err(|source| crate::Error::Thread {
                            context: format!(
                                "storing systemd-creds encrypted non-administrative secrets: {source:?}"
                            ),
                        })?;

                        let command_output =
                            command_child.wait_with_output().map_err(|source| {
                                crate::Error::CommandExec {
                                    command: format!("{command:?}"),
                                    source,
                                }
                            })?;

                        if !command_output.status.success() {
                            return Err(crate::Error::CommandNonZero {
                                command: format!("{command:?}"),
                                exit_status: command_output.status,
                                stderr: String::from_utf8_lossy(&command_output.stderr)
                                    .into_owned(),
                            });
                        }
                        command_output.stdout
                    }
                }
            };

            // Write secret to file and adjust permission and ownership of file.
            let mut file = File::create(secrets_file.as_path()).map_err(|source| {
                Error::SecretsFileCreate {
                    path: secrets_file.clone(),
                    system_user: system_user.clone(),
                    source,
                }
            })?;
            file.write_all(&secret)
                .map_err(|source| Error::SecretsFileWrite {
                    path: secrets_file.clone(),
                    system_user: system_user.clone(),
                    source,
                })?;
            chown(
                &secrets_file,
                Some(user.uid.as_raw()),
                Some(user.gid.as_raw()),
            )
            .map_err(|source| crate::Error::Chown {
                path: secrets_file.clone(),
                user: system_user.to_string(),
                source,
            })?;
            set_permissions(
                secrets_file.as_path(),
                Permissions::from_mode(SECRET_FILE_MODE),
            )
            .map_err(|source| crate::Error::ApplyPermissions {
                path: secrets_file.clone(),
                mode: SECRET_FILE_MODE,
                source,
            })?;
        }
        Ok(())
    }
}
