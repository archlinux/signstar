//! Non-administrative credentials handling for a NetHSM backend.
use std::{
    fmt::Debug,
    fs::{File, Permissions, create_dir_all, read_to_string, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    string::FromUtf8Error,
};

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{Credentials, Passphrase, UserId};
use nethsm_config::{
    ConfigInteractivity,
    ConfigSettings,
    ExtendedUserMapping,
    HermeticParallelConfig,
    NonAdministrativeSecretHandling,
    SystemUserId,
};
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use signstar_core::{
    common::SECRET_FILE_MODE,
    system_user::{
        get_home_base_dir_path,
        get_plaintext_secret_file,
        get_systemd_creds_secret_file,
        get_user_secrets_dir,
    },
};

use crate::utils::{
    fail_non_root,
    get_command,
    get_current_system_user,
    get_system_user_pair,
    match_current_system_user,
};

/// An error that may occur when handling non-administrative credentials for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Applying permissions to a file failed.
    #[error("Unable to apply permissions to {path}:\n{source}")]
    ApplyPermissions {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Unable to attach to stdin of a command.
    #[error("Unable to attach to stdin of command \"{command}\"")]
    AttachToStdin { command: String },

    /// A utility function returned an error.
    #[error("Utility function error: {0}")]
    Utils(#[from] crate::utils::Error),

    /// Unable to write to stdin of a command.
    #[error("Unable to write to stdin of command \"{command}\"")]
    WriteToStdin {
        command: String,
        source: std::io::Error,
    },

    /// A command exited unsuccessfully.
    #[error(
        "The command \"{command}\" exited with non-zero status code \"{exit_status}\":\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )]
    CommandNonZero {
        command: String,
        exit_status: ExitStatus,
        stdout: String,
        stderr: String,
    },

    /// No credentials file could be found
    #[error("No credentials file found at: {path:?}")]
    CredsFileMissing { path: PathBuf },

    /// The credentials path is not a file
    #[error("The credentials path is not a file: {path:?}")]
    CredsNotAFile { path: PathBuf },

    /// The secret handling for a [`ExtendedUserMapping`] does not match the requested secret
    /// retrieval operation.
    #[error(
        "Expected secret handling \"{expected}\" but got \"{provided}\". Passphrases for the user mapping can not be retrieved:\n{mapping:#?}"
    )]
    MismatchingSecretHandling {
        expected: NonAdministrativeSecretHandling,
        provided: NonAdministrativeSecretHandling,
        mapping: String,
    },

    /// A passphrase file does not exist.
    #[error("Passphrase file not found: {passphrase_path}")]
    MissingPassphraseFile { passphrase_path: PathBuf },

    /// An error with an NetHSM configuration occurred.
    #[error("NetHSM configuration error: {0}")]
    NetHsmConfig(#[source] nethsm_config::Error),

    /// No signstar configuration file is present.
    #[error("There is no Signstar config.")]
    NoSignstarConfig,

    /// A passphrase directory can not be created.
    #[error(
        "Passphrase directory {passphrase_dir} for user {system_user} can not be created: {source}"
    )]
    PassphraseDirCreation {
        passphrase_dir: PathBuf,
        system_user: SystemUserId,
        source: std::io::Error,
    },

    /// The ownership of a directory can not be set.
    #[error("Ownership of directory {dir} can not be changed for user {system_user}: {source}")]
    DirChangeOwner {
        dir: PathBuf,
        system_user: SystemUserId,
        source: std::io::Error,
    },

    /// A secrets file can not be written
    #[error("The secrets file {dir} can not be written for user {system_user}: {source}")]
    WriteSecretsFile {
        dir: PathBuf,
        system_user: SystemUserId,
        source: std::io::Error,
    },

    /// A passphrase file does not exist.
    #[error("Passphrase file is not a file: {passphrase_path}")]
    PassphraseFileNotAFile { passphrase_path: PathBuf },

    /// A passphrase file does not have the correct permissions.
    #[error(
        "Passphrase file {passphrase_path} has permissions {mode}, but {default_mode} is required"
    )]
    PassphraseFilePermissions {
        passphrase_path: PathBuf,
        mode: u32,
        default_mode: u32,
    },

    /// The file metadata of a passphrase file could not be retrieved.
    #[error("Passphrase file metadata could not be retrieved: {passphrase_path}")]
    Metadata {
        passphrase_path: PathBuf,
        source: std::io::Error,
    },

    /// A passphrase file can not be read.
    #[error("Failed reading secrets file {secrets_file}:\n{source}")]
    ReadSecretsFile {
        secrets_file: PathBuf,
        source: std::io::Error,
    },

    /// Encrypting administrative secrets with systemd-creds failed
    #[error(
        "Decrypting secret at {path} for system user {system_user} and backend user {backend_user} using \"systemd-creds\" failed:\n{source}"
    )]
    DecryptSystemdCreds {
        path: PathBuf,
        system_user: SystemUserId,
        backend_user: UserId,
        source: std::io::Error,
    },

    /// Encrypting administrative secrets with systemd-creds failed
    #[error(
        "Encrypting secret at {path} for system user {system_user} and backend user {backend_user} using \"systemd-creds\" failed:\n{source}"
    )]
    EncryptSystemdCreds {
        path: PathBuf,
        system_user: SystemUserId,
        backend_user: UserId,
        source: std::io::Error,
    },

    /// There is no user mapping for the user associated with the current process.
    #[error(
        "There is no user mapping for the system user {user} associated with the current process:\n{source}"
    )]
    NoUserMapping {
        user: String,
        source: nethsm_config::Error,
    },

    /// There is more than one user mapping for the user associated with the current process.
    #[error(
        "There are {mappings} user mappings (instead of 1) for the user associated with the current process: {user}"
    )]
    TooManyUserMappings { user: String, mappings: usize },

    /// A UTF-8 error when trying to convert a string.
    #[error("UTF-8 error while trying to convert string in {context}:\n{source}")]
    Utf8Creds {
        context: String,
        source: std::str::Utf8Error,
    },

    /// A UTF-8 error occurred when trying to convert a byte vector to a string.
    #[error("UTF-8 error while {context}:\n{source}")]
    Utf8String {
        context: String,
        source: FromUtf8Error,
    },
}

/// A collection of credentials and credential loading errors for a system user.
///
/// Tracks a [`SystemUserId`], zero or more [`Credentials`] mapped to it, as well as zero or more
/// errors related to loading the passphrase for a [`UserId`].
pub struct CredentialsLoading {
    system_user: SystemUserId,
    credentials: Vec<Credentials>,
    errors: Vec<(UserId, Error)>,
}

impl CredentialsLoading {
    /// Creates a new [`CredentialsLoading`].
    pub fn new(
        system_user: SystemUserId,
        credentials: Vec<Credentials>,
        errors: Vec<(UserId, Error)>,
    ) -> Self {
        Self {
            system_user,
            credentials,
            errors,
        }
    }

    /// Returns the [`SystemUserId`].
    pub fn get_system_user(&self) -> &SystemUserId {
        &self.system_user
    }

    /// Returns all [`Credentials`].
    pub fn get_credentials(&self) -> &[Credentials] {
        &self.credentials
    }

    /// Indicates whether there are any errors with [`UserId`]s.
    ///
    /// Returns `true` if there are errors, `false` otherwise.
    pub fn has_userid_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    /// Returns the collected errors for [`UserId`]s.
    pub fn get_userid_errors(&self) -> &[(UserId, Error)] {
        &self.errors
    }
}

impl Debug for CredentialsLoading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("system_user_id: {}", self.get_system_user()))?;
        f.write_str("credentials:")?;
        for creds in self.get_credentials() {
            f.write_fmt(format_args!("user: {}", creds.user_id))?;
        }
        f.write_str("errors: \n")?;
        for (user_id, error) in self.get_userid_errors() {
            f.write_fmt(format_args!("user_id: {}, error:\n{}", user_id, error))?;
        }
        Ok(())
    }
}

/// A trait to implement loading of credentials, which includes reading of secrets.
pub trait SecretsReader {
    /// Loads credentials.
    fn load_credentials(&self) -> Result<CredentialsLoading, Error>;
}

/// Checks the accessibility of a passphrase file.
///
/// Checks whether file at `passphrase_path`
/// - exists,
/// - is a file,
/// - has accessible metadata,
/// - and has the file mode `100600`.
///
/// # Errors
///
/// Returns an error, if the file at `passphrase_path`
/// - does not exist,
/// - is not a file,
/// - does not have accessible metadata,
/// - or has a file mode other than `100600`.
fn check_passphrase_file(passphrase_path: &Path) -> Result<(), Error> {
    // check if a path exists
    if !passphrase_path.exists() {
        return Err(Error::MissingPassphraseFile {
            passphrase_path: passphrase_path.to_path_buf(),
        });
    }

    // check if this is a file
    if !passphrase_path.is_file() {
        return Err(Error::PassphraseFileNotAFile {
            passphrase_path: passphrase_path.to_path_buf(),
        });
    }

    // check for correct permissions
    match passphrase_path.metadata() {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode != SECRET_FILE_MODE {
                return Err(Error::PassphraseFilePermissions {
                    passphrase_path: passphrase_path.to_path_buf(),
                    mode,
                    default_mode: SECRET_FILE_MODE,
                });
            }
        }
        Err(source) => {
            return Err(Error::Metadata {
                passphrase_path: passphrase_path.to_path_buf(),
                source,
            });
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
    fn load_credentials(&self) -> Result<CredentialsLoading, Error> {
        // Retrieve required SystemUserId and User and compare with current User.
        let (system_user, user) = get_system_user_pair(self)?;
        match_current_system_user(&get_current_system_user()?, &user)?;

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
            if let Err(error) = check_passphrase_file(secrets_file.as_path()) {
                errors.push((user_id, error));
                continue;
            };

            match secret_handling {
                // Read from plaintext secrets file.
                NonAdministrativeSecretHandling::Plaintext => {
                    // get passphrase or error
                    match read_to_string(&secrets_file).map_err(|source| Error::ReadSecretsFile {
                        secrets_file,
                        source,
                    }) {
                        Ok(passphrase) => credentials
                            .push(Credentials::new(user_id, Some(Passphrase::new(passphrase)))),
                        Err(error) => {
                            errors.push((user_id, error));
                            continue;
                        }
                    }
                }
                // Read from systemd-creds encrypted secrets file.
                NonAdministrativeSecretHandling::SystemdCreds => {
                    // Decrypt secret using systemd-creds.
                    let creds_command = get_command("systemd-creds")?;
                    let mut command = Command::new(creds_command);
                    command.arg("--user");
                    command.arg("decrypt");
                    command.arg(&secrets_file);
                    command.arg("-");
                    match command
                        .output()
                        .map_err(|source| Error::DecryptSystemdCreds {
                            path: secrets_file.clone(),
                            system_user: system_user.clone(),
                            backend_user: user_id.clone(),
                            source,
                        }) {
                        Ok(command_output) => {
                            // fail if decryption did not result in a successful status code
                            if !command_output.status.success() {
                                errors.push((
                                    user_id,
                                    Error::CommandNonZero {
                                        command: format!("{command:?}"),
                                        exit_status: command_output.status,
                                        stdout: String::from_utf8_lossy(&command_output.stdout)
                                            .into_owned(),
                                        stderr: String::from_utf8_lossy(&command_output.stderr)
                                            .into_owned(),
                                    },
                                ));
                                continue;
                            }

                            let creds = match String::from_utf8(command_output.stdout) {
                                Ok(creds) => creds,
                                Err(source) => {
                                    errors.push((
                                        user_id.clone(),
                                        Error::Utf8String {
                                            context: format!(
                                                "converting stdout of {command:?} to string"
                                            ),
                                            source,
                                        },
                                    ));
                                    continue;
                                }
                            };

                            credentials
                                .push(Credentials::new(user_id, Some(Passphrase::new(creds))));
                        }
                        Err(error) => {
                            errors.push((user_id, error));
                            continue;
                        }
                    }
                }
            }
        }

        Ok(CredentialsLoading::new(
            system_user.clone(),
            credentials,
            errors,
        ))
    }
}

/// Returns the [`NetHsm`] credentials for the calling system user.
///
/// Uses the data of the calling system user to derive the specific mapping for it from the Signstar
/// configuration (a [`HermeticParallelConfig`]).
/// Then continues to retrieve the credentials for all associated [`NetHsm`] users of the mapping.
///
/// # Errors
///
/// Returns an error if
/// - it is not possible to derive user data from the calling process,
/// - if there is no user data for the calling process,
/// - the Signstar configuration file does not exist,
/// - it is not possible to load the Signstar configuration,
/// - if not exactly one user mapping exists for the calling system user,
/// - or if credentials loading fails due to a severe error.
pub fn get_nethsm_credentials_for_system_user()
-> Result<(ExtendedUserMapping, CredentialsLoading), Error> {
    let user = get_current_system_user()?;

    let Some(config_file_path) = signstar_core::config::get_config_file() else {
        return Err(Error::NoSignstarConfig);
    };
    let system_config = HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            "my_app".to_string(),
            ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(config_file_path.as_path()),
    )
    .map_err(Error::NetHsmConfig)?;

    let mapping = system_config
        .get_extended_mapping_for_user(&user.name)
        .map_err(|source| Error::NoUserMapping {
            user: user.name,
            source,
        })?;

    // get all credentials for the mapping
    let credentials_loading = mapping.load_credentials()?;

    Ok((mapping, credentials_loading))
}

/// A trait for [`ExtendedUserMapping`] to handle secrets and accompanying directories.
pub trait PassphraseCreation {
    /// Creates secrets directories for all non-administrative mappings.
    fn create_secrets_dir(&self) -> Result<(), Error>;

    /// Creates non-administrative secrets for all mappings of system users to backend users.
    fn create_non_administrative_secrets(&self) -> Result<(), Error>;
}

impl PassphraseCreation for ExtendedUserMapping {
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
    fn create_secrets_dir(&self) -> Result<(), Error> {
        // Retrieve required SystemUserId and User and compare with current User.
        let (system_user, user) = get_system_user_pair(self)?;

        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

        // get and create the user's passphrase directory
        let secrets_dir = get_user_secrets_dir(system_user.as_ref());
        create_dir_all(&secrets_dir).map_err(|source| Error::PassphraseDirCreation {
            passphrase_dir: secrets_dir.clone(),
            system_user: system_user.clone(),
            source,
        })?;

        // Recursively chown all directories to the user and group, until `HOME_BASE_DIR` is
        // reached.
        let home_dir = get_home_base_dir_path().join(PathBuf::from(system_user.as_ref()));
        let mut chown_dir = secrets_dir.clone();
        while chown_dir != home_dir {
            chown(&chown_dir, Some(user.uid.as_raw()), Some(user.gid.as_raw())).map_err(
                |source| Error::DirChangeOwner {
                    dir: chown_dir.to_path_buf(),
                    system_user: system_user.clone(),
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
    /// # Errors
    ///
    /// Returns an error if
    /// - or the [systemd-creds] command is not available when trying to decrypt secrets.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    fn create_non_administrative_secrets(&self) -> Result<(), Error> {
        // Retrieve required SystemUserId and User.
        let (system_user, user) = get_system_user_pair(self)?;

        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

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
                        command.arg("--user");
                        command.arg("--name=");
                        command.arg("--uid");
                        command.arg(system_user.as_ref());
                        command.arg("encrypt");
                        command.arg("-");
                        command.arg("-");
                        let mut command_child = command
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .spawn()
                            .map_err(|source| Error::EncryptSystemdCreds {
                                path: secrets_file.clone(),
                                system_user: system_user.clone(),
                                backend_user: user_id.clone(),
                                source,
                            })?;
                        let Some(mut stdin) = command_child.stdin.take() else {
                            return Err(Error::AttachToStdin {
                                command: format!("{command:?}"),
                            })?;
                        };

                        std::thread::spawn(move || {
                            stdin
                                .write_all(initial_secret.as_bytes())
                                .map_err(|source| Error::WriteToStdin {
                                    command: "systemd-creds".to_string(),
                                    source,
                                })
                        });

                        let command_output =
                            command_child.wait_with_output().map_err(|source| {
                                Error::EncryptSystemdCreds {
                                    path: secrets_file.clone(),
                                    system_user: system_user.clone(),
                                    backend_user: user_id.clone(),
                                    source,
                                }
                            })?;

                        if !command_output.status.success() {
                            return Err(Error::CommandNonZero {
                                command: format!("{command:?}"),
                                exit_status: command_output.status,
                                stdout: String::from_utf8_lossy(&command_output.stdout)
                                    .into_owned(),
                                stderr: String::from_utf8_lossy(&command_output.stderr)
                                    .into_owned(),
                            });
                        }
                        command_output.stdout
                    }
                }
            };

            // Write secret to file and adjust permission and ownership of file.
            let mut file =
                File::create(secrets_file.as_path()).map_err(|source| Error::WriteSecretsFile {
                    dir: secrets_file.clone(),
                    system_user: system_user.clone(),
                    source,
                })?;
            file.write_all(&secret)
                .map_err(|source| Error::WriteSecretsFile {
                    dir: secrets_file.clone(),
                    system_user: system_user.clone(),
                    source,
                })?;
            chown(
                &secrets_file,
                Some(user.uid.as_raw()),
                Some(user.gid.as_raw()),
            )
            .map_err(|source| Error::DirChangeOwner {
                dir: secrets_file.clone(),
                system_user: system_user.clone(),
                source,
            })?;
            set_permissions(
                secrets_file.as_path(),
                Permissions::from_mode(SECRET_FILE_MODE),
            )
            .map_err(|source| Error::ApplyPermissions {
                path: secrets_file.clone(),
                source,
            })?;
            assert!(secrets_file.exists());
        }
        Ok(())
    }
}
