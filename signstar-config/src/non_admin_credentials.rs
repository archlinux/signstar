//! Non-administrative credentials handling for a NetHSM backend.
use std::{
    fmt::Debug,
    fs::read_to_string,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{Credentials, Passphrase, UserId};
use nethsm_config::{
    ConfigInteractivity,
    ConfigSettings,
    CredsAwareUserMapping,
    HermeticParallelConfig,
    NonAdministrativeSecretHandling,
    SystemUserId,
    UserMapping,
};
use nix::unistd::{User, geteuid};
use signstar_core::system_user::{
    EPHEMERAL_CREDENTIALS_BASE_DIR,
    HOME_BASE_DIR,
    PLAINTEXT_CREDENTIALS_EXTENSION,
    SYSTEMD_CREDS_CREDENTIALS_EXTENSION,
    USER_CREDENTIALS_DIR,
};

use crate::utils::delete_tmp_file;

/// An error that may occur when handling unprivileged credentials for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A command exited unsuccessfully.
    #[error(
        "The command exited with non-zero status code \"{exit_status}\":\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )]
    CommandNonZero {
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

    /// A [`UserMapping`] does not provide a system user.
    #[error("The user mapping does not provide a system user:\n{0}")]
    MissingSystemUser(String),

    /// The secret handling for a [`UserMapping`] does not match the requested secret retrieval
    /// operation.
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

    #[error("There is no Signstar config.")]
    NoSignstarConfig,

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
    #[error("Failed reading passphrase file {passphrase_path}:\n{source}")]
    ReadPassphraseFile {
        passphrase_path: PathBuf,
        source: std::io::Error,
    },

    /// Encrypting administrative secrets with systemd-creds failed
    #[error("Decrypting \"systemd-creds\" encrypted credentials failed:\n{0}")]
    DecryptSystemdCreds(#[source] std::io::Error),

    /// Unable to retrieve user data from the current process.
    #[error("Unable to retrieve user data from the current process:\n{0}")]
    GetUserData(#[source] nix::errno::Errno),

    /// There is no user data associated with the current process.
    #[error("There is no user data associated with the current process. Does the user exist?")]
    NoUserData,

    /// There is no user mapping for the user associated with the current process.
    #[error("There is no user mapping for the user associated with the current process: {user}")]
    NoUserMapping { user: String },

    /// There is more than one user mapping for the user associated with the current process.
    #[error(
        "There are {mappings} user mappings (instead of 1) for the user associated with the current process: {user}"
    )]
    TooManyUserMappings { user: String, mappings: usize },
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
        f.write_str("errors:")?;
        for (user_id, error) in self.get_userid_errors() {
            f.write_fmt(format_args!("user_id: {}, error:\n{}", user_id, error))?;
        }
        Ok(())
    }
}

pub trait PlaintextReader {
    /// Loads passphrases from plaintext files.
    fn load_plaintext(&self) -> Result<CredentialsLoading, Error>;
}

pub trait SystemdCredsReader {
    /// Loads passphrases from systemd-creds encrypted files.
    fn load_systemd_creds(&self) -> Result<CredentialsLoading, Error>;
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
    let default_mode = 100600;
    match passphrase_path.metadata() {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode != default_mode {
                return Err(Error::PassphraseFilePermissions {
                    passphrase_path: passphrase_path.to_path_buf(),
                    mode,
                    default_mode,
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

impl PlaintextReader for CredsAwareUserMapping {
    /// Loads passphrases for each [`UserId`] from plaintext files.
    ///
    /// Relies on [`get_persistent_passphrase_path_for_user`] to retrieve the specific path to a
    /// passphrase file for each [`UserId`] mapped to a [`SystemUserId`].
    ///
    /// Returns a [`CredentialsLoading`], which may contain critical errors related to loading a
    /// passphrase for each available [`UserId`].
    /// The caller is expected to handle any errors tracked in the returned object based on context.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the [`CredsAwareUserMapping`] provides no [`SystemUserId`],
    /// - or the [`CredsAwareUserMapping`] is not setup to track passphrases using
    ///   [`NonAdministrativeSecretHandling::Plaintext`].
    fn load_plaintext(&self) -> Result<CredentialsLoading, Error> {
        let Some(system_user) = self.get_user_mapping().get_system_user() else {
            return Err(Error::MissingSystemUser(format!(
                "{:?}",
                self.get_user_mapping()
            )));
        };

        let secret_handling = self.get_non_admin_secret_handling();
        if secret_handling != NonAdministrativeSecretHandling::Plaintext {
            return Err(Error::MismatchingSecretHandling {
                expected: NonAdministrativeSecretHandling::Plaintext,
                provided: secret_handling,
                mapping: format!("{:?}", self.get_user_mapping()),
            });
        }

        let mut credentials = Vec::new();
        let mut errors = Vec::new();
        for user_id in self.get_user_mapping().get_nethsm_users() {
            let passphrase_str =
                get_persistent_passphrase_path_for_user(system_user, &user_id, secret_handling);
            let passphrase_path = PathBuf::from(passphrase_str);

            // ensure the passphrase file is alright
            if let Err(error) = check_passphrase_file(passphrase_path.as_path()) {
                errors.push((user_id, error));
                continue;
            };

            // get passphrase or error
            match read_to_string(&passphrase_path).map_err(|source| Error::ReadPassphraseFile {
                passphrase_path,
                source,
            }) {
                Ok(passphrase) => {
                    credentials.push(Credentials::new(user_id, Some(Passphrase::new(passphrase))))
                }
                Err(error) => {
                    errors.push((user_id, error));
                    continue;
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

impl SystemdCredsReader for CredsAwareUserMapping {
    /// Loads passphrases for each [`UserId`] from `systemd-creds` encrypted files.
    ///
    /// Relies on [`get_persistent_passphrase_path_for_user`] to retrieve the specific path to a
    /// passphrase file for each [`UserId`] mapped to a [`SystemUserId`].
    ///
    /// Returns a [`CredentialsLoading`], which may contain critical errors related to loading a
    /// passphrase for each available [`UserId`].
    /// The caller is expected to handle any errors tracked in the returned object based on context.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the [`CredsAwareUserMapping`] provides no [`SystemUserId`],
    /// - or the [`CredsAwareUserMapping`] is not setup to track passphrases using
    ///   [`NonAdministrativeSecretHandling::SystemdCreds`].
    fn load_systemd_creds(&self) -> Result<CredentialsLoading, Error> {
        let Some(system_user) = self.get_user_mapping().get_system_user() else {
            return Err(Error::MissingSystemUser(format!(
                "{:?}",
                self.get_user_mapping()
            )));
        };

        let secret_handling = self.get_non_admin_secret_handling();
        if secret_handling != NonAdministrativeSecretHandling::SystemdCreds {
            return Err(Error::MismatchingSecretHandling {
                expected: NonAdministrativeSecretHandling::SystemdCreds,
                provided: secret_handling,
                mapping: format!("{:?}", self.get_user_mapping()),
            });
        }

        let mut credentials = Vec::new();
        let mut errors = Vec::new();
        for user_id in self.get_user_mapping().get_nethsm_users() {
            let passphrase_str =
                get_persistent_passphrase_path_for_user(system_user, &user_id, secret_handling);
            let passphrase_path = PathBuf::from(&passphrase_str);
            let ephemeral_passphrase_str =
                get_ephemeral_passphrase_path_for_user(system_user, &user_id);
            let ephemeral_passphrase_path = PathBuf::from(&ephemeral_passphrase_str);

            // ensure the passphrase file is alright
            if let Err(error) = check_passphrase_file(passphrase_path.as_path()) {
                errors.push((user_id, error));
                continue;
            };

            // decrypt passphrase using systemd-creds
            // TODO: directly use stdout instead of tmp file!
            match Command::new("systemd-creds")
                .args([
                    "--user",
                    "decrypt",
                    &passphrase_str,
                    &ephemeral_passphrase_str,
                ])
                .output()
                .map_err(Error::DecryptSystemdCreds)
            {
                Ok(decrypt_creds) => {
                    // fail if decryption did not result in a successful status code
                    if !decrypt_creds.status.success() {
                        delete_tmp_file(ephemeral_passphrase_path.as_path());
                        errors.push((
                            user_id,
                            Error::CommandNonZero {
                                exit_status: decrypt_creds.status,
                                stdout: String::from_utf8_lossy(&decrypt_creds.stdout).into_owned(),
                                stderr: String::from_utf8_lossy(&decrypt_creds.stderr).into_owned(),
                            },
                        ));
                        continue;
                    }

                    // ensure the decrypted passphrase file is alright
                    if let Err(error) = check_passphrase_file(ephemeral_passphrase_path.as_path()) {
                        errors.push((user_id, error));
                        continue;
                    };

                    // get passphrase from decrypted file or error
                    match read_to_string(&ephemeral_passphrase_path).map_err(|source| {
                        Error::ReadPassphraseFile {
                            passphrase_path,
                            source,
                        }
                    }) {
                        Ok(passphrase) => credentials
                            .push(Credentials::new(user_id, Some(Passphrase::new(passphrase)))),
                        Err(error) => {
                            errors.push((user_id, error));
                            continue;
                        }
                    }
                }
                Err(error) => {
                    delete_tmp_file(ephemeral_passphrase_path.as_path());
                    errors.push((user_id, error));
                    continue;
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
/// # Results
///
/// Returns an error if
/// - it is not possible to derive user data from the calling process,
/// - if there is no user data for the calling process,
/// - the Signstar configuration file does not exist,
/// - it is not possible to load the Signstar configuration,
/// - if not exactly one user mapping exists for the calling system user,
/// - or if credentials loading fails due to a severe error.
pub fn get_nethsm_credentials_for_system_user() -> Result<(UserMapping, CredentialsLoading), Error>
{
    let Some(user) = User::from_uid(geteuid()).map_err(Error::GetUserData)? else {
        return Err(Error::NoUserData);
    };

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

    // retrieve all mappings (and the secret handling) for the calling system user
    let user_mappings = Into::<Vec<CredsAwareUserMapping>>::into(system_config)
        .iter()
        .filter(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .is_some_and(|system_user_id| system_user_id.as_ref() == user.name)
        })
        .cloned()
        .collect::<Vec<CredsAwareUserMapping>>();

    // ensure that there is exactly one mapping for the calling system user
    if user_mappings.len() > 1 {
        return Err(Error::TooManyUserMappings {
            user: user.name,
            mappings: user_mappings.len(),
        });
    }
    let Some(user_mapping) = user_mappings.first().cloned() else {
        return Err(Error::NoUserMapping { user: user.name });
    };

    // get all credentials for the mapping
    let credentials_loading = match user_mapping.get_non_admin_secret_handling() {
        NonAdministrativeSecretHandling::Plaintext => user_mapping.load_plaintext()?,
        NonAdministrativeSecretHandling::SystemdCreds => user_mapping.load_systemd_creds()?,
    };

    Ok((user_mapping.get_user_mapping().clone(), credentials_loading))
}

/// Returns the path to a persistent passphrase file for a specific [`SystemUserId`] and [`UserId`].
pub fn get_persistent_passphrase_path_for_user(
    system_user: &SystemUserId,
    nethsm_user: &UserId,
    secret_handling: NonAdministrativeSecretHandling,
) -> String {
    let extension = match secret_handling {
        NonAdministrativeSecretHandling::Plaintext => PLAINTEXT_CREDENTIALS_EXTENSION,
        NonAdministrativeSecretHandling::SystemdCreds => SYSTEMD_CREDS_CREDENTIALS_EXTENSION,
    };
    [
        HOME_BASE_DIR,
        system_user.as_ref(),
        "/",
        USER_CREDENTIALS_DIR,
        &nethsm_user.to_string(),
        extension,
    ]
    .concat()
}

/// Returns the path to an ephemeral plaintext passphrase file for a [`SystemUserId`] and
/// [`UserId`].
pub fn get_ephemeral_passphrase_path_for_user(
    system_user: &SystemUserId,
    nethsm_user: &UserId,
) -> String {
    [
        EPHEMERAL_CREDENTIALS_BASE_DIR,
        system_user.as_ref(),
        "/",
        USER_CREDENTIALS_DIR,
        &nethsm_user.to_string(),
        PLAINTEXT_CREDENTIALS_EXTENSION,
    ]
    .concat()
}
