//! Administrative credentials handling for a NetHSM backend.

use std::{
    fs::{File, Permissions, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(doc)]
use nethsm::UserId;
use nethsm::{FullCredentials, Passphrase};
use nethsm_config::AdministrativeSecretHandling;
use serde::{Deserialize, Serialize};
use signstar_common::{
    admin_credentials::{
        create_credentials_dir,
        get_plaintext_credentials_file,
        get_systemd_creds_credentials_file,
    },
    common::SECRET_FILE_MODE,
};

use crate::utils::{fail_if_not_root, get_command, get_current_system_user};

/// An error that may occur when handling administrative credentials for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is no top-level administrator.
    #[error("There is no top-level administrator but at least one is required")]
    AdministratorMissing,

    /// There is no top-level administrator with the name "admin".
    #[error("The default top-level administrator \"admin\" is missing")]
    AdministratorNoDefault,

    /// Deserializing administrative secrets from a TOML string failed.
    #[error("Deserializing administrative secrets in {path} as TOML string failed:\n{source}")]
    ConfigFromToml {
        /// The path to a config file that can not be deserialization as TOML string.
        path: PathBuf,
        /// The boxed source error.
        source: Box<toml::de::Error>,
    },

    /// Administrative secrets can not be loaded.
    #[error("Unable to load administrative secrets from {path}:\n{source}")]
    ConfigLoad {
        /// The path to a config file from which administrative secrets can not be loaded.
        path: PathBuf,
        /// The boxed source error.
        source: Box<confy::ConfyError>,
    },

    /// Administrative secrets can not be stored to file.
    #[error("Unable to store administrative secrets in {path}:\n{source}")]
    ConfigStore {
        /// The path to a config file in which administrative secrets can not be stored.
        path: PathBuf,
        /// The source error.
        source: Box<confy::ConfyError>,
    },

    /// Serializing a Signstar config as TOML string failed.
    #[error("Serializing administrative secrets as TOML string failed:\n{0}")]
    ConfigToToml(#[source] toml::ser::Error),

    /// A credentials file can not be created.
    #[error("The credentials file {path} can not be created:\n{source}")]
    CredsFileCreate {
        /// The path to a credentials file administrative secrets can not be stored.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },

    /// A credentials file does not exist.
    #[error("The credentials file {path} does not exist")]
    CredsFileMissing {
        /// The path to a missing credentials file.
        path: PathBuf,
    },

    /// A credentials file is not a file.
    #[error("The credentials file {path} is not a file")]
    CredsFileNotAFile {
        /// The path to a credentials file that is not a file.
        path: PathBuf,
    },

    /// A credentials file can not be written to.
    #[error("The credentials file {path} can not be written to:\n{source}")]
    CredsFileWrite {
        /// The path to a credentials file that can not be written to.
        path: PathBuf,
        /// The source error
        source: std::io::Error,
    },

    /// A passphrase is too short.
    #[error(
        "The passphrase for {context} is too short (should be at least {minimum_length} characters)"
    )]
    PassphraseTooShort {
        /// The context in which the passphrase is used.
        ///
        /// This is inserted into the sentence "The _context_ passphrase is not long enough"
        context: String,

        /// The minimum length of a passphrase.
        minimum_length: usize,
    },
}

/// Administrative credentials.
///
/// Tracks the following credentials and passphrases:
/// - the backup passphrase of the backend,
/// - the unlock passphrase of the backend,
/// - the top-level administrator credentials of the backend,
/// - the namespace administrator credentials of the backend.
///
/// # Note
///
/// The unlock and backup passphrase must be at least 10 characters long.
/// The passphrases of top-level and namespace administrator accounts must be at least 10 characters
/// long.
/// The list of top-level administrator credentials must include an account with the username
/// "admin".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct AdminCredentials {
    iteration: u32,
    backup_passphrase: Passphrase,
    unlock_passphrase: Passphrase,
    administrators: Vec<FullCredentials>,
    namespace_administrators: Vec<FullCredentials>,
}

impl AdminCredentials {
    /// Creates a new [`AdminCredentials`] instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::FullCredentials;
    /// use signstar_config::admin_credentials::AdminCredentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = AdminCredentials::new(
    ///     1,
    ///     "backup-passphrase".parse()?,
    ///     "unlock-passphrase".parse()?,
    ///     vec![FullCredentials::new(
    ///         "admin".parse()?,
    ///         "admin-passphrase".parse()?,
    ///     )],
    ///     vec![FullCredentials::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".parse()?,
    ///     )],
    /// )?;
    /// # // the backup passphrase is too short
    /// # assert!(AdminCredentials::new(
    /// #     1,
    /// #     "short".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("admin".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // the unlock passphrase is too short
    /// # assert!(AdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "short".parse()?,
    /// #     vec![FullCredentials::new("admin".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // there is no top-level administrator
    /// # assert!(AdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     Vec::new(),
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // there is no default top-level administrator
    /// # assert!(AdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("some".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // a top-level administrator passphrase is too short
    /// # assert!(AdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("admin".parse()?, "short".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // a namespace administrator passphrase is too short
    /// # assert!(AdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("some".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "short".parse()?,
    /// #     )],
    /// # ).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        iteration: u32,
        backup_passphrase: Passphrase,
        unlock_passphrase: Passphrase,
        administrators: Vec<FullCredentials>,
        namespace_administrators: Vec<FullCredentials>,
    ) -> Result<Self, crate::Error> {
        let admin_credentials = Self {
            iteration,
            backup_passphrase,
            unlock_passphrase,
            administrators,
            namespace_administrators,
        };
        admin_credentials.validate()?;

        Ok(admin_credentials)
    }

    /// Loads an [`AdminCredentials`] from the default file location.
    ///
    /// Depending on `secrets_handling`, the file path and contents differ:
    ///
    /// - [`AdministrativeSecretHandling::Plaintext`]: the file path is defined by
    ///   [`get_plaintext_credentials_file`] and the contents are plaintext,
    /// - [`AdministrativeSecretHandling::SystemdCreds`]: the file path is defined by
    ///   [`get_systemd_creds_credentials_file`] and the contents are [systemd-creds] encrypted.
    ///
    /// Delegates to [`AdminCredentials::load_from_file`], providing the specific file path and the
    /// selected `secrets_handling`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm_config::AdministrativeSecretHandling;
    /// use signstar_config::admin_credentials::AdminCredentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// // load plaintext credentials from default location
    /// let plaintext_admin_creds = AdminCredentials::load(AdministrativeSecretHandling::Plaintext)?;
    ///
    /// // load systemd-creds encrypted credentials from default location
    /// let systemd_creds_admin_creds =
    ///     AdminCredentials::load(AdministrativeSecretHandling::SystemdCreds)?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if [`AdminCredentials::load_from_file`] fails.
    ///
    /// # Panics
    ///
    /// This function panics when providing [`AdministrativeSecretHandling::ShamirsSecretSharing`]
    /// as `secrets_handling`.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn load(secrets_handling: AdministrativeSecretHandling) -> Result<Self, crate::Error> {
        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        Self::load_from_file(
            match secrets_handling {
                AdministrativeSecretHandling::Plaintext => get_plaintext_credentials_file(),
                AdministrativeSecretHandling::SystemdCreds => get_systemd_creds_credentials_file(),
                AdministrativeSecretHandling::ShamirsSecretSharing => {
                    unimplemented!("Shamir's Secret Sharing is not yet supported")
                }
            },
            secrets_handling,
        )
    }

    /// Loads an [`AdminCredentials`] instance from file.
    ///
    /// Depending on `path` and `secrets_handling`, the behavior of this function differs:
    ///
    /// - If `secrets_handling` is set to [`AdministrativeSecretHandling::Plaintext`] the contents
    ///   at `path` are considered to be plaintext.
    /// - If `secrets_handling` is set to [`AdministrativeSecretHandling::SystemdCreds`] the
    ///   contents at `path` are considered to be [systemd-creds] encrypted.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::io::Write;
    ///
    /// use nethsm_config::AdministrativeSecretHandling;
    /// use signstar_config::admin_credentials::AdminCredentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let admin_creds = r#"iteration = 1
    /// backup_passphrase = "backup-passphrase"
    /// unlock_passphrase = "unlock-passphrase"
    ///
    /// [[administrators]]
    /// name = "admin"
    /// passphrase = "admin-passphrase"
    ///
    /// [[namespace_administrators]]
    /// name = "ns1~admin"
    /// passphrase = "ns1-admin-passphrase"
    /// "#;
    /// let mut tempfile = tempfile::NamedTempFile::new()?;
    /// write!(tempfile.as_file_mut(), "{admin_creds}");
    ///
    /// assert!(
    ///     AdminCredentials::load_from_file(tempfile.path(), AdministrativeSecretHandling::Plaintext)
    ///         .is_ok()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the function is called by a system user that is not root,
    /// - the file at `path` does not exist,
    /// - the file at `path` is not a file,
    /// - the file at `path` is considered as plaintext but can not be loaded,
    /// - the file at `path` is considered as [systemd-creds] encrypted but can not be decrypted,
    /// - or the file at `path` is considered as [systemd-creds] encrypted but can not be loaded
    ///   after decryption.
    ///
    /// # Panics
    ///
    /// This function panics when providing [`AdministrativeSecretHandling::ShamirsSecretSharing`]
    /// as `secrets_handling`.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn load_from_file(
        path: impl AsRef<Path>,
        secrets_handling: AdministrativeSecretHandling,
    ) -> Result<Self, crate::Error> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(crate::Error::AdminSecretHandling(Error::CredsFileMissing {
                path: path.to_path_buf(),
            }));
        }
        if !path.is_file() {
            return Err(crate::Error::AdminSecretHandling(
                Error::CredsFileNotAFile {
                    path: path.to_path_buf(),
                },
            ));
        }

        let config: Self = match secrets_handling {
            AdministrativeSecretHandling::Plaintext => {
                confy::load_path(path).map_err(|source| {
                    crate::Error::AdminSecretHandling(Error::ConfigLoad {
                        path: path.to_path_buf(),
                        source: Box::new(source),
                    })
                })?
            }
            AdministrativeSecretHandling::SystemdCreds => {
                // Decrypt the credentials using systemd-creds.
                let creds_command = get_command("systemd-creds")?;
                let mut command = Command::new(creds_command);
                let command = command.arg("decrypt").arg(path).arg("-");
                let command_output = command.output().map_err(|source| {
                    signstar_common::error::Error::CommandExec {
                        command: format!("{command:?}"),
                        source,
                    }
                })?;
                if !command_output.status.success() {
                    return Err(signstar_common::error::Error::CommandNonZero {
                        command: format!("{command:?}"),
                        exit_status: command_output.status,
                        stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
                    })?;
                }

                // Read the resulting TOML string from stdout and construct an AdminCredentials from
                // it.
                let config_str = String::from_utf8(command_output.stdout).map_err(|source| {
                    crate::Error::Utf8String {
                        path: path.to_path_buf(),
                        context: "after decrypting".to_string(),
                        source,
                    }
                })?;
                toml::from_str(&config_str).map_err(|source| {
                    crate::Error::AdminSecretHandling(Error::ConfigFromToml {
                        path: path.to_path_buf(),
                        source: Box::new(source),
                    })
                })?
            }
            AdministrativeSecretHandling::ShamirsSecretSharing => {
                unimplemented!("Shamir's Secret Sharing is not yet supported")
            }
        };
        config.validate()?;
        Ok(config)
    }

    /// Stores the [`AdminCredentials`] as a file in the default location.
    ///
    /// Depending on `secrets_handling`, the file path and contents differ:
    ///
    /// - [`AdministrativeSecretHandling::Plaintext`]: the file path is defined by
    ///   [`get_plaintext_credentials_file`] and the contents are plaintext,
    /// - [`AdministrativeSecretHandling::SystemdCreds`]: the file path is defined by
    ///   [`get_systemd_creds_credentials_file`] and the contents are [systemd-creds] encrypted.
    ///
    /// Automatically creates the directory in which the administrative credentials are created.
    /// After storing the [`AdminCredentials`] as file, its file permissions and ownership are
    /// adjusted so that it is only accessible by root.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::FullCredentials;
    /// use nethsm_config::AdministrativeSecretHandling;
    /// use signstar_config::admin_credentials::AdminCredentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = AdminCredentials::new(
    ///     1,
    ///     "backup-passphrase".parse()?,
    ///     "unlock-passphrase".parse()?,
    ///     vec![FullCredentials::new(
    ///         "admin".parse()?,
    ///         "admin-passphrase".parse()?,
    ///     )],
    ///     vec![FullCredentials::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".parse()?,
    ///     )],
    /// )?;
    ///
    /// // store as plaintext file
    /// creds.store(AdministrativeSecretHandling::Plaintext)?;
    ///
    /// // store as systemd-creds encrypted file
    /// creds.store(AdministrativeSecretHandling::SystemdCreds)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the function is called by a system user that is not root,
    /// - the directory for administrative credentials cannot be created,
    /// - `self` cannot be turned into its TOML representation,
    /// - the [systemd-creds] command is not found,
    /// - [systemd-creds] fails to encrypt the TOML representation of `self`,
    /// - the target file can not be created,
    /// - the plaintext or [systemd-creds] encrypted data can not be written to file,
    /// - or the ownership or permissions of the target file can not be adjusted.
    ///
    /// # Panics
    ///
    /// This function panics when providing [`AdministrativeSecretHandling::ShamirsSecretSharing`]
    /// as `secrets_handling`.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn store(
        &self,
        secrets_handling: AdministrativeSecretHandling,
    ) -> Result<(), crate::Error> {
        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        create_credentials_dir()?;

        let (config_data, path) = {
            // Get the TOML string representation of self.
            let config_data = toml::to_string_pretty(self)
                .map_err(|source| crate::Error::AdminSecretHandling(Error::ConfigToToml(source)))?;
            match secrets_handling {
                AdministrativeSecretHandling::Plaintext => (
                    config_data.as_bytes().to_vec(),
                    get_plaintext_credentials_file(),
                ),
                AdministrativeSecretHandling::SystemdCreds => {
                    // Encrypt self as systemd-creds encrypted TOML file.
                    let creds_command = get_command("systemd-creds")?;
                    let mut command = Command::new(creds_command);
                    let command = command.args(["encrypt", "-", "-"]);

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

                    let handle = std::thread::spawn(move || {
                        stdin.write_all(config_data.as_bytes()).map_err(|source| {
                            crate::Error::CommandWriteToStdin {
                                command: "systemd-creds encrypt - -".to_string(),
                                source,
                            }
                        })
                    });

                    let _handle_result = handle.join().map_err(|source| crate::Error::Thread {
                        context: format!(
                            "storing systemd-creds encrypted administrative credentials: {source:?}"
                        ),
                    })?;

                    let command_output = command_child.wait_with_output().map_err(|source| {
                        signstar_common::error::Error::CommandExec {
                            command: format!("{command:?}"),
                            source,
                        }
                    })?;
                    if !command_output.status.success() {
                        return Err(signstar_common::error::Error::CommandNonZero {
                            command: format!("{command:?}"),
                            exit_status: command_output.status,
                            stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
                        })?;
                    }
                    (command_output.stdout, get_systemd_creds_credentials_file())
                }
                AdministrativeSecretHandling::ShamirsSecretSharing => {
                    unimplemented!("Shamir's Secret Sharing is not yet supported")
                }
            }
        };

        // Write administrative credentials to file and adjust permission and ownership
        // of file
        {
            let mut file = File::create(path.as_path()).map_err(|source| {
                crate::Error::AdminSecretHandling(Error::CredsFileCreate {
                    path: path.clone(),
                    source,
                })
            })?;
            file.write_all(&config_data).map_err(|source| {
                crate::Error::AdminSecretHandling(Error::CredsFileWrite {
                    path: path.to_path_buf(),
                    source,
                })
            })?;
        }
        chown(&path, Some(0), Some(0)).map_err(|source| crate::Error::Chown {
            path: path.clone(),
            user: "root".to_string(),
            source,
        })?;
        set_permissions(path.as_path(), Permissions::from_mode(SECRET_FILE_MODE)).map_err(
            |source| crate::Error::ApplyPermissions {
                path: path.clone(),
                mode: SECRET_FILE_MODE,
                source,
            },
        )?;

        Ok(())
    }

    /// Returns the iteration.
    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns the backup passphrase.
    pub fn get_backup_passphrase(&self) -> &str {
        self.backup_passphrase.expose_borrowed()
    }

    /// Returns the unlock passphrase.
    pub fn get_unlock_passphrase(&self) -> &str {
        self.unlock_passphrase.expose_borrowed()
    }

    /// Returns the list of administrators.
    pub fn get_administrators(&self) -> &[FullCredentials] {
        &self.administrators
    }

    /// Returns the default system-wide administrator "admin".
    ///
    /// # Errors
    ///
    /// Returns an error if no administrative account with the system-wide [`UserId`] "admin" is
    /// found.
    pub fn get_default_administrator(&self) -> Result<&FullCredentials, crate::Error> {
        let Some(first_admin) = self
            .administrators
            .iter()
            .find(|user| user.name.to_string() == "admin")
        else {
            return Err(Error::AdministratorNoDefault.into());
        };
        Ok(first_admin)
    }

    /// Returns the list of namespace administrators.
    pub fn get_namespace_administrators(&self) -> &[FullCredentials] {
        &self.namespace_administrators
    }

    /// Validates the [`AdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - there is no top-level administrator user,
    /// - the default top-level administrator user (with the name "admin") is missing,
    /// - a user passphrase is too short,
    /// - the backup passphrase is too short,
    /// - or the unlock passphrase is too short.
    fn validate(&self) -> Result<(), crate::Error> {
        // there is no top-level administrator user
        if self.get_administrators().is_empty() {
            return Err(crate::Error::AdminSecretHandling(
                Error::AdministratorMissing,
            ));
        }

        // there is no top-level administrator user with the name "admin"
        if !self
            .get_administrators()
            .iter()
            .any(|user| user.name.to_string() == "admin")
        {
            return Err(crate::Error::AdminSecretHandling(
                Error::AdministratorNoDefault,
            ));
        }

        let minimum_length: usize = 10;

        // a top-level administrator user passphrase is too short
        for user in self.get_administrators().iter() {
            if user.passphrase.expose_borrowed().len() < minimum_length {
                return Err(crate::Error::AdminSecretHandling(
                    Error::PassphraseTooShort {
                        context: format!("user {}", user.name),
                        minimum_length,
                    },
                ));
            }
        }

        // a namespace administrator user passphrase is too short
        for user in self.get_namespace_administrators().iter() {
            if user.passphrase.expose_borrowed().len() < minimum_length {
                return Err(crate::Error::AdminSecretHandling(
                    Error::PassphraseTooShort {
                        context: format!("user {}", user.name),
                        minimum_length,
                    },
                ));
            }
        }

        // the backup passphrase is too short
        if self.get_backup_passphrase().len() < minimum_length {
            return Err(crate::Error::AdminSecretHandling(
                Error::PassphraseTooShort {
                    context: "backups".to_string(),
                    minimum_length,
                },
            ));
        }

        // the unlock passphrase is too short
        if self.get_unlock_passphrase().len() < minimum_length {
            return Err(crate::Error::AdminSecretHandling(
                Error::PassphraseTooShort {
                    context: "unlocking".to_string(),
                    minimum_length,
                },
            ));
        }

        Ok(())
    }
}
