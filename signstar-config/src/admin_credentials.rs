//! Administrative credentials handling for an HSM backend.

use std::{
    fs::{File, Permissions, read_to_string, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use serde::{de::DeserializeOwned, ser::Serialize};
use signstar_common::{
    admin_credentials::{
        create_credentials_dir,
        get_plaintext_credentials_file,
        get_systemd_creds_credentials_file,
    },
    common::SECRET_FILE_MODE,
};

use crate::{
    AdministrativeSecretHandling,
    utils::{fail_if_not_root, get_command, get_current_system_user},
};

/// An error that may occur when handling administrative credentials for a backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is no top-level administrator.
    #[error("There is no top-level administrator but at least one is required")]
    AdministratorMissing,

    /// There is no top-level administrator with the name "admin".
    #[error("The default top-level administrator \"admin\" is missing")]
    AdministratorNoDefault,

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
/// Requires implementations to also derive [`DeserializeOwned`] and [`Serialize`].
///
/// Provides blanket implementations for loading of administrative credentials from default system
/// locations ([`AdminCredentials::load`]) and specific paths
/// ([`AdminCredentials::load_from_file`]), as well as storing of administrative credentials in the
/// default system location ([`AdminCredentials::store`]).
/// Technically, only the implementation of [`AdminCredentials::validate`] is required.
pub trait AdminCredentials: DeserializeOwned + Serialize {
    /// Loads an [`AdminCredentials`] from the default file location.
    ///
    /// # Errors
    ///
    /// Returns an error if [`AdminCredentials::load_from_file`] fails.
    ///
    /// # Panics
    ///
    /// This method panics when providing [`AdministrativeSecretHandling::ShamirsSecretSharing`]
    /// as `secrets_handling`.
    fn load(secrets_handling: AdministrativeSecretHandling) -> Result<Self, crate::Error> {
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

    /// Loads an [`AdminCredentials`] from file.
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the method is called by a system user that is not root,
    /// - the file at `path` does not exist,
    /// - the file at `path` is not a file,
    /// - the file at `path` is considered as plaintext but can not be loaded,
    /// - the file at `path` is considered as [systemd-creds] encrypted but can not be decrypted,
    /// - or the file at `path` is considered as [systemd-creds] encrypted but can not be loaded
    ///   after decryption.
    ///
    /// # Panics
    ///
    /// This method panics when providing [`AdministrativeSecretHandling::ShamirsSecretSharing`]
    /// as `secrets_handling`.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    fn load_from_file(
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
            AdministrativeSecretHandling::Plaintext => toml::from_str(
                &read_to_string(path).map_err(|source| crate::Error::IoPath {
                    path: path.to_path_buf(),
                    context: "reading administrative credentials",
                    source,
                })?,
            )
            .map_err(|source| crate::Error::TomlRead {
                path: path.to_path_buf(),
                context: "deserializing a TOML string as administrative credentials",
                source: Box::new(source),
            })?,
            AdministrativeSecretHandling::SystemdCreds => {
                // Decrypt the credentials using systemd-creds.
                let creds_command = get_command("systemd-creds")?;
                let mut command = Command::new(creds_command);
                let command = command.arg("decrypt").arg(path).arg("-");
                let command_output =
                    command
                        .output()
                        .map_err(|source| crate::Error::CommandExec {
                            command: format!("{command:?}"),
                            source,
                        })?;
                if !command_output.status.success() {
                    return Err(crate::Error::CommandNonZero {
                        command: format!("{command:?}"),
                        exit_status: command_output.status,
                        stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
                    });
                }

                // Read the resulting TOML string from stdout and construct an AdminCredentials
                // from it.
                let config_str = String::from_utf8(command_output.stdout).map_err(|source| {
                    crate::Error::Utf8String {
                        path: path.to_path_buf(),
                        context: "after decrypting".to_string(),
                        source,
                    }
                })?;
                toml::from_str(&config_str).map_err(|source| crate::Error::TomlRead {
                    path: path.to_path_buf(),
                    context: "deserializing a TOML string as administrative credentials",
                    source: Box::new(source),
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
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the method is called by a system user that is not root,
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
    /// This method panics when providing [`AdministrativeSecretHandling::ShamirsSecretSharing`]
    /// as `secrets_handling`.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    fn store(&self, secrets_handling: AdministrativeSecretHandling) -> Result<(), crate::Error> {
        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        create_credentials_dir()?;

        let (config_data, path) = {
            // Get the TOML string representation of self.
            let config_data =
                toml::to_string_pretty(self).map_err(|source| crate::Error::TomlWrite {
                    path: PathBuf::new(),
                    context: "serializing administrative credentials",
                    source,
                })?;
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
                        crate::Error::CommandExec {
                            command: format!("{command:?}"),
                            source,
                        }
                    })?;
                    if !command_output.status.success() {
                        return Err(crate::Error::CommandNonZero {
                            command: format!("{command:?}"),
                            exit_status: command_output.status,
                            stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
                        });
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

    /// Validates the [`AdminCredentials`].
    ///
    /// # Errors
    ///
    /// This method is supposed to return an error if an assumption about the integrity of the
    /// administrative credentials cannot be met.
    /// It is called in the blanket implementation of [`AdminCredentials::load_from_file`].
    fn validate(&self) -> Result<(), crate::Error>;
}
