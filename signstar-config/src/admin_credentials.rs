//! Administrative credentials handling for a NetHSM backend.

use std::{
    fmt::Display,
    fs::{File, Permissions, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use nethsm::UserId;
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
use zeroize::Zeroize;

use crate::utils::{fail_non_root, get_command, get_current_system_user};

/// An error that may occur when handling administrative credentials for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Deserializing administrative secrets from a TOML string failed.
    #[error("Deserializing administrative secrets in {path} as TOML string failed:\n{source}")]
    ConfigFromToml {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },

    /// Administrative secrets can not be loaded.
    #[error("Unable to load administrative secrets from {path}:\n{source}")]
    ConfigLoad {
        path: PathBuf,
        source: Box<confy::ConfyError>,
    },

    /// Administrative secrets can not be stored to file.
    #[error("Unable to store administrative secrets in {path}:\n{source}")]
    ConfigStore {
        path: PathBuf,
        source: confy::ConfyError,
    },

    /// Serializing a Signstar config as TOML string failed.
    #[error("Serializing administrative secrets as TOML string failed:\n{0}")]
    ConfigToToml(#[source] toml::ser::Error),

    /// A credentials file can not be created.
    #[error("The credentials file {path} can not be created: {source}")]
    CredsFileCreate {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A credentials file does not exist.
    #[error("Credentials file not found: {path}")]
    CredsFileMissing { path: PathBuf },

    /// A credentials file is not a file.
    #[error("Credentials file is not a file: {path}")]
    CredsFileNotAFile { path: PathBuf },

    /// A credentials file can not be written to.
    #[error("The credentials file {path} can not be written to: {source}")]
    CredsFileWrite {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// User data for [`AdminCredentials`].
#[derive(Clone, Debug, Deserialize, Serialize, Zeroize)]
pub struct User {
    #[zeroize(skip)]
    name: UserId,
    passphrase: String,
}

impl User {
    /// Creates a new [`User`] instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::admin_credentials::User;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mut user = User::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".to_string(),
    ///     );
    ///
    /// assert_eq!(format!("{user}"), format!("{}", user.get_name()));
    /// assert_eq!(user.get_passphrase(), "ns1-admin-passphrase");
    ///
    /// user.set_passphrase("new-passphrase".to_string());
    /// assert_eq!(user.get_passphrase(), "new-passphrase");
    /// # Ok(())
    /// # }
    pub fn new(name: UserId, passphrase: String) -> Self {
        Self { name, passphrase }
    }

    /// Returns the name of the [`User`].
    pub fn get_name(&self) -> UserId {
        self.name.clone()
    }

    /// Returns the passphrase of the [`User`].
    pub fn get_passphrase(&self) -> &str {
        &self.passphrase
    }

    /// Sets the passphrase of the [`User`].
    pub fn set_passphrase(&mut self, passphrase: String) {
        self.passphrase = passphrase
    }
}

impl Display for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Administrative credentials.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Zeroize)]
pub struct AdminCredentials {
    #[zeroize(skip)]
    iteration: u32,
    backup_passphrase: String,
    unlock_passphrase: String,
    administrators: Vec<User>,
    namespace_administrators: Vec<User>,
}

impl AdminCredentials {
    /// Creates a new [`AdminCredentials`] instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::admin_credentials::{AdminCredentials, User};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = AdminCredentials::new(
    ///     1,
    ///     "backup-passphrase".to_string(),
    ///     "unlock-passphrase".to_string(),
    ///     vec![User::new("admin".parse()?, "admin-passphrase".to_string())],
    ///     vec![User::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".to_string(),
    ///     )],
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        iteration: u32,
        backup_passphrase: String,
        unlock_passphrase: String,
        administrators: Vec<User>,
        namespace_administrators: Vec<User>,
    ) -> Self {
        Self {
            iteration,
            backup_passphrase,
            unlock_passphrase,
            administrators,
            namespace_administrators,
        }
    }

    /// Loads an [`AdminCredentials`] instance from a TOML file.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io::Write;
    ///
    /// use signstar_config::admin_credentials::{AdminCredentials, User};
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
    /// assert!(AdminCredentials::load(tempfile.path()).is_ok());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file can not be loaded.
    pub fn load<P>(path: P) -> Result<Self, crate::Error>
    where
        P: AsRef<Path>,
    {
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

        confy::load_path(path).map_err(|source| {
            crate::Error::AdminSecretHandling(Error::ConfigLoad {
                path: path.to_path_buf(),
                source: Box::new(source),
            })
        })
    }

    /// Loads plaintext credentials from the default persistent file location.
    ///
    /// Creates an [`AdminCredentials`] from the file contents.
    /// Plaintext administrative credentials are retrieved using
    /// [`get_plaintext_credentials_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if the file can not be loaded.
    pub fn load_plaintext() -> Result<Self, crate::Error> {
        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

        Self::load(get_plaintext_credentials_file())
    }

    /// Loads systemd-creds encrypted credentials from the default persistent file location.
    ///
    /// Creates an [`AdminCredentials`] from the file contents.
    /// Plaintext administrative credentials are retrieved using
    /// [`get_systemd_creds_credentials_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or loading fails.
    pub fn load_systemd_creds() -> Result<Self, crate::Error> {
        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

        let credentials_file = get_systemd_creds_credentials_file();

        // Decrypt the credentials using systemd-creds.
        let creds_command = get_command("systemd-creds")?;
        let mut command = Command::new(creds_command);
        let command = command.arg("decrypt").arg(&credentials_file).arg("-");
        let command_output = command
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

        // Read the resulting TOML string from stdout and construct an AdminCredentials from it.
        let config_str = String::from_utf8(command_output.stdout).map_err(|source| {
            crate::Error::Utf8String {
                path: credentials_file.clone(),
                context: "after decryptiong".to_string(),
                source,
            }
        })?;
        toml::from_str(&config_str).map_err(|source| {
            crate::Error::AdminSecretHandling(Error::ConfigFromToml {
                path: credentials_file.clone(),
                source: Box::new(source),
            })
        })
    }

    /// Stores the [`AdminCredentials`] as a plaintext file.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use signstar_config::admin_credentials::{AdminCredentials, User};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = AdminCredentials::new(
    ///     1,
    ///     "backup-passphrase".to_string(),
    ///     "unlock-passphrase".to_string(),
    ///     vec![User::new("admin".parse()?, "admin-passphrase".to_string())],
    ///     vec![User::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".to_string(),
    ///     )],
    /// );
    ///
    /// let tmpdir = tempfile::tempdir()?;
    /// let output = tmpdir.path().join("administrative-credentials.toml");
    /// creds.store(&output)?;
    /// #
    /// # let admin_creds = r#"iteration = 1
    /// # backup_passphrase = "backup-passphrase"
    /// # unlock_passphrase = "unlock-passphrase"
    /// #
    /// # [[administrators]]
    /// # name = "admin"
    /// # passphrase = "admin-passphrase"
    /// #
    /// # [[namespace_administrators]]
    /// # name = "ns1~admin"
    /// # passphrase = "ns1-admin-passphrase"
    /// # "#;
    /// # let written_creds = std::fs::read_to_string(&output)?;
    /// #
    /// # assert_eq!(admin_creds, written_creds);
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file can not be stored.
    pub fn store<P>(&self, path: P) -> Result<(), crate::Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

        confy::store_path(path, self).map_err(|source| {
            crate::Error::AdminSecretHandling(Error::ConfigStore {
                path: path.to_path_buf(),
                source,
            })
        })
    }

    /// Stores the [`AdminCredentials`] in the default plaintext file location.
    ///
    /// The default plaintext file location is determined by
    /// [`get_plaintext_credentials_file`].
    ///
    /// # Warning
    ///
    /// This stores administrative secrets in a **plaintext** file in a persistent storage location!
    ///
    /// # Errors
    ///
    /// Returns an error if the file can not be stored.
    pub fn store_plaintext(&self) -> Result<(), crate::Error> {
        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

        self.store(get_plaintext_credentials_file())
    }

    /// Stores the [`AdminCredentials`] as an encrypted file in a persistent location.
    ///
    /// Uses [systemd-creds] to encrypt the data.
    /// The default systemd-creds encrypted file location is determined by
    /// [`get_systemd_creds_credentials_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the credentials directory can not be created or if its permissions and ownership can not
    ///   be set,
    /// - or serialization or encryption of the secret fails.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn store_systemd_creds(&self) -> Result<(), crate::Error> {
        // fail if not running as root
        fail_non_root(&get_current_system_user()?)?;

        create_credentials_dir()?;

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
            return Err(crate::Error::AttachToStdin {
                command: format!("{command:?}"),
            })?;
        };

        // Get the TOML string representation of self.
        let config_str = toml::to_string_pretty(self)
            .map_err(|source| crate::Error::AdminSecretHandling(Error::ConfigToToml(source)))?;

        let handle = std::thread::spawn(move || {
            stdin
                .write_all(config_str.as_bytes())
                .map_err(|source| crate::Error::WriteToStdin {
                    command: "systemd-creds encrypt - -".to_string(),
                    source,
                })
        });

        let _handle_result = handle.join().map_err(|source| crate::Error::Thread {
            context: format!(
                "storing systemd-creds encrypted administrative credentials: {source:?}"
            ),
        })?;

        let command_output =
            command_child
                .wait_with_output()
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

        // Write administrative credentials to file and adjust permission and ownership of file
        let credentials_file = get_systemd_creds_credentials_file();
        let mut file = File::create(credentials_file.as_path()).map_err(|source| {
            crate::Error::AdminSecretHandling(Error::CredsFileCreate {
                path: credentials_file.clone(),
                source,
            })
        })?;
        file.write_all(&command_output.stdout).map_err(|source| {
            crate::Error::AdminSecretHandling(Error::CredsFileWrite {
                path: credentials_file.clone(),
                source,
            })
        })?;
        chown(&credentials_file, Some(0), Some(0)).map_err(|source| crate::Error::Chown {
            path: credentials_file.clone(),
            user: "root".to_string(),
            source,
        })?;
        set_permissions(
            credentials_file.as_path(),
            Permissions::from_mode(SECRET_FILE_MODE),
        )
        .map_err(|source| crate::Error::ApplyPermissions {
            path: credentials_file.clone(),
            mode: SECRET_FILE_MODE,
            source,
        })?;

        Ok(())
    }

    /// Returns the iteration.
    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns the backup passphrase.
    pub fn get_backup_passphrase(&self) -> &str {
        &self.backup_passphrase
    }

    /// Returns the unlock passphrase.
    pub fn get_unlock_passphrase(&self) -> &str {
        &self.unlock_passphrase
    }

    /// Returns the list of administrators.
    pub fn get_administrators(&self) -> Vec<&User> {
        self.administrators.iter().collect()
    }

    /// Returns the list of namespace administrators.
    pub fn get_namespace_administrators(&self) -> Vec<&User> {
        self.namespace_administrators.iter().collect()
    }
}

/// Loads [`AdminCredentials`] from a default location.
///
/// The default location depends on the provided [`AdministrativeSecretHandling`].
///
/// # Errors
///
/// Returns an error if loading of the administrative credentials fails.
pub fn load_admin_creds(
    handling: AdministrativeSecretHandling,
) -> Result<AdminCredentials, crate::Error> {
    match handling {
        AdministrativeSecretHandling::Plaintext => AdminCredentials::load_plaintext(),
        AdministrativeSecretHandling::SystemdCreds => AdminCredentials::load_systemd_creds(),
        AdministrativeSecretHandling::ShamirsSecretSharing => {
            unimplemented!("Shamir's Secret Sharing is not yet implemented!");
        }
    }
}

/// Stores [`AdminCredentials`] in a default location.
///
/// The default location depends on the provided [`AdministrativeSecretHandling`].
///
/// # Errors
///
/// Returns an error if storing of the administrative credentials fails.
pub fn store_admin_creds(
    admin_creds: AdminCredentials,
    handling: AdministrativeSecretHandling,
) -> Result<(), crate::Error> {
    match handling {
        AdministrativeSecretHandling::Plaintext => admin_creds.store_plaintext(),
        AdministrativeSecretHandling::SystemdCreds => admin_creds.store_systemd_creds(),
        AdministrativeSecretHandling::ShamirsSecretSharing => {
            unimplemented!("Shamir's Secret Sharing is not yet implemented!");
        }
    }
}
