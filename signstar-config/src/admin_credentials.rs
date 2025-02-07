//! Administrative credentials handling for a NetHSM backend.

use std::{
    fmt::Display,
    path::{Path, PathBuf},
    process::{Command, ExitStatus},
};

use nethsm::UserId;
use nethsm_config::AdministrativeSecretHandling;
use serde::{Deserialize, Serialize};
use signstar_core::admin_credentials::{
    create_ephemeral_credentials_dir,
    create_persistent_credentials_dir,
    get_ephemeral_plaintext_credentials,
    get_persistent_plaintext_credentials,
    get_persistent_systemd_creds_credentials,
};
use zeroize::Zeroize;

use crate::utils::delete_tmp_file;

/// An error that may occur when handling administrative credentials for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`Command`] exited unsuccessfully
    #[error(
        "The command exited with non-zero status code \"{exit_status}\":\nstdout:\n{stdout}\nstderr:\n{stderr}"
    )]
    CommandNonZero {
        exit_status: ExitStatus,
        stdout: String,
        stderr: String,
    },

    /// Low-level administrative credentials handling failed.
    #[error("Handling of administrative credentials failed:\n{0}")]
    CoreCredentials(#[from] signstar_core::admin_credentials::Error),

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

    /// No credentials file could be found
    #[error("No credentials file found at: {path:?}")]
    NoCredsFile { path: PathBuf },

    /// The credentials path is not a file
    #[error("The credentials path is not a file: {path:?}")]
    CredsNotAFile { path: PathBuf },

    /// A config storing error
    #[error("Config storing issue: {0}")]
    Store(#[source] confy::ConfyError),

    /// Encrypting administrative secrets with systemd-creds failed
    #[error("Encrypting administrative secrets with \"systemd-creds\" failed:\n{0}")]
    SystemdCreds(#[source] std::io::Error),
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
    pub fn load<P>(path: P) -> Result<Self, Error>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        if !path.exists() {
            return Err(Error::NoCredsFile {
                path: path.to_path_buf(),
            });
        }
        if !path.is_file() {
            return Err(Error::CredsNotAFile {
                path: path.to_path_buf(),
            });
        }

        confy::load_path(path).map_err(|error| Error::Load {
            source: error,
            description: "Unable to load administrative credentials.".to_string(),
        })
    }

    /// Loads plaintext credentials from the default persistent file location.
    ///
    /// Creates an [`AdminCredentials`] from the file contents.
    /// Plaintext administrative credentials are retrieved using
    /// [`get_persistent_plaintext_credentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if the file can not be loaded.
    pub fn load_plaintext() -> Result<Self, Error> {
        Self::load(PathBuf::from(get_persistent_plaintext_credentials()))
    }

    /// Loads systemd-creds encrypted credentials from the default persistent file location.
    ///
    /// Creates an [`AdminCredentials`] from the file contents.
    /// Plaintext administrative credentials are retrieved using
    /// [`get_persistent_plaintext_credentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if decryption or loading fails.
    pub fn load_systemd_creds() -> Result<Self, Error> {
        let tmp_creds_file = get_ephemeral_plaintext_credentials();
        let systemd_creds_file = get_persistent_systemd_creds_credentials();
        let tmp_creds_path = PathBuf::from(&tmp_creds_file);

        // decrypt the credentials as a TOML file in a temporary location
        match Command::new("systemd-creds")
            .args(["decrypt", &systemd_creds_file, &tmp_creds_file])
            .output()
            .map_err(Error::SystemdCreds)
        {
            Ok(decrypt_creds) => {
                // fail if decryption did not result in a successful status code
                if !decrypt_creds.status.success() {
                    delete_tmp_file(tmp_creds_path.as_path());
                    return Err(Error::CommandNonZero {
                        exit_status: decrypt_creds.status,
                        stdout: String::from_utf8_lossy(&decrypt_creds.stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&decrypt_creds.stderr).into_owned(),
                    });
                }

                // load a new AdminCredentials from decrypted TOML
                match Self::load(tmp_creds_path.as_path()) {
                    Ok(admin_creds) => {
                        delete_tmp_file(tmp_creds_path.as_path());
                        Ok(admin_creds)
                    }
                    Err(error) => {
                        delete_tmp_file(tmp_creds_path.as_path());
                        Err(error)
                    }
                }
            }
            Err(error) => {
                delete_tmp_file(tmp_creds_path.as_path());
                Err(error)
            }
        }
    }

    /// Stores the [`AdminCredentials`] as a plaintext file.
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
    pub fn store<P>(&self, path: P) -> Result<(), Error>
    where
        P: AsRef<Path>,
    {
        confy::store_path(path, self).map_err(Error::Store)
    }

    /// Stores the [`AdminCredentials`] in the default plaintext file location.
    ///
    /// The default plaintext file location is determined by
    /// [`get_persistent_plaintext_credentials`].
    ///
    /// # Warning
    ///
    /// This stores administrative secrets in a **plaintext** file in a persistent storage location!
    ///
    /// # Errors
    ///
    /// Returns an error if the file can not be stored.
    pub fn store_plaintext(&self) -> Result<(), Error> {
        self.store(PathBuf::from(get_persistent_plaintext_credentials()))
    }

    /// Stores the [`AdminCredentials`] as an encrypted file in a persistent location.
    ///
    /// Uses [systemd-creds] to encrypt the data.
    /// The default systemd-creds encrypted file location is determined by
    /// [`get_persistent_systemd_creds_credentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if serialization or encryption fails.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn store_systemd_creds(&self) -> Result<(), Error> {
        let tmp_creds_file = get_ephemeral_plaintext_credentials();
        let tmp_creds_path = PathBuf::from(&tmp_creds_file);
        let systemd_creds_file = get_persistent_systemd_creds_credentials();
        create_ephemeral_credentials_dir()?;
        create_persistent_credentials_dir()?;

        // store the AdminCredentials as a TOML file in a temporary location
        match self.store(tmp_creds_path.as_path()) {
            Ok(()) => {
                // encrypt the temporary TOML file
                match Command::new("systemd-creds")
                    .args(["encrypt", &tmp_creds_file, &systemd_creds_file])
                    .output()
                    .map_err(Error::SystemdCreds)
                {
                    Ok(encrypted_creds) => {
                        if !encrypted_creds.status.success() {
                            delete_tmp_file(tmp_creds_path.as_path());
                            delete_tmp_file(PathBuf::from(&systemd_creds_file).as_path());
                            return Err(Error::CommandNonZero {
                                exit_status: encrypted_creds.status,
                                stdout: String::from_utf8_lossy(&encrypted_creds.stdout)
                                    .into_owned(),
                                stderr: String::from_utf8_lossy(&encrypted_creds.stderr)
                                    .into_owned(),
                            });
                        }
                        delete_tmp_file(tmp_creds_path.as_path());
                        Ok(())
                    }
                    Err(error) => {
                        delete_tmp_file(tmp_creds_path.as_path());
                        delete_tmp_file(PathBuf::from(&systemd_creds_file).as_path());
                        Err(error)
                    }
                }
            }
            Err(error) => {
                delete_tmp_file(tmp_creds_path.as_path());
                Err(error)
            }
        }
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
pub fn load_admin_creds(handling: AdministrativeSecretHandling) -> Result<AdminCredentials, Error> {
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
) -> Result<(), Error> {
    match handling {
        AdministrativeSecretHandling::Plaintext => admin_creds.store_plaintext(),
        AdministrativeSecretHandling::SystemdCreds => admin_creds.store_systemd_creds(),
        AdministrativeSecretHandling::ShamirsSecretSharing => {
            unimplemented!("Shamir's Secret Sharing is not yet implemented!");
        }
    }
}
