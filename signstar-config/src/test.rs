//! Utilities used for test setups.

use std::{
    fs::{File, Permissions, create_dir_all, read_dir, set_permissions, write},
    io::Write,
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command},
    str::FromStr,
    thread,
    time,
};

use change_user_run::create_users;
use log::debug;
#[cfg(feature = "nethsm")]
use nethsm::{FullCredentials, UserId};
#[cfg(feature = "nethsm")]
use rand::{Rng, distributions::Alphanumeric, thread_rng};
use signstar_common::system_user::get_home_base_dir_path;
#[cfg(feature = "nethsm")]
use signstar_crypto::AdministrativeSecretHandling;
#[cfg(feature = "nethsm")]
use signstar_crypto::passphrase::Passphrase;
use tempfile::NamedTempFile;
use which::which;

use crate::config::{Config, ConfigSystemUserIds};
#[cfg(feature = "nethsm")]
use crate::{AdminCredentials, NetHsmAdminCredentials};
/// When any of the HSM backends is present.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
pub mod impl_any {
    use super::*;
    use crate::config::UserBackendConnectionFilter;

    impl SystemUserConfig {
        /// Applies the chosen system user configuration items based on a [`Config`].
        ///
        /// # Errors
        ///
        /// Returns an error if secrets for a non-administrative backend user cannot be created.
        pub fn apply(&self, config: &Config) -> Result<(), Error> {
            if self.create_secrets {
                let user_backend_connections =
                    config.user_backend_connections(UserBackendConnectionFilter::NonAdmin);

                for user_backend_connection in user_backend_connections {
                    user_backend_connection.create_non_admin_backend_user_secrets()?;
                }
            }

            Ok(())
        }
    }
}

/// When no HSM backend is present.
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
mod impl_none {
    use super::*;

    impl SystemUserConfig {
        /// Applies the chosen system user configuration items based on a [`Config`].
        ///
        /// # Note
        ///
        /// Without any HSM backends, no backend-related actions are taken.
        ///
        /// # Errors
        ///
        /// Never returns an error.
        pub fn apply(&self, _config: &Config) -> Result<(), Error> {
            Ok(())
        }
    }
}

/// No HSM backend, plain administrative secrets handling.
const NO_BACKEND_PLAIN_ADMIN: &[u8] =
    include_bytes!("../../fixtures/config/no_backend/admin-plaintext-non-admin-systemd-creds.yaml");

/// No HSM backend, systemd-creds administrative secrets handling.
const NO_BACKEND_SYSTEMD_CREDS_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/no_backend/admin-systemd-creds-non-admin-systemd-creds.yaml"
);

/// No HSM backend, Shamir's Secret Sharing administrative secrets handling.
const NO_BACKEND_SSS_ADMIN: &[u8] =
    include_bytes!("../../fixtures/config/no_backend/admin-sss-non-admin-systemd-creds.yaml");

/// NetHSM backend, plain administrative secrets handling.
const ONLY_NETHSM_PLAIN_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/nethsm_backend/admin-plaintext-non-admin-systemd-creds.yaml"
);

/// NetHSM backend, systemd-creds administrative secrets handling.
const ONLY_NETHSM_SYSTEMD_CREDS_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/nethsm_backend/admin-systemd-creds-non-admin-systemd-creds.yaml"
);

/// NetHSM backend, Shamir's Secret Sharing administrative secrets handling.
const ONLY_NETHSM_SSS_ADMIN: &[u8] =
    include_bytes!("../../fixtures/config/nethsm_backend/admin-sss-non-admin-systemd-creds.yaml");

/// YubiHSM2 backend, plain administrative secrets handling.
const ONLY_YUBIHSM2_PLAIN_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/yubihsm2_backend/admin-plaintext-non-admin-systemd-creds.yaml"
);

/// YubiHSM2 backend, systemd-creds administrative secrets handling.
const ONLY_YUBIHSM2_SYSTEMD_CREDS_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/yubihsm2_backend/admin-systemd-creds-non-admin-systemd-creds.yaml"
);

/// YubiHSM2 backend, Shamir's Secret Sharing administrative secrets handling.
const ONLY_YUBIHSM2_SSS_ADMIN: &[u8] =
    include_bytes!("../../fixtures/config/yubihsm2_backend/admin-sss-non-admin-systemd-creds.yaml");

/// YubiHSM2 backend, plain administrative secrets handling.
const ONLY_YUBIHSM2_MOCKHSM_PLAIN_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/yubihsm2_mockhsm_backend/admin-plaintext-non-admin-systemd-creds.yaml"
);

/// YubiHSM2 backend, systemd-creds administrative secrets handling.
const ONLY_YUBIHSM2_MOCKHSM_SYSTEMD_CREDS_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/yubihsm2_mockhsm_backend/admin-systemd-creds-non-admin-systemd-creds.yaml"
);

/// YubiHSM2 backend, Shamir's Secret Sharing administrative secrets handling.
const ONLY_YUBIHSM2_MOCKHSM_SSS_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/yubihsm2_mockhsm_backend/admin-sss-non-admin-systemd-creds.yaml"
);

/// NetHSM and YubiHSM2 backends, plain administrative secrets handling.
const ALL_BACKENDS_PLAIN_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/all_backends/admin-plaintext-non-admin-systemd-creds.yaml"
);

/// NetHSM and YubiHSM2 backends, systemd-creds administrative secrets handling.
const ALL_BACKENDS_SYSTEMD_CREDS_ADMIN: &[u8] = include_bytes!(
    "../../fixtures/config/all_backends/admin-systemd-creds-non-admin-systemd-creds.yaml"
);

/// NetHSM and YubiHSM2 backends, Shamir's Secret Sharing administrative secrets handling.
const ALL_BACKENDS_SSS_ADMIN: &[u8] =
    include_bytes!("../../fixtures/config/all_backends/admin-sss-non-admin-systemd-creds.yaml");

/// An error that may occur when using test utils.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Applying permissions to a file failed.
    #[error("Unable to apply permissions to {path}:\n{source}")]
    ApplyPermissions {
        /// The file that was being modified.
        path: PathBuf,

        /// The source error.
        source: std::io::Error,
    },

    /// A [`change_user_run::Error`] occurred.
    #[error(transparent)]
    ChangeUserRun(#[from] change_user_run::Error),

    /// A directory can not be created.
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory {
        /// The directory which was about to be created.
        dir: PathBuf,

        /// The source error.
        source: std::io::Error,
    },

    /// The socket for io.systemd.Credentials could not be started.
    #[error("Unable to start socket for io.systemd.Credentials:\n{0}")]
    CredentialsSocket(#[source] std::io::Error),

    /// An I/O error.
    #[error("I/O error while {context}:\n{source}")]
    Io {
        /// The short description of the operation.
        context: &'static str,

        /// The source error.
        source: std::io::Error,
    },

    /// An I/O error with a specific path.
    #[error("I/O error at {path} while {context}:\n{source}")]
    IoPath {
        /// The file that was being accessed.
        path: PathBuf,

        /// The short description of the operation.
        context: &'static str,

        /// The source error.
        source: std::io::Error,
    },

    /// A signstar-config error.
    #[error("Signstar-config error:\n{0}")]
    SignstarConfig(#[from] crate::Error),

    /// A timeout has been reached.
    #[error("Timeout of {timeout}ms reached while {context}")]
    Timeout {
        /// The value of the timeout in milliseconds.
        timeout: u64,

        /// The short description of the operation.
        context: String,
    },

    /// A temporary file cannot be created.
    #[error("A temporary file for {purpose} cannot be created:\n{source}")]
    Tmpfile {
        /// The purpose of the temporary file.
        purpose: &'static str,

        /// The source error.
        source: std::io::Error,
    },
}

/// The targeted location for a Signstar configuration file.
#[derive(Clone, Copy, Debug, Default)]
pub enum ConfigFileLocation {
    /// The override location in `/run/signstar/`.
    Run,

    /// The override location in `/etc/signstar/`.
    Etc,

    /// The default location in `/usr/share/signstar/`.
    #[default]
    UsrShare,
}

impl ConfigFileLocation {
    /// Returns the path of the configuration file's parent directory.
    pub fn to_parent_dir_path(&self) -> PathBuf {
        match self {
            ConfigFileLocation::Run => PathBuf::from(Config::RUN_OVERRIDE_CONFIG_DIR),
            ConfigFileLocation::Etc => PathBuf::from(Config::ETC_OVERRIDE_CONFIG_DIR),
            ConfigFileLocation::UsrShare => PathBuf::from(Config::DEFAULT_CONFIG_DIR),
        }
    }
}

impl From<ConfigFileLocation> for PathBuf {
    fn from(value: ConfigFileLocation) -> Self {
        value
            .to_parent_dir_path()
            .join(format!("{}.yaml", Config::CONFIG_NAME))
    }
}

/// The Signstar configuration file variant used for the file contents.
#[derive(Clone, Copy, Debug, Default)]
pub enum ConfigFileVariant {
    /// No HSM backend, plain administrative secrets handling.
    NoBackendPlainAdmin,

    /// No HSM backend, systemd-creds administrative secrets handling.
    NoBackendSystemdCredsAdmin,

    /// No HSM backend, Shamir's Secret Sharing administrative secrets handling.
    NoBackendSssAdmin,

    /// NetHSM backend, plain administrative secrets handling.
    OnlyNetHsmBackendPlainAdmin,

    /// NetHSM backend, systemd-creds administrative secrets handling.
    OnlyNetHsmBackendSystemdCredsAdmin,

    /// NetHSM backend, Shamir's Secret Sharing administrative secrets handling.
    OnlyNetHsmBackendSssAdmin,

    /// YubiHSM2 backend, plain administrative secrets handling.
    OnlyYubiHsm2BackendPlainAdmin,

    /// YubiHSM2 backend, systemd-creds administrative secrets handling.
    OnlyYubiHsm2BackendSystemdCredsAdmin,

    /// YubiHSM2 backend, Shamir's Secret Sharing administrative secrets handling.
    OnlyYubiHsm2BackendSssAdmin,

    /// YubiHSM2 backend, plain administrative secrets handling.
    OnlyYubiHsm2MockHsmBackendPlainAdmin,

    /// YubiHSM2 backend, systemd-creds administrative secrets handling.
    OnlyYubiHsm2MockHsmBackendSystemdCredsAdmin,

    /// YubiHSM2 backend, Shamir's Secret Sharing administrative secrets handling.
    OnlyYubiHsm2MockHsmBackendSssAdmin,

    /// NetHSM and YubiHSM2 backends, plain administrative secrets handling.
    AllBackendsPlainAdmin,

    /// NetHSM and YubiHSM2 backends, systemd-creds administrative secrets handling.
    AllBackendsSystemdCredsAdmin,

    /// NetHSM and YubiHSM2 backends, Shamir's Secret Sharing administrative secrets handling.
    #[default]
    AllBackendsSssAdmin,
}

impl ConfigFileVariant {
    /// Returns the bytes of a Signstar configuration matching the chosen variant.
    pub fn as_config_bytes(&self) -> &[u8] {
        match self {
            ConfigFileVariant::NoBackendPlainAdmin => NO_BACKEND_PLAIN_ADMIN,
            ConfigFileVariant::NoBackendSystemdCredsAdmin => NO_BACKEND_SYSTEMD_CREDS_ADMIN,
            ConfigFileVariant::NoBackendSssAdmin => NO_BACKEND_SSS_ADMIN,
            ConfigFileVariant::OnlyNetHsmBackendPlainAdmin => ONLY_NETHSM_PLAIN_ADMIN,
            ConfigFileVariant::OnlyNetHsmBackendSystemdCredsAdmin => {
                ONLY_NETHSM_SYSTEMD_CREDS_ADMIN
            }
            ConfigFileVariant::OnlyNetHsmBackendSssAdmin => ONLY_NETHSM_SSS_ADMIN,
            ConfigFileVariant::OnlyYubiHsm2BackendPlainAdmin => ONLY_YUBIHSM2_PLAIN_ADMIN,
            ConfigFileVariant::OnlyYubiHsm2BackendSystemdCredsAdmin => {
                ONLY_YUBIHSM2_SYSTEMD_CREDS_ADMIN
            }
            ConfigFileVariant::OnlyYubiHsm2BackendSssAdmin => ONLY_YUBIHSM2_SSS_ADMIN,
            ConfigFileVariant::OnlyYubiHsm2MockHsmBackendPlainAdmin => {
                ONLY_YUBIHSM2_MOCKHSM_PLAIN_ADMIN
            }
            ConfigFileVariant::OnlyYubiHsm2MockHsmBackendSystemdCredsAdmin => {
                ONLY_YUBIHSM2_MOCKHSM_SYSTEMD_CREDS_ADMIN
            }
            ConfigFileVariant::OnlyYubiHsm2MockHsmBackendSssAdmin => {
                ONLY_YUBIHSM2_MOCKHSM_SSS_ADMIN
            }
            ConfigFileVariant::AllBackendsPlainAdmin => ALL_BACKENDS_PLAIN_ADMIN,
            ConfigFileVariant::AllBackendsSystemdCredsAdmin => ALL_BACKENDS_SYSTEMD_CREDS_ADMIN,
            ConfigFileVariant::AllBackendsSssAdmin => ALL_BACKENDS_SSS_ADMIN,
        }
    }

    /// Creates a [`Config`] from the selected configuration variant in `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the bytes cannot be converted to a valid UTF-8 string
    /// - a valid [`Config`] cannot be created from the variant
    pub fn to_config(&self) -> Result<Config, crate::Error> {
        Config::from_str(
            &String::from_utf8(self.as_config_bytes().to_vec()).map_err(|source| {
                crate::Error::Utf8String {
                    path: PathBuf::from("/dev/null"),
                    context: "creating a Signstar config object from config fixture bytes"
                        .to_string(),
                    source,
                }
            })?,
        )
    }
}

/// Configuration for the creation of system users.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemUserConfig {
    /// Whether to create the secrets for each system user with at least one backend user.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    pub create_secrets: bool,
}

/// Configuration for how and where to provide a Signstar configuration file.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConfigFileConfig {
    /// The optional location in which the Signstar config is placed.
    ///
    /// If `location` is [`None`], the Signstar config is not written to a file.
    pub location: Option<ConfigFileLocation>,

    /// The variant of Signstar configuration that is added.
    pub variant: ConfigFileVariant,

    /// The optional configuration for system users.
    ///
    /// # Note
    ///
    /// When set, this implies the creation of all system users.
    pub system_user_config: Option<SystemUserConfig>,
}

/// Creates a configuration file in a location based on [`ConfigFileLocation`] and
/// [`ConfigFileVariant`].
///
/// Creates all parent directories.
///
/// # Errors
///
/// Returns an error if
///
/// - the creation of parent directories fails
/// - the configuration file cannot be created
/// - the configuration file cannot be written to
fn create_config(location: ConfigFileLocation, variant: ConfigFileVariant) -> Result<(), Error> {
    create_dir_all(location.to_parent_dir_path()).map_err(|source| Error::IoPath {
        path: location.to_parent_dir_path(),
        context: "creating the parent directory for the Signstar config",
        source,
    })?;
    let path = PathBuf::from(location);

    let mut file = File::create(&path).map_err(|source| crate::Error::IoPath {
        path: path.clone(),
        context: "creating a Signstar configuration file",
        source,
    })?;
    let config_bytes = variant.as_config_bytes();
    file.write_all(config_bytes)
        .map_err(|source| crate::Error::IoPath {
            path,
            context: "writing data to a Signstar configuration file",
            source,
        })?;

    Ok(())
}

/// Creates all Unix users and their homes based on a [`Config`].
///
/// # Errors
///
/// Returns an error if any of the Unix users cannot be created.
fn create_unix_users_and_homes(config: &Config) -> Result<(), Error> {
    let users = config
        .system_user_ids()
        .iter()
        .cloned()
        .map(|id| id.as_ref())
        .collect::<Vec<_>>();
    Ok(create_users(&users, Some(&get_home_base_dir_path()), None)?)
}

/// Configuration on how to prepare a system for a test setup.
#[derive(Clone, Copy, Debug)]
pub struct SystemPrepareConfig {
    /// Whether to write an `/etc/machine-id`.
    pub machine_id: bool,

    /// Whether to start a socket for `io.systemd.Credentials`.
    pub credentials_socket: bool,

    /// How to handle the Signstar config file.
    pub signstar_config: ConfigFileConfig,
}

impl SystemPrepareConfig {
    /// Applies the chosen system configuration items.
    ///
    /// Optionally returns the [`BackgroundProcess`] tracking an `io.systemd.Credentials`
    /// socket.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - an `/etc/machine-id` file should be written, but [`write_machine_id`] fails
    /// - an `io.systemd.Credentials` socket should be created, but [`start_credentials_socket`]
    ///   fails
    /// - a configuration file should be created, but writing it fails
    /// - the creation of system users and/or their home directories fails
    /// - the creation of backend user secrets fails
    pub fn apply(&self) -> Result<Option<BackgroundProcess>, Error> {
        if self.machine_id {
            write_machine_id()?;
        }

        let background_process = if self.credentials_socket {
            Some(start_credentials_socket()?)
        } else {
            None
        };

        if let Some(config_file_location) = self.signstar_config.location {
            create_config(config_file_location, self.signstar_config.variant)?;

            if let Some(system_user_config) = self.signstar_config.system_user_config {
                let config = Config::from_str(&String::from_utf8_lossy(
                    self.signstar_config.variant.as_config_bytes(),
                ))?;
                create_unix_users_and_homes(&config)?;
                system_user_config.apply(&config)?;
            }
        }

        Ok(background_process)
    }
}

impl Default for SystemPrepareConfig {
    fn default() -> Self {
        Self {
            machine_id: true,
            credentials_socket: true,
            signstar_config: ConfigFileConfig::default(),
        }
    }
}

/// Recursively lists files, their permissions and ownership.
pub fn list_files_in_dir(path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();
    let entries = read_dir(path).map_err(|source| Error::IoPath {
        path: path.to_path_buf(),
        context: "reading its children",
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| Error::IoPath {
            path: path.to_path_buf(),
            context: "getting an entry below it",
            source,
        })?;
        let meta = entry.metadata().map_err(|source| Error::IoPath {
            path: path.to_path_buf(),
            context: "getting metadata",
            source,
        })?;

        debug!(
            "{} {}/{} {entry:?}",
            meta.permissions().mode(),
            meta.st_uid(),
            meta.st_gid()
        );

        if meta.is_dir() {
            list_files_in_dir(entry.path())?;
        }
    }

    Ok(())
}

/// Returns a configuration file with `data` as contents in a temporary location.
pub fn get_tmp_config(data: &[u8]) -> Result<NamedTempFile, Error> {
    let tmp_config = NamedTempFile::new().map_err(|source| Error::Tmpfile {
        purpose: "full signstar configuration",
        source,
    })?;
    write(&tmp_config, data).map_err(|source| Error::Io {
        context: "writing full signstar configuration to temporary file",
        source,
    })?;
    Ok(tmp_config)
}

/// Writes a dummy `/etc/machine-id`, which is required for systemd-creds.
///
/// # Errors
///
/// Returns an error if
///
/// - a static machine-id can not be written to `/etc/machine-id`,
/// - or metadata on the created `/etc/machine-id` can not be retrieved.
pub fn write_machine_id() -> Result<(), Error> {
    debug!("Write dummy /etc/machine-id, required for systemd-creds");
    let machine_id = PathBuf::from("/etc/machine-id");
    std::fs::write(&machine_id, "d3b07384d113edec49eaa6238ad5ff00").map_err(|source| {
        Error::IoPath {
            path: machine_id.to_path_buf(),
            context: "writing machine-id",
            source,
        }
    })?;

    let metadata = machine_id.metadata().map_err(|source| Error::IoPath {
        path: machine_id,
        context: "getting metadata of file",
        source,
    })?;
    debug!(
        "/etc/machine-id\nmode: {}\nuid: {}\ngid: {}",
        metadata.permissions().mode(),
        metadata.st_uid(),
        metadata.st_gid()
    );
    Ok(())
}

/// A background process.
///
/// Tracks a [`Child`] which represents a process that runs in the background.
/// The background process is automatically killed upon dropping the [`BackgroundProcess`].
#[derive(Debug)]
pub struct BackgroundProcess {
    child: Child,
    command: String,
}

impl BackgroundProcess {
    /// Kills the tracked background process.
    ///
    /// # Errors
    ///
    /// Returns an error if the process could not be killed.
    pub fn kill(&mut self) -> Result<(), Error> {
        self.child.kill().map_err(|source| Error::Io {
            context: "killing process",
            source,
        })
    }
}

impl Drop for BackgroundProcess {
    /// Kills the tracked background process when destructing the [`BackgroundProcess`].
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            log::debug!(
                "Unable to kill background process of command {}:\n{error}",
                self.command
            )
        }
    }
}

/// Starts a socket for `io.systemd.Credentials` using `systemd-socket-activate`.
///
/// Sets the file mode of the socket to `666` so that all users on the system have access.
///
/// # Errors
///
/// Returns an error if
///
/// - `systemd-socket-activate` is unable to start the required socket,
/// - one or more files in `/run/systemd` can not be listed,
/// - applying of permissions on `/run/systemd/io.systemd.Credentials` fails,
/// - or the socket has not been made available within 10000ms.
pub fn start_credentials_socket() -> Result<BackgroundProcess, Error> {
    let systemd_run_path = PathBuf::from("/run/systemd");
    let socket_path = PathBuf::from("/run/systemd/io.systemd.Credentials");
    create_dir_all(&systemd_run_path).map_err(|source| Error::CreateDirectory {
        dir: systemd_run_path,
        source,
    })?;

    // Run systemd-socket-activate to provide /run/systemd/io.systemd.Credentials
    let command = "systemd-socket-activate";
    let systemd_socket_activate = which(command).map_err(|source| {
        Error::SignstarConfig(
            crate::utils::Error::ExecutableNotFound {
                command: command.to_string(),
                source,
            }
            .into(),
        )
    })?;
    let mut command = Command::new(systemd_socket_activate);
    let command = command.args([
        "--listen",
        "/run/systemd/io.systemd.Credentials",
        "--accept",
        "--fdname=varlink",
        "systemd-creds",
    ]);
    let child = command.spawn().map_err(Error::CredentialsSocket)?;

    // Set the socket to be writable by all, once it's available.
    let timeout = 10000;
    let step = 100;
    let mut elapsed = 0;
    let mut permissions_set = false;
    while elapsed < timeout {
        if socket_path.exists() {
            debug!("Found {socket_path:?}");
            set_permissions(socket_path.as_path(), Permissions::from_mode(0o666)).map_err(
                |source| Error::ApplyPermissions {
                    path: socket_path.to_path_buf(),
                    source,
                },
            )?;
            permissions_set = true;
            break;
        } else {
            thread::sleep(time::Duration::from_millis(step));
            elapsed += step;
        }
    }
    if !permissions_set {
        return Err(Error::Timeout {
            timeout,
            context: format!("waiting for {socket_path:?}"),
        });
    }

    Ok(BackgroundProcess {
        child,
        command: format!("{command:?}"),
    })
}

/// Creates an [`AdminCredentials`] from config data.
///
/// Accepts a byte slice containing configuration data.
///
/// # Errors
///
/// Returns an error if
///
/// - a temporary config file can not be created from `config_data`,
/// - an [`AdminCredentials`] can not be created from the temporary config file.
#[cfg(feature = "nethsm")]
pub fn nethsm_admin_credentials(config_data: &[u8]) -> Result<NetHsmAdminCredentials, Error> {
    let config_file = get_tmp_config(config_data)?;
    NetHsmAdminCredentials::load_from_file(
        config_file.path(),
        AdministrativeSecretHandling::Plaintext,
    )
    .map_err(Error::SignstarConfig)
}

/// Creates a list of [`FullCredentials`] for a list of [`UserId`]s.
///
/// Creates a 30-char long alphanumeric passphrase for each [`UserId`] in `users` and then
/// constructs a [`FullCredentials`].
#[cfg(feature = "nethsm")]
pub fn create_full_credentials(users: &[UserId]) -> Vec<FullCredentials> {
    /// Creates a passphrase
    fn create_passphrase() -> String {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect()
    }

    users
        .iter()
        .map(|user| FullCredentials::new(user.clone(), Passphrase::new(create_passphrase())))
        .collect()
}
