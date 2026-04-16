#![doc = include_str!("../README.md")]

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, id},
    str::FromStr,
};

use log::{debug, info};
use nix::unistd::User;
use signstar_common::{
    ssh::{get_ssh_authorized_key_base_dir, get_sshd_config_dropin_dir},
    system_user::get_home_base_dir_path,
};
use signstar_config::config::{
    AuthorizedKeyEntry,
    Config,
    MappingAuthorizedKeyEntry,
    MappingSystemUserId,
    SystemUserId,
    SystemUserMapping,
};
#[cfg(feature = "nethsm")]
use signstar_config::nethsm::NetHsmUserMapping;
#[cfg(feature = "yubihsm2")]
use signstar_config::yubihsm2::YubiHsm2UserMapping;
use sysinfo::{Pid, System};

/// Specific implementations for when any of the HSM backends are compiled in.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
mod impl_any {
    use signstar_config::config::{UserBackendConnection, UserBackendConnectionFilter};

    use super::*;

    /// Creates system users and their integration.
    ///
    /// Uses the mappings found in a [`Config`] and creates relevant Unix users, if they don't exist
    /// on the system yet.
    /// System users are created unlocked, without passphrase, with their homes located in the
    /// directory returned by [`get_home_base_dir_path`].
    /// The home directories of users are not created upon user creation, but instead a [tmpfiles.d]
    /// configuration is added for them to automate their creation upon system boot.
    ///
    /// Additionally, if an [`SshForceCommand`] can be derived from a particular mapping in the
    /// [`Config`] and one or more SSH [authorized_keys] are defined for it, a dedicated SSH
    /// integration is created for the system user.
    /// This entails the creation of a dedicated [authorized_keys] file as well as an [sshd_config]
    /// drop-in in a system-wide location.
    /// Depending on the mapping in the [`Config`], a specific [ForceCommand] is set for the system
    /// user, reflecting its role in the system.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - a system user name ([`SystemUserId`]) in the configuration can not be transformed into a
    ///   valid system user name [`User`]
    /// - a new user can not be created
    /// - a newly created user can not be modified
    /// - the tmpfiles.d integration for a newly created user can not be created
    /// - the sshd_config drop-in file for a newly created user can not be created
    ///
    /// [tmpfiles.d]: https://man.archlinux.org/man/tmpfiles.d.5
    /// [authorized_keys]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
    /// [sshd_config]: https://man.archlinux.org/man/sshd_config.5
    /// [ForceCommand]: https://man.archlinux.org/man/sshd_config.5#ForceCommand
    pub fn create_system_users(config: &Config) -> Result<(), Error> {
        // Only operate on non-administrative users.
        for user_backend_connection in config
            .user_backend_connections(UserBackendConnectionFilter::NonAdmin)
            .iter()
        {
            let user = {
                let user = match user_backend_connection {
                    #[cfg(feature = "nethsm")]
                    UserBackendConnection::NetHsm {
                        admin_secret_handling: _,
                        non_admin_secret_handling: _,
                        connections: _,
                        mapping,
                    } => mapping.system_user_id(),
                    #[cfg(feature = "yubihsm2")]
                    UserBackendConnection::YubiHsm2 {
                        admin_secret_handling: _,
                        non_admin_secret_handling: _,
                        connections: _,
                        mapping,
                    } => mapping.system_user_id(),
                };

                // if there is no system user, there is nothing to do
                let Some(user) = user else {
                    continue;
                };
                user
            };

            add_user_and_home(user)?;
            add_tmpfilesd_integration(user)?;

            let (ssh_force_command, authorized_key_entry) = {
                match user_backend_connection {
                    #[cfg(feature = "nethsm")]
                    UserBackendConnection::NetHsm { mapping, .. } => (
                        SshForceCommand::try_from(mapping),
                        mapping.authorized_key_entry(),
                    ),
                    #[cfg(feature = "yubihsm2")]
                    UserBackendConnection::YubiHsm2 { mapping, .. } => (
                        SshForceCommand::try_from(mapping),
                        mapping.authorized_key_entry(),
                    ),
                }
            };

            if let Ok(force_command) = ssh_force_command
                && let Some(authorized_key) = authorized_key_entry
            {
                add_ssh_integration(user, authorized_key, &force_command)?;
            }
        }

        for mapping in config.system().mappings() {
            // if there is no system user, there is nothing to do
            let Some(user) = mapping.system_user_id() else {
                continue;
            };
            add_user_and_home(user)?;
            add_tmpfilesd_integration(user)?;

            let Some(authorized_key) = mapping.authorized_key_entry() else {
                continue;
            };
            let force_command = SshForceCommand::from(mapping);
            add_ssh_integration(user, authorized_key, &force_command)?;
        }

        Ok(())
    }
}

/// Specific implementations for when none of the HSM backends are compiled in.
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
mod impl_none {
    use super::*;

    /// Creates system users and their integration.
    ///
    /// Works on the [`UserMapping`]s of the provided `config` and creates system users for all
    /// mappings, that define system users, if they don't exist on the system yet.
    /// System users are created unlocked, without passphrase, with their homes located in the
    /// directory returned by [`get_home_base_dir_path`].
    /// The home directories of users are not created upon user creation, but instead a [tmpfiles.d]
    /// configuration is added for them to automate their creation upon system boot.
    ///
    /// Additionally, if an [`SshForceCommand`] can be derived from the particular [`UserMapping`]
    /// and one or more SSH [authorized_keys] are defined for it, a dedicated SSH integration is
    /// created for the system user.
    /// This entails the creation of a dedicated [authorized_keys] file as well as an [sshd_config]
    /// drop-in in a system-wide location.
    /// Depending on [`UserMapping`], a specific [ForceCommand] is set for the system user,
    /// reflecting its role in the system.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - a system user name ([`SystemUserId`]) in the configuration can not be transformed into a
    ///   valid system user name [`User`]
    /// - a new user can not be created
    /// - a newly created user can not be modified
    /// - the tmpfiles.d integration for a newly created user can not be created
    /// - the sshd_config drop-in file for a newly created user can not be created
    ///
    /// [tmpfiles.d]: https://man.archlinux.org/man/tmpfiles.d.5
    /// [authorized_keys]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
    /// [sshd_config]: https://man.archlinux.org/man/sshd_config.5
    /// [ForceCommand]: https://man.archlinux.org/man/sshd_config.5#ForceCommand
    pub fn create_system_users(config: &Config) -> Result<(), Error> {
        for mapping in config.system().mappings() {
            // if there is no system user, there is nothing to do
            let Some(user) = mapping.system_user_id() else {
                continue;
            };
            add_user_and_home(user)?;
            add_tmpfilesd_integration(user)?;

            let Some(authorized_key) = mapping.authorized_key_entry() else {
                continue;
            };
            let force_command = SshForceCommand::from(mapping);
            add_ssh_integration(user, authorized_key, &force_command)?;
        }

        Ok(())
    }
}

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
pub use impl_any::create_system_users;
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
pub use impl_none::create_system_users;

pub mod cli;

/// The error that may occur when using the "signstar-configure-build" executable.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A config error
    #[error("Configuration issue: {0}")]
    Config(#[from] signstar_config::Error),

    /// A [`Command`] exited unsuccessfully
    #[error(
        "The command exited with non-zero status code (\"{exit_status}\") and produced the following output on stderr:\n{stderr}"
    )]
    CommandNonZero {
        /// The exit status of the failed command.
        exit_status: ExitStatus,
        /// The stderr of the failed command.
        stderr: String,
    },

    /// A `u32` value can not be converted to `usize` on the current platform
    #[error("Unable to convert u32 to usize on this platform.")]
    FailedU32ToUsizeConversion,

    /// There is no SSH ForceCommand defined for a mapping implementation.
    #[error(
        "No SSH ForceCommand defined for user mapping (HSM users: {}{})",
        backend_users.join(", "),
        if let Some(system_user) = system_user {
            format!(", system user: {}", system_user)
        } else {
            "".to_string()
        }
    )]
    NoForceCommandForMapping {
        /// The list of HSM backend users for which no SSH `ForceCommand` is defined.
        backend_users: Vec<String>,
        /// The optional system user mapped to `backend_users`.
        system_user: Option<String>,
    },

    /// No process information could be retrieved from the current PID
    #[error("The information on the current process could not be retrieved")]
    NoProcess,

    /// The application is not run as root
    #[error("This application must be run as root!")]
    NotRoot,

    /// No process information could be retrieved from the current PID
    #[error("No user ID could be retrieved for the current process with PID {0}")]
    NoUidForProcess(usize),

    /// A string could not be converted to a sysinfo::Uid
    #[error("The string {0} could not be converted to a \"sysinfo::Uid\"")]
    SysUidFromStr(String),

    /// A `Path` value for a tmpfiles.d integration is not valid.
    #[error(
        "The Path value {path} for the tmpfiles.d integration for {user} is not valid:\n{reason}"
    )]
    TmpfilesDPath {
        /// The path that is not valid.
        path: String,
        /// The system user for which a `path` is invalid.
        user: SystemUserId,
        /// The reason why a path is not valid.
        ///
        /// # Note
        ///
        /// This is meant to complete the sentence "The Path value {path} for the tmpfiles.d
        /// integration for {user} is not valid: "
        reason: &'static str,
    },

    /// Adding a user failed
    #[error("Adding user {user} failed:\n{source}")]
    UserAdd {
        /// The system user which cannot be added.
        user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },

    /// Modifying a user failed
    #[error("Modifying the user {user} failed:\n{source}")]
    UserMod {
        /// The system user which cannot be modified.
        user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },

    /// A system user name can not be derived from a configuration user name
    #[error("Getting a system user for the username {user} failed:\n{source}")]
    UserNameConversion {
        /// The system user that only exists in the configuration file.
        user: SystemUserId,
        /// The source error.
        source: nix::Error,
    },

    /// Writing authorized_keys file for user failed
    #[error("Writing authorized_keys file for {user} failed:\n{source}")]
    WriteAuthorizedKeys {
        /// The system user for which no "authorized_keys" file can be written.
        user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },

    /// Writing sshd_config drop-in file for user failed
    #[error("Writing sshd_config drop-in for {user} failed:\n{source}")]
    WriteSshdConfig {
        /// The system user for which an sshd_config drop-in cannot be written.
        user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },

    /// Writing tmpfiles.d integration for user failed
    #[error("Writing tmpfiles.d integration for {user} failed:\n{source}")]
    WriteTmpfilesD {
        /// The system user for which a tmpfiles.d file cannot be written.
        user: SystemUserId,
        /// The source error.
        source: std::io::Error,
    },
}

/// Adds a specific Unix user and its home, if it does not exist yet.
///
/// In addition, the system record for `user` is modified to be unlocked.
///
/// # Note
///
/// Requires the commands [useradd] and [usermod] to be present on the system.
///
/// # Errors
///
/// Returns an error, if
///
/// - retrieving user information on the system fails
/// - creation of the user and its home fails
/// - unlocking of the user fails
///
/// [useradd]: https://man.archlinux.org/man/useradd.8
/// [usermod]: https://man.archlinux.org/man/usermod.8
fn add_user_and_home(user: &SystemUserId) -> Result<(), Error> {
    // If the Unix user exists already, we don't have to create it.
    if User::from_name(user.as_ref())
        .map_err(|source| Error::UserNameConversion {
            user: user.clone(),
            source,
        })?
        .is_none()
    {
        let home_base_dir = get_home_base_dir_path();

        // add user, but do not create its home
        info!("Creating user \"{user}\"...");
        let user_add = Command::new("useradd")
            .arg("--base-dir")
            .arg(home_base_dir.as_path())
            .arg("--user-group")
            .arg("--shell")
            .arg("/usr/bin/bash")
            .arg(user.as_ref())
            .output()
            .map_err(|error| Error::UserAdd {
                user: user.clone(),
                source: error,
            })?;

        if !user_add.status.success() {
            return Err(Error::CommandNonZero {
                exit_status: user_add.status,
                stderr: String::from_utf8_lossy(&user_add.stderr).into_owned(),
            });
        }
        debug!("{}", String::from_utf8_lossy(&user_add.stdout));
    } else {
        debug!("Skipping existing user \"{user}\"...");
    }

    // Modify user to unlock it.
    info!("Unlocking user \"{user}\"...");
    let user_mod = Command::new("usermod")
        .args(["--unlock", user.as_ref()])
        .output()
        .map_err(|source| Error::UserMod {
            user: user.clone(),
            source,
        })?;

    if !user_mod.status.success() {
        return Err(Error::CommandNonZero {
            exit_status: user_mod.status,
            stderr: String::from_utf8_lossy(&user_mod.stderr).into_owned(),
        });
    }
    debug!("{}", String::from_utf8_lossy(&user_mod.stdout));

    Ok(())
}

/// Adds [tmpfiles.d] integration for a `user`.
///
/// # Errors
///
/// Returns an error, if
///
/// - creating the [tmpfiles.d] file for `user` fails
/// - writing the [tmpfiles.d] file for `user` fails
///
/// [tmpfiles.d]: https://man.archlinux.org/man/tmpfiles.d.5
fn add_tmpfilesd_integration(user: &SystemUserId) -> Result<(), Error> {
    // add tmpfiles.d integration for the user to create its home directory
    info!("Adding tmpfiles.d integration for user \"{user}\"...");

    let mut buffer = File::create(format!("/usr/lib/tmpfiles.d/signstar-user-{user}.conf"))
        .map_err(|source| Error::WriteTmpfilesD {
            user: user.clone(),
            source,
        })?;
    let home_base_dir = get_home_base_dir_path();

    // ensure that the `Path` component in the tmpfiles.d file
    // - has whitespace replaced with a c-style escape
    // - does not contain specifiers
    let home_dir = {
        let home_dir = format!("{}/{user}", home_base_dir.to_string_lossy()).replace(" ", "\\x20");
        if home_dir.contains("%") {
            return Err(Error::TmpfilesDPath {
                path: home_dir.clone(),
                user: user.clone(),
                reason: "Specifiers (%) are not supported at this point.",
            });
        }
        home_dir
    };

    buffer
        .write_all(format!("d {home_dir} 700 {user} {user}\n",).as_bytes())
        .map_err(|source| Error::WriteTmpfilesD {
            user: user.clone(),
            source,
        })?;

    Ok(())
}

/// Adds the SSH integration for a specific Unix user.
///
/// Sets a single `authorized_key` entry for `user` in the system-wide SSH configuration location.
/// Sets up a system-wide SSH configuration for `user` in which its `authorized_key` configuration
/// as well as a specific `force_command` is enforced.
///
/// # Errors
///
/// Returns an error if
///
/// - the `authorized_key` entry for `user` cannot be created
/// - the sshd configuration file for `user` cannot be created
fn add_ssh_integration(
    user: &SystemUserId,
    authorized_key: &AuthorizedKeyEntry,
    force_command: &SshForceCommand,
) -> Result<(), Error> {
    info!("Adding SSH authorized_keys file for user \"{user}\"...");
    {
        let mut buffer = File::create(
            get_ssh_authorized_key_base_dir().join(format!("signstar-user-{user}.authorized_keys")),
        )
        .map_err(|source| Error::WriteAuthorizedKeys {
            user: user.clone(),
            source,
        })?;
        buffer
            .write_all(authorized_key.to_string().as_bytes())
            .map_err(|source| Error::WriteAuthorizedKeys {
                user: user.clone(),
                source,
            })?;
    }

    // add sshd_config drop-in configuration for user
    info!("Adding sshd_config drop-in configuration for user \"{user}\"...");
    {
        let mut buffer = File::create(
            get_sshd_config_dropin_dir().join(format!("10-signstar-user-{user}.conf")),
        )
        .map_err(|source| Error::WriteSshdConfig {
            user: user.clone(),
            source,
        })?;
        buffer
            .write_all(
                format!(
                    r#"Match user {user}
    AuthorizedKeysFile /etc/ssh/signstar-user-{user}.authorized_keys
    ForceCommand /usr/bin/{force_command}
"#
                )
                .as_bytes(),
            )
            .map_err(|source| Error::WriteSshdConfig {
                user: user.clone(),
                source,
            })?;
    }

    Ok(())
}

/// The configuration file path for the application.
#[derive(Clone, Debug)]
pub struct ConfigPath(PathBuf);

impl ConfigPath {
    /// Creates a new [`ConfigPath`] from a path.
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }
}

impl AsRef<Path> for ConfigPath {
    fn as_ref(&self) -> &Path {
        self.0.as_path()
    }
}

impl Default for ConfigPath {
    /// Returns the default [`ConfigPath`].
    ///
    /// Uses [`Config::first_existing_system_path`] to find the first usable configuration file
    /// path, or [`Config::default_system_path`] if none is found.
    fn default() -> Self {
        Self(Config::first_existing_system_path().unwrap_or(Config::default_system_path()))
    }
}

impl From<PathBuf> for ConfigPath {
    fn from(value: PathBuf) -> Self {
        Self(value)
    }
}

impl FromStr for ConfigPath {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(PathBuf::from(s)))
    }
}

/// A command enforced for a user connecting over SSH.
///
/// Tracks specific executables that are set using [ForceCommand] in an [sshd_config] drop-in
/// configuration.
///
/// [sshd_config]: https://man.archlinux.org/man/sshd_config.5
/// [ForceCommand]: https://man.archlinux.org/man/sshd_config.5#ForceCommand
#[derive(strum::AsRefStr, Debug, strum::Display, strum::EnumString, strum::VariantNames)]
pub enum SshForceCommand {
    /// Enforce calling signstar-download-backup
    #[strum(serialize = "signstar-download-backup")]
    DownloadBackup,

    /// Enforce calling signstar-download-key-certificate
    #[strum(serialize = "signstar-download-key-certificate")]
    DownloadKeyCertificate,

    /// Enforce calling signstar-download-metrics
    #[strum(serialize = "signstar-download-metrics")]
    DownloadMetrics,

    /// Enforce calling `signstar-shareholder` for handling SSS shares.
    #[strum(serialize = "signstar-shareholder")]
    Shareholder,

    /// Enforce calling signstar-download-wireguard
    #[strum(serialize = "signstar-download-wireguard")]
    DownloadWireGuard,

    /// Enforce calling `signstar-sign`.
    #[strum(serialize = "signstar-sign")]
    Sign,

    /// Enforce calling signstar-upload-backup
    #[strum(serialize = "signstar-upload-backup")]
    UploadBackup,

    /// Enforce calling signstar-upload-update
    #[strum(serialize = "signstar-upload-update")]
    UploadUpdate,
}

impl From<&SystemUserMapping> for SshForceCommand {
    fn from(value: &SystemUserMapping) -> Self {
        match value {
            SystemUserMapping::ShareHolder { .. } => SshForceCommand::Shareholder,
            SystemUserMapping::WireGuardDownload { .. } => SshForceCommand::DownloadWireGuard,
        }
    }
}

#[cfg(feature = "nethsm")]
impl TryFrom<&NetHsmUserMapping> for SshForceCommand {
    type Error = Error;

    fn try_from(value: &NetHsmUserMapping) -> Result<Self, Self::Error> {
        match value {
            NetHsmUserMapping::Admin(admin) => Err(Error::NoForceCommandForMapping {
                backend_users: vec![admin.to_string()],
                system_user: None,
            }),
            NetHsmUserMapping::Backup { .. } => Ok(Self::DownloadBackup),
            NetHsmUserMapping::HermeticMetrics {
                backend_users,
                system_user,
            } => Err(Error::NoForceCommandForMapping {
                backend_users: backend_users
                    .get_users()
                    .iter()
                    .map(|user| user.to_string())
                    .collect(),
                system_user: Some(system_user.to_string()),
            }),
            NetHsmUserMapping::Metrics { .. } => Ok(Self::DownloadMetrics),
            NetHsmUserMapping::Signing { .. } => Ok(SshForceCommand::Sign),
        }
    }
}

#[cfg(feature = "yubihsm2")]
impl TryFrom<&YubiHsm2UserMapping> for SshForceCommand {
    type Error = Error;

    fn try_from(value: &YubiHsm2UserMapping) -> Result<Self, Self::Error> {
        match value {
            YubiHsm2UserMapping::Admin {
                authentication_key_id,
            } => Err(Error::NoForceCommandForMapping {
                backend_users: vec![authentication_key_id.to_string()],
                system_user: None,
            }),
            YubiHsm2UserMapping::AuditLog { .. } => Ok(SshForceCommand::DownloadMetrics),
            YubiHsm2UserMapping::Backup { .. } => Ok(SshForceCommand::DownloadBackup),
            YubiHsm2UserMapping::HermeticAuditLog {
                authentication_key_id,
                system_user,
            } => Err(Error::NoForceCommandForMapping {
                backend_users: vec![authentication_key_id.to_string()],
                system_user: Some(system_user.to_string()),
            }),
            YubiHsm2UserMapping::Signing { .. } => Ok(SshForceCommand::Sign),
        }
    }
}

/// Checks whether the current process is run by root.
///
/// Gets the effective user ID of the current process and checks whether it is `0`.
///
/// # Errors
///
/// Returns an error if
/// - conversion of PID to usize `fails`
/// - the root user ID can not be converted from `"0"`
/// - no user ID can be retrieved from the current process
/// - the process is not run by root
pub fn ensure_root() -> Result<(), Error> {
    let pid: usize = id()
        .try_into()
        .map_err(|_| Error::FailedU32ToUsizeConversion)?;

    let system = System::new_all();
    let Some(process) = system.process(Pid::from(pid)) else {
        return Err(Error::NoProcess);
    };

    let Some(uid) = process.effective_user_id() else {
        return Err(Error::NoUidForProcess(pid));
    };

    let root_uid_str = "0";
    let root_uid = sysinfo::Uid::from_str(root_uid_str)
        .map_err(|_| Error::SysUidFromStr(root_uid_str.to_string()))?;

    if uid.ne(&root_uid) {
        return Err(Error::NotRoot);
    }

    Ok(())
}
