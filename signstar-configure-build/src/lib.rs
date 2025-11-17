#![doc = include_str!("../README.md")]

use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, id},
    str::FromStr,
};

use nix::unistd::User;
use signstar_common::{
    config::get_config_file_or_default,
    ssh::{get_ssh_authorized_key_base_dir, get_sshd_config_dropin_dir},
    system_user::get_home_base_dir_path,
};
use signstar_config::{SignstarConfig, SystemUserId, UserMapping};
use sysinfo::{Pid, System};

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

    /// There is no SSH ForceCommand defined for a [`UserMapping`]
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

/// The configuration file path for the application.
///
/// The configuration file location is defined by the behavior of [`get_config_file_or_default`].
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
    /// Uses [`get_config_file_or_default`] to find the first usable configuration file path, or the
    /// default if none is found.
    fn default() -> Self {
        Self(get_config_file_or_default())
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

    /// Enforce calling signstar-download-secret-share
    #[strum(serialize = "signstar-download-secret-share")]
    DownloadSecretShare,

    /// Enforce calling signstar-download-wireguard
    #[strum(serialize = "signstar-download-wireguard")]
    DownloadWireGuard,

    /// Enforce calling `signstar-sign`.
    #[strum(serialize = "signstar-sign")]
    Sign,

    /// Enforce calling signstar-upload-backup
    #[strum(serialize = "signstar-upload-backup")]
    UploadBackup,

    /// Enforce calling signstar-upload-secret-share
    #[strum(serialize = "signstar-upload-secret-share")]
    UploadSecretShare,

    /// Enforce calling signstar-upload-update
    #[strum(serialize = "signstar-upload-update")]
    UploadUpdate,
}

impl TryFrom<&UserMapping> for SshForceCommand {
    type Error = Error;

    fn try_from(value: &UserMapping) -> Result<Self, Self::Error> {
        match value {
            UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                ssh_authorized_key: _,
                system_user: _,
            } => Ok(Self::DownloadBackup),
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                ssh_authorized_key: _,
                system_user: _,
            } => Ok(Self::DownloadMetrics),
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: _,
                key_id: _,
                nethsm_key_setup: _,
                ssh_authorized_key: _,
                system_user: _,
                tag: _,
            } => Ok(Self::Sign),
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsm2Backup { .. } => Ok(Self::DownloadBackup),
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsmOperatorSigning { .. } => Ok(Self::Sign),
            UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_key: _,
            } => Ok(SshForceCommand::DownloadSecretShare),
            UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_key: _,
            } => Ok(SshForceCommand::UploadSecretShare),
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_key: _,
            } => Ok(SshForceCommand::DownloadWireGuard),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(admin) => Err(Error::NoForceCommandForMapping {
                backend_users: vec![admin.to_string()],
                system_user: None,
            }),
            UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
            } => Err(Error::NoForceCommandForMapping {
                backend_users: value
                    .get_nethsm_users()
                    .iter()
                    .map(|user| user.to_string())
                    .collect(),
                system_user: value.get_system_user().map(|user| user.to_string()),
            }),
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

/// Creates system users and their integration.
///
/// Works on the [`UserMapping`]s of the provided `config` and creates system users for all
/// mappings, that define system users, if they don't exist on the system yet.
/// System users are created unlocked, without passphrase, with their homes located in the directory
/// returned by [`get_home_base_dir_path`].
/// The home directories of users are not created upon user creation, but instead a [tmpfiles.d]
/// configuration is added for them to automate their creation upon system boot.
///
/// Additionally, if an [`SshForceCommand`] can be derived from the particular [`UserMapping`] and
/// one or more SSH [authorized_keys] are defined for it, a dedicated SSH integration is created for
/// the system user.
/// This entails the creation of a dedicated [authorized_keys] file as well as an [sshd_config]
/// drop-in in a system-wide location.
/// Depending on [`UserMapping`], a specific [ForceCommand] is set for the system user, reflecting
/// its role in the system.
///
/// # Errors
///
/// Returns an error if
/// - a system user name ([`SystemUserId`]) in the configuration can not be transformed into a valid
///   system user name [`User`]
/// - a new user can not be created
/// - a newly created user can not be modified
/// - the tmpfiles.d integration for a newly created user can not be created
/// - the sshd_config drop-in file for a newly created user can not be created
///
/// [tmpfiles.d]: https://man.archlinux.org/man/tmpfiles.d.5
/// [authorized_keys]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
/// [sshd_config]: https://man.archlinux.org/man/sshd_config.5
/// [ForceCommand]: https://man.archlinux.org/man/sshd_config.5#ForceCommand
pub fn create_system_users(config: &SignstarConfig) -> Result<(), Error> {
    for mapping in config.iter_user_mappings() {
        // if there is no system user, there is nothing to do
        let Some(user) = mapping.get_system_user() else {
            continue;
        };

        // if the system user exists already, there is nothing to do
        if User::from_name(user.as_ref())
            .map_err(|source| Error::UserNameConversion {
                user: user.clone(),
                source,
            })?
            .is_some()
        {
            eprintln!("Skipping existing user \"{user}\"...");
            continue;
        }

        let home_base_dir = get_home_base_dir_path();

        // add user, but do not create its home
        print!("Creating user \"{user}\"...");
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
        } else {
            println!(" Done.");
        }

        // modify user to unlock it
        print!("Unlocking user \"{user}\"...");
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
        } else {
            println!(" Done.");
        }

        // add tmpfiles.d integration for the user to create its home directory
        print!("Adding tmpfiles.d integration for user \"{user}\"...");
        {
            let mut buffer = File::create(format!("/usr/lib/tmpfiles.d/signstar-user-{user}.conf"))
                .map_err(|source| Error::WriteTmpfilesD {
                    user: user.clone(),
                    source,
                })?;

            // ensure that the `Path` component in the tmpfiles.d file
            // - has whitespace replaced with a c-style escape
            // - does not contain specifiers
            let home_dir = {
                let home_dir =
                    format!("{}/{user}", home_base_dir.to_string_lossy()).replace(" ", "\\x20");
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
        }
        println!(" Done.");

        if let Ok(force_command) = SshForceCommand::try_from(mapping)
            && let Some(authorized_key) = mapping.get_ssh_authorized_key()
        {
            // add SSH authorized keys file user in system-wide location
            print!("Adding SSH authorized_keys file for user \"{user}\"...");
            {
                let mut buffer = File::create(
                    get_ssh_authorized_key_base_dir()
                        .join(format!("signstar-user-{user}.authorized_keys")),
                )
                .map_err(|source| Error::WriteAuthorizedKeys {
                    user: user.clone(),
                    source,
                })?;
                buffer
                    .write_all(authorized_key.as_ref().as_bytes())
                    .map_err(|source| Error::WriteAuthorizedKeys {
                        user: user.clone(),
                        source,
                    })?;
            }
            println!(" Done.");

            // add sshd_config drop-in configuration for user
            print!("Adding sshd_config drop-in configuration for user \"{user}\"...");
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
            println!(" Done.");
        };
    }

    Ok(())
}
