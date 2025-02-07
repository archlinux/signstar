//! Utilities used for test setups.
use std::{
    fs::{Permissions, create_dir_all, read_dir, read_to_string, set_permissions, write},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output},
    thread,
    time,
};

use nethsm_config::{
    ConfigInteractivity,
    ConfigSettings,
    ExtendedUserMapping,
    HermeticParallelConfig,
};
use signstar_common::{config::get_default_config_file_path, system_user::get_home_base_dir_path};
use tempfile::NamedTempFile;
use testresult::TestResult;
use which::which;

pub const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");
pub const SIGNSTAR_CONFIG_PLAINTEXT: &[u8] =
    include_bytes!("../fixtures/signstar-config-plaintext.toml");
pub const SIGNSTAR_ADMIN_CREDS_SIMPLE: &[u8] =
    include_bytes!("../fixtures/admin-creds-simple.toml");

/// An error that may occur when using test utils.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Applying permissions to a file failed.
    #[error("Unable to apply permissions to {path}:\n{source}")]
    ApplyPermissions {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A directory can not be created.
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory {
        dir: PathBuf,
        source: std::io::Error,
    },

    /// The socket for io.systemd.Credentials could not be started.
    #[error("Unable to start socket for io.systemd.Credentials:\n{0}")]
    CredentialsSocket(#[source] std::io::Error),

    /// An I/O error.
    #[error("I/O error while {context}:\n{source}")]
    Io {
        context: &'static str,
        source: std::io::Error,
    },

    /// An I/O error with a specific path.
    #[error("I/O error at {path} while {context}:\n{source}")]
    IoPath {
        path: PathBuf,
        context: &'static str,
        source: std::io::Error,
    },

    /// A signstar-config error.
    #[error("Signstar-config error:\n{0}")]
    SignstarConfig(#[from] signstar_config::Error),

    /// A timeout has been reached.
    #[error("Timeout of {timeout}ms reached while {context}")]
    Timeout { timeout: u64, context: String },

    /// A temporary file cannot be created.
    #[error("A temporary file for {purpose} cannot be created:\n{source}")]
    Tmpfile {
        purpose: &'static str,
        source: std::io::Error,
    },
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

        println!(
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

/// Writes a dummy /etc/machine-id, which is required for systemd-creds.
pub fn write_machine_id() -> Result<(), Error> {
    println!("Write dummy /etc/machine-id, required for systemd-creds");
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
    println!(
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
            eprintln!(
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
            signstar_config::utils::Error::ExecutableNotFound {
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
            println!("Found {socket_path:?}");
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

/// Runs a `command` as a specific `user` and returns its [`Output`] and the command's [`String`]
/// representation.
///
/// Uses `su` to run the the command as a specific user.
pub fn run_command_as_user(
    user_command: &str,
    user_command_args: &[&str],
    user: &str,
) -> Result<(Output, String), Error> {
    /// Returns the path to a `command`.
    ///
    /// # Errors
    ///
    /// Returns an error if `command` can not be found in PATH.
    fn get_command(command: &str) -> Result<PathBuf, Error> {
        which(command).map_err(|source| {
            Error::SignstarConfig(signstar_config::Error::Utils(
                signstar_config::utils::Error::ExecutableNotFound {
                    command: command.to_string(),
                    source,
                },
            ))
        })
    }

    let priv_command = get_command("runuser")?;
    eprintln!("Checking availability of command {user_command}");
    get_command(user_command)?;

    // Run command as user
    let mut command = Command::new(priv_command);
    let command = command
        .arg(format!(
            "--command='{user_command}{}'",
            if !user_command_args.is_empty() {
                format!(" {}", user_command_args.join(" "))
            } else {
                "".to_string()
            }
        ))
        .arg("--group")
        .arg(user)
        .arg("--login")
        .arg(user);

    let command_string = format!("{command:?}");
    eprintln!("Running command {command_string}");
    let command_output = command.output().map_err(|source| {
        Error::SignstarConfig(signstar_config::Error::CommandExec {
            command: command_string.clone(),
            source,
        })
    })?;
    eprintln!(
        "stdout:\n{}",
        String::from_utf8_lossy(&command_output.stdout).into_owned()
    );
    eprintln!(
        "stderr:\n{}",
        String::from_utf8_lossy(&command_output.stderr).into_owned()
    );

    Ok((command_output, command_string))
}

/// Creates a set of users.
pub fn create_users(users: &[String]) -> TestResult {
    println!("Creating users: {:?}", users);
    for user in users {
        println!("Creating user: {}", user);

        // create the user and its home
        let mut command = Command::new("useradd");
        let command = command
            .arg("--base-dir")
            .arg(get_home_base_dir_path())
            .arg("--create-home")
            .arg("--user-group")
            .arg("--shell")
            .arg("/usr/bin/bash")
            .arg(user);

        let command_output = command.output()?;
        if !command_output.status.success() {
            return Err(signstar_config::Error::CommandNonZero {
                command: format!("{command:?}"),
                exit_status: command_output.status,
                stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
            }
            .into());
        }

        // unlock the user
        let mut command = Command::new("usermod");
        command.arg("--unlock");
        command.arg(user);
        let command_output = command.output()?;
        if !command_output.status.success() {
            return Err(signstar_config::Error::CommandNonZero {
                command: format!("{command:?}"),
                exit_status: command_output.status,
                stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
            }
            .into());
        }
    }

    println!("/etc/passwd:\n{}", read_to_string("/etc/passwd")?);

    Ok(())
}

/// Prepares a system for use with Signstar.
///
/// Prepares the following:
///
/// - Creates `/etc/machine-id`, which is needed for `systemd-creds` to function.
/// - Reads Signstar configuration from data and writes to default config location.
/// - Creates `/run/systemd/io.systemd.Credentials` by running `systemd-socket-activate` in the
///   background
///
/// Returns the list of [`ExtendedUserMapping`]s derived from the Signstar configuration and the
/// [`Child`] of the `systemd-socket-activate` process that created
/// `/run/systemd/io.systemd.Credentials`.
pub fn prepare_system_with_config(
    config_data: &[u8],
) -> Result<(Vec<ExtendedUserMapping>, BackgroundProcess), Error> {
    write_machine_id()?;

    // Read Signstar config from `config_data`
    let config = HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            "my_app".to_string(),
            ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(get_tmp_config(config_data)?.path()),
    )
    .map_err(|source| {
        Error::SignstarConfig(signstar_config::Error::Config(
            signstar_config::config::Error::NetHsmConfig(source),
        ))
    })?;

    // Store Signstar config in default location
    config
        .store(Some(&get_default_config_file_path()))
        .map_err(|source| {
            Error::SignstarConfig(signstar_config::Error::Config(
                signstar_config::config::Error::NetHsmConfig(source),
            ))
        })?;

    // Get extended user mappings for all users.
    let creds_mapping: Vec<ExtendedUserMapping> = config.into();

    // Return extended user mappings contained in Signstar config and the background process
    // providing /run/systemd/io.systemd.Credentials
    Ok((creds_mapping, start_credentials_socket()?))
}
