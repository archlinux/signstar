//! Utilities used for test setups.

use std::{
    fs::{Permissions, create_dir_all, set_permissions, write},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command},
    thread,
    time,
};

use change_user_run::get_command;
use log::debug;

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

    /// A timeout has been reached.
    #[error("Timeout of {timeout}ms reached while {context}")]
    Timeout {
        /// The value of the timeout in milliseconds.
        timeout: u64,

        /// The short description of the operation.
        context: String,
    },
}

/// Writes a dummy `/etc/machine-id`
///
/// # Note
///
/// This is a requirement for using systemd-creds.
///
/// # Errors
///
/// Returns an error if
///
/// - a static machine-id can not be written to `/etc/machine-id`,
/// - or metadata on the created `/etc/machine-id` can not be retrieved.
pub(crate) fn write_machine_id() -> Result<(), Error> {
    debug!("Write dummy /etc/machine-id, required for systemd-creds");
    let machine_id = PathBuf::from("/etc/machine-id");
    write(&machine_id, "d3b07384d113edec49eaa6238ad5ff00").map_err(|source| Error::IoPath {
        path: machine_id.to_path_buf(),
        context: "writing machine-id",
        source,
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
        if let Err(error) = self.kill() {
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
pub fn start_credentials_socket() -> Result<BackgroundProcess, crate::Error> {
    write_machine_id()?;
    let systemd_run_path = PathBuf::from("/run/systemd");
    let socket_path = PathBuf::from("/run/systemd/io.systemd.Credentials");
    create_dir_all(&systemd_run_path).map_err(|source| Error::CreateDirectory {
        dir: systemd_run_path,
        source,
    })?;

    // Run systemd-socket-activate to provide /run/systemd/io.systemd.Credentials
    let command = "systemd-socket-activate";
    let systemd_socket_activate = get_command(command)?;
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
        }
        .into());
    }

    Ok(BackgroundProcess {
        child,
        command: format!("{command:?}"),
    })
}
