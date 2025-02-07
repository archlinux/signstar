// Clippy can not detect used code in here, because we're a test module
#![allow(dead_code)]
use std::{
    fs::{Permissions, create_dir_all, read_to_string, set_permissions, write},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command},
    thread,
    time,
};

use signstar_common::system_user::get_home_base_dir_path;
use tempfile::NamedTempFile;
use testresult::TestResult;

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
    #[error("An I/O error while {context}:\n{source}")]
    Io {
        context: &'static str,
        source: std::io::Error,
    },

    /// Listing of directory contents failed.
    #[error("Unable to list files in directory {path}:\n{source}")]
    ListDirectory {
        path: PathBuf,
        source: std::io::Error,
    },

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
pub fn write_machine_id() -> TestResult {
    println!("Write dummy /etc/machine-id, required for systemd-creds");
    let machine_id = PathBuf::from("/etc/machine-id");
    std::fs::write(&machine_id, "d3b07384d113edec49eaa6238ad5ff00")?;

    println!(
        "/etc/machine-id\nmode: {}\nuid: {}\ngid: {}",
        machine_id.metadata()?.permissions().mode(),
        machine_id.metadata()?.st_uid(),
        machine_id.metadata()?.st_gid()
    );
    Ok(())
}

/// Starts a socket for `io.systemd.Credentials` using `systemd-socket-activate`
///
/// Sets the file mode of the socket to '666' so that all users on the system have access.
///
/// # Errors
///
/// Returns an error if
///
/// - `systemd-socket-activate` is unable to start the required socket,
/// - one or more files in `/run/systemd` can not be listed,
/// - applying of permissions on `/run/systemd/io.systemd.Credentials` fails,
/// - or the socket has not been made available within 2000ms.
pub fn start_credentials_socket() -> Result<Child, Error> {
    let systemd_run_path = PathBuf::from("/run/systemd");
    create_dir_all(&systemd_run_path).map_err(|source| Error::CreateDirectory {
        dir: systemd_run_path,
        source,
    })?;

    let socket_path = PathBuf::from("/run/systemd/io.systemd.Credentials");
    let creds_socket = Command::new("systemd-socket-activate")
        .args([
            "--listen",
            "/run/systemd/io.systemd.Credentials",
            "--accept",
            "--fdname=varlink",
            "systemd-creds",
        ])
        .spawn()
        .map_err(Error::CredentialsSocket)?;

    // set the socket to be writable by all, once it's available.
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

    Ok(creds_socket)
}

/// Installs packages using pacman.
pub fn install_packages(packages: &[&str]) -> TestResult {
    println!("Install packages: {:?}", packages);
    let install_params = {
        let mut params = Vec::from(["-Syu", "--needed", "--noconfirm"]);
        params.extend_from_slice(packages);
        params
    };

    // initialize the pacman keyring
    Command::new("pacman-key").arg("--init").output()?;

    // first update pacman-keyring
    Command::new("pacman")
        .args(["-Sy", "--needed", "--noconfirm", "archlinux-keyring"])
        .output()?;

    // then install all packages
    Command::new("pacman").args(install_params).output()?;

    Ok(())
}

/// Runs a command as a specific user.
pub fn run_command_as_user(command: &[&str], user: &str) -> TestResult {
    println!("Run command {:?} as user {:?}.", command, user);

    let run_params = {
        let mut params = Vec::from(["--command"]);
        params.extend_from_slice(command);
        params.extend_from_slice(&["--group", user, "--login", user]);
        params
    };

    // run command as user using su
    let mut command = Command::new("su");
    command.args(&run_params);
    let output = command.output()?;

    if !output.status.success() {
        return Err(signstar_config::Error::CommandNonZero {
            command: format!("su {}", run_params.join(" ")),
            exit_status: output.status,
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
        .into());
    }

    println!("{}", String::from_utf8_lossy(&output.stdout).into_owned());

    Ok(())
}

/// Creates a set of users.
pub fn create_users(users: &[String]) -> TestResult {
    println!("Creating users: {:?}", users);
    for user in users {
        println!("Creating user: {}", user);

        // create the user and its home
        let mut command = Command::new("useradd");
        command.arg("--base-dir");
        command.arg(get_home_base_dir_path());
        command.arg("--create-home");
        command.arg("--user-group");
        command.arg("--shell");
        command.arg("/usr/bin/bash");
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
