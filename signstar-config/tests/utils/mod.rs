// Clippy can not detect used code in here, because we're a test module
#![allow(dead_code)]
use std::{
    fs::{Permissions, read_to_string, set_permissions},
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command},
    thread,
    time,
};

use signstar_core::system_user::HOME_BASE_DIR;
use testresult::TestResult;

/// An error that may occur when using test utils.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Applying permissions to a file failed.
    #[error("Unable to apply permissions to {path}:\n{source}")]
    ApplyPermissions {
        path: PathBuf,
        source: std::io::Error,
    },

    /// The socket for io.systemd.Credentials could not be started.
    #[error("Unable to start socket for io.systemd.Credentials:\n{0}")]
    CredentialsSocket(#[source] std::io::Error),

    /// Listing of directory contents failed.
    #[error("Unable to list files in directory {path}:\n{source}")]
    ListDirectory {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A timeout has been reached.
    #[error("Timeout of {timeout}ms reached while {context}")]
    Timeout { timeout: u64, context: String },
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
    let timeout = 2000;
    let step = 100;
    let mut elapsed = 0;
    let mut permissions_set = false;
    while elapsed < timeout {
        for direntry in PathBuf::from("/run/systemd/")
            .read_dir()
            .map_err(|source| Error::ListDirectory {
                path: PathBuf::from("/run/systemd/"),
                source,
            })?
        {
            let dir_entry = direntry.map_err(|source| Error::ListDirectory {
                path: PathBuf::from("/run/systemd/"),
                source,
            })?;
            if dir_entry.path() == socket_path {
                println!("Found {socket_path:?}");
                set_permissions(socket_path.as_path(), Permissions::from_mode(0o666)).map_err(
                    |source| Error::ApplyPermissions {
                        path: socket_path.to_path_buf(),
                        source,
                    },
                )?;
                permissions_set = true;
                break;
            }
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
    let systemd_run_output = Command::new("su").args(&run_params).output()?;
    if !systemd_run_output.status.success() {
        return Err(
            signstar_config::non_admin_credentials::Error::CommandNonZero {
                command: format!("su {}", run_params.join(" ")),
                exit_status: systemd_run_output.status,
                stdout: String::from_utf8_lossy(&systemd_run_output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&systemd_run_output.stderr).into_owned(),
            }
            .into(),
        );
    } else {
        println!(
            "{}",
            String::from_utf8_lossy(&systemd_run_output.stdout).into_owned()
        );
    }

    Ok(())
}

/// Creates a set of users.
pub fn create_users(users: &[String]) -> TestResult {
    println!("Creating users: {:?}", users);
    for user in users {
        println!("Creating user: {}", user);

        // create the user and its home
        let useradd_args = [
            "--base-dir",
            HOME_BASE_DIR,
            "--create-home",
            "--user-group",
            "--shell",
            "/usr/bin/bash",
            user,
        ];
        let useradd_output = Command::new("useradd").args(useradd_args).output()?;
        if !useradd_output.status.success() {
            return Err(
                signstar_config::non_admin_credentials::Error::CommandNonZero {
                    command: format!("useradd {}", useradd_args.join(" ")),
                    exit_status: useradd_output.status,
                    stdout: String::from_utf8_lossy(&useradd_output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&useradd_output.stderr).into_owned(),
                }
                .into(),
            );
        }

        // unlock the user
        let usermod_args = ["--unlock", user];
        let usermod_output = Command::new("usermod").args(usermod_args).output()?;
        if !usermod_output.status.success() {
            return Err(
                signstar_config::non_admin_credentials::Error::CommandNonZero {
                    command: format!("usermod {}", usermod_args.join(" ")),
                    exit_status: usermod_output.status,
                    stdout: String::from_utf8_lossy(&usermod_output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&usermod_output.stderr).into_owned(),
                }
                .into(),
            );
        }
    }

    println!("/etc/passwd:\n{}", read_to_string("/etc/passwd")?);

    Ok(())
}
