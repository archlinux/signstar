//! Reading and writing of non-administrative secrets.

use std::{
    fs::{File, Permissions, create_dir_all, read_to_string, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::PathBuf,
    process::{Command, Stdio},
};

use change_user_run::get_command;
use log::info;
use nix::unistd::{User, geteuid};
use serde::{Deserialize, Serialize};
use signstar_common::{
    common::SECRET_FILE_MODE,
    system_user::{
        get_home_base_dir_path,
        get_plaintext_secret_file,
        get_systemd_creds_secret_file,
        get_user_secrets_dir,
    },
};

use crate::{
    passphrase::Passphrase,
    secret_file::{Error, common::check_secrets_file},
};

/// The handling of non-administrative secrets.
///
/// Non-administrative secrets represent passphrases for (non-administrator) HSM users and may be
/// handled in different ways (e.g. encrypted or not encrypted).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum NonAdministrativeSecretHandling {
    /// Each non-administrative secret is handled in a plaintext file in a non-volatile
    /// directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted non-administrative secrets on a file system.
    Plaintext,

    /// Each non-administrative secret is encrypted for a specific system user using
    /// [systemd-creds(1)] and the resulting files are stored in a non-volatile directory.
    ///
    /// ## Note
    ///
    /// Although secrets are stored as encrypted strings in dedicated files, they may be extracted
    /// under certain circumstances:
    ///
    /// - the root account is compromised
    ///   - decrypts and exfiltrates _all_ secrets
    ///   - the secret is not encrypted using a [TPM] and the file
    ///     `/var/lib/systemd/credential.secret` as well as _any_ encrypted secret is exfiltrated
    /// - a specific user is compromised, decrypts and exfiltrates its own secret
    ///
    /// It is therefore crucial to follow common best-practices:
    ///
    /// - rely on a [TPM] for encrypting secrets, so that files become host-specific
    /// - heavily guard access to all users, especially root
    ///
    /// [systemd-creds(1)]: https://man.archlinux.org/man/systemd-creds.1
    /// [TPM]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
    #[default]
    SystemdCreds,
}

/// Writes a [`Passphrase`] to a secret file location of a system user.
///
/// The secret file location is established based on the chosen `secret_handling`, `system_user` and
/// `backend_user`.
///
/// # Note
///
/// This function must be run as root, as the secrets file is created for a specific `system_user`
/// and the ownership of the resulting secrets file is adjusted in such a way that the
/// `system_user` has access.
///
/// # Errors
///
/// Returns an error if
///
/// - the effective user ID of the calling user is not that of root
/// - the secret is a plaintext file, but reading it as a string fails
/// - the secret needs to be encrypted using [systemd-creds(1)], but
///   - [systemd-creds(1)] cannot be found or the [systemd-creds(1)] command
///   - cannot be spawned in the background
///   - cannot be attached to on stdin in the background
///   - cannot be written to on its stdin
///   - fails to execute
///   - returned with a non-zero exit code
/// - the file at `path` cannot be created
/// - the file at `path` cannot be written to
/// - the ownership of file at `path` cannot be changed to that of [systemd-creds(1)]
/// - the file permissions of the file at `path` cannot be adjusted
///
/// [systemd-creds(1)]: https://man.archlinux.org/man/systemd-creds.1
pub fn write_passphrase_to_secrets_file(
    secret_handling: NonAdministrativeSecretHandling,
    system_user: &User,
    backend_user: &str,
    passphrase: &Passphrase,
) -> Result<(), crate::Error> {
    let path = match secret_handling {
        NonAdministrativeSecretHandling::Plaintext => {
            get_plaintext_secret_file(&system_user.name, backend_user)
        }
        NonAdministrativeSecretHandling::SystemdCreds => {
            get_systemd_creds_secret_file(&system_user.name, backend_user)
        }
    };

    if !geteuid().is_root() {
        return Err(Error::NotRunningAsRoot {
            context: format!(
                "writing a passphrase to secrets file at path {path:?} for system user {} and backend user {backend_user}",
                system_user.name
            ),
        }
        .into());
    }

    info!(
        "Write passphrase to secrets file {path:?} of system user {} and backend user {backend_user}",
        system_user.name
    );

    create_secrets_dir(system_user)?;

    let secret = {
        // Create credentials files depending on secret handling
        match secret_handling {
            NonAdministrativeSecretHandling::Plaintext => {
                passphrase.expose_borrowed().as_bytes().to_vec()
            }
            NonAdministrativeSecretHandling::SystemdCreds => {
                // Create systemd-creds encrypted secret.
                let creds_command = get_command("systemd-creds")?;
                let mut command = Command::new(creds_command);
                let command = command
                    .arg("--user")
                    .arg("--name=")
                    .arg("--uid")
                    .arg(system_user.name.as_str())
                    .arg("encrypt")
                    .arg("-")
                    .arg("-")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let mut command_child =
                    command.spawn().map_err(|source| Error::CommandBackground {
                        command: format!("{command:?}"),
                        source,
                    })?;

                // write to stdin
                command_child
                    .stdin
                    .take()
                    .ok_or(Error::CommandAttachToStdin {
                        command: format!("{command:?}"),
                    })?
                    .write_all(passphrase.expose_borrowed().as_bytes())
                    .map_err(|source| Error::CommandWriteToStdin {
                        command: format!("{command:?}"),
                        source,
                    })?;

                let command_output =
                    command_child
                        .wait_with_output()
                        .map_err(|source| Error::CommandExec {
                            command: format!("{command:?}"),
                            source,
                        })?;

                if !command_output.status.success() {
                    return Err(Error::CommandNonZero {
                        command: format!("{command:?}"),
                        exit_status: command_output.status,
                        stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
                    }
                    .into());
                }
                command_output.stdout
            }
        }
    };

    // Write secret to file and adjust permission and ownership of file.
    let mut file = File::create(&path).map_err(|source| Error::SecretsFileCreate {
        path: path.clone(),
        system_user: system_user.name.clone(),
        source,
    })?;
    file.write_all(&secret)
        .map_err(|source| Error::SecretsFileWrite {
            path: path.to_path_buf(),
            system_user: system_user.name.clone(),
            source,
        })?;
    chown(
        &path,
        Some(system_user.uid.as_raw()),
        Some(system_user.gid.as_raw()),
    )
    .map_err(|source| Error::Chown {
        path: path.clone(),
        user: system_user.name.clone(),
        source,
    })?;
    set_permissions(&path, Permissions::from_mode(SECRET_FILE_MODE)).map_err(|source| {
        Error::ApplyPermissions {
            path: path.clone(),
            mode: SECRET_FILE_MODE,
            source,
        }
    })?;

    Ok(())
}

/// Reads a secret from a secret file location of a user and returns it as a [`Passphrase`].
///
/// The secret file location is established based on the chosen `secret_handling`, `system_user` and
/// `backend_user`.
///
/// # Notes
///
/// This function must be called using an unprivileged user, as the `path` is assumed to be in that
/// user's home directory.
/// If [systemd-creds(1)] based encryption is used, then the same user used to encrypt the secret
/// must be used to decrypt the secret.
///
/// # Errors
///
/// Returns an error if
///
/// - the effective user ID of the calling user is that of root,
/// - the secret is a plaintext file, but reading it as a string fails,
/// - the secret is encrypted using [systemd-creds(1)], but
///   - [systemd-creds(1)] cannot be found,
///   - or the [systemd-creds(1)] command fails to execute,
///   - or the [systemd-creds(1)] command returned with a non-zero exit code,
///   - or the returned output cannot be converted into valid UTF-8 string
///
/// [systemd-creds(1)]: https://man.archlinux.org/man/systemd-creds.1
pub fn load_passphrase_from_secrets_file(
    secret_handling: NonAdministrativeSecretHandling,
    system_user: &User,
    backend_user: &str,
) -> Result<Passphrase, crate::Error> {
    if geteuid().is_root() {
        return Err(Error::RunningAsRoot {
            target_user: system_user.name.clone(),
            context: format!("loading a passphrase from secrets file for system user {} and backend user {backend_user}",
                system_user.name
            ),
        }
        .into());
    }

    let path = match secret_handling {
        NonAdministrativeSecretHandling::Plaintext => {
            get_plaintext_secret_file(&system_user.name, backend_user)
        }
        NonAdministrativeSecretHandling::SystemdCreds => {
            get_systemd_creds_secret_file(&system_user.name, backend_user)
        }
    };

    info!(
        "Load passphrase from secrets file {path:?} for system user {} and backend user {backend_user}",
        system_user.name
    );

    check_secrets_file(&path)?;

    match secret_handling {
        // Read from plaintext secrets file.
        NonAdministrativeSecretHandling::Plaintext => Ok(Passphrase::new(
            read_to_string(&path).map_err(|source| Error::IoPath {
                path: path.clone(),
                context: "reading the secrets file as a string",
                source,
            })?,
        )),
        // Read from systemd-creds encrypted secrets file.
        NonAdministrativeSecretHandling::SystemdCreds => {
            let creds_command = get_command("systemd-creds")?;
            let mut command = Command::new(creds_command);
            let command = command.arg("--user").arg("decrypt").arg(&path).arg("-");
            let command_output = command.output().map_err(|source| Error::CommandExec {
                command: format!("{command:?}"),
                source,
            })?;

            if !command_output.status.success() {
                return Err(Error::CommandNonZero {
                    command: format!("{command:?}"),
                    exit_status: command_output.status,
                    stderr: String::from_utf8_lossy(&command_output.stderr).into_owned(),
                }
                .into());
            }

            Ok(Passphrase::new(
                String::from_utf8(command_output.stdout).map_err(|source| Error::Utf8String {
                    path: path.clone(),
                    context: format!("converting stdout of {command:?} to string"),
                    source,
                })?,
            ))
        }
    }
}

/// Creates the secrets directory for a [`User`].
///
/// Creates the secrets directory for the user and ensures correct ownership of it and all
/// parent directories up until the user's home directory.
///
/// # Note
///
/// Relies on [`get_user_secrets_dir`] to retrieve the secrets dir for the `system_user`.
///
/// # Errors
///
/// Returns an error if
///
/// - the effective user ID of the calling process is not that of root,
/// - the directory or one of its parents could not be created,
/// - the ownership of any directory between the user's home and the secrets directory can not be
///   changed
pub(crate) fn create_secrets_dir(system_user: &User) -> Result<(), crate::Error> {
    if !geteuid().is_root() {
        return Err(Error::NotRunningAsRoot {
            context: format!("creating secrets dir for user {}", system_user.name),
        }
        .into());
    }

    // get and create the user's passphrase directory
    let path = get_user_secrets_dir(&system_user.name);
    create_dir_all(&path).map_err(|source| crate::secret_file::Error::SecretsDirCreate {
        path: path.clone(),
        system_user: system_user.name.clone(),
        source,
    })?;

    // Recursively chown all directories to the user and group, until `HOME_BASE_DIR` is
    // reached.
    let home_dir = get_home_base_dir_path().join(PathBuf::from(&system_user.name));
    let mut chown_dir = path.clone();
    while chown_dir != home_dir {
        chown(
            &chown_dir,
            Some(system_user.uid.as_raw()),
            Some(system_user.gid.as_raw()),
        )
        .map_err(|source| Error::Chown {
            path: chown_dir.to_path_buf(),
            user: system_user.name.clone(),
            source,
        })?;
        if let Some(parent) = &chown_dir.parent() {
            chown_dir = parent.to_path_buf()
        } else {
            break;
        }
    }

    Ok(())
}
