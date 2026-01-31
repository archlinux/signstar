//! Utilities for signstar-config.
use std::path::PathBuf;

use nix::unistd::{User, geteuid};
use which::which;

use crate::SystemUserId;

/// An error that may occur when using signstar-config utils.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An executable that is supposed to be called, is not found.
    #[error("Unable to to find executable \"{command}\"")]
    ExecutableNotFound {
        /// The executable that could not be found.
        command: String,
        /// The source error.
        source: which::Error,
    },

    /// There is no data about a system user.
    #[error("Data for system user {user} is missing")]
    SystemUserData {
        /// The user identifier for which data is missing.
        user: NameOrUid,
    },

    /// Unable to lookup system user data (by name or from process EUID).
    #[error(
        "Unable to lookup data for system user {}:\n{source}",
        match user {
            NameOrUid::Name(name) => format!("user {name}"),
            NameOrUid::Uid(uid) => format!("uid {uid}"),
        }
    )]
    SystemUserLookup {
        /// The user identifier for which data could not be looked up.
        user: NameOrUid,
        /// The source error.
        source: nix::errno::Errno,
    },

    /// The calling user does not match the targeted system user.
    #[error(
        "The targeted system user {target_user} is not the currently calling system user {current_user}."
    )]
    SystemUserMismatch {
        /// The system user that is the target of the operation.
        target_user: String,
        /// The currently calling system user.
        current_user: String,
    },

    /// The current user is an unprivileged user, but should be root.
    #[error("The command requires running as root, but running as \"{user}\"")]
    SystemUserNotRoot {
        /// The system user that is used instead of `root`.
        user: String,
    },
}

/// A name or uid of a system user on a host
#[derive(Debug, strum::Display)]
pub enum NameOrUid {
    /// The name of the system user.
    Name(SystemUserId),
    /// The ID of the system user.
    Uid(nix::unistd::Uid),
}

/// Returns the path to a `command`.
///
/// Searches for an executable in `$PATH` of the current environment and returns the first one
/// found.
///
/// # Errors
///
/// Returns an error if no executable matches the provided `command`.
pub(crate) fn get_command(command: &str) -> Result<PathBuf, Error> {
    which(command).map_err(|source| Error::ExecutableNotFound {
        command: command.to_string(),
        source,
    })
}

/// Fails if not running as root.
///
/// Evaluates the effective user ID.
///
/// # Errors
///
/// Returns an error if the effective user ID is not that of root.
pub(crate) fn fail_if_not_root(user: &User) -> Result<(), Error> {
    if !user.uid.is_root() {
        return Err(Error::SystemUserNotRoot {
            user: user.name.clone(),
        });
    }
    Ok(())
}

/// Returns the [`User`] associated with the current process.
///
/// Retrieves user data of the system based on the effective user ID of the current process.
///
/// # Errors
///
/// Returns an error if
/// - no user data can be derived from the current process
/// - no user data can be found on the system, associated with the ID of the user of the current
///   process.
pub(crate) fn get_current_system_user() -> Result<User, Error> {
    let euid = geteuid();
    let Some(user) = User::from_uid(euid).map_err(|source| Error::SystemUserLookup {
        user: NameOrUid::Uid(euid),
        source,
    })?
    else {
        return Err(Error::SystemUserData {
            user: NameOrUid::Uid(euid),
        });
    };
    Ok(user)
}
