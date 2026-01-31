//! Utilities for signstar-config.
use std::path::PathBuf;

use nix::unistd::{User, geteuid};
use which::which;

#[cfg(feature = "nethsm")]
use crate::ExtendedUserMapping;
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

    /// An [`ExtendedUserMapping`] does not provide a system user.
    #[error("The user mapping does not provide a system user:\n{0}")]
    MappingSystemUserGet(String),

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

    /// The current user is root, but should be an unprivileged user.
    #[error("The command must not be run as root, but running as \"root\"")]
    SystemUserRoot,
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

/// Fails if running as root.
///
/// Evaluates the effective user ID.
///
/// # Errors
///
/// Returns an error if the effective user ID is that of root.
#[cfg(feature = "nethsm")]
pub(crate) fn fail_if_root(user: &User) -> Result<(), Error> {
    if user.uid.is_root() {
        return Err(Error::SystemUserRoot);
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

/// Checks whether the current system user is the targeted user.
///
/// Compares two [`User`] instances and fails if they are not the same.
///
/// # Errors
///
/// Returns an error if the current system user is not the targeted user.
#[cfg(feature = "nethsm")]
pub(crate) fn match_current_system_user(
    current_user: &User,
    target_user: &User,
) -> Result<(), Error> {
    if current_user != target_user {
        return Err(Error::SystemUserMismatch {
            target_user: target_user.name.clone(),
            current_user: current_user.name.clone(),
        });
    }
    Ok(())
}

/// Returns a [`SystemUserId`] and matching Unix system [`User`] associated with it.
///
/// # Errors
///
/// Returns an error if
/// - there is no [`SystemUserId`] in the mapping,
/// - or no [`User`] data can be retrieved from a found [`SystemUserId`].
#[cfg(feature = "nethsm")]
pub(crate) fn get_system_user_pair(
    mapping: &ExtendedUserMapping,
) -> Result<(SystemUserId, User), Error> {
    // retrieve the targeted system user from the mapping
    let Some(system_user) = mapping.get_user_mapping().get_system_user() else {
        return Err(Error::MappingSystemUserGet(format!(
            "{:?}",
            mapping.get_user_mapping()
        )));
    };

    // retrieve the actual user data on the system
    let Some(user) =
        User::from_name(system_user.as_ref()).map_err(|source| Error::SystemUserLookup {
            user: NameOrUid::Name(system_user.clone()),
            source,
        })?
    else {
        return Err(Error::SystemUserData {
            user: NameOrUid::Name(system_user.clone()),
        });
    };

    Ok((system_user.clone(), user))
}
