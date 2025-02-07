//! Utilities for signstar-config.
use std::path::PathBuf;

use nethsm_config::{ExtendedUserMapping, SystemUserId};
use nix::unistd::{User, geteuid};
use which::which;

/// An error that may occur when using signstar-config utils.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An executable that is supposed to be called, is not found.
    #[error("Unable to to find executable \"{command}\"")]
    ExecutableNotFound {
        command: &'static str,
        source: which::Error,
    },

    /// Unable to retrieve user data from the current process.
    #[error("Unable to retrieve user data from the current process:\n{0}")]
    GetUserDataFromProcess(#[source] nix::errno::Errno),

    /// Unable to retrieve user data from an [`ExtendedUserMapping`].
    #[error("Unable to retrieve user data for the system user {system_user}:\n{source}")]
    GetUserDataFromMapping {
        system_user: SystemUserId,
        source: nix::errno::Errno,
    },

    /// An [`ExtendedUserMapping`] does not provide a system user.
    #[error("The user mapping does not provide a system user:\n{0}")]
    NoSystemUserInMapping(String),

    /// The current user is not root.
    #[error("The command requires running as root, but running as \"{user}\"")]
    NotRoot { user: String },

    /// There is no user data associated with the current process.
    #[error("There is no user data associated with the current process. Does the user exist?")]
    NoUserData,

    /// Unable to retrieve user data from the current process.
    #[error("No system user {system_user} is not present on the system.")]
    SystemUserMissing { system_user: SystemUserId },

    /// The calling user does not match the targeted system user.
    #[error(
        "The targeted system user {target_user} is not the currently calling system user {current_user}."
    )]
    UserMismatch {
        target_user: String,
        current_user: String,
    },
}

/// Returns the path to a `command`.
///
/// Searches for an executable in `$PATH` of the current environment and returns the first one
/// found.
///
/// # Errors
///
/// Returns an error if no executable matches the provided `command`.
pub(crate) fn get_command(command: &'static str) -> Result<PathBuf, Error> {
    which(command).map_err(|source| Error::ExecutableNotFound { command, source })
}

/// Fails if not running as root.
///
/// Evaluates the effective user ID.
///
/// # Errors
///
/// Returns an error if the effective user ID is not that of root.
pub(crate) fn fail_non_root(user: &User) -> Result<(), Error> {
    if &user.name != "root" {
        return Err(Error::NotRoot {
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
    let Some(user) = User::from_uid(geteuid()).map_err(Error::GetUserDataFromProcess)? else {
        return Err(Error::NoUserData);
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
pub(crate) fn match_current_system_user(
    current_user: &User,
    target_user: &User,
) -> Result<(), Error> {
    if current_user != target_user {
        return Err(Error::UserMismatch {
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
pub(crate) fn get_system_user_pair(
    mapping: &ExtendedUserMapping,
) -> Result<(SystemUserId, User), Error> {
    // retrieve the targeted system user from the mapping
    let Some(system_user) = mapping.get_user_mapping().get_system_user() else {
        return Err(Error::NoSystemUserInMapping(format!(
            "{:?}",
            mapping.get_user_mapping()
        )));
    };

    // retrieve the actual user data on the system
    let user =
        User::from_name(system_user.as_ref()).map_err(|source| Error::GetUserDataFromMapping {
            system_user: system_user.clone(),
            source,
        })?;
    let Some(user) = user else {
        return Err(Error::SystemUserMissing {
            system_user: system_user.clone(),
        });
    };

    Ok((system_user.clone(), user))
}
