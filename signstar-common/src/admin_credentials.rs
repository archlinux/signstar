//! Data and functions for using administrative credentials on a Signstar host.
//!
//! # Examples
//!
//! ```
//! use signstar_common::admin_credentials::get_credentials_dir;
//!
//! // Get the directory path in which administrative credentials reside.
//! println!("{:?}", get_credentials_dir());
//! ```

use std::{
    fs::{Permissions, create_dir_all, set_permissions},
    os::unix::fs::{PermissionsExt, chown},
    path::PathBuf,
};

use crate::common::{CREDENTIALS_DIR_MODE, get_data_home};

/// File name of plaintext administrative credentials.
const PLAINTEXT_CREDENTIALS_FILE: &str = "admin-credentials.toml";

/// File name of systemd-creds encrypted administrative credentials.
const SYSTEMD_CREDS_CREDENTIALS_FILE: &str = "admin-credentials.creds";

/// The directory for administrative credentials (encrypted and unencrypted).
const CREDENTIALS_DIR: &str = "creds/";

/// An error that may occur when handling credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Applying permissions to a file failed.
    #[error("Unable to apply permissions {permissions} to {path}:\n{source}")]
    ApplyPermissions {
        /// The octal permissions applied to a `path`.
        permissions: u32,
        /// The path the `permissions` are applied to.
        path: PathBuf,
        /// The error source.
        source: std::io::Error,
    },

    /// No plaintext administrative credentials file can be found
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory {
        /// The directory that cannot be created.
        dir: &'static str,
        /// The error source.
        source: std::io::Error,
    },

    /// The ownership of a directory can not be set.
    #[error("Ownership of directory {dir} can not be changed to user {system_user}: {source}")]
    DirChangeOwner {
        /// The directory for which ownership cannot be transferred to a `system_user`.
        dir: PathBuf,
        /// The system user that cannot be made owner of `dir`.
        system_user: String,
        /// The error source.
        source: std::io::Error,
    },
}

/// Returns the path of the directory in which administrative credentials reside.
pub fn get_credentials_dir() -> PathBuf {
    get_data_home().join(PathBuf::from(CREDENTIALS_DIR))
}

/// Returns the file path for plaintext administrative credentials.
pub fn get_plaintext_credentials_file() -> PathBuf {
    get_credentials_dir().join(PathBuf::from(PLAINTEXT_CREDENTIALS_FILE))
}

/// Returns the file path for systemd-creds encrypted administrative credentials.
pub fn get_systemd_creds_credentials_file() -> PathBuf {
    get_credentials_dir().join(PathBuf::from(SYSTEMD_CREDS_CREDENTIALS_FILE))
}

/// Creates the directory for administrative credentials.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_credentials_dir() -> Result<(), Error> {
    let credentials_dir = get_credentials_dir();
    create_dir_all(credentials_dir.as_path()).map_err(|source| Error::CreateDirectory {
        dir: CREDENTIALS_DIR,
        source,
    })?;

    // Set the permissions of the credentials directory to `CREDENTIALS_DIR_MODE`.
    set_permissions(
        credentials_dir.as_path(),
        Permissions::from_mode(CREDENTIALS_DIR_MODE),
    )
    .map_err(|source| Error::ApplyPermissions {
        permissions: CREDENTIALS_DIR_MODE,
        path: credentials_dir.clone(),
        source,
    })?;

    // Recursively chown all directories to root, until `DATA_HOME` is
    // reached.
    let data_home = get_data_home();
    let mut chown_dir = credentials_dir.clone();
    while chown_dir != data_home {
        chown(&chown_dir, Some(0), Some(0)).map_err(|source| Error::DirChangeOwner {
            dir: chown_dir.to_path_buf(),
            system_user: "root".to_string(),
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
