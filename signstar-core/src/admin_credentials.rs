//! Data and functions for handling administrative credentials on a Signstar host.

use std::{
    fs::{create_dir_all, read_dir},
    path::PathBuf,
};

/// File name of plaintext administrative credentials.
pub const PLAINTEXT_CREDENTIALS_FILE: &str = "admin-credentials.toml";

/// File name of systemd-creds encrypted administrative credentials.
pub const SYSTEMD_CREDS_CREDENTIALS_FILE: &str = "admin-credentials.creds";

/// File name of SSS encrypted administrative credentials.
pub const SSS_CREDENTIALS_FILE: &str = "admin-credentials.sss";

/// The persistent directory location for administrative credentials (encrypted and unencrypted).
pub const PERSISTENT_CREDENTIALS_DIR: &str = "/var/lib/signstar/creds/";

/// The ephemeral directory location for administrative credentials.
pub const EPHEMERAL_CREDENTIALS_DIR: &str = "/run/signstar/creds/";

/// The directory location for uploaded SSS shares of administrative credentials.
pub const SSS_SHARES_UPLOAD_LOCATION: &str = "/run/signstar/creds/shares-upload/";

/// The directory location for downloaded SSS shares of administrative credentials.
pub const SSS_SHARES_DOWNLOAD_LOCATION: &str = "/run/signstar/creds/shares-download/";

/// An error that may occur when handling credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No plaintext administrative credentials file can be found
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory { dir: String, source: std::io::Error },

    /// Looking up files in the SSS shares directory location is not possible
    #[error("Unable to access files in {SSS_SHARES_UPLOAD_LOCATION}.")]
    SssDir(#[source] std::io::Error),
}

/// Returns the file path of the persistent plaintext administrative credentials as String.
pub fn get_persistent_plaintext_credentials() -> String {
    [PERSISTENT_CREDENTIALS_DIR, PLAINTEXT_CREDENTIALS_FILE].concat()
}

/// Returns the directory of the persistent administrative credentials as String.
pub fn persistent_credentials_dir() -> String {
    PERSISTENT_CREDENTIALS_DIR.to_string()
}

/// Returns the file path of the ephemeral plaintext administrative credentials as String.
pub fn get_ephemeral_plaintext_credentials() -> String {
    [EPHEMERAL_CREDENTIALS_DIR, PLAINTEXT_CREDENTIALS_FILE].concat()
}

/// Returns the file path of the persistent systemd-creds encrypted administrative credentials.
pub fn get_persistent_systemd_creds_credentials() -> String {
    [PERSISTENT_CREDENTIALS_DIR, SYSTEMD_CREDS_CREDENTIALS_FILE].concat()
}

/// Creates the persistent directory for administrative credentials.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_persistent_credentials_dir() -> Result<(), Error> {
    create_dir_all(PathBuf::from(PERSISTENT_CREDENTIALS_DIR)).map_err(|source| {
        Error::CreateDirectory {
            dir: PERSISTENT_CREDENTIALS_DIR.to_string(),
            source,
        }
    })
}

/// Creates the ephemeral directory for administrative credentials.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_ephemeral_credentials_dir() -> Result<(), Error> {
    create_dir_all(PathBuf::from(EPHEMERAL_CREDENTIALS_DIR)).map_err(|source| {
        Error::CreateDirectory {
            dir: EPHEMERAL_CREDENTIALS_DIR.to_string(),
            source,
        }
    })
}

/// Checks whether enough uploaded shares of SSS encrypted administrative credentials are available.
///
/// Uses `threshold` to determine whether enough SSS shares are available in
/// [`SSS_SHARES_UPLOAD_LOCATION`].
///
/// Returns `true` if more than or equal to `threshold` files with an `.sss` file suffix are present
/// in [`SSS_SHARES_UPLOAD_LOCATION`], `false` otherwise.
///
/// # Errors
///
/// Returns an error if retrieving the file paths of the SSS shares fails.
pub fn enough_uploaded_sss_shares(threshold: usize) -> Result<bool, Error> {
    let shares = get_uploaded_sss_shares()?;
    if shares.len() >= threshold {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Returns a list of file paths representing all uploaded SSS shares of administrative credentials.
///
/// Creates a vector containing all file paths in [`SSS_SHARES_UPLOAD_LOCATION`] that have an ".sss"
/// suffix.
///
/// # Errors
///
/// Returns an error if the directory containing the SSS shares can not be accessed.
pub fn get_uploaded_sss_shares() -> Result<Vec<PathBuf>, Error> {
    Ok(read_dir(PathBuf::from(SSS_SHARES_UPLOAD_LOCATION))
        .map_err(Error::SssDir)?
        .filter_map(|entry| {
            entry.ok().and_then(|entry| {
                Some(entry.path()).filter(|path| {
                    if let Some(extension) = path.extension() {
                        extension == "sss" && path.exists() && path.is_file()
                    } else {
                        false
                    }
                })
            })
        })
        .collect::<Vec<PathBuf>>())
}

/// Returns a list of file paths representing all downloadable SSS shares of administrative
/// credentials.
///
/// Creates a vector containing all file paths in [`SSS_SHARES_DOWNLOAD_LOCATION`] that have an
/// ".sss" suffix.
///
/// # Errors
///
/// Returns an error if the directory containing the SSS shares can not be accessed.
pub fn get_downloadable_sss_shares() -> Result<Vec<PathBuf>, Error> {
    Ok(read_dir(PathBuf::from(SSS_SHARES_DOWNLOAD_LOCATION))
        .map_err(Error::SssDir)?
        .filter_map(|entry| {
            entry.ok().and_then(|entry| {
                Some(entry.path()).filter(|path| {
                    if let Some(extension) = path.extension() {
                        extension == "sss" && path.exists() && path.is_file()
                    } else {
                        false
                    }
                })
            })
        })
        .collect::<Vec<PathBuf>>())
}
