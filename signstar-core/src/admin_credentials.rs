//! Data and functions for handling administrative credentials on a Signstar host.

use std::{fs::create_dir_all, path::PathBuf};

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

/// An error that may occur when handling credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No plaintext administrative credentials file can be found
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory { dir: String, source: std::io::Error },
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
