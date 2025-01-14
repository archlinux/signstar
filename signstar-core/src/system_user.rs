//! Defaults for system users.
//!
//! ```
//! use signstar_core::system_user::{get_home_base_dir_path, get_user_credentials_dir};
//!
//! // Get the base directory below which Signstar system user homes are located.
//! println!("{:?}", get_home_base_dir_path());
//!
//! // Get the directory below which Signstar secrets are located per system user.
//! println!("{:?}", get_user_credentials_dir());
//! ```

use std::path::PathBuf;

/// The base directory below which system user homes are located.
pub const HOME_BASE_DIR: &str = "/var/lib/signstar/home/";

/// The directory name below which credentials files are stored.
///
/// The directory is evaluated relative to a user's home.
pub const USER_CREDENTIALS_DIR: &str = ".local/state/signstar/credentials/";

/// The file extension of plaintext credential files.
pub const PLAINTEXT_CREDENTIALS_EXTENSION: &str = "txt";

/// The file extension of systemd-creds encrypted credential files.
pub const SYSTEMD_CREDS_CREDENTIALS_EXTENSION: &str = "creds";

/// Returns the base directory below which Signstar system user homes are located.
pub fn get_home_base_dir_path() -> PathBuf {
    PathBuf::from(HOME_BASE_DIR)
}

/// Returns the directory below which Signstar secrets are located per system user.
pub fn get_user_credentials_dir() -> PathBuf {
    PathBuf::from(USER_CREDENTIALS_DIR)
}
