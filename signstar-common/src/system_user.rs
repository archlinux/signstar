//! Defaults for system users.
//!
//! ```
//! use signstar_common::system_user::{get_home_base_dir_path, get_relative_user_secrets_dir};
//!
//! // Get the base directory below which Signstar system user homes are located.
//! println!("{:?}", get_home_base_dir_path());
//!
//! // Get the relative directory below which Signstar secrets are located per system user.
//! println!("{:?}", get_relative_user_secrets_dir());
//! ```

use std::path::PathBuf;

use crate::common::get_data_home;

/// The relative base directory below which system user homes are located.
///
/// This directory resides relative to the data home on the system.
const HOME_BASE_DIR: &str = "home/";

/// The directory name below which credentials files are stored.
///
/// The directory is evaluated relative to a user's home.
const USER_SECRETS_DIR: &str = ".local/state/signstar/secrets/";

/// The file extension of plaintext credential files.
const PLAINTEXT_SECRETS_EXTENSION: &str = "txt";

/// The file extension of systemd-creds encrypted credential files.
const SYSTEMD_CREDS_SECRETS_EXTENSION: &str = "creds";

/// Returns the base directory below which Signstar system user homes are located.
pub fn get_home_base_dir_path() -> PathBuf {
    get_data_home().join(PathBuf::from(HOME_BASE_DIR))
}

/// Returns the relative directory below which Signstar secrets are located per system user.
pub fn get_relative_user_secrets_dir() -> PathBuf {
    PathBuf::from(USER_SECRETS_DIR)
}

/// Returns the path to the secrets directory for a specific system user.
pub fn get_user_secrets_dir(system_user: &str) -> PathBuf {
    get_home_base_dir_path()
        .join(PathBuf::from(system_user))
        .join(get_relative_user_secrets_dir())
}

/// Returns the path to a plaintext secrets file for a system user and backend user.
pub fn get_plaintext_secret_file(system_user: &str, backend_user: &str) -> PathBuf {
    get_user_secrets_dir(system_user).join(PathBuf::from(
        [backend_user, ".", PLAINTEXT_SECRETS_EXTENSION].concat(),
    ))
}

/// Returns the path to a systemd-creds encrypted secrets file for a system user and backend user.
pub fn get_systemd_creds_secret_file(system_user: &str, backend_user: &str) -> PathBuf {
    get_user_secrets_dir(system_user).join(PathBuf::from(
        [backend_user, ".", SYSTEMD_CREDS_SECRETS_EXTENSION].concat(),
    ))
}
