//! Defaults for SSH.
//!
//! # Examples
//!
//! ```
//! use signstar_common::ssh::{get_ssh_authorized_key_base_dir, get_sshd_config_dropin_dir};
//!
//! // Get directory path for SSH authorized_keys files for Signstar users.
//! println!("{:?}", get_ssh_authorized_key_base_dir());
//!
//! // Get directory path for sshd_config drop-in files.
//! println!("{:?}", get_sshd_config_dropin_dir());
//! ```

use std::path::PathBuf;

/// The base directory below which SSH authorized_keys files for users are located.
const SSH_AUTHORIZED_KEY_BASE_DIR: &str = "/etc/ssh/";

/// The directory below which sshd_config drop-in files are located.
const SSHD_CONFIG_DROPIN_DIR: &str = "/etc/ssh/sshd_config.d/";

/// Returns the directory path below which SSH authorized_keys files for Signstar users are located.
pub fn get_ssh_authorized_key_base_dir() -> PathBuf {
    PathBuf::from(SSH_AUTHORIZED_KEY_BASE_DIR)
}

/// Returns the directory path below which SSH authorized_keys files for Signstar users are located.
pub fn get_sshd_config_dropin_dir() -> PathBuf {
    PathBuf::from(SSHD_CONFIG_DROPIN_DIR)
}
