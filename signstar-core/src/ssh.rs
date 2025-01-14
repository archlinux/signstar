//! Defaults for SSH.

/// The base directory below which SSH authorized_keys files for users are created
pub const SSH_AUTHORIZED_KEY_BASE_DIR: &str = "/etc/ssh/";

/// The directory below which sshd_config drop-in files are created
pub const SSHD_DROPIN_CONFIG_DIR: &str = "/etc/ssh/sshd_config.d/";
