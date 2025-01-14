//! Defaults for system users.

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
