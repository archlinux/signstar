//! Defaults for system users.

/// The base directory below which system user homes are created.
pub const HOME_BASE_DIR: &str = "/var/lib/signstar/home/";

/// The directory name below which credentials files are stored.
///
/// The directory is evaluated relative to a user's home.
pub const USER_CREDENTIALS_DIR: &str = ".local/state/signstar/credentials/";

/// The base for a directory in which ephemeral, plaintext credential files are stored.
///
/// This directory path is concatenated with the effective user ID of a system user and
/// [`EPHEMERAL_CREDENTIALS_DIR`] to get a user-specific path for the storage of ephemeral,
/// plaintext credential files.
pub const EPHEMERAL_CREDENTIALS_BASE_DIR: &str = "/run/user/";

/// The directory in a user's runtime directory in which ephemeral, plaintext credential files are
/// stored.
///
/// This directory path appended to a user's runtime directory to get a user-specific path for the
/// storage of ephemeral, plaintext credential files.
pub const EPHEMERAL_CREDENTIALS_DIR: &str = "signstar/credentials/";

/// The file extension of plaintext credential files.
pub const PLAINTEXT_CREDENTIALS_EXTENSION: &str = "txt";

/// The file extension of systemd-creds encrypted credential files.
pub const SYSTEMD_CREDS_CREDENTIALS_EXTENSION: &str = "creds";
