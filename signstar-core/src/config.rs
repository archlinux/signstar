//! Default configuration file locations for Signstar hosts.

use std::{fs::create_dir_all, path::PathBuf};

/// The default config directory below "/usr" for Signstar hosts.
pub const DEFAULT_CONFIG_DIR: &str = "/usr/share/signstar/";

/// The override config directory below "/etc" for Signstar hosts.
pub const ETC_OVERRIDE_CONFIG_DIR: &str = "/etc/signstar/";

/// The override config directory below "/run" for Signstar hosts.
pub const RUN_OVERRIDE_CONFIG_DIR: &str = "/run/signstar/";

/// The override config directory below "/usr/local" for Signstar hosts.
pub const USR_LOCAL_OVERRIDE_CONFIG_DIR: &str = "/usr/local/share/signstar/";

/// The filename of a Signstar configuration file.
pub const CONFIG_FILE: &str = "config.toml";

/// An error that may occur when handling configuration directories or files.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A directory can not be created.
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory { dir: String, source: std::io::Error },
}

/// Returns the first Signstar configuration file available, or [`None`] if none found.
///
/// Considers files named [`CONFIG_FILE`] in the following directories in descending priority:
/// - [`ETC_OVERRIDE_CONFIG_DIR`]
/// - [`RUN_OVERRIDE_CONFIG_DIR`]
/// - [`USR_LOCAL_OVERRIDE_CONFIG_DIR`]
/// - [`DEFAULT_CONFIG_DIR`]
///
/// The first existing file is returned.
/// If no file is found [`None`] is returned.
pub fn get_config_file() -> Option<PathBuf> {
    for dir in [
        ETC_OVERRIDE_CONFIG_DIR,
        RUN_OVERRIDE_CONFIG_DIR,
        USR_LOCAL_OVERRIDE_CONFIG_DIR,
        DEFAULT_CONFIG_DIR,
    ] {
        let path = PathBuf::from([dir, CONFIG_FILE].concat());
        if path.exists() && path.is_file() {
            return Some(path);
        }
    }
    None
}

/// Returns the first Signstar configuration file available, or the default if none found.
///
/// Considers files named [`CONFIG_FILE`] in the following directories in descending priority:
/// - [`ETC_OVERRIDE_CONFIG_DIR`]
/// - [`RUN_OVERRIDE_CONFIG_DIR`]
/// - [`USR_LOCAL_OVERRIDE_CONFIG_DIR`]
/// - [`DEFAULT_CONFIG_DIR`]
///
/// The first existing file is returned.
/// If no file is found, the default location [`DEFAULT_CONFIG_DIR`][`CONFIG_FILE`] is returned.
pub fn get_config_file_or_default() -> PathBuf {
    let Some(config) = get_config_file() else {
        return PathBuf::from([DEFAULT_CONFIG_DIR, CONFIG_FILE].concat());
    };
    config
}

/// Provides all configuration file locations in order, formatted as String
pub fn get_config_locations() -> String {
    format!(
        "{ETC_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}, {RUN_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}, {USR_LOCAL_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}, or {DEFAULT_CONFIG_DIR}{CONFIG_FILE}."
    )
}

/// Returns the file path of the configuration file override below /etc as String.
pub fn get_etc_override_config_file() -> String {
    [ETC_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat()
}

/// Returns the file path of the configuration file override below /run as String.
pub fn get_run_override_config_file() -> String {
    [RUN_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat()
}

/// Returns the file path of the configuration file override below /usr/local as String.
pub fn get_usr_local_override_config_file() -> String {
    [USR_LOCAL_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat()
}

/// Returns the file path of the default configuration file /usr as String.
pub fn get_default_config_file() -> String {
    [DEFAULT_CONFIG_DIR, CONFIG_FILE].concat()
}

/// Creates the default configuration directory below /usr.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_default_config_dir() -> Result<(), Error> {
    create_dir_all(PathBuf::from(DEFAULT_CONFIG_DIR)).map_err(|source| Error::CreateDirectory {
        dir: DEFAULT_CONFIG_DIR.to_string(),
        source,
    })
}

/// Creates the configuration override dir below /etc.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_etc_override_config_dir() -> Result<(), Error> {
    create_dir_all(PathBuf::from(ETC_OVERRIDE_CONFIG_DIR)).map_err(|source| {
        Error::CreateDirectory {
            dir: ETC_OVERRIDE_CONFIG_DIR.to_string(),
            source,
        }
    })
}

/// Creates the configuration override dir below /run.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_run_override_config_dir() -> Result<(), Error> {
    create_dir_all(PathBuf::from(RUN_OVERRIDE_CONFIG_DIR)).map_err(|source| {
        Error::CreateDirectory {
            dir: RUN_OVERRIDE_CONFIG_DIR.to_string(),
            source,
        }
    })
}

/// Creates the configuration override dir below /usr/local.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_usr_local_override_config_dir() -> Result<(), Error> {
    create_dir_all(PathBuf::from(USR_LOCAL_OVERRIDE_CONFIG_DIR)).map_err(|source| {
        Error::CreateDirectory {
            dir: USR_LOCAL_OVERRIDE_CONFIG_DIR.to_string(),
            source,
        }
    })
}
