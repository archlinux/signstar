//! Default locations for Signstar configuration files.
//!
//! # Examples
//!
//! ```
//! use signstar_common::config::{
//!     get_config_file_or_default,
//!     get_config_file_paths,
//!     get_config_file,
//!     get_default_config_dir_path,
//!     get_default_config_file_path,
//!     get_etc_override_config_file_path,
//!     get_etc_override_dir_path,
//!     get_run_override_config_file_path,
//!     get_run_override_dir_path,
//!     get_usr_local_override_config_file_path,
//!     get_usr_local_override_dir_path,
//! };
//!
//! // Get directory paths for Signstar configuration files.
//! println!("{:?}", get_etc_override_dir_path());
//! println!("{:?}", get_run_override_dir_path());
//! println!("{:?}", get_usr_local_override_dir_path());
//! println!("{:?}", get_default_config_dir_path());
//!
//! // Get file paths for Signstar configuration files.
//! println!("{:?}", get_etc_override_config_file_path());
//! println!("{:?}", get_run_override_config_file_path());
//! println!("{:?}", get_usr_local_override_config_file_path());
//! println!("{:?}", get_default_config_file_path());
//!
//! // Get the first config file found, according to directory precedence.
//! println!("{:?}", get_config_file());
//!
//! // Get the first config file found, according to directory precedence, or the default if none are found.
//! println!("{:?}", get_config_file_or_default());
//!
//! // Get all configuration file paths, sorted by directory precedence.
//! println!("{:?}", get_config_file_paths());
//! ```

use std::{fs::create_dir_all, path::PathBuf};

/// The default config directory below "/usr" for Signstar hosts.
const DEFAULT_CONFIG_DIR: &str = "/usr/share/signstar/";

/// The override config directory below "/etc" for Signstar hosts.
const ETC_OVERRIDE_CONFIG_DIR: &str = "/etc/signstar/";

/// The override config directory below "/run" for Signstar hosts.
const RUN_OVERRIDE_CONFIG_DIR: &str = "/run/signstar/";

/// The override config directory below "/usr/local" for Signstar hosts.
const USR_LOCAL_OVERRIDE_CONFIG_DIR: &str = "/usr/local/share/signstar/";

/// The filename of a Signstar configuration file.
const CONFIG_FILE: &str = "config.toml";

/// An error that may occur when handling configuration directories or files.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A directory can not be created.
    #[error("Unable to create directory {dir}:\n{source}")]
    CreateDirectory { dir: String, source: std::io::Error },
}

/// Returns the first Signstar configuration file available, or [`None`] if none found.
///
/// Considers files named `config.toml` in the following directories in descending priority:
/// - `/etc/signstar`
/// - `/run/signstar`
/// - `/usr/local/share/signstar`
/// - `/usr/share/signstar`
///
/// The first existing file is returned.
/// If no file is found [`None`] is returned.
pub fn get_config_file() -> Option<PathBuf> {
    [
        get_etc_override_config_file_path(),
        get_run_override_config_file_path(),
        get_usr_local_override_config_file_path(),
        get_default_config_file_path(),
    ]
    .into_iter()
    .find(|file| file.is_file())
}

/// Returns the first Signstar configuration file available, or the default if none found.
///
/// Considers files named `config.toml` in the following directories in descending priority:
/// - `/etc/signstar`
/// - `/run/signstar`
/// - `/usr/local/share/signstar`
/// - `/usr/share/signstar`
///
/// The first existing file is returned.
/// If no file is found, the default location `/usr/share/signstar/config.toml` is returned.
pub fn get_config_file_or_default() -> PathBuf {
    let Some(config) = get_config_file() else {
        return get_default_config_file_path();
    };
    config
}

/// Returns a list of all configuration file locations, sorted by precedence.
pub fn get_config_file_paths() -> Vec<PathBuf> {
    vec![
        get_etc_override_config_file_path(),
        get_run_override_config_file_path(),
        get_usr_local_override_config_file_path(),
        get_default_config_file_path(),
    ]
}

/// Returns the file path of the configuration file override below /etc.
pub fn get_etc_override_config_file_path() -> PathBuf {
    PathBuf::from([ETC_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Returns the directory path of the configuration override directory below /etc.
pub fn get_etc_override_dir_path() -> PathBuf {
    PathBuf::from(ETC_OVERRIDE_CONFIG_DIR)
}

/// Returns the file path of the configuration file override below /run.
pub fn get_run_override_config_file_path() -> PathBuf {
    PathBuf::from([RUN_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Returns the directory path of the configuration override directory below /run.
pub fn get_run_override_dir_path() -> PathBuf {
    PathBuf::from(RUN_OVERRIDE_CONFIG_DIR)
}

/// Returns the file path of the configuration file override below /usr/local.
pub fn get_usr_local_override_config_file_path() -> PathBuf {
    PathBuf::from([USR_LOCAL_OVERRIDE_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Returns the directory path of the configuration override directory below /usr/local.
pub fn get_usr_local_override_dir_path() -> PathBuf {
    PathBuf::from(USR_LOCAL_OVERRIDE_CONFIG_DIR)
}

/// Returns the file path of the default configuration file /usr.
pub fn get_default_config_file_path() -> PathBuf {
    PathBuf::from([DEFAULT_CONFIG_DIR, CONFIG_FILE].concat())
}

/// Returns the directory path of the default configuration directory below /usr.
pub fn get_default_config_dir_path() -> PathBuf {
    PathBuf::from(DEFAULT_CONFIG_DIR)
}

/// Creates the default configuration directory below /usr.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_default_config_dir() -> Result<(), Error> {
    create_dir_all(get_default_config_dir_path()).map_err(|source| Error::CreateDirectory {
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
    create_dir_all(get_etc_override_dir_path()).map_err(|source| Error::CreateDirectory {
        dir: ETC_OVERRIDE_CONFIG_DIR.to_string(),
        source,
    })
}

/// Creates the configuration override dir below /run.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_run_override_config_dir() -> Result<(), Error> {
    create_dir_all(get_run_override_dir_path()).map_err(|source| Error::CreateDirectory {
        dir: RUN_OVERRIDE_CONFIG_DIR.to_string(),
        source,
    })
}

/// Creates the configuration override dir below /usr/local.
///
/// # Errors
///
/// Returns an error if the directory or one of its parents can not be created.
/// Refer to [`create_dir_all`] for further information on failure scenarios.
pub fn create_usr_local_override_config_dir() -> Result<(), Error> {
    create_dir_all(get_usr_local_override_dir_path()).map_err(|source| Error::CreateDirectory {
        dir: USR_LOCAL_OVERRIDE_CONFIG_DIR.to_string(),
        source,
    })
}
