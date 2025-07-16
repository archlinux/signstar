//! Utilities for configuration file handling on _Signstar hosts_.

use signstar_common::config::get_config_file;

use crate::{ConfigError, Error, SignstarConfig};

/// Loads a [`SignstarConfig`].
///
/// Gets a configuration file from the default locations using [`get_config_file`] and returns it as
/// [`SignstarConfig`].
///
/// # Errors
///
/// Returns an error if no config file is found or if the [`SignstarConfig`] can not be
/// created.
pub fn load_config() -> Result<SignstarConfig, Error> {
    let Some(config_path) = get_config_file() else {
        return Err(Error::Config(ConfigError::ConfigIsMissing));
    };

    SignstarConfig::new_from_file(Some(&config_path))
}
