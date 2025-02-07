//! Configuration file handling for a NetHSM backend.

use nethsm_config::{ConfigSettings, HermeticParallelConfig};
use signstar_core::config::{get_config_file, get_config_locations};

/// The error that may occur when handling a configuration file for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A config issue.
    #[error("Config file issue: {0}")]
    Config(#[source] nethsm_config::Error),

    /// No configuration file can be found.
    #[error("No configuration file found in {}", get_config_locations())]
    ConfigMissing,
}

/// Loads a [`HermeticParallelConfig`].
///
/// Gets a configuration file from the default locations using [`get_config_file`] and returns it as
/// [`HermeticParallelConfig`].
///
/// # Errors
///
/// Returns an error if no config file is found or if the [`HermeticParallelConfig`] can not be
/// created.
pub fn load_config() -> Result<HermeticParallelConfig, Error> {
    let Some(config_path) = get_config_file() else {
        return Err(Error::ConfigMissing);
    };

    HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            "signstar".to_string(),
            nethsm_config::ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(&config_path),
    )
    .map_err(Error::Config)
}
