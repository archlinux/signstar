//! Configuration file handling for a NetHSM backend.

use nethsm_config::{ConfigSettings, HermeticParallelConfig};
use signstar_common::config::{get_config_file, get_config_file_paths};

/// The error that may occur when handling a configuration file for a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The Signstar configuration is missing.
    #[error("No configuration file found in {}.", get_config_file_paths().iter().map(|path| path.display().to_string()).collect::<Vec<String>>().join(", "))]
    ConfigMissing,

    /// An error specific to NetHsm config handling.
    #[error("NetHSM config error:\n{0}")]
    NetHsmConfig(#[from] nethsm_config::Error),
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
pub fn load_config() -> Result<HermeticParallelConfig, crate::Error> {
    let Some(config_path) = get_config_file() else {
        return Err(crate::Error::Config(Error::ConfigMissing));
    };

    HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            "signstar".to_string(),
            nethsm_config::ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(&config_path),
    )
    .map_err(|source| crate::Error::Config(Error::NetHsmConfig(source)))
}
