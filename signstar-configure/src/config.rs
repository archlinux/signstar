//! Configuration handling.

use signstar_config::config::Config;

use crate::Error;

/// Loads the Signstar configuration from the default system paths.
///
/// # Errors
///
/// Returns an error, if [`Config::from_system_path`] fails.
pub fn load_config() -> Result<Config, Error> {
    Config::from_system_path().map_err(Error::SignstarConfig)
}
