//! Functionality when support for all backends is compiled in.

use log::info;

use crate::{ConfigurationResult, Error, HostConfiguration};

impl<'config> HostConfiguration<'config> {
    /// Syncs the Signstar host with its configuration.
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - the syncing of NetHSM backends fails
    /// - the syncing of YubiHSM2 backends fails
    pub fn sync(&self) -> Result<ConfigurationResult, Error> {
        info!("Sync the Signstar host with its configuration.");

        let nethsm_config_result = self.sync_nethsm()?;
        let yubihsm_config_result = self.sync_yubihsm2()?;

        if matches!(
            nethsm_config_result,
            ConfigurationResult::MissingConfigurationForBackend
        ) && matches!(
            yubihsm_config_result,
            ConfigurationResult::MissingConfigurationForBackend
        ) {
            return Ok(ConfigurationResult::MissingConfigurationForBackend);
        }

        if !matches!(
            nethsm_config_result,
            ConfigurationResult::SyncSucceeded
                | ConfigurationResult::MissingConfigurationForBackend
        ) {
            return Ok(nethsm_config_result);
        }

        if !matches!(
            yubihsm_config_result,
            ConfigurationResult::SyncSucceeded
                | ConfigurationResult::MissingConfigurationForBackend
        ) {
            return Ok(yubihsm_config_result);
        }

        Ok(ConfigurationResult::SyncSucceeded)
    }
}
