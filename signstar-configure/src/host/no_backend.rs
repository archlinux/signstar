//! Functionality when no support for a backend is compiled in.

use log::{info, warn};

use crate::{ConfigurationResult, Error, HostConfiguration};

impl<'config> HostConfiguration<'config> {
    /// Syncs the Signstar host with its configuration.
    ///
    /// # Note
    ///
    /// This is a no-op, as no backend support is compiled in.
    pub fn sync(&self) -> Result<ConfigurationResult, Error> {
        info!("Sync the Signstar host with its configuration.");
        warn!("No backend support compiled in. Skipping...");

        Ok(ConfigurationResult::MissingConfigurationForBackend)
    }
}
