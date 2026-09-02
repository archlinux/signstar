//! Functionality when only support for YubiHSM2 is compiled in.
use log::info;

use crate::{ConfigurationResult, Error, HostConfiguration};

impl<'config> HostConfiguration<'config> {
    /// Syncs the Signstar host with its configuration.
    ///
    /// # Errors
    ///
    /// Returns an error, if the syncing of YubiHSM2 backends fails.
    pub fn sync(&self) -> Result<ConfigurationResult, Error> {
        info!("Sync the Signstar host with its configuration.");
        self.sync_yubihsm2()
    }
}
