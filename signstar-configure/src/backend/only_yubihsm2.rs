//! Functionality when only support for YubiHSM2 is compiled in.
use log::info;

use crate::{BackendSync, Error};

impl<'config> BackendSync<'config> {
    /// Syncs the backend.
    ///
    /// # Errors
    ///
    /// Returns an error, if the syncing of YubiHSM2 backends fails.
    pub fn sync(&self) -> Result<(), Error> {
        info!("Syncing all available backends.");
        self.sync_yubihsm2()?;

        Ok(())
    }
}
