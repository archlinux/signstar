//! Functionality when only support for NetHSM is compiled in.
use log::info;

use crate::{BackendSync, Error};

impl<'config> BackendSync<'config> {
    /// Syncs the backend.
    ///
    /// # Errors
    ///
    /// Returns an error, if the syncing of NetHSM backends fails.
    pub fn sync(&self) -> Result<(), Error> {
        info!("Syncing all available backends.");
        self.sync_nethsm()?;

        Ok(())
    }
}
