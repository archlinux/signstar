//! Functionality when no support for a backend is compiled in.

use log::info;

use crate::{BackendSync, Error};

impl<'config> BackendSync<'config> {
    /// Syncs all backends.
    ///
    /// # Note
    ///
    /// This is a no-op, as no backend support is compiled in.
    pub fn sync(&self) -> Result<(), Error> {
        info!("There is no backend.");
        Ok(())
    }
}
