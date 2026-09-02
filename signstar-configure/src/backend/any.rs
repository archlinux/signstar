//! Basic functionality for any or no backend.

use signstar_config::config::Config;

/// Generic backend sync.
#[derive(Debug)]
pub struct BackendSync<'config> {
    /// The Signstar configuration.
    config: &'config Config,
}

impl<'config> BackendSync<'config> {
    /// Creates a new [`BackendSync`] from a [`Config`].
    pub fn new(config: &'config Config) -> Self {
        Self { config }
    }

    /// Returns a reference to the [`Config`].
    pub fn config(&self) -> &Config {
        self.config
    }
}
