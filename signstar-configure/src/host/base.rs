//! Basic functionality for any or no backend.

use signstar_config::config::Config;

/// Signstar host configuration.
///
/// Manages the synchronization of HSM backends with the Signstar configuration, as well as the
/// configuration of non-administrative users and their credentials for their respective backends.
#[derive(Debug)]
pub struct HostConfiguration<'config> {
    /// The Signstar configuration.
    config: &'config Config,
}

impl<'config> HostConfiguration<'config> {
    /// Creates a new [`HostConfiguration`] from a [`Config`].
    pub fn new(config: &'config Config) -> Self {
        Self { config }
    }

    /// Returns a reference to the [`Config`].
    pub fn config(&self) -> &Config {
        self.config
    }
}
