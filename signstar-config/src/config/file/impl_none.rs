//! Impls for [`UserBackendConnection`], [`Config`] and [`ConfigBuilder`] when using no HSM
//! backends.
//!
//! # Note
//!
//! This module with `impl` blocks is only used, if _none_ of the HSM backend features are used:
//!
//! - `nethsm`: for NetHSM backends
//! - `yubihsm2`: for YubiHSM2 backends

use std::collections::HashSet;

use crate::config::{
    AuthorizedKeyEntry,
    Config,
    ConfigAuthorizedKeyEntries,
    ConfigBuilder,
    ConfigSystemUserIds,
    SystemConfig,
    SystemUserId,
};

impl ConfigAuthorizedKeyEntries for Config {
    fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry> {
        self.system.authorized_key_entries()
    }
}

impl ConfigSystemUserIds for Config {
    fn system_user_ids(&self) -> HashSet<&SystemUserId> {
        self.system.system_user_ids()
    }
}

impl ConfigBuilder {
    /// Creates a new [`ConfigBuilder`].
    pub fn new(system: SystemConfig) -> Self {
        Self(Config { system })
    }
}
