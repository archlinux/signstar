//! Impls for [`UserBackendConnection`], [`Config`] and [`ConfigBuilder`] when using no HSM
//! backends.
//!
//! # Note
//!
//! This module with `impl` blocks is only used, if _none_ of the HSM backend features are used:
//!
//! - `nethsm`: for NetHSM backends
//! - `yubihsm2`: for YubiHSM2 backends

use crate::config::{Config, ConfigBuilder, SystemConfig};

impl ConfigBuilder {
    /// Creates a new [`ConfigBuilder`].
    pub fn new(system: SystemConfig) -> Self {
        Self(Config { system })
    }
}
