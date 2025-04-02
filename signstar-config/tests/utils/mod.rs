//! Utilities used for test setups.

/// Plaintext configuration
pub const SIGNSTAR_CONFIG_PLAINTEXT: &[u8] =
    include_bytes!("../fixtures/signstar-config-plaintext.toml");

/// Full configuration
pub const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");

/// Simple configuration
pub const SIGNSTAR_ADMIN_CREDS_SIMPLE: &[u8] =
    include_bytes!("../fixtures/admin-creds-simple.toml");
