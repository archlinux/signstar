//! Utilities used for test setups.

pub const SIGNSTAR_CONFIG_PLAINTEXT: &[u8] =
    include_bytes!("../fixtures/signstar-config-plaintext.toml");
pub const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");
#[cfg(feature = "yubihsm2")]
pub const SIGNSTAR_CONFIG_YUBI: &[u8] =
    include_bytes!("../fixtures/yubihsm2/signstar-config-plaintext.toml");
