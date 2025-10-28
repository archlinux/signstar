//! Integration tests for [`signstar_config::admin_credentials`].

pub mod nethsm;
#[cfg(feature = "yubihsm2")]
pub mod yubihsm2;
