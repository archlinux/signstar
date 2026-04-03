//! Integration tests for [`signstar_config::admin_credentials`].

#[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
pub mod nethsm;
#[cfg(feature = "yubihsm2")]
pub mod yubihsm2;
