//! HSM backend handling.

#[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
pub mod all_backends;
mod any;
#[cfg(feature = "nethsm")]
pub mod nethsm;
#[cfg(all(not(feature = "nethsm"), not(feature = "yubihsm2")))]
pub mod no_backend;
#[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
pub mod only_nethsm;
#[cfg(all(not(feature = "nethsm"), feature = "yubihsm2"))]
pub mod only_yubihsm2;
#[cfg(feature = "yubihsm2")]
pub mod yubihsm2;

pub use any::BackendSync;
