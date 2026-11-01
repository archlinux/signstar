//! Error handling for signing operations on a Signstar host.

/// An error that may occur when signing with a Signstar host.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
    /// No HSM backend support is compiled in.
    #[error("No HSM backend support compiled in")]
    NoBackend,

    /// The configuration offers no connection for a backend.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No connection set for the backend")]
    NoConnection,

    /// No credentials found for current system user.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No credentials for the system user")]
    NoCredentials,

    /// Parameters of the signing request are unsupported.
    #[error("Unsupported signing request parameters")]
    UnsupportedParameters,

    /// Parameters of the signing setup are unsupported.
    #[error("Unsupported signer setup")]
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    UnsupportedSignerSetup,
}
