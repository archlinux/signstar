//! Error handling.

/// An error that may occur when using Signstar hosts.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error occurred while configuring a Signstar host.
    #[error("Signstar host configure error: {0}")]
    Configure(#[from] crate::configure::Error),

    /// An error occurred while configuring a Signstar host during image build.
    #[error("Signstar host configure build error: {0}")]
    ConfigureBuild(#[from] crate::configure_build::Error),

    /// An error occurred while making key certificates available for download on a Signstar host.
    #[error("Signstar download key certificates error: {0}")]
    DownloadKeyCertificates(#[from] crate::download_key_certificates::Error),

    /// A JSON serialization error occurred.
    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    /// A [`nethsm::Error`] occurred.
    #[cfg(feature = "nethsm")]
    #[error("NetHsm error")]
    NetHsm(#[from] nethsm::Error),

    /// A [`std::num::ParseIntError`] occurred.
    #[cfg(feature = "yubihsm2")]
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),

    /// An error occurred while signing with a Signstar host.
    #[error("Signstar host signing error: {0}")]
    Sign(#[from] crate::sign::Error),

    /// A [`signstar_common::Error`] occurred.
    #[error("Signstar common error: {0}")]
    SignstarCommon(#[from] signstar_common::Error),

    /// A [`signstar_config::Error`] occurred.
    #[error(transparent)]
    SignstarConfig(#[from] Box<signstar_config::Error>),

    /// A [`signstar_crypto::Error`] occurred.
    #[error(transparent)]
    SignstarCrypto(#[from] signstar_crypto::Error),

    /// A [`signstar_yubihsm2::Error`] occurred.
    #[cfg(feature = "yubihsm2")]
    #[error(transparent)]
    SignstarYubiHsm2(#[from] signstar_yubihsm2::Error),
}
