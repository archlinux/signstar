//! Error handling.

/// An error that can occur when using the common Signstar functionalities.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An administrative credentials error occurred.
    #[error(transparent)]
    AdminCredentials(#[from] crate::admin_credentials::Error),

    /// A config error occurred.
    #[error(transparent)]
    Config(#[from] crate::config::Error),

    /// A logging error occurred.
    #[cfg(feature = "logging")]
    #[error(transparent)]
    Logging(#[from] crate::logging::Error),
}
