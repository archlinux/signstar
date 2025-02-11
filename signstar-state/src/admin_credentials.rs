//! Handles loading of administrative credentials.

/// The error that may occur when handling administrative credentials.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Loading administrative credentials file failed.
    #[error("Loading administrative credentials failed:\n{0}")]
    LoadAdminCreds(#[source] signstar_config::admin_credentials::Error),

    /// Storing administrative credentials file failed.
    #[error("Storing administrative credentials failed:\n{0}")]
    StoreAdminCreds(#[source] signstar_config::admin_credentials::Error),
}
