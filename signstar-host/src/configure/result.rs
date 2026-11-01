//! The result of a Signstar host configuration operation.

use std::process::{ExitCode, Termination};

/// The possible result of a Signstar host configuration.
///
/// # Note
///
/// The variants of this enum are not considered run-time errors.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ConfigurationResult {
    /// The synchronization of the host's configuration with its system users and backends
    /// succeeded.
    SyncSucceeded,

    /// There is no configuration section for a particular type of HSM backend.
    MissingConfigurationForBackend,

    /// There are no connections available for a particular type of HSM backend.
    ///
    /// # Note
    ///
    /// This may indicate a transient network issue, or USB hardware failure.
    NoAvailableBackendConnection,

    /// There are provisioned backends, but no administrative credentials.
    ///
    /// # Note
    ///
    /// This likely indicates, that a backup and administrative credentials need to be provided to
    /// the system to restore from the backup.
    ProvisionedBackendsButNoAdminCreds,

    /// Not all connections of a particular type of HSM backend are present and there are no
    /// administrative credentials.
    ///
    /// # Note
    ///
    /// This may indicate a transient network issue, or USB hardware failure.
    /// Only with all configured connections available, the system can consider creating (new)
    /// administrative credentials.
    NotAllConnectionsAvailableAndNoAdminCreds,
}

impl Termination for ConfigurationResult {
    fn report(self) -> ExitCode {
        match self {
            Self::SyncSucceeded => ExitCode::SUCCESS,
            Self::MissingConfigurationForBackend => ExitCode::from(100),
            Self::NoAvailableBackendConnection => ExitCode::from(101),
            Self::ProvisionedBackendsButNoAdminCreds => ExitCode::from(102),
            Self::NotAllConnectionsAvailableAndNoAdminCreds => ExitCode::from(103),
        }
    }
}
