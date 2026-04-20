//! Credentials handling for Signstar configuration.

use std::{fmt::Display, path::PathBuf, str::FromStr};

use nix::unistd::User;
use serde::{Deserialize, Serialize};
use ssh_key::authorized_keys::Entry;
use zeroize::Zeroize;

use crate::{config::Error, utils::get_current_system_user};

/// The name of a user on a Unix system
///
/// The username may only contain characters in the set of alphanumeric ASCII characters and the
/// `-`, or `_` character.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Zeroize)]
#[serde(into = "String", try_from = "String")]
pub struct SystemUserId(String);

impl SystemUserId {
    /// Creates a new [`SystemUserId`]
    ///
    /// # Errors
    ///
    /// Returns an error if `user` contains chars other than alphanumeric ones, `-`, or `_`.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::config::SystemUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// SystemUserId::new("user1".to_string())?;
    /// SystemUserId::new("User_1".to_string())?;
    /// assert!(SystemUserId::new("?ser-1".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user: String) -> Result<Self, crate::Error> {
        if user.is_empty()
            || !(user
                .chars()
                .all(|char| char.is_ascii_alphanumeric() || char == '_' || char == '-'))
        {
            return Err(Error::InvalidSystemUserName { name: user }.into());
        }
        Ok(Self(user))
    }

    /// Creates a new [`SystemUserId`] from the currently calling Unix user.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the currently calling Unix user cannot be determined
    /// - the String representation of the currently calling Unix user cannot be used to create a
    ///   new [`SystemUserId`]
    pub fn from_current_unix_user() -> Result<Self, crate::Error> {
        let current_unix_user = get_current_system_user()?;
        Self::try_from(current_unix_user)
    }
}

impl AsRef<str> for SystemUserId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for SystemUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<SystemUserId> for String {
    fn from(value: SystemUserId) -> Self {
        value.0
    }
}

impl FromStr for SystemUserId {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl TryFrom<String> for SystemUserId {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<User> for SystemUserId {
    type Error = crate::Error;

    fn try_from(value: User) -> Result<Self, Self::Error> {
        Self::new(value.name)
    }
}

/// An entry of an authorized_keys file
///
/// This type ensures compliance with SSH's [AuhtorizedKeysFile] format.
///
/// [AuhtorizedKeysFile]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct AuthorizedKeyEntry(Entry);

impl AuthorizedKeyEntry {
    /// Creates a new [`AuthorizedKeyEntry`]
    ///
    /// # Errors
    ///
    /// Returns an error, if `data` can not be converted to an
    /// [`ssh_key::authorized_keys::Entry`].
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::config::AuthorizedKeyEntry;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let auth_key = AuthorizedKeyEntry::new("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".to_string())?;
    /// assert_eq!("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host", auth_key.to_string());
    ///
    /// // this fails because the empty string is not a valid AuthorizedKeyEntry
    /// assert!(AuthorizedKeyEntry::new("".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(entry: String) -> Result<Self, crate::Error> {
        Ok(Self(Entry::from_str(&entry).map_err(|_source| {
            Error::InvalidAuthorizedKeyEntry { entry }
        })?))
    }
}

impl AsRef<Entry> for AuthorizedKeyEntry {
    fn as_ref(&self) -> &Entry {
        &self.0
    }
}

impl Display for AuthorizedKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.to_string())
    }
}

impl From<AuthorizedKeyEntry> for String {
    fn from(value: AuthorizedKeyEntry) -> Self {
        value.to_string()
    }
}

impl FromStr for AuthorizedKeyEntry {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl From<&AuthorizedKeyEntry> for Entry {
    fn from(value: &AuthorizedKeyEntry) -> Self {
        value.0.clone()
    }
}

impl TryFrom<String> for AuthorizedKeyEntry {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, crate::Error> {
        Self::new(value)
    }
}

impl std::hash::Hash for AuthorizedKeyEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_string().hash(state);
    }
}

impl Ord for AuthorizedKeyEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.to_string().cmp(&other.0.to_string())
    }
}

impl PartialOrd for AuthorizedKeyEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// The available data on system users on a Signstar host or its configuration.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SystemUserData<'a> {
    /// The system user is used to do administrative tasks on a Signstar backend.
    ///
    /// # Note
    ///
    /// This user must not be setup for remote login.
    BackendAdmin {
        /// The system user.
        system_user: SystemUserId,
    },

    /// The system user is used to handle backup tasks for a Signstar backend.
    BackendBackup {
        /// The system user.
        system_user: &'a SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_key: &'a AuthorizedKeyEntry,
    },

    /// The system user is used to deal with the metrics of a Signstar backend.
    ///
    /// # Note
    ///
    /// This user must not be setup for remote login.
    BackendHermeticMetrics {
        /// The system user.
        system_user: &'a SystemUserId,
    },

    /// The system user is used to deal with the metrics of a Signstar backend.
    BackendMetrics {
        /// The system user.
        system_user: &'a SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_key: &'a AuthorizedKeyEntry,
    },

    /// The system user is used for signing operations with a Signstar backend.
    BackendSign {
        /// The system user.
        system_user: &'a SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_key: &'a AuthorizedKeyEntry,
    },

    /// The system user is used for the upload of Signstar backend firmware updates.
    BackendUpdate {
        /// The system user.
        system_user: &'a SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_key: &'a AuthorizedKeyEntry,
    },

    /// The system user is used to download network config data.
    HostDownloadNetworkConfig {
        /// The system user.
        system_user: &'a SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_key: &'a AuthorizedKeyEntry,
    },

    /// The system user is used to handle shares of a shared secret.
    HostShareholder {
        /// The system user.
        system_user: &'a SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_key: &'a AuthorizedKeyEntry,
    },

    /// It is not known what the system user is used for.
    ///
    /// # Note
    ///
    /// This variant is commonly used for all system user information derived from a host.
    Unknown {
        /// The system user.
        system_user: SystemUserId,
        /// The SSH authorized key for `system_user`.
        ssh_authorized_keys: Vec<AuthorizedKeyEntry>,
        /// The home directory of `system_user`.
        home_dir: PathBuf,
    },
}

impl<'a> SystemUserData<'a> {
    /// Returns a reference to the tracked [`SystemUserId`].
    pub fn system_user(&'a self) -> &'a SystemUserId {
        match self {
            Self::BackendAdmin { system_user } | Self::Unknown { system_user, .. } => system_user,
            Self::BackendBackup { system_user, .. }
            | Self::BackendHermeticMetrics { system_user }
            | Self::BackendMetrics { system_user, .. }
            | Self::BackendSign { system_user, .. }
            | Self::BackendUpdate { system_user, .. }
            | Self::HostDownloadNetworkConfig { system_user, .. }
            | Self::HostShareholder { system_user, .. } => system_user,
        }
    }

    /// Returns a list of references to tracked [`AuthorizedKeyEntry`].
    pub fn ssh_authorized_keys(&'a self) -> Vec<&'a AuthorizedKeyEntry> {
        match self {
            Self::BackendAdmin { .. } | Self::BackendHermeticMetrics { .. } => Vec::new(),
            Self::BackendBackup {
                ssh_authorized_key, ..
            }
            | Self::BackendMetrics {
                ssh_authorized_key, ..
            }
            | Self::BackendSign {
                ssh_authorized_key, ..
            }
            | Self::HostDownloadNetworkConfig {
                ssh_authorized_key, ..
            }
            | Self::HostShareholder {
                ssh_authorized_key, ..
            }
            | Self::BackendUpdate {
                ssh_authorized_key, ..
            } => vec![ssh_authorized_key],
            Self::Unknown {
                ssh_authorized_keys,
                ..
            } => ssh_authorized_keys.iter().collect::<Vec<_>>(),
        }
    }
}

impl<'a> Display for SystemUserData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "system user {} ", self.system_user())?;
        let ssh_authorized_keys = self.ssh_authorized_keys();
        if let Self::Unknown { home_dir, .. } = self {
            write!(f, "in home dir {home_dir:?} ")?;
        }
        if !ssh_authorized_keys.is_empty() {
            write!(
                f,
                "with ssh keys {} ",
                ssh_authorized_keys
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )?;
        }

        write!(
            f,
            "{}",
            match self {
                Self::BackendAdmin { .. } => "for backend administration",
                Self::BackendBackup { .. } => "for backend backups",
                Self::BackendHermeticMetrics { .. } => "for hermetic backend metrics",
                Self::BackendMetrics { .. } => "for backend metrics",
                Self::BackendSign { .. } => "for signing using a backend",
                Self::BackendUpdate { .. } => "for backend updates",
                Self::HostDownloadNetworkConfig { .. } => "for downloading host network config",
                Self::HostShareholder { .. } => "for handling shares of a shared secret",
                Self::Unknown { .. } => "for unknown use",
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn system_user_id_new_fails() {
        assert!(SystemUserId::new("üser".to_string()).is_err());
    }

    #[test]
    fn authorized_key_entry_new_fails() {
        assert!(AuthorizedKeyEntry::new("foo".to_string()).is_err());
    }

    #[test]
    fn authorized_key_to_string() -> TestResult {
        let entry = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host";
        let authorized_key = AuthorizedKeyEntry::new(entry.to_string())?;

        assert_eq!(authorized_key.to_string(), entry);
        Ok(())
    }

    #[rstest]
    #[case::backend_admin(SystemUserData::BackendAdmin{system_user: SystemUserId::new("root".to_string())?}, SystemUserId::new("root".to_string())?)]
    #[case::backend_backup(SystemUserData::BackendBackup { system_user: &SystemUserId::new("backup".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, SystemUserId::new("backup".to_string())?)]
    #[case::backend_hermetic_metrics(SystemUserData::BackendHermeticMetrics { system_user: &SystemUserId::new("hermetic-metrics".to_string())?}, SystemUserId::new("hermetic-metrics".to_string())?)]
    #[case::backend_metrics(SystemUserData::BackendMetrics { system_user: &SystemUserId::new("metrics".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, SystemUserId::new("metrics".to_string())?)]
    #[case::backend_sign(SystemUserData::BackendSign { system_user: &SystemUserId::new("sign".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, SystemUserId::new("sign".to_string())?)]
    #[case::backend_update(SystemUserData::BackendUpdate { system_user: &SystemUserId::new("update".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, SystemUserId::new("update".to_string())?)]
    #[case::host_download_network_config(SystemUserData::HostDownloadNetworkConfig { system_user: &SystemUserId::new("network-download".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, SystemUserId::new("network-download".to_string())?)]
    #[case::host_shareholder(SystemUserData::HostShareholder { system_user: &SystemUserId::new("shareholder".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, SystemUserId::new("shareholder".to_string())?)]
    #[case::unknown(SystemUserData::Unknown { system_user: SystemUserId::new("someone".to_string())?, ssh_authorized_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?], home_dir: PathBuf::from("/home/someone") }, SystemUserId::new("someone".to_string())?)]
    fn system_user_data_system_user<'a>(
        #[case] system_user_data: SystemUserData<'a>,
        #[case] system_user: SystemUserId,
    ) -> TestResult {
        assert_eq!(system_user_data.system_user(), &system_user);
        Ok(())
    }

    #[rstest]
    #[case::backend_admin(SystemUserData::BackendAdmin{system_user: SystemUserId::new("root".to_string())?}, Vec::new())]
    #[case::backend_backup(SystemUserData::BackendBackup { system_user: &SystemUserId::new("backup".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    #[case::backend_hermetic_metrics(SystemUserData::BackendHermeticMetrics { system_user: &SystemUserId::new("hermetic-metrics".to_string())?}, Vec::new())]
    #[case::backend_metrics(SystemUserData::BackendMetrics { system_user: &SystemUserId::new("metrics".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    #[case::backend_sign(SystemUserData::BackendSign { system_user: &SystemUserId::new("sign".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    #[case::backend_update(SystemUserData::BackendUpdate { system_user: &SystemUserId::new("update".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    #[case::host_download_network_config(SystemUserData::HostDownloadNetworkConfig { system_user: &SystemUserId::new("network-download".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    #[case::host_shareholder(SystemUserData::HostShareholder { system_user: &SystemUserId::new("shareholder".to_string())?, ssh_authorized_key: &"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()? }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    #[case::unknown(SystemUserData::Unknown { system_user: SystemUserId::new("someone".to_string())?, ssh_authorized_keys: vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?], home_dir: PathBuf::from("/home/someone") }, vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?])]
    fn system_user_data_ssh_authorized_keys<'a>(
        #[case] system_user_data: SystemUserData<'a>,
        #[case] ssh_authorized_keys: Vec<AuthorizedKeyEntry>,
    ) -> TestResult {
        assert_eq!(
            system_user_data.ssh_authorized_keys(),
            ssh_authorized_keys.iter().collect::<Vec<_>>()
        );
        Ok(())
    }
}
