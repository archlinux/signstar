//! Credentials handling for [`SignstarConfig`].

use std::{fmt::Display, str::FromStr};

use nethsm::UserId;
use serde::{Deserialize, Serialize};
use ssh_key::authorized_keys::Entry;
use zeroize::Zeroize;

use crate::ConfigError;
#[cfg(doc)]
use crate::SignstarConfig;

/// The name of a user on a Unix system
///
/// The username may only contain characters in the set of alphanumeric ASCII characters and the
/// `-`, or `_` character.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Zeroize)]
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
    /// use signstar_config::SystemUserId;
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
            return Err(ConfigError::InvalidSystemUserName { name: user }.into());
        }
        Ok(Self(user))
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

/// An entry of an authorized_keys file
///
/// This type ensures compliance with SSH's [AuhtorizedKeysFile] format.
///
/// [AuhtorizedKeysFile]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Zeroize)]
#[serde(into = "String", try_from = "String")]
pub struct AuthorizedKeyEntry(String);

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
    /// use signstar_config::AuthorizedKeyEntry;
    ///
    /// # fn main() -> testresult::TestResult {
    /// AuthorizedKeyEntry::new("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".to_string())?;
    ///
    /// // this fails because the empty string is not a valid AuthorizedKeyEntry
    /// assert!(AuthorizedKeyEntry::new("".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(entry: String) -> Result<Self, crate::Error> {
        if Entry::from_str(&entry).is_err() {
            return Err(ConfigError::InvalidAuthorizedKeyEntry { entry }.into());
        }

        Ok(Self(entry))
    }
}

impl AsRef<str> for AuthorizedKeyEntry {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for AuthorizedKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
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

impl TryFrom<&AuthorizedKeyEntry> for Entry {
    type Error = crate::Error;

    fn try_from(value: &AuthorizedKeyEntry) -> Result<Self, crate::Error> {
        Entry::from_str(&value.0)
            .map_err(|source| crate::Error::Config(ConfigError::SshKey(source)))
    }
}

impl TryFrom<String> for AuthorizedKeyEntry {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, crate::Error> {
        Self::new(value)
    }
}

/// A guaranteed to be system-wide [`NetHsm`][`nethsm::NetHsm`] user
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct SystemWideUserId(UserId);

impl SystemWideUserId {
    /// Creates a new [`SystemWideUserId`] from an owned string
    ///
    /// # Errors
    ///
    /// Returns an error, if the provided `user_id` contains a namespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::SystemWideUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// SystemWideUserId::new("user1".to_string())?;
    ///
    /// // this fails because the User ID contains a namespace
    /// assert!(SystemWideUserId::new("ns1~user1".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_id: String) -> Result<Self, crate::Error> {
        let user_id = UserId::new(user_id)
            .map_err(|source| crate::Error::Config(ConfigError::User(source)))?;
        if user_id.is_namespaced() {
            return Err(ConfigError::SystemWideUserIdWithNamespace(user_id).into());
        }
        Ok(Self(user_id))
    }
}

impl Display for SystemWideUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SystemWideUserId {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl From<SystemWideUserId> for String {
    fn from(value: SystemWideUserId) -> Self {
        value.to_string()
    }
}

impl From<SystemWideUserId> for UserId {
    fn from(value: SystemWideUserId) -> Self {
        value.0
    }
}

impl TryFrom<String> for SystemWideUserId {
    type Error = crate::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
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
    fn authorized_key_as_ref() -> TestResult {
        let entry = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host";
        let authorized_key = AuthorizedKeyEntry::new(entry.to_string())?;

        assert_eq!(authorized_key.as_ref(), entry);
        Ok(())
    }

    #[test]
    fn system_wide_user_id_new_fails() -> TestResult {
        assert!(SystemWideUserId::new("ns1~test".to_string()).is_err());
        Ok(())
    }

    #[test]
    fn system_wide_user_id_from_str() -> TestResult {
        assert!(SystemWideUserId::from_str("ns1~test").is_err());
        assert!(SystemWideUserId::from_str("test").is_ok());
        Ok(())
    }
}
