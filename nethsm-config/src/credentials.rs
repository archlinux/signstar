use std::{collections::HashSet, fmt::Display, str::FromStr};

use nethsm::{Credentials, Passphrase, UserId, UserRole};
use serde::{Deserialize, Serialize};
use ssh_key::{authorized_keys::Entry, PublicKey};
use zeroize::Zeroize;

/// Errors related to credentials
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There is a duplicate SSH public key in a list of SSH authorized keys
    #[error("The SSH authorized key is used multiple times: {ssh_authorized_key}")]
    DuplicateAuthorizedKeys {
        ssh_authorized_key: AuthorizedKeyEntry,
    },

    /// A system username is invalid
    #[error("Invalid system user name: {0}")]
    InvalidSystemUserName(String),

    /// There are no SSH authorized keys
    #[error("The SSH authorized key is not valid: {entry}")]
    InvalidAuthorizedKeyEntry { entry: String },

    /// There are no SSH authorized keys
    #[error("No SSH authorized key provided!")]
    NoAuthorizedKeys,

    /// An SSH key error
    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),
}

/// A set of credentials for a [`NetHsm`][`nethsm::NetHsm`]
///
/// Tracks the [`UserRole`], [`UserId`] and optionally the passphrase of the user.
#[derive(Clone, Debug, Deserialize, Hash, PartialEq, Eq, Serialize, Zeroize)]
pub struct ConfigCredentials {
    #[zeroize(skip)]
    role: UserRole,
    #[zeroize(skip)]
    name: UserId,
    passphrase: Option<String>,
}

impl ConfigCredentials {
    /// Creates a new [`ConfigCredentials`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserRole;
    /// use nethsm_config::{ConfigCredentials, ConfigInteractivity};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // credentials for an Operator user with passphrase
    /// ConfigCredentials::new(
    ///     UserRole::Operator,
    ///     "user1".parse()?,
    ///     Some("my-passphrase".into()),
    /// );
    ///
    /// // credentials for an Administrator user without passphrase
    /// ConfigCredentials::new(UserRole::Administrator, "admin1".parse()?, None);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(role: UserRole, name: UserId, passphrase: Option<String>) -> Self {
        Self {
            role,
            name,
            passphrase,
        }
    }

    /// Returns the name (a [`UserId`])
    pub fn get_name(&self) -> UserId {
        self.name.clone()
    }

    /// Returns the role (a [`UserRole`])
    pub fn get_role(&self) -> UserRole {
        self.role
    }

    /// Returns the passphrase of the [`ConfigCredentials`]
    pub fn get_passphrase(&self) -> Option<&str> {
        self.passphrase.as_deref()
    }

    /// Sets the passphrase of the [`ConfigCredentials`]
    pub fn set_passphrase(&mut self, passphrase: String) {
        self.passphrase = Some(passphrase)
    }

    /// Returns whether a passphrase is set for the [`ConfigCredentials`]
    pub fn has_passphrase(&self) -> bool {
        self.passphrase.is_some()
    }
}

impl From<ConfigCredentials> for Credentials {
    fn from(value: ConfigCredentials) -> Self {
        Self::new(value.name, value.passphrase.map(Passphrase::new))
    }
}

/// The name of a user on a Unix system
///
/// The username may only contain characters in the set of alphanumeric characters and the `'_'`
/// character.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize, Zeroize)]
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
    /// use nethsm_config::SystemUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// SystemUserId::new("user1".to_string())?;
    /// SystemUserId::new("User_1".to_string())?;
    /// assert!(SystemUserId::new("?ser-1".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user: String) -> Result<Self, Error> {
        if user.is_empty()
            || !(user
                .chars()
                .all(|char| char.is_alphanumeric() || char == '_' || char == '-'))
        {
            return Err(Error::InvalidSystemUserName(user));
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
        value.to_string()
    }
}

impl FromStr for SystemUserId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl TryFrom<String> for SystemUserId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// An entry of an authorized_keys file
///
/// This type ensures compliance with SSH's [AuhtorizedKeysFile] format.
///
/// [AuhtorizedKeysFile]: https://man.archlinux.org/man/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize, Zeroize)]
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
    /// use nethsm_config::AuthorizedKeyEntry;
    ///
    /// # fn main() -> testresult::TestResult {
    /// AuthorizedKeyEntry::new("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".to_string())?;
    ///
    /// // this fails because the empty string is not a valid AuthorizedKeyEntry
    /// assert!(AuthorizedKeyEntry::new("".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(entry: String) -> Result<Self, Error> {
        if Entry::from_str(&entry).is_err() {
            return Err(Error::InvalidAuthorizedKeyEntry { entry });
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
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl TryFrom<&AuthorizedKeyEntry> for Entry {
    type Error = Error;

    fn try_from(value: &AuthorizedKeyEntry) -> Result<Self, Error> {
        Entry::from_str(&value.0).map_err(Error::SshKey)
    }
}

impl TryFrom<String> for AuthorizedKeyEntry {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Error> {
        Self::new(value)
    }
}

/// A list of [`AuthorizedKeyEntry`]s
///
/// The list is guaranteed to contain at least one item and be unique (no duplicate SSH public key
/// can exist).
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
#[serde(into = "Vec<String>", try_from = "Vec<String>")]
pub struct AuthorizedKeyEntryList(Vec<AuthorizedKeyEntry>);

impl AuthorizedKeyEntryList {
    /// Creates a new [`AuthorizedKeyEntryList`]
    ///
    /// # Errors
    ///
    /// Returns an error, if a duplicate SSH public key exists in the provided list of
    /// [`AuthorizedKeyEntry`] objects or if the list is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::AuthorizedKeyEntryList;
    ///
    /// # fn main() -> testresult::TestResult {
    /// AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINP4nWGVLC7kq4EdwgnJTXCjN0l32GL9ZxII6mx9uGqV user@host".parse()?])?;
    ///
    /// // this fails because the AuthorizedKeyEntry are duplicates
    /// assert!(AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?]).is_err());
    ///
    /// // this fails because there are no SSH authorized keys
    /// assert!(AuthorizedKeyEntryList::new(vec![]).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(ssh_authorized_keys: Vec<AuthorizedKeyEntry>) -> Result<Self, Error> {
        if ssh_authorized_keys.is_empty() {
            return Err(Error::NoAuthorizedKeys);
        }

        let mut set = HashSet::new();
        for (ssh_authorized_key, pub_key) in ssh_authorized_keys
            .iter()
            .filter_map(|ssh_authorized_key| {
                if let Ok(entry) = Entry::try_from(ssh_authorized_key) {
                    Some((ssh_authorized_key.clone(), entry.public_key().clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<(AuthorizedKeyEntry, PublicKey)>>()
        {
            if !set.insert(pub_key) {
                return Err(Error::DuplicateAuthorizedKeys { ssh_authorized_key });
            }
        }

        Ok(Self(ssh_authorized_keys))
    }
}

impl AsRef<[AuthorizedKeyEntry]> for AuthorizedKeyEntryList {
    fn as_ref(&self) -> &[AuthorizedKeyEntry] {
        &self.0
    }
}

impl From<AuthorizedKeyEntryList> for Vec<String> {
    fn from(value: AuthorizedKeyEntryList) -> Self {
        value
            .0
            .iter()
            .map(|authorized_key| authorized_key.to_string())
            .collect()
    }
}

impl From<&AuthorizedKeyEntryList> for Vec<AuthorizedKeyEntry> {
    fn from(value: &AuthorizedKeyEntryList) -> Self {
        value.0.to_vec()
    }
}

impl TryFrom<Vec<String>> for AuthorizedKeyEntryList {
    type Error = Error;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let authorized_keys = {
            let mut authorized_keys: Vec<AuthorizedKeyEntry> = vec![];
            for authorized_key in value {
                authorized_keys.push(AuthorizedKeyEntry::new(authorized_key)?)
            }
            authorized_keys
        };

        Self::new(authorized_keys)
    }
}
