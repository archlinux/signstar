use std::{fmt::Display, str::FromStr};

use nethsm::{Credentials, Passphrase, UserId, UserRole};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Errors related to credentials
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A system username is invalid
    #[error("Invalid system user name: {0}")]
    InvalidSystemUserName(String),
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
