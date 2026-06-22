use nethsm::{Credentials, Passphrase, UserId, UserRole};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// A set of credentials for a [`NetHsm`][`nethsm::NetHsm`]
///
/// Tracks the [`UserRole`], [`UserId`] and optionally the passphrase of the user.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize, Zeroize)]
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
