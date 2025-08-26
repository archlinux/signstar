//! Administrative credentials for [`NetHsm`] backends.

use nethsm::{FullCredentials, Passphrase};
#[cfg(doc)]
use nethsm::{NetHsm, UserId};
use serde::{Deserialize, Serialize};

use crate::{AdminCredentials, admin_credentials::Error};

/// Administrative credentials.
///
/// Tracks the following credentials and passphrases:
/// - the backup passphrase of the backend,
/// - the unlock passphrase of the backend,
/// - the top-level administrator credentials of the backend,
/// - the namespace administrator credentials of the backend.
///
/// # Note
///
/// The unlock and backup passphrase must be at least 10 characters long.
/// The passphrases of top-level and namespace administrator accounts must be at least 10 characters
/// long.
/// The list of top-level administrator credentials must include an account with the username
/// "admin".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct NetHsmAdminCredentials {
    iteration: u32,
    backup_passphrase: Passphrase,
    unlock_passphrase: Passphrase,
    administrators: Vec<FullCredentials>,
    namespace_administrators: Vec<FullCredentials>,
}

impl NetHsmAdminCredentials {
    /// Creates a new [`NetHsmAdminCredentials`] instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::FullCredentials;
    /// use signstar_config::NetHsmAdminCredentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = NetHsmAdminCredentials::new(
    ///     1,
    ///     "backup-passphrase".parse()?,
    ///     "unlock-passphrase".parse()?,
    ///     vec![FullCredentials::new(
    ///         "admin".parse()?,
    ///         "admin-passphrase".parse()?,
    ///     )],
    ///     vec![FullCredentials::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".parse()?,
    ///     )],
    /// )?;
    /// # // the backup passphrase is too short
    /// # assert!(NetHsmAdminCredentials::new(
    /// #     1,
    /// #     "short".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("admin".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // the unlock passphrase is too short
    /// # assert!(NetHsmAdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "short".parse()?,
    /// #     vec![FullCredentials::new("admin".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // there is no top-level administrator
    /// # assert!(NetHsmAdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     Vec::new(),
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // there is no default top-level administrator
    /// # assert!(NetHsmAdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("some".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // a top-level administrator passphrase is too short
    /// # assert!(NetHsmAdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("admin".parse()?, "short".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "ns1-admin-passphrase".parse()?,
    /// #     )],
    /// # ).is_err());
    /// #
    /// # // a namespace administrator passphrase is too short
    /// # assert!(NetHsmAdminCredentials::new(
    /// #     1,
    /// #     "backup-passphrase".parse()?,
    /// #     "unlock-passphrase".parse()?,
    /// #     vec![FullCredentials::new("some".parse()?, "admin-passphrase".parse()?)],
    /// #     vec![FullCredentials::new(
    /// #         "ns1~admin".parse()?,
    /// #         "short".parse()?,
    /// #     )],
    /// # ).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        iteration: u32,
        backup_passphrase: Passphrase,
        unlock_passphrase: Passphrase,
        administrators: Vec<FullCredentials>,
        namespace_administrators: Vec<FullCredentials>,
    ) -> Result<Self, crate::Error> {
        let admin_credentials = Self {
            iteration,
            backup_passphrase,
            unlock_passphrase,
            administrators,
            namespace_administrators,
        };
        admin_credentials.validate()?;

        Ok(admin_credentials)
    }

    /// Returns the iteration.
    pub fn get_iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns the backup passphrase.
    pub fn get_backup_passphrase(&self) -> &str {
        self.backup_passphrase.expose_borrowed()
    }

    /// Returns the unlock passphrase.
    pub fn get_unlock_passphrase(&self) -> &str {
        self.unlock_passphrase.expose_borrowed()
    }

    /// Returns the list of administrators.
    pub fn get_administrators(&self) -> &[FullCredentials] {
        &self.administrators
    }

    /// Returns the default system-wide administrator "admin".
    ///
    /// # Errors
    ///
    /// Returns an error if no administrative account with the system-wide [`UserId`] "admin" is
    /// found.
    pub fn get_default_administrator(&self) -> Result<&FullCredentials, crate::Error> {
        let Some(first_admin) = self
            .administrators
            .iter()
            .find(|user| user.name.to_string() == "admin")
        else {
            return Err(Error::AdministratorNoDefault.into());
        };
        Ok(first_admin)
    }

    /// Returns the list of namespace administrators.
    pub fn get_namespace_administrators(&self) -> &[FullCredentials] {
        &self.namespace_administrators
    }
}

impl AdminCredentials for NetHsmAdminCredentials {
    /// Validates the [`NetHsmAdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - there is no top-level administrator user,
    /// - the default top-level administrator user (with the name "admin") is missing,
    /// - a user passphrase is too short,
    /// - the backup passphrase is too short,
    /// - or the unlock passphrase is too short.
    fn validate(&self) -> Result<(), crate::Error> {
        // there is no top-level administrator user
        if self.get_administrators().is_empty() {
            return Err(crate::Error::AdminSecretHandling(
                Error::AdministratorMissing,
            ));
        }

        // there is no top-level administrator user with the name "admin"
        if !self
            .get_administrators()
            .iter()
            .any(|user| user.name.to_string() == "admin")
        {
            return Err(crate::Error::AdminSecretHandling(
                Error::AdministratorNoDefault,
            ));
        }

        let minimum_length: usize = 10;

        // a top-level administrator user passphrase is too short
        for user in self.get_administrators().iter() {
            if user.passphrase.expose_borrowed().len() < minimum_length {
                return Err(crate::Error::AdminSecretHandling(
                    Error::PassphraseTooShort {
                        context: format!("user {}", user.name),
                        minimum_length,
                    },
                ));
            }
        }

        // a namespace administrator user passphrase is too short
        for user in self.get_namespace_administrators().iter() {
            if user.passphrase.expose_borrowed().len() < minimum_length {
                return Err(crate::Error::AdminSecretHandling(
                    Error::PassphraseTooShort {
                        context: format!("user {}", user.name),
                        minimum_length,
                    },
                ));
            }
        }

        // the backup passphrase is too short
        if self.get_backup_passphrase().len() < minimum_length {
            return Err(crate::Error::AdminSecretHandling(
                Error::PassphraseTooShort {
                    context: "backups".to_string(),
                    minimum_length,
                },
            ));
        }

        // the unlock passphrase is too short
        if self.get_unlock_passphrase().len() < minimum_length {
            return Err(crate::Error::AdminSecretHandling(
                Error::PassphraseTooShort {
                    context: "unlocking".to_string(),
                    minimum_length,
                },
            ));
        }

        Ok(())
    }
}
