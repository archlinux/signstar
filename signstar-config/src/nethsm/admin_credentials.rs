//! Administrative credentials for [`NetHsm`] backends.

use log::warn;
use nethsm::{FullCredentials, Passphrase};
#[cfg(doc)]
use nethsm::{NetHsm, UserId};
use serde::{Deserialize, Serialize};

use crate::{
    admin_credentials::{AdminCredentials, Error},
    nethsm::{NetHsmConfig, NetHsmUserMapping},
};

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
    /// use signstar_config::nethsm::NetHsmAdminCredentials;
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
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns the backup passphrase.
    pub fn backup_passphrase(&self) -> &str {
        self.backup_passphrase.expose_borrowed()
    }

    /// Returns the unlock passphrase.
    pub fn unlock_passphrase(&self) -> &str {
        self.unlock_passphrase.expose_borrowed()
    }

    /// Returns the list of administrators.
    pub fn administrators(&self) -> &[FullCredentials] {
        &self.administrators
    }

    /// Returns the default system-wide administrator "admin".
    ///
    /// # Errors
    ///
    /// Returns an error if no administrative account with the system-wide [`UserId`] "admin" is
    /// found.
    pub fn default_administrator(&self) -> Result<&FullCredentials, crate::Error> {
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

    /// Returns the list of system-wide administrators, also present in a [`NetHsmConfig`].
    ///
    /// Retrieves the list of [`NetHsmUserMapping`] instances that represent system-wide
    /// administrators from `config`.
    /// Filters out all [`UserId`]s that cannot be matched and emits warnings for all unmatched
    /// ones.
    pub fn administrators_in_config(&self, config: &NetHsmConfig) -> Vec<&FullCredentials> {
        let user_mappings = config
            .mappings()
            .iter()
            .filter(|mapping| matches!(mapping, NetHsmUserMapping::Admin(..)))
            .collect::<Vec<_>>();
        // Only use administrative credentials that are also available in the NetHSM config.
        {
            let mut user_list = Vec::new();

            for creds in self.administrators() {
                if !user_mappings
                    .iter()
                    .any(|user_mapping| user_mapping.nethsm_user_ids().contains(&creds.name))
                {
                    warn!(
                        "The administrative credentials for system-wide administrator {} are skipped because the user is not found in the Signstar configuration.",
                        creds.name
                    );
                    continue;
                }
                user_list.push(creds);
            }
            // The available user IDs.
            let available_users = user_list
                .iter()
                .map(|creds| &creds.name)
                .collect::<Vec<_>>();

            let unmatched_config_users = user_mappings
                .iter()
                .flat_map(|user_mapping| {
                    user_mapping
                        .nethsm_user_ids()
                        .iter()
                        .filter(|user_id| !available_users.contains(user_id))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            if !unmatched_config_users.is_empty() {
                warn!(
                    "The following system-wide administrators (R-Administrators) in the Signstar configuration are skipped, because they cannot be found in the provided administrative credentials: {}",
                    unmatched_config_users
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            user_list
        }
    }

    /// Returns the list of namespace administrators, also present in a [`NetHsmConfig`].
    ///
    /// Retrieves the list of [`NetHsmUserMapping`] instances that represent namespace
    /// administrators from `config`.
    /// Filters out all [`UserId`]s that cannot be matched and emits warnings for all unmatched
    /// ones.
    pub fn namespace_administrators_in_config(
        &self,
        config: &NetHsmConfig,
    ) -> Vec<&FullCredentials> {
        // The list of namespace administrators.
        let user_mappings = config
            .mappings()
            .iter()
            .filter(|mapping| {
                if let NetHsmUserMapping::Admin(user_id) = mapping {
                    user_id.is_namespaced()
                } else {
                    false
                }
            })
            .collect::<Vec<_>>();
        // Only use administrative credentials that are also available in the NetHSM config.
        {
            let mut user_list = Vec::new();

            for creds in self.get_namespace_administrators() {
                if !user_mappings
                    .iter()
                    .any(|user_mapping| user_mapping.nethsm_user_ids().contains(&creds.name))
                {
                    warn!(
                        "The administrative credentials for namespace administrator (N-Administrator) {} are skipped because the user is not found in the Signstar configuration.",
                        creds.name
                    );
                    continue;
                }
                user_list.push(creds);
            }
            // The available user IDs.
            let available_users = user_list
                .iter()
                .map(|creds| &creds.name)
                .collect::<Vec<_>>();

            let unmatched_config_users = user_mappings
                .iter()
                .flat_map(|user_mapping| {
                    user_mapping
                        .nethsm_user_ids()
                        .iter()
                        .filter(|user_id| !available_users.contains(user_id))
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            if !unmatched_config_users.is_empty() {
                warn!(
                    "The following namespace administrators (N-Administrators) in the Signstar configuration are skipped, because they cannot be found in the provided administrative credentials: {}",
                    unmatched_config_users
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            user_list
        }
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
        if self.administrators().is_empty() {
            return Err(crate::Error::AdminSecretHandling(
                Error::AdministratorMissing,
            ));
        }

        // there is no top-level administrator user with the name "admin"
        if !self
            .administrators()
            .iter()
            .any(|user| user.name.to_string() == "admin")
        {
            return Err(crate::Error::AdminSecretHandling(
                Error::AdministratorNoDefault,
            ));
        }

        let minimum_length: usize = 10;

        // a top-level administrator user passphrase is too short
        for user in self.administrators().iter() {
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
        if self.backup_passphrase().len() < minimum_length {
            return Err(crate::Error::AdminSecretHandling(
                Error::PassphraseTooShort {
                    context: "backups".to_string(),
                    minimum_length,
                },
            ));
        }

        // the unlock passphrase is too short
        if self.unlock_passphrase().len() < minimum_length {
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, str::FromStr};

    use nethsm::{Connection, UserId};
    use rstest::{fixture, rstest};
    use testresult::TestResult;

    use super::*;

    #[fixture]
    fn nethsm_admin_credentials() -> TestResult<NetHsmAdminCredentials> {
        Ok(NetHsmAdminCredentials::new(
            1,
            "backup-passphrase".parse()?,
            "unlock-passphrase".parse()?,
            vec![
                FullCredentials::new("admin".parse()?, "admin-passphrase".parse()?),
                FullCredentials::new("admin2".parse()?, "admin2-passphrase".parse()?),
            ],
            vec![
                FullCredentials::new("ns1~admin".parse()?, "ns1~admin-passphrase".parse()?),
                FullCredentials::new("ns1~admin2".parse()?, "ns1~admin2-passphrase".parse()?),
            ],
        )?)
    }

    #[fixture]
    fn nethsm_config() -> TestResult<NetHsmConfig> {
        Ok(NetHsmConfig::new(
            BTreeSet::from_iter([Connection::new(
                "https://nethsm1.example.org/".parse()?,
                nethsm::ConnectionSecurity::Unsafe,
            )]),
            BTreeSet::from_iter([
                NetHsmUserMapping::Admin("admin".parse()?),
                NetHsmUserMapping::Admin("ns1~admin".parse()?),
            ]),
        )?)
    }

    #[rstest]
    fn nethsm_admin_credentials_administrators_in_config(
        nethsm_admin_credentials: TestResult<NetHsmAdminCredentials>,
        nethsm_config: TestResult<NetHsmConfig>,
    ) -> TestResult {
        let nethsm_admin_credentials = nethsm_admin_credentials?;
        let nethsm_config = nethsm_config?;
        let users = nethsm_admin_credentials
            .administrators_in_config(&nethsm_config)
            .iter()
            .map(|creds| creds.name.clone())
            .collect::<Vec<_>>();

        assert_eq!(users, vec![UserId::from_str("admin")?]);

        Ok(())
    }

    #[rstest]
    fn nethsm_admin_credentials_namespace_administrators_in_config(
        nethsm_admin_credentials: TestResult<NetHsmAdminCredentials>,
        nethsm_config: TestResult<NetHsmConfig>,
    ) -> TestResult {
        let nethsm_admin_credentials = nethsm_admin_credentials?;
        let nethsm_config = nethsm_config?;
        let users = nethsm_admin_credentials
            .namespace_administrators_in_config(&nethsm_config)
            .iter()
            .map(|creds| creds.name.clone())
            .collect::<Vec<_>>();

        assert_eq!(users, vec![UserId::from_str("ns1~admin")?]);

        Ok(())
    }
}
