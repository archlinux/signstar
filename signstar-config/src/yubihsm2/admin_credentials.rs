//! Administrative credentials for YubiHSM2 backends.

use serde::{Deserialize, Serialize};
use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
use signstar_yubihsm2::Credentials;

use crate::{AdminCredentials, admin_credentials::Error};

/// Administrative credentials for YubiHSM2 backends.
///
/// Tracks the following items:
///
/// - the minimum iteration for which the credentials should apply,
/// - the backup passphrase of the backend,
/// - the administrator credentials of the backend,
///
/// # Note
///
/// There must be at least one set of [`Credentials`] in the list of administrators.
/// The passphrases of administrator accounts must be at least
/// [`Self::MINIMUM_PASSPHRASE_LENGTH_USER`] characters long.
/// The backup passphrase must be at least [`Self::MINIMUM_PASSPHRASE_LENGTH_BACKUP`] characters
/// long.
///
/// It is implied, that the administrator users of a YubiHSM2 backend have the necessary
/// [capabilities] for the creation of other users and keys.
///
/// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct YubiHsm2AdminCredentials {
    iteration: u32,
    backup_passphrase: Passphrase,
    administrators: Vec<Credentials>,
}

impl YubiHsm2AdminCredentials {
    /// The default ID on an unprovisioned YubiHSM2 device.
    pub const DEFAULT_ID: u16 = 1;

    /// The default passphrase on an unprovisioned YubiHSM2 device.
    pub const DEFAULT_PASSPHRASE: &str = "password";

    /// The default passphrase on an unprovisioned YubiHSM2 device.
    pub const MINIMUM_PASSPHRASE_LENGTH_USER: usize = 8;

    /// The minimum length of a backup passphrase.
    pub const MINIMUM_PASSPHRASE_LENGTH_BACKUP: usize = 10;

    /// Creates a new [`YubiHsm2AdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - there is no administrator user,
    /// - a user passphrase is too short,
    /// - or the backup passphrase is too short.
    pub fn new(
        iteration: u32,
        backup_passphrase: Passphrase,
        administrators: Vec<Credentials>,
    ) -> Result<Self, crate::Error> {
        let creds = Self {
            iteration,
            backup_passphrase,
            administrators,
        };
        creds.validate()?;

        Ok(creds)
    }
}

impl AdminCredentials for YubiHsm2AdminCredentials {
    /// Validates the [`YubiHsm2AdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - there is no administrator user,
    /// - a user passphrase is too short,
    /// - or the backup passphrase is too short.
    fn validate(&self) -> Result<(), crate::Error> {
        // There is no administrator user.
        if self.administrators.is_empty() {
            return Err(Error::AdministratorMissing.into());
        }

        // An administrator user passphrase is too short.
        for creds in self.administrators.iter() {
            if creds.passphrase().expose_borrowed().len() < Self::MINIMUM_PASSPHRASE_LENGTH_USER {
                return Err(Error::PassphraseTooShort {
                    context: format!("user {}", creds.user()),
                    minimum_length: Self::MINIMUM_PASSPHRASE_LENGTH_USER,
                }
                .into());
            }
        }

        // The backup passphrase is too short.
        if self.backup_passphrase.expose_borrowed().len() < Self::MINIMUM_PASSPHRASE_LENGTH_BACKUP {
            return Err(Error::PassphraseTooShort {
                context: "backups".to_string(),
                minimum_length: Self::MINIMUM_PASSPHRASE_LENGTH_USER,
            }
            .into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use testresult::TestResult;

    use super::*;

    #[test]
    fn yubihsm2_admin_credentials_new_succeeds() -> TestResult {
        let _creds = YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase".to_string()),
            vec![Credentials::new(1, Passphrase::new("password".to_string()))],
        )?;

        Ok(())
    }

    #[test]
    fn yubihsm2_admin_credentials_new_fails_on_no_admins() -> TestResult {
        match YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase".to_string()),
            Vec::new(),
        ) {
            Ok(creds) => {
                return Err(format!(
                    "Expected Error::AdministratorMissing but succeeded instead:\n{creds:?}"
                )
                .into());
            }
            Err(crate::Error::AdminSecretHandling(Error::AdministratorMissing)) => {}
            Err(error) => {
                return Err(format!(
                    "Expected Error::AdministratorMissing but failed differently instead:\n{error}"
                )
                .into());
            }
        }

        Ok(())
    }

    #[test]
    fn yubihsm2_admin_credentials_new_fails_on_admin_passphrase_too_short() -> TestResult {
        match YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase".to_string()),
            vec![Credentials::new(1, Passphrase::new("pass".to_string()))],
        ) {
            Ok(creds) => {
                return Err(format!(
                    "Expected Error::PassphraseTooShort but succeeded instead:\n{creds:?}"
                )
                .into());
            }
            Err(crate::Error::AdminSecretHandling(Error::PassphraseTooShort { .. })) => {}
            Err(error) => {
                return Err(format!(
                    "Expected Error::PassphraseTooShort but failed differently instead:\n{error}"
                )
                .into());
            }
        }

        Ok(())
    }

    #[test]
    fn yubihsm2_admin_credentials_new_fails_on_backup_passphrase_too_short() -> TestResult {
        match YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup".to_string()),
            vec![Credentials::new(1, Passphrase::new("password".to_string()))],
        ) {
            Ok(creds) => {
                return Err(format!(
                    "Expected Error::PassphraseTooShort but succeeded instead:\n{creds:?}"
                )
                .into());
            }
            Err(crate::Error::AdminSecretHandling(Error::PassphraseTooShort { .. })) => {}
            Err(error) => {
                return Err(format!(
                    "Expected Error::PassphraseTooShort but failed differently instead:\n{error}"
                )
                .into());
            }
        }

        Ok(())
    }
}
