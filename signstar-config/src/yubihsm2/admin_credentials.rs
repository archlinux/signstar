//! Administrative credentials for YubiHSM2 backends.

use serde::{Deserialize, Serialize};
use signstar_crypto::{
    passphrase::{Passphrase, PassphrasePolicy},
    traits::UserWithPassphrase,
};
use signstar_yubihsm2::{Credentials, object::WrapKey};

use crate::admin_credentials::{AdminCredentials, Error};

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
/// The passphrases of administrator users are checked against [`Self::ADMIN_PASSPHRASE_POLICY`].
/// The backup passphrase is checked against [`Self::BACKUP_PASSPHRASE_POLICY`].
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

    /// The minimum passphrase length for the backup key.
    ///
    /// # Note
    ///
    /// This reuses [`WrapKey::PASSPHRASE_POLICY`].
    pub const BACKUP_PASSPHRASE_POLICY: PassphrasePolicy = WrapKey::PASSPHRASE_POLICY;

    /// The minimum passphrase length for an administrative user.
    pub const ADMIN_PASSPHRASE_POLICY: PassphrasePolicy = PassphrasePolicy { minimum_length: 30 };

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
            creds
                .passphrase()
                .check_against_policy(&Self::ADMIN_PASSPHRASE_POLICY)?;
        }

        // The backup passphrase is too short.
        self.backup_passphrase
            .check_against_policy(&Self::BACKUP_PASSPHRASE_POLICY)?;

        Ok(())
    }

    /// Returns the iteration of the administrative credentials.
    fn iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns the backup passphrase.
    fn backup_passphrase(&self) -> &Passphrase {
        &self.backup_passphrase
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
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![Credentials::new(
                "1".parse()?,
                Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string()),
            )],
        )?;

        Ok(())
    }

    #[test]
    fn yubihsm2_admin_credentials_new_fails_on_no_admins() -> TestResult {
        match YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            Vec::new(),
        ) {
            Ok(creds) => {
                panic!("Expected Error::AdministratorMissing but succeeded instead:\n{creds:?}")
            }

            Err(crate::Error::AdminSecretHandling(Error::AdministratorMissing)) => {}
            Err(error) => panic!(
                "Expected Error::AdministratorMissing but failed differently instead:\n{error}"
            ),
        }

        Ok(())
    }

    #[test]
    fn yubihsm2_admin_credentials_new_fails_on_admin_passphrase_too_short() -> TestResult {
        match YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![Credentials::new(
                "1".parse()?,
                Passphrase::new("short".to_string()),
            )],
        ) {
            Ok(creds) => {
                panic!("Expected Error::PassphraseTooShort but succeeded instead:\n{creds:?}")
            }
            Err(crate::Error::SignstarCrypto(signstar_crypto::Error::Passphrase(
                signstar_crypto::passphrase::Error::Length { .. },
            ))) => {}
            Err(error) => panic!(
                "Expected crate::Error::SignstarCrypto(signstar_crypto::Error::Passphrase(
                signstar_crypto::passphrase::Error::Length)) but failed differently instead:\n{error}"
            ),
        }

        Ok(())
    }

    #[test]
    fn yubihsm2_admin_credentials_new_fails_on_backup_passphrase_too_short() -> TestResult {
        match YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("short".to_string()),
            vec![Credentials::new(
                "1".parse()?,
                Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string()),
            )],
        ) {
            Ok(creds) => {
                panic!("Expected Error::PassphraseTooShort but succeeded instead:\n{creds:?}")
            }
            Err(crate::Error::SignstarCrypto(signstar_crypto::Error::Passphrase(
                signstar_crypto::passphrase::Error::Length { .. },
            ))) => {}
            Err(error) => panic!(
                "Expected crate::Error::SignstarCrypto(signstar_crypto::Error::Passphrase(
                signstar_crypto::passphrase::Error::Length)) but failed differently instead:\n{error}"
            ),
        }

        Ok(())
    }
}
