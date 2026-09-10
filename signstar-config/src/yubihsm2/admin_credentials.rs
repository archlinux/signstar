//! Administrative credentials for YubiHSM2 backends.

use log::info;
use serde::{Deserialize, Serialize};
use signstar_crypto::{
    passphrase::{Passphrase, PassphrasePolicy},
    traits::UserWithPassphrase,
};
use signstar_yubihsm2::{Credentials, object::WrapKey, yubihsm::Id};

use crate::{
    admin_credentials::{AdminCredentials, Error},
    config::Config,
    yubihsm2::YubiHsm2UserMapping,
};

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
    /// The [default ID] on an unprovisioned YubiHSM2 device.
    ///
    /// [default ID]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-access-control.html#authentication-key-as-a-credential-holder
    pub const DEFAULT_ID: Id = 1;

    /// The [default passphrase] on an unprovisioned YubiHSM2 device.
    ///
    /// [default passphrase]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-access-control.html#authentication-key-as-a-credential-holder
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

    /// Returns the list of administrators.
    pub fn administrators(&self) -> &[Credentials] {
        &self.administrators
    }

    /// Returns the [default ID].
    ///
    /// [default ID]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-access-control.html#authentication-key-as-a-credential-holder
    pub fn default_id() -> Id {
        Self::DEFAULT_ID
    }

    /// Returns the [default credentials].
    ///
    /// [default credentials]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-intro-access-control.html#authentication-key-as-a-credential-holder
    pub fn default_credentials() -> Credentials {
        Credentials::new(
            Self::default_id(),
            Passphrase::new(Self::DEFAULT_PASSPHRASE.to_string()),
        )
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

impl TryFrom<&Config> for YubiHsm2AdminCredentials {
    type Error = crate::Error;

    /// Creates a new [`YubiHsm2AdminCredentials`] from a [`Config`].
    ///
    /// # Note
    ///
    /// This generates a new backup passphrase and administrative passphrases, adhering to the
    /// hardcoded passphrase policies (e.g. minimum length).
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - `config` does not contain a [`YubiHsm2Config`][`crate::yubihsm2::YubiHsm2Config`]
    /// - [`YubiHsm2AdminCredentials::new`] fails on the generated data
    fn try_from(config: &Config) -> Result<Self, Self::Error> {
        info!("Create new administrative credentials for the Signstar configuration...");

        let Some(yubihsm2_config) = config.yubihsm2() else {
            return Err(crate::config::Error::YubiHsm2SectionMissing.into());
        };

        let administrators = yubihsm2_config
            .mappings()
            .iter()
            .filter_map(|mapping| {
                let YubiHsm2UserMapping::Admin {
                    authentication_key_id,
                } = mapping
                else {
                    return None;
                };
                Some(Credentials::new(
                    *authentication_key_id,
                    Passphrase::generate(Some(
                        YubiHsm2AdminCredentials::ADMIN_PASSPHRASE_POLICY.minimum_length,
                    )),
                ))
            })
            .collect::<Vec<_>>();

        YubiHsm2AdminCredentials::new(
            config.system().iteration(),
            Passphrase::generate(Some(
                YubiHsm2AdminCredentials::BACKUP_PASSPHRASE_POLICY.minimum_length,
            )),
            administrators,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use signstar_crypto::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};
    #[cfg(feature = "_yubihsm2-mockhsm")]
    use signstar_yubihsm2::Connection;
    use testresult::TestResult;

    use super::*;
    use crate::config::{ConfigBuilder, SystemConfig};
    #[cfg(feature = "_yubihsm2-mockhsm")]
    use crate::yubihsm2::YubiHsm2Config;

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

    /// Ensures, that creating [`YubiHsm2AdminCredentials`] from [`Config`] fails if it doesn't
    /// contain a section for YubiHSM2 devices.
    #[test]
    fn yubihsm2_admin_credentials_try_from_config_fails_on_no_yubihsm2_config() -> TestResult {
        let config = ConfigBuilder::new(SystemConfig::new(
            1,
            AdministrativeSecretHandling::Plaintext,
            NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::new(),
        )?)
        .finish()?;

        match YubiHsm2AdminCredentials::try_from(&config) {
            Err(crate::Error::Config(crate::config::Error::YubiHsm2SectionMissing)) => {}
            Err(error) => panic!(
                "Expected to fail with Error::YubiHsm2SectionMissing but failed differently: {error}"
            ),
            Ok(creds) => panic!(
                "Expected to fail with Error::YubiHsm2SectionMissing but succeeded instead: {creds:?}"
            ),
        }

        Ok(())
    }

    /// Ensures, that creating [`YubiHsm2AdminCredentials`] from [`Config`] succeeds if it contains
    /// a section for YubiHSM2 devices.
    #[cfg(feature = "_yubihsm2-mockhsm")]
    #[test]
    fn yubihsm2_admin_credentials_try_from_config_succeeds() -> TestResult {
        let config = ConfigBuilder::new(SystemConfig::new(
            1,
            AdministrativeSecretHandling::Plaintext,
            NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::new(),
        )?)
        .set_yubihsm2_config(YubiHsm2Config::new(
            BTreeSet::from_iter([Connection::Mock]),
            BTreeSet::from_iter([YubiHsm2UserMapping::Admin {
                authentication_key_id: 1,
            }]),
        )?)
        .finish()?;

        let _ = YubiHsm2AdminCredentials::try_from(&config)?;

        Ok(())
    }
}
