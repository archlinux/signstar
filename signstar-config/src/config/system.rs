//! Configuration objects for system users and functionality.

use std::{collections::HashSet, num::NonZeroUsize};

use garde::Validate;
use serde::{Deserialize, Serialize};

use crate::{
    AuthorizedKeyEntry,
    SystemUserId,
    config::{
        ConfigAuthorizedKeyEntries,
        ConfigSystemUserIds,
        MappingAuthorizedKeyEntry,
        MappingSystemUserId,
        duplicate_authorized_keys,
        duplicate_system_user_ids,
        ordered_set,
    },
};

/// The default number of shares for [Shamir's Secret Sharing] (SSS).
///
/// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
const SSS_DEFAULT_NUMBER_OF_SHARES: NonZeroUsize =
    NonZeroUsize::new(6).expect("6 is larger than 0");
/// The default number of shares required for decrypting secrets encrypted using [Shamir's Secret
/// Sharing] (SSS).
///
/// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
const SSS_DEFAULT_THRESHOLD: NonZeroUsize = NonZeroUsize::new(3).expect("3 is larger than 0");

/// The handling of administrative secrets.
///
/// Administrative secrets may be handled in different ways (e.g. persistent or non-persistent).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdministrativeSecretHandling {
    /// The administrative secrets are handled in a plaintext file in a non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted administrative secrets on a file system.
    Plaintext,

    /// The administrative secrets are handled in a file encrypted using [systemd-creds] in a
    /// non-volatile directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of (host-specific) encrypted administrative secrets on a file system, that
    /// could be extracted if the host is compromised.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    SystemdCreds,

    /// The administrative secrets are handled using [Shamir's Secret Sharing] (SSS).
    ///
    /// This variant is the default for production use, as the administrative secrets are only ever
    /// exposed on a volatile filesystem for the time of their use.
    /// The secrets are only made available to the system as shares of a shared secret, split using
    /// SSS.
    /// This way no holder of a share is aware of the administrative secrets and the system only
    /// for as long as it needs to use the administrative secrets.
    ///
    /// [Shamir's Secret Sharing]: https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing
    ShamirsSecretSharing {
        /// The number of shares used to encrypt the shared secret.
        number_of_shares: NonZeroUsize,

        /// The number of shares (see `number_of_shares`) required to decrypt the shared secret.
        threshold: NonZeroUsize,
    },
}

impl Default for AdministrativeSecretHandling {
    fn default() -> Self {
        Self::ShamirsSecretSharing {
            number_of_shares: SSS_DEFAULT_NUMBER_OF_SHARES,
            threshold: SSS_DEFAULT_THRESHOLD,
        }
    }
}

/// The handling of non-administrative secrets.
///
/// Non-administrative secrets represent passphrases for (non-administrator) HSM users and may be
/// handled in different ways (e.g. encrypted or not encrypted).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    strum::EnumString,
    Eq,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
#[serde(rename_all = "kebab-case")]
#[strum(serialize_all = "kebab-case")]
pub enum NonAdministrativeSecretHandling {
    /// Each non-administrative secret is handled in a plaintext file in a non-volatile
    /// directory.
    ///
    /// ## Warning
    ///
    /// This variant should only be used in non-production test setups, as it implies the
    /// persistence of unencrypted non-administrative secrets on a file system.
    Plaintext,

    /// Each non-administrative secret is encrypted for a specific system user using
    /// [systemd-creds] and the resulting files are stored in a non-volatile directory.
    ///
    /// ## Note
    ///
    /// Although secrets are stored as encrypted strings in dedicated files, they may be extracted
    /// under certain circumstances:
    ///
    /// - the root account is compromised
    ///   - decrypts and exfiltrates _all_ secrets
    ///   - the secret is not encrypted using a [TPM] and the file
    ///     `/var/lib/systemd/credential.secret` as well as _any_ encrypted secret is exfiltrated
    /// - a specific user is compromised, decrypts and exfiltrates its own secret
    ///
    /// It is therefore crucial to follow common best-practices:
    ///
    /// - rely on a [TPM] for encrypting secrets, so that files become host-specific
    /// - heavily guard access to all users, especially root
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    /// [TPM]: https://en.wikipedia.org/wiki/Trusted_Platform_Module
    #[default]
    SystemdCreds,
}

/// Mappings for system users.
///
/// # Note
///
/// None of the variants are mapped to backend users.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemUserMapping {
    /// A user for up and downloading shares of a shared secret.
    ShareHolder {
        /// The name of the system user.
        system_user: SystemUserId,

        /// The list of SSH public keys used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
    },

    /// A system user, with SSH access, not mapped to any backend user, that is used for downloading
    /// the WireGuard configuration of the host.
    WireGuardDownload {
        /// The name of the system user.
        system_user: SystemUserId,

        /// The list of SSH public keys used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
    },
}

impl MappingAuthorizedKeyEntry for SystemUserMapping {
    fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry> {
        match self {
            Self::ShareHolder {
                ssh_authorized_key, ..
            }
            | Self::WireGuardDownload {
                ssh_authorized_key, ..
            } => Some(ssh_authorized_key),
        }
    }
}

impl MappingSystemUserId for SystemUserMapping {
    fn system_user_id(&self) -> Option<&SystemUserId> {
        match self {
            Self::ShareHolder { system_user, .. } | Self::WireGuardDownload { system_user, .. } => {
                Some(system_user)
            }
        }
    }
}

/// Validates a set of [`SystemUserMapping`] objects against [`AdministrativeSecretHandling`].
///
/// Ensures that `value` is not empty.
///
/// Ensures that in `mappings` there are
///
/// - no duplicate system users
/// - no duplicate SSH authorized keys (by comparing the actual SSH public keys)
/// - enough shareholders for SSS, if SSS is configured in `admin_secret_handling`
/// - no shareholders for SSS, if SSS is _not_ configured in `admin_secret_handling`
///
/// # Errors
///
/// Returns an error if there are
///
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
/// - not enough shareholders for SSS, if SSS is configured in `admin_secret_handling`
/// - shareholders for SSS, if SSS is _not_ configured in `admin_secret_handling`
fn validate_system_config_mappings(
    admin_secret_handling: &AdministrativeSecretHandling,
) -> impl FnOnce(&HashSet<SystemUserMapping>, &()) -> garde::Result + '_ {
    move |mappings, _| {
        // Collect all duplicate system user IDs.
        let duplicate_system_user_ids = duplicate_system_user_ids(mappings);

        // Collect all duplicate SSH public keys used as authorized_keys.
        let duplicate_authorized_keys = duplicate_authorized_keys(mappings);

        // Get the number of user mappings that represent a shareholder for SSS.
        let num_shares = mappings
            .iter()
            .filter(|mapping| matches!(mapping, SystemUserMapping::ShareHolder { .. }))
            .count();

        // Collect issues around the use of SSS shareholders.
        let mismatching_sss_shares = match admin_secret_handling {
            AdministrativeSecretHandling::ShamirsSecretSharing {
                number_of_shares, ..
            } => {
                if number_of_shares.get() > num_shares {
                    Some(format!(
                        "only {num_shares} shareholders, but the SSS setup requires {}",
                        number_of_shares.get()
                    ))
                } else {
                    None
                }
            }
            AdministrativeSecretHandling::Plaintext => {
                if num_shares != 0 {
                    Some(format!(
                        "{num_shares} SSS shareholders, but the administrative secret handling is plaintext"
                    ))
                } else {
                    None
                }
            }
            AdministrativeSecretHandling::SystemdCreds => {
                if num_shares != 0 {
                    Some(format!(
                        "{num_shares} SSS shareholders, but the administrative secret handling is systemd-creds"
                    ))
                } else {
                    None
                }
            }
        };

        let messages = [
            duplicate_system_user_ids,
            duplicate_authorized_keys,
            mismatching_sss_shares,
        ];
        let error_messages = {
            let mut error_messages = Vec::new();

            for message in messages.iter().flatten() {
                error_messages.push(message.as_str());
            }

            error_messages
        };

        match error_messages.len() {
            0 => Ok(()),
            1 => Err(garde::Error::new(format!(
                "contains {}",
                error_messages.join("\n")
            ))),
            _ => Err(garde::Error::new(format!(
                "contains multiple issues:\n⤷ {}",
                error_messages.join("\n⤷ ")
            ))),
        }
    }
}

/// System-wide configuration items.
///
/// This struct tracks various items:
///
/// - the `iteration` (version) of the configuration
/// - the `admin_secret_handling` which describes how administrative secrets are stored/handled on
///   the system
/// - the `non_admin_secret_handling` which describes how non-administrative secrets are stored on
///   the system
/// - the `mappings` which describe user mappings for system users (e.g. SSS shareholders or users
///   for downloading wireguard configurations)
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct SystemConfig {
    #[garde(skip)]
    iteration: u32,

    #[garde(skip)]
    admin_secret_handling: AdministrativeSecretHandling,

    #[garde(skip)]
    non_admin_secret_handling: NonAdministrativeSecretHandling,

    #[serde(serialize_with = "ordered_set", default)]
    #[garde(custom(validate_system_config_mappings(&self.admin_secret_handling)))]
    mappings: HashSet<SystemUserMapping>,
}

impl SystemConfig {
    /// Creates a new [`SystemConfig`].
    pub fn new(
        iteration: u32,
        admin_secret_handling: AdministrativeSecretHandling,
        non_admin_secret_handling: NonAdministrativeSecretHandling,
        mappings: HashSet<SystemUserMapping>,
    ) -> Result<Self, crate::Error> {
        let config = Self {
            iteration,
            admin_secret_handling,
            non_admin_secret_handling,
            mappings,
        };
        config
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "validating a system configuration object".to_string(),
                source,
            })?;

        Ok(config)
    }

    /// Returns the iteration of the configuration.
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// Returns a reference to the [`AdministrativeSecretHandling`].
    pub fn admin_secret_handling(&self) -> &AdministrativeSecretHandling {
        &self.admin_secret_handling
    }

    /// Returns a reference to the [`NonAdministrativeSecretHandling`].
    pub fn non_admin_secret_handling(&self) -> &NonAdministrativeSecretHandling {
        &self.non_admin_secret_handling
    }

    /// Returns a reference to the set of [`SystemUserMapping`] objects.
    pub fn mappings(&self) -> &HashSet<SystemUserMapping> {
        &self.mappings
    }
}

impl ConfigAuthorizedKeyEntries for SystemConfig {
    fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry> {
        self.mappings
            .iter()
            .filter_map(|mapping| mapping.authorized_key_entry())
            .collect()
    }
}

impl ConfigSystemUserIds for SystemConfig {
    fn system_user_ids(&self) -> HashSet<&SystemUserId> {
        self.mappings
            .iter()
            .filter_map(|mapping| mapping.system_user_id())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::thread::current;

    use insta::{assert_snapshot, with_settings};
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    const SNAPSHOT_PATH: &str = "fixtures/system_config/";

    #[test]
    fn system_config_new_succeeds() -> TestResult {
        let _config = SystemConfig::new(
                1,
                AdministrativeSecretHandling::ShamirsSecretSharing {
                    number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                    threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                },
                NonAdministrativeSecretHandling::SystemdCreds,
                HashSet::from_iter([
                    SystemUserMapping::ShareHolder {
                        system_user: "share-holder1".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
                    },
                    SystemUserMapping::ShareHolder {
                        system_user: "share-holder2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                    },
                    SystemUserMapping::ShareHolder {
                        system_user: "share-holder3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
                    },
                    SystemUserMapping::WireGuardDownload {
                        system_user: "wireguard-downloader".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                    },
                ]),
            )?;

        Ok(())
    }

    #[rstest]
    #[case::duplicate_user_ids(
        "Error message for SystemConfig::new with duplicate system user IDs",
        AdministrativeSecretHandling::ShamirsSecretSharing {
            number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
            threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
        },
        HashSet::from_iter([
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
            },
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::duplicate_ssh_public_keys(
        "Error message for SystemConfig::new with duplicate SSH public keys as authorized_keys",
        AdministrativeSecretHandling::ShamirsSecretSharing {
            number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
            threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
        },
        HashSet::from_iter([
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user2@host3".parse()?,
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
            },
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::too_few_sss_shares(
        "Error message for SystemConfig::new with too few SSS shareholders",
        AdministrativeSecretHandling::ShamirsSecretSharing {
            number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
            threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
        },
        HashSet::from_iter([
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
            },
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::plaintext_admin_creds_with_sss_shareholders(
        "Error message for SystemConfig::new with SSS shareholders but plaintext based admin credentials handling",
        AdministrativeSecretHandling::Plaintext,
        HashSet::from_iter([
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
            },
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::systemd_creds_admin_creds_with_sss_shareholders(
        "Error message for SystemConfig::new with SSS shareholders but systemd-creds based admin credentials handling",
        AdministrativeSecretHandling::SystemdCreds,
        HashSet::from_iter([
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
            },
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::multiple_issues(
        "Error message for SystemConfig::new with SSS shareholders but plaintext based admin credentials handling, duplicate system user IDs and SSH public keys",
        AdministrativeSecretHandling::SystemdCreds,
        HashSet::from_iter([
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?
            },
            SystemUserMapping::ShareHolder {
                system_user: "share-holder1".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user1@host5".parse()?,
            },
            SystemUserMapping::ShareHolder {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user2@host3".parse()?
            },
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    fn system_config_new_fails_validation(
        #[case] description: &str,
        #[case] admin_secret_handling: AdministrativeSecretHandling,
        #[case] mappings: HashSet<SystemUserMapping>,
    ) -> TestResult {
        let error_msg = match SystemConfig::new(
            1,
            admin_secret_handling,
            NonAdministrativeSecretHandling::default(),
            mappings,
        ) {
            Err(crate::Error::Validation { source, .. }) => source.to_string(),
            Ok(config) => {
                panic!(
                    "Expected to fail with Error::Validation, but succeeded instead:
    {config:?}"
                )
            }
            Err(error) => panic!(
                "Expected to fail with Error::Validation, but failed with a different error
    instead: {error}"
            ),
        };

        with_settings!({
            description => description,
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a
    name").to_string().replace("::", "__"), error_msg);     });
        Ok(())
    }
}
