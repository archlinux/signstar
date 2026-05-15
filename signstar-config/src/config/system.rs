//! Configuration objects for system users and functionality.

use std::collections::{BTreeSet, HashSet};

use garde::Validate;
use serde::{Deserialize, Serialize};
use signstar_common::system_user::get_home_base_dir_path;
use signstar_crypto::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};

use crate::{
    config::{
        AuthorizedKeyEntry,
        ConfigAuthorizedKeyEntries,
        ConfigSystemUserIds,
        MappingAuthorizedKeyEntry,
        MappingSystemUserId,
        SystemUserConfigState,
        SystemUserData,
        SystemUserHostState,
        SystemUserId,
        duplicate_authorized_keys,
        duplicate_system_user_ids,
    },
    state::{StateDiff, StateDiffFailure, StateDiffFailureTarget, StateDiffReport},
};

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

impl<'a> From<&'a SystemUserMapping> for SystemUserData<'a> {
    fn from(value: &'a SystemUserMapping) -> Self {
        match value {
            SystemUserMapping::ShareHolder {
                system_user,
                ssh_authorized_key,
            } => Self::HostShareholder {
                system_user,
                ssh_authorized_key,
            },
            SystemUserMapping::WireGuardDownload {
                system_user,
                ssh_authorized_key,
            } => Self::HostDownloadNetworkConfig {
                system_user,
                ssh_authorized_key,
            },
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
) -> impl FnOnce(&BTreeSet<SystemUserMapping>, &()) -> garde::Result + '_ {
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

    #[garde(custom(validate_system_config_mappings(&self.admin_secret_handling)))]
    mappings: BTreeSet<SystemUserMapping>,
}

impl SystemConfig {
    /// Creates a new [`SystemConfig`].
    pub fn new(
        iteration: u32,
        admin_secret_handling: AdministrativeSecretHandling,
        non_admin_secret_handling: NonAdministrativeSecretHandling,
        mappings: BTreeSet<SystemUserMapping>,
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
    pub fn mappings(&self) -> &BTreeSet<SystemUserMapping> {
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

/// The diff between [`SystemUserConfigState`] and [`SystemUserHostState`].
#[derive(Debug)]
pub struct SystemUserDiff<'a, 'b> {
    /// The state of system users according to a configuration.
    pub config: &'a SystemUserConfigState<'a>,

    /// The state of system users on the host.
    pub system: &'b SystemUserHostState<'b>,
}

impl<'a, 'b> StateDiff<'a, 'b> for SystemUserDiff<'a, 'b> {
    fn diff(&self) -> StateDiffReport<'a, 'b> {
        let user_state_discrepancies = {
            let mut matched_config_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for host_user_state in self.system.system_user_data.iter() {
                for config_user_state in self.config.system_user_data.iter() {
                    // The `SystemUserData` on the host side are unknown but fully map to an
                    // existing system user in the configuration.
                    if let &SystemUserData::Unknown {
                        system_user,
                        ssh_authorized_keys,
                        home_dir,
                    } = &host_user_state
                        && config_user_state.system_user() == system_user
                        && config_user_state.ssh_authorized_keys()
                            == ssh_authorized_keys.iter().collect::<Vec<_>>()
                        && *home_dir
                            == get_home_base_dir_path()
                                .join(config_user_state.system_user().as_ref())
                    {
                        matched_config_states.push(config_user_state);
                        continue 'outer;
                    }

                    // The unique system user name matches, but not the remaining data.
                    if host_user_state.system_user() == config_user_state.system_user() {
                        matched_config_states.push(config_user_state);
                        state_discrepancies.push(StateDiffFailure::Mismatch {
                            one_state: host_user_state.to_string(),
                            one: Box::new(self.config),
                            other_state: config_user_state.to_string(),
                            other: Box::new(self.system),
                        });
                        continue 'outer;
                    }
                }
                // NOTE: We ignore unmatched users on the host, as they are not relevant to the
                // Signstar system.
            }

            // Unmatched other states.
            self.config
                .system_user_data
                .iter()
                .filter(|data| !matched_config_states.contains(data))
                .for_each(|data| {
                    state_discrepancies.push(StateDiffFailure::DoesNotExist {
                        one: Box::new(self.config),
                        other: Box::new(self.system),
                        target: StateDiffFailureTarget::Other,
                        state: data.to_string(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() {
            return StateDiffReport::Success;
        }

        StateDiffReport::Failure {
            messages: user_state_discrepancies,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, thread::current};

    use insta::{assert_snapshot, with_settings};
    use rstest::{fixture, rstest};
    use signstar_crypto::secret_file::{SSS_DEFAULT_NUMBER_OF_SHARES, SSS_DEFAULT_THRESHOLD};
    use testresult::TestResult;

    use super::*;

    const SNAPSHOT_PATH: &str = "fixtures/system_config/";

    #[test]
    fn administrative_secret_handling_default() {
        assert_eq!(
            AdministrativeSecretHandling::default(),
            AdministrativeSecretHandling::ShamirsSecretSharing {
                number_of_shares: SSS_DEFAULT_NUMBER_OF_SHARES,
                threshold: SSS_DEFAULT_THRESHOLD,
            },
        )
    }

    #[rstest]
    #[case::shamirs_secret_sharing_plaintext(
        AdministrativeSecretHandling::ShamirsSecretSharing {
            number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
            threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
        },
        NonAdministrativeSecretHandling::Plaintext,
        BTreeSet::from_iter([
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
    #[case::shamirs_secret_sharing_systemd_creds(
        AdministrativeSecretHandling::ShamirsSecretSharing {
            number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
            threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
        },
        NonAdministrativeSecretHandling::SystemdCreds,
        BTreeSet::from_iter([
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
    #[case::systemd_creds_plaintext(
        AdministrativeSecretHandling::SystemdCreds,
        NonAdministrativeSecretHandling::Plaintext,
        BTreeSet::from_iter([
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::systemd_creds_systemd_creds(
        AdministrativeSecretHandling::SystemdCreds,
        NonAdministrativeSecretHandling::SystemdCreds,
        BTreeSet::from_iter([
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::plaintext_plaintext(
        AdministrativeSecretHandling::Plaintext,
        NonAdministrativeSecretHandling::Plaintext,
        BTreeSet::from_iter([
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    #[case::plaintext_systemd_creds(
        AdministrativeSecretHandling::Plaintext,
        NonAdministrativeSecretHandling::SystemdCreds,
        BTreeSet::from_iter([
            SystemUserMapping::WireGuardDownload {
                system_user: "wireguard-downloader".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            },
        ]),
    )]
    fn system_config_new_succeeds(
        #[case] administrative_secret_handling: AdministrativeSecretHandling,
        #[case] non_administrative_secret_handling: NonAdministrativeSecretHandling,
        #[case] mappings: BTreeSet<SystemUserMapping>,
    ) -> TestResult {
        assert!(
            SystemConfig::new(
                1,
                administrative_secret_handling,
                non_administrative_secret_handling,
                mappings,
            )
            .is_ok()
        );

        Ok(())
    }

    #[rstest]
    #[case::duplicate_user_ids(
        "Error message for SystemConfig::new with duplicate system user IDs",
        AdministrativeSecretHandling::ShamirsSecretSharing {
            number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
            threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
        },
        BTreeSet::from_iter([
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
        BTreeSet::from_iter([
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
        BTreeSet::from_iter([
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
        BTreeSet::from_iter([
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
        BTreeSet::from_iter([
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
        BTreeSet::from_iter([
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
        #[case] mappings: BTreeSet<SystemUserMapping>,
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

    #[fixture]
    fn administrative_secret_handling() -> AdministrativeSecretHandling {
        AdministrativeSecretHandling::default()
    }

    #[fixture]
    fn non_administrative_secret_handling() -> NonAdministrativeSecretHandling {
        NonAdministrativeSecretHandling::default()
    }

    #[fixture]
    fn mappings() -> TestResult<BTreeSet<SystemUserMapping>> {
        Ok(BTreeSet::from_iter([
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
                    SystemUserMapping::ShareHolder {
                        system_user: "share-holder4".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINsej5PBntjmthtYKXUrPKwYKadruZMhvZE3EmVxbOwL user@host".parse()?
                    },
                    SystemUserMapping::ShareHolder {
                        system_user: "share-holder5".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJMmh08ZQTPRQS9NDNJY6zRVdjwSBwcPcefiXnAEtsgE user@host".parse()?
                    },
                    SystemUserMapping::ShareHolder {
                        system_user: "share-holder6".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJAW0YOVnJHm5qqiZBvIwPc0GH1D7ALDGwDRsBZHWbGU user@host".parse()?
                    },
                    SystemUserMapping::WireGuardDownload {
                        system_user: "wireguard-downloader".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                    },
                ]))
    }

    #[fixture]
    fn system_config(
        administrative_secret_handling: AdministrativeSecretHandling,
        non_administrative_secret_handling: NonAdministrativeSecretHandling,
        mappings: TestResult<BTreeSet<SystemUserMapping>>,
    ) -> TestResult<SystemConfig> {
        let mappings = mappings?;
        Ok(SystemConfig::new(
            1,
            administrative_secret_handling,
            non_administrative_secret_handling,
            mappings,
        )?)
    }

    #[rstest]
    fn system_config_iteration(system_config: TestResult<SystemConfig>) -> TestResult {
        let system_config = system_config?;
        assert_eq!(system_config.iteration(), 1);

        Ok(())
    }

    #[rstest]
    fn system_config_admin_secret_handling(
        system_config: TestResult<SystemConfig>,
        administrative_secret_handling: AdministrativeSecretHandling,
    ) -> TestResult {
        let system_config = system_config?;
        assert_eq!(
            system_config.admin_secret_handling(),
            &administrative_secret_handling
        );

        Ok(())
    }

    #[rstest]
    fn system_config_non_admin_secret_handling(
        system_config: TestResult<SystemConfig>,
        non_administrative_secret_handling: NonAdministrativeSecretHandling,
    ) -> TestResult {
        let system_config = system_config?;
        assert_eq!(
            system_config.non_admin_secret_handling(),
            &non_administrative_secret_handling
        );

        Ok(())
    }

    #[rstest]
    fn system_config_mappings(
        system_config: TestResult<SystemConfig>,
        mappings: TestResult<BTreeSet<SystemUserMapping>>,
    ) -> TestResult {
        let system_config = system_config?;
        let mappings = mappings?;
        assert_eq!(system_config.mappings(), &mappings);

        Ok(())
    }

    #[rstest]
    fn system_config_authorized_key_entries(
        system_config: TestResult<SystemConfig>,
        mappings: TestResult<BTreeSet<SystemUserMapping>>,
    ) -> TestResult {
        let system_config = system_config?;
        let mappings = mappings?;
        let authorized_keys = mappings
            .iter()
            .filter_map(|mapping| mapping.authorized_key_entry())
            .collect::<HashSet<_>>();
        assert_eq!(system_config.authorized_key_entries(), authorized_keys);

        Ok(())
    }

    #[rstest]
    fn system_config_system_user_ids(
        system_config: TestResult<SystemConfig>,
        mappings: TestResult<BTreeSet<SystemUserMapping>>,
    ) -> TestResult {
        let system_config = system_config?;
        let mappings = mappings?;
        let system_user_ids = mappings
            .iter()
            .filter_map(|mapping| mapping.system_user_id())
            .collect::<HashSet<_>>();
        assert_eq!(system_config.system_user_ids(), system_user_ids);

        Ok(())
    }
}
