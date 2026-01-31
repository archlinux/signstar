//! Configuration file handling.

#[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
pub mod impl_all;
#[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
pub mod impl_nethsm;
#[cfg(not(feature = "_hsm-backend"))]
pub mod impl_none;
#[cfg(all(feature = "yubihsm2", not(feature = "nethsm")))]
pub mod impl_yubihsm2;

#[cfg(feature = "_hsm-backend")]
use std::collections::HashSet;
use std::{fs::read_to_string, path::Path};

use garde::Validate;
use log::info;
#[cfg(feature = "nethsm")]
use nethsm::Connection;
use serde::{Deserialize, Serialize};
use signstar_common::config::get_config_file;
#[cfg(feature = "_hsm-backend")]
use signstar_crypto::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};

use crate::config::SystemConfig;
#[cfg(feature = "_hsm-backend")]
use crate::config::{ConfigAuthorizedKeyEntries, ConfigSystemUserIds};
#[cfg(feature = "nethsm")]
use crate::nethsm::{NetHsmConfig, NetHsmUserMapping};
#[cfg(feature = "yubihsm2")]
use crate::yubihsm2::{YubiHsm2Config, YubiHsm2UserMapping, backend::YubiHsmConnection};

/// Backend specific data for a user mapping.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserBackendConnection {
    /// The connection configuration for a user of a NetHSM backend.
    ///
    /// # Note
    ///
    /// Only supported when using the `nethsm` feature.
    #[cfg(feature = "nethsm")]
    NetHsm {
        /// Administrative credentials handling.
        admin_secret_handling: AdministrativeSecretHandling,

        /// Non-administrative credentials handling.
        non_admin_secret_handling: NonAdministrativeSecretHandling,

        /// The available connections to the NetHSM backend.
        connections: HashSet<Connection>,

        /// A specific NetHSM user mapping.
        mapping: NetHsmUserMapping,
    },

    /// The connection configuration for a user of a YubiHSM2 backend.
    ///
    /// # Note
    ///
    /// Only supported when using the `yubihsm2` feature.
    #[cfg(feature = "yubihsm2")]
    YubiHsm2 {
        /// Administrative credentials handling.
        admin_secret_handling: AdministrativeSecretHandling,

        /// Non-administrative credentials handling.
        non_admin_secret_handling: NonAdministrativeSecretHandling,

        /// The available connections to the YubiHSM2 backend.
        connections: HashSet<YubiHsmConnection>,

        /// A specific YubiHSM2 user mapping.
        mapping: YubiHsm2UserMapping,
    },
}

/// A filter for the retrieval of lists of [`UserBackendConnection`] from a [`Config`].
#[derive(Clone, Copy, Debug)]
pub enum UserBackendConnectionFilter {
    /// Target all backend users.
    All,

    /// Only target administrative backend users.
    Admin,

    /// Only target non-administrative backend users.
    NonAdmin,
}

/// Validates overlapping assumptions of two configuration objects.
///
/// Ensures that `config_a` and `config_b` have no overlapping system user IDs or SSH
/// authorized_keys.
///
/// # Errors
///
/// Returns an error if there are
///
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
#[cfg(feature = "_hsm-backend")]
fn validate_confs<T, U>(config_a: &T, config_b: &U) -> garde::Result
where
    T: ConfigAuthorizedKeyEntries + ConfigSystemUserIds,
    U: ConfigAuthorizedKeyEntries + ConfigSystemUserIds,
{
    // Collect duplicate system user IDs.
    let duplicate_system_user_ids = {
        let system_config_user_ids = config_a.system_user_ids();
        let config_user_ids = config_b.system_user_ids();
        let duplicates = system_config_user_ids
            .intersection(&config_user_ids)
            .map(|system_user_id| system_user_id.to_string())
            .collect::<HashSet<_>>();

        if duplicates.is_empty() {
            None
        } else {
            let mut duplicates = Vec::from_iter(duplicates);
            duplicates.sort();
            Some(format!(
                "the duplicate system user ID{} {}",
                if duplicates.len() > 1 { "s" } else { "" },
                duplicates.join(", ")
            ))
        }
    };

    // Collect all duplicate SSH public keys in authorized_keys.
    let duplicate_public_keys = {
        let system_config_public_keys: HashSet<_> = config_a
            .authorized_key_entries()
            .iter()
            .cloned()
            .map(|authorized_key| authorized_key.as_ref().public_key())
            .collect();
        let config_public_keys: HashSet<_> = config_b
            .authorized_key_entries()
            .iter()
            .cloned()
            .map(|authorized_key| authorized_key.as_ref().public_key())
            .collect();
        let duplicates: HashSet<_> = system_config_public_keys
            .intersection(&config_public_keys)
            .cloned()
            .map(|public_key| {
                let mut public_key = public_key.clone();
                // Unset the comment as it may be set to different values.
                public_key.set_comment("");
                format!("\"{}\"", public_key.to_string())
            })
            .collect();

        if duplicates.is_empty() {
            None
        } else {
            let mut duplicates = Vec::from_iter(duplicates);
            duplicates.sort();
            Some(format!(
                "the duplicate SSH public key{} {}",
                if duplicates.len() > 1 { "s" } else { "" },
                duplicates.join(", ")
            ))
        }
    };

    let messages = [duplicate_system_user_ids, duplicate_public_keys];
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

/// Validates a required config object against an optional one.
///
/// Ensures that the the two configuration objects have no overlapping system user IDs or SSH
/// authorized_keys.
///
/// # Errors
///
/// Returns an error if there are
///
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
#[cfg(feature = "_hsm-backend")]
fn validate_config_against_optional_config<T, U>(
    config_a: &Option<T>,
) -> impl FnOnce(&U, &()) -> garde::Result + '_
where
    T: ConfigAuthorizedKeyEntries + ConfigSystemUserIds,
    U: ConfigAuthorizedKeyEntries + ConfigSystemUserIds,
{
    move |config_b, _| {
        let Some(config_a) = config_a else {
            return Ok(());
        };

        validate_confs(config_a, config_b)
    }
}

/// Validates two optional config objects against each other.
///
/// Ensures that - if both config objects are present - they have no overlapping system user IDs or
/// SSH authorized_keys.
///
/// # Errors
///
/// Returns an error if there are
///
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
#[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
fn validate_two_optional_configs<T, U>(
    backend_config_a: &Option<T>,
) -> impl FnOnce(&Option<U>, &()) -> garde::Result + '_
where
    T: ConfigAuthorizedKeyEntries + ConfigSystemUserIds,
    U: ConfigAuthorizedKeyEntries + ConfigSystemUserIds,
{
    move |backend_config_b, _| {
        if let Some(backend_config_a) = backend_config_a
            && let Some(backend_config_b) = backend_config_b
        {
            validate_confs(backend_config_a, backend_config_b)?;
        };
        Ok(())
    }
}

/// The configuration of a Signstar system.
///
/// Tracks system-wide configuration items, as well as configurations for specific backends.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// System configuration object.
    // Validate against NetHsmConfig if support is compiled in.
    #[cfg_attr(
        feature = "nethsm",
        garde(custom(validate_config_against_optional_config(&self.nethsm)))
    )]
    // Validate against YubiHsm2Config if support is compiled in.
    #[cfg_attr(
        feature = "yubihsm2",
        garde(custom(validate_config_against_optional_config(&self.yubihsm2)))
    )]
    #[garde(dive)]
    system: SystemConfig,

    /// Optional configuration object for NetHSM backends.
    ///
    /// # Note
    ///
    /// Only supported when using the `nethsm` feature.
    #[cfg(feature = "nethsm")]
    // Validate against YubiHsm2Config if support is compiled in.
    #[cfg_attr(
        all(feature = "nethsm", feature = "yubihsm2"),
        garde(custom(validate_two_optional_configs(&self.yubihsm2)))
    )]
    #[garde(dive)]
    #[serde(skip_serializing_if = "Option::is_none")]
    nethsm: Option<NetHsmConfig>,

    /// Optional configuration object for YubiHSM2 backends.
    ///
    /// # Note
    ///
    /// Only supported when using the `yubihsm2` feature.
    #[cfg(feature = "yubihsm2")]
    // Validate against NetHsmConfig if support is compiled in.
    #[cfg_attr(
        all(feature = "nethsm", feature = "yubihsm2"),
        garde(custom(validate_two_optional_configs(&self.nethsm)))
    )]
    #[garde(dive)]
    #[serde(skip_serializing_if = "Option::is_none")]
    yubihsm2: Option<YubiHsm2Config>,
}

impl Config {
    /// Serializes `self` as a YAML string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_yaml_string(&self) -> Result<String, crate::Error> {
        serde_saphyr::to_string(&self).map_err(|source| {
            crate::ConfigError::YamlSerialize {
                context: "serializing Signstar config",
                source,
            }
            .into()
        })
    }

    /// Creates a new [`Config`] from a string slice containing YAML data.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization or validation fails.
    pub fn from_yaml_str(s: &str) -> Result<Self, crate::Error> {
        let config: Self =
            serde_saphyr::from_str(s).map_err(|source| crate::ConfigError::YamlDeserialize {
                context: "creating a Signstar configuration object".to_string(),
                source,
            })?;

        config
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "validating a Signstar configuration object".to_string(),
                source,
            })?;

        Ok(config)
    }

    /// Creates a new [`Config`] from a file containing YAML data.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization or validation fails.
    pub fn from_yaml_file(path: Option<&Path>) -> Result<Self, crate::Error> {
        let path = if let Some(path) = path {
            path.to_path_buf()
        } else {
            let Some(path) = get_config_file() else {
                return Err(crate::ConfigError::ConfigIsMissing.into());
            };
            path
        };
        info!("Reading Signstar configuration file {path:?}");

        let config: Self = serde_saphyr::from_str(&read_to_string(&path).map_err(|source| {
            crate::Error::IoPath {
                path: path.clone(),
                context: "reading it to string",
                source,
            }
        })?)
        .map_err(|source| crate::ConfigError::YamlDeserialize {
            context: "creating a Signstar configuration object".to_string(),
            source,
        })?;

        config
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "validating a Signstar configuration object".to_string(),
                source,
            })?;

        Ok(config)
    }

    /// Returns a reference to the [`SystemConfig`].
    pub fn system(&self) -> &SystemConfig {
        &self.system
    }

    /// Returns a reference to the [`NetHsmConfig`].
    #[cfg(feature = "nethsm")]
    pub fn nethsm(&self) -> Option<&NetHsmConfig> {
        self.nethsm.as_ref()
    }

    /// Returns a reference to the [`YubiHsm2Config`].
    #[cfg(feature = "yubihsm2")]
    pub fn yubihsm2(&self) -> Option<&YubiHsm2Config> {
        self.yubihsm2.as_ref()
    }
}

/// A builder for [`Config`].
#[derive(Clone, Debug)]
pub struct ConfigBuilder(Config);

impl ConfigBuilder {
    /// Adds a [`NetHsmConfig`] to the builder.
    #[cfg(feature = "nethsm")]
    pub fn set_nethsm_config(mut self, nethsm: NetHsmConfig) -> Self {
        self.0.nethsm = Some(nethsm);
        self
    }

    /// Adds a [`YubiHsm2Config`] to the builder.
    #[cfg(feature = "yubihsm2")]
    pub fn set_yubihsm2_config(mut self, yubihsm2: YubiHsm2Config) -> Self {
        self.0.yubihsm2 = Some(yubihsm2);
        self
    }

    /// Creates a [`Config`] from the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if validation for the [`Config`] fails.
    pub fn finish(self) -> Result<Config, crate::Error> {
        self.0
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "validating a configuration object".to_string(),
                source,
            })?;

        Ok(self.0)
    }
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, thread::current};

    use insta::{assert_snapshot, with_settings};
    use rstest::rstest;
    #[cfg(feature = "_hsm-backend")]
    use signstar_crypto::{
        key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
        openpgp::OpenPgpUserIdList,
    };
    use testresult::TestResult;

    use super::*;

    const SNAPSHOT_PATH: &str = "fixtures/file/";

    mod system {
        use std::collections::HashSet;

        #[cfg(feature = "nethsm")]
        use nethsm::ConnectionSecurity;
        use signstar_crypto::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};

        use super::*;
        #[cfg(feature = "nethsm")]
        use crate::NetHsmMetricsUsers;
        use crate::config::SystemUserMapping;

        #[rstest]
        #[case::only_system_config(
            "Configuration with system-wide configuration but no backend settings",
            ConfigBuilder::new(SystemConfig::new(
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
                )?).finish()?
        )]
        #[cfg_attr(feature = "nethsm", case::system_and_nethsm_config(
            "Configuration with system-wide and NetHSM configuration",
            ConfigBuilder::new(SystemConfig::new(
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
                )?).set_nethsm_config(NetHsmConfig::new(
                    HashSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    HashSet::from_iter([
                        NetHsmUserMapping::Admin("admin".parse()?),
                        NetHsmUserMapping::Backup{
                            backend_user: "backup".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host".parse()?,
                            system_user: "backup-user".parse()?,
                        },
                        NetHsmUserMapping::Metrics {
                            backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                            system_user: "metrics-user".parse()?,
                        },
                        NetHsmUserMapping::Signing {
                            backend_user: "signing".parse()?,
                            signing_key_id: "signing1".parse()?,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                            system_user: "signing-user".parse()?,
                            tag: "signing1".to_string(),
                        }
                    ]),
                )?).finish()?
        ))]
        #[cfg_attr(feature = "yubihsm2", case::system_and_yubishm2_config(
            "Configuration with system-wide and YubiHSM2 configuration",
            ConfigBuilder::new(SystemConfig::new(
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
                )?).set_yubihsm2_config(YubiHsm2Config::new(
                    HashSet::from_iter([
                        YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    HashSet::from_iter([
                        YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                        YubiHsm2UserMapping::Backup {
                            authentication_key_id: 2,
                            wrapping_key_id: 2,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host".parse()?,
                            system_user: "backup-user".parse()?,
                        },
                        YubiHsm2UserMapping::AuditLog {
                            authentication_key_id: 3,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                            system_user: "metrics-user".parse()?,
                        },
                        YubiHsm2UserMapping::Signing {
                            authentication_key_id: 4,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            signing_key_id: 1,
                            domain: 1.try_into()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                            system_user: "signing2".parse()? }
                    ]),
                )?).finish()?
        ))]
        #[cfg_attr(all(feature = "yubihsm2", feature = "nethsm"), case::system_nethsm_and_yubishm2_config(
            "Configuration with system-wide, NetHSM and YubiHSM2 configuration",
            ConfigBuilder::new(SystemConfig::new(
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
                )?).set_nethsm_config(NetHsmConfig::new(
                    HashSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    HashSet::from_iter([
                        NetHsmUserMapping::Admin("admin".parse()?),
                        NetHsmUserMapping::Backup{
                            backend_user: "backup".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                            system_user: "nethsm-backup-user".parse()?,
                        },
                        NetHsmUserMapping::Metrics {
                            backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                            system_user: "nethsm-metrics-user".parse()?,
                        },
                        NetHsmUserMapping::Signing {
                            backend_user: "signing".parse()?,
                            signing_key_id: "signing1".parse()?,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
                            system_user: "nethsm-signing-user".parse()?,
                            tag: "signing1".to_string(),
                        }
                    ]),
                )?).set_yubihsm2_config(YubiHsm2Config::new(
                    HashSet::from_iter([
                        YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    HashSet::from_iter([
                        YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                        YubiHsm2UserMapping::Backup {
                            authentication_key_id: 2,
                            wrapping_key_id: 2,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrIYA+bfMBThUP5lKbMFEHiytmcCPhpkGrB/85n0mAN user@host".parse()?,
                            system_user: "yubihsm2-backup-user".parse()?,
                        },
                        YubiHsm2UserMapping::AuditLog {
                            authentication_key_id: 3,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                            system_user: "yubihsm2-metrics-user".parse()?,
                        },
                        YubiHsm2UserMapping::Signing {
                            authentication_key_id: 4,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            signing_key_id: 1,
                            domain: 1.try_into()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                            system_user: "yubihsm2-signing-user".parse()? }
                    ]),
                )?).finish()?
        ))]
        fn config_to_yaml_string(#[case] description: &str, #[case] config: Config) -> TestResult {
            let config_str = config.to_yaml_string()?;

            with_settings!({
                description => description,
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), config_str);
            });

            Ok(())
        }

        #[cfg(feature = "_hsm-backend")]
        #[rstest]
        #[cfg_attr(feature = "nethsm", case::system_and_nethsm_config(
            "Configuration with system-wide and NetHSM configuration has duplicate system users and SSH public keys",
            ConfigBuilder::new(SystemConfig::new(
                    1,
                    AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    NonAdministrativeSecretHandling::SystemdCreds,
                    HashSet::from_iter([
                        SystemUserMapping::ShareHolder {
                            system_user: "share-holder1".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                        },
                        SystemUserMapping::ShareHolder {
                            system_user: "share-holder2".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                        },
                        SystemUserMapping::ShareHolder {
                            system_user: "share-holder3".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        },
                        SystemUserMapping::WireGuardDownload {
                            system_user: "signing-user".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                        },
                    ]),
                )?).set_nethsm_config(NetHsmConfig::new(
                    HashSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    HashSet::from_iter([
                        NetHsmUserMapping::Admin("admin".parse()?),
                        NetHsmUserMapping::Backup{
                            backend_user: "backup".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                            system_user: "share-holder1".parse()?,
                        },
                        NetHsmUserMapping::Metrics {
                            backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                            system_user: "metrics-user".parse()?,
                        },
                        NetHsmUserMapping::Signing {
                            backend_user: "signing".parse()?,
                            signing_key_id: "signing1".parse()?,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                            system_user: "signing-user".parse()?,
                            tag: "signing1".to_string(),
                        }
                    ]),
                )?).finish()
        ))]
        #[cfg_attr(feature = "yubihsm2", case::system_and_yubishm2_config(
            "Configuration with system-wide and YubiHSM2 configuration",
            ConfigBuilder::new(SystemConfig::new(
                    1,
                    AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    NonAdministrativeSecretHandling::SystemdCreds,
                    HashSet::from_iter([
                        SystemUserMapping::ShareHolder {
                            system_user: "share-holder1".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                        },
                        SystemUserMapping::ShareHolder {
                            system_user: "share-holder2".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                        },
                        SystemUserMapping::ShareHolder {
                            system_user: "share-holder3".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        },
                        SystemUserMapping::WireGuardDownload {
                            system_user: "signing2".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                        },
                    ]),
                )?).set_yubihsm2_config(YubiHsm2Config::new(
                    HashSet::from_iter([
                        YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    HashSet::from_iter([
                        YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                        YubiHsm2UserMapping::Backup {
                            authentication_key_id: 2,
                            wrapping_key_id: 2,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                            system_user: "share-holder1".parse()?,
                        },
                        YubiHsm2UserMapping::AuditLog {
                            authentication_key_id: 3,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                            system_user: "metrics-user".parse()?,
                        },
                        YubiHsm2UserMapping::Signing {
                            authentication_key_id: 4,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            signing_key_id: 1,
                            domain: 1.try_into()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                            system_user: "signing2".parse()? }
                    ]),
                )?).finish()
        ))]
        #[cfg_attr(all(feature = "yubihsm2", feature = "nethsm"), case::system_nethsm_and_yubishm2_config(
            "Configuration with system-wide, NetHSM and YubiHSM2 configuration",
            ConfigBuilder::new(SystemConfig::new(
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
                )?).set_nethsm_config(NetHsmConfig::new(
                    HashSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    HashSet::from_iter([
                        NetHsmUserMapping::Admin("admin".parse()?),
                        NetHsmUserMapping::Backup{
                            backend_user: "backup".parse()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                            system_user: "backup-user".parse()?,
                        },
                        NetHsmUserMapping::Metrics {
                            backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                            system_user: "metrics-user".parse()?,
                        },
                        NetHsmUserMapping::Signing {
                            backend_user: "signing".parse()?,
                            signing_key_id: "signing1".parse()?,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
                            system_user: "signing-user".parse()?,
                            tag: "signing1".to_string(),
                        }
                    ]),
                )?).set_yubihsm2_config(YubiHsm2Config::new(
                    HashSet::from_iter([
                        YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    HashSet::from_iter([
                        YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                        YubiHsm2UserMapping::Backup {
                            authentication_key_id: 2,
                            wrapping_key_id: 2,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                            system_user: "backup-user".parse()?,
                        },
                        YubiHsm2UserMapping::AuditLog {
                            authentication_key_id: 3,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                            system_user: "metrics-user".parse()?,
                        },
                        YubiHsm2UserMapping::Signing {
                            authentication_key_id: 4,
                            key_setup: SigningKeySetup::new(
                                KeyType::Curve25519,
                                vec![KeyMechanism::EdDsaSignature],
                                None,
                                SignatureType::EdDsa,
                                CryptographicKeyContext::OpenPgp {
                                    user_ids: OpenPgpUserIdList::new(vec![
                                        "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                    ])?,
                                    version: "v4".parse()?,
                                },
                            )?,
                            signing_key_id: 1,
                            domain: 1.try_into()?,
                            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
                            system_user: "signing-user".parse()? }
                    ]),
                )?).finish()
        ))]
        fn config_fails_validation(
            #[case] description: &str,
            #[case] config_result: Result<Config, crate::Error>,
        ) -> TestResult {
            let error_message = match config_result {
                Err(error) => error.to_string(),
                Ok(config) => panic!(
                    "Expected to fail with Error::Validation, but succeeded instead: {}",
                    config.to_yaml_string()?
                ),
            };
            eprintln!(" foo");

            with_settings!({
                description => description,
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), error_message);
            });

            Ok(())
        }

        #[rstest]
        fn roundtrip_yaml_config_only_system_config(
            #[files("src/config/file/fixtures/valid_config/only-system-config-*.yaml")]
            #[mode = str]
            s: &str,
        ) -> TestResult {
            let config = Config::from_yaml_str(s)?;

            assert_eq!(config.to_yaml_string()?, s);

            Ok(())
        }

        #[rstest]
        #[cfg(feature = "nethsm")]
        fn roundtrip_yaml_config_system_and_nethsm_config(
            #[files("src/config/file/fixtures/valid_config/system-and-nethsm-config-*.yaml")]
            #[mode = str]
            s: &str,
        ) -> TestResult {
            let config = Config::from_yaml_str(s)?;

            assert_eq!(config.to_yaml_string()?, s);

            Ok(())
        }

        #[rstest]
        #[cfg(feature = "yubihsm2")]
        fn roundtrip_yaml_config_system_and_yubihsm2_config(
            #[files("src/config/file/fixtures/valid_config/system-and-yubihsm2-config-*.yaml")]
            #[mode = str]
            s: &str,
        ) -> TestResult {
            let config = Config::from_yaml_str(s)?;

            assert_eq!(config.to_yaml_string()?, s);

            Ok(())
        }

        #[rstest]
        #[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
        fn roundtrip_yaml_config_system_nethsm_and_yubihsm2_config(
            #[files(
                "src/config/file/fixtures/valid_config/system-nethsm-and-yubihsm2-config-*.yaml"
            )]
            #[mode = str]
            s: &str,
        ) -> TestResult {
            let config = Config::from_yaml_str(s)?;

            assert_eq!(config.to_yaml_string()?, s);

            Ok(())
        }
    }
}
