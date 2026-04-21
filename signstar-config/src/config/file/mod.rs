//! Configuration file handling.

#[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
pub mod impl_all;
#[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
pub mod impl_nethsm;
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
pub mod impl_none;
#[cfg(all(feature = "yubihsm2", not(feature = "nethsm")))]
pub mod impl_yubihsm2;

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use std::collections::BTreeSet;
use std::{
    collections::HashSet,
    fs::read_to_string,
    path::{Path, PathBuf},
    str::FromStr,
};

use garde::Validate;
use log::info;
#[cfg(feature = "nethsm")]
use nethsm::Connection;
use serde::{Deserialize, Serialize};
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_crypto::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};
#[cfg(feature = "yubihsm2")]
use signstar_yubihsm2::Connection as YubiHsm2Connection;
use strum::{AsRefStr, VariantNames};

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use crate::config::{ConfigAuthorizedKeyEntries, ConfigSystemUserIds};
use crate::config::{ConfigSystemUserData, Error, SystemConfig, SystemUserData};
#[cfg(feature = "nethsm")]
use crate::nethsm::{NetHsmConfig, NetHsmUserMapping};
#[cfg(feature = "yubihsm2")]
use crate::yubihsm2::{YubiHsm2Config, YubiHsm2UserMapping};

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
        connections: BTreeSet<Connection>,

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
        connections: BTreeSet<YubiHsm2Connection>,

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
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
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
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
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
        }

        Ok(())
    }
}

/// The supported configuration file formats.
#[derive(AsRefStr, Clone, Copy, Debug, Default, strum::Display, VariantNames)]
#[strum(serialize_all = "lowercase")]
enum ConfigFileFormat {
    #[default]
    Yaml,
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
    /// The default config directory below "/usr/".
    pub const DEFAULT_CONFIG_DIR: &str = "/usr/share/signstar/";

    /// The override config directory below "/run/".
    pub const RUN_OVERRIDE_CONFIG_DIR: &str = "/run/signstar/";

    /// The override config directory below "/etc/".
    pub const ETC_OVERRIDE_CONFIG_DIR: &str = "/etc/signstar/";

    /// The configuration file name (without file type suffix).
    pub const CONFIG_NAME: &str = "config";

    /// Returns the default location of the Signstar configuration file on a system.
    pub fn default_system_path() -> PathBuf {
        PathBuf::from(Self::DEFAULT_CONFIG_DIR).join(PathBuf::from(format!(
            "{}.{}",
            Self::CONFIG_NAME,
            ConfigFileFormat::default()
        )))
    }

    /// Returns the first found path of a Signstar configuratino on the system.
    ///
    /// # Errors
    ///
    /// Returns an error if no configuration file is found.
    pub fn first_existing_system_path() -> Result<PathBuf, crate::Error> {
        let path = Self::list_config_file_paths()
            .into_iter()
            .find(|path| path.is_file());
        path.ok_or(Error::ConfigIsMissing.into())
    }

    /// Returns the list of supported directory paths in which configuration files may reside.
    ///
    /// The returned list of paths is sorted in increasing precedence.
    pub fn list_config_dirs() -> Vec<PathBuf> {
        [
            Self::DEFAULT_CONFIG_DIR,
            Self::RUN_OVERRIDE_CONFIG_DIR,
            Self::ETC_OVERRIDE_CONFIG_DIR,
        ]
        .iter()
        .map(PathBuf::from)
        .collect()
    }

    /// Returns the list of supported configuration file paths.
    ///
    /// The returned list of paths is sorted in increasing precedence.
    pub fn list_config_file_paths() -> Vec<PathBuf> {
        Self::list_config_dirs()
            .into_iter()
            .map(|dir| {
                dir.join(
                    PathBuf::from(Self::CONFIG_NAME)
                        .with_added_extension(ConfigFileFormat::default().as_ref()),
                )
            })
            .collect()
    }

    /// Creates a new [`Config`] from a string slice containing YAML data.
    ///
    /// # Errors
    ///
    /// Returns an error if deserialization or validation fails.
    fn from_yaml_str(s: &str) -> Result<Self, crate::Error> {
        let config: Self = serde_saphyr::from_str(s).map_err(|source| Error::YamlDeserialize {
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
    /// Returns an error if
    /// - the file does not exist
    /// - deserialization or validation fails.
    fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        let path = path.as_ref();
        info!("Reading Signstar configuration file {path:?}");

        let config_data = read_to_string(path).map_err(|source| crate::Error::IoPath {
            path: path.to_path_buf(),
            context: "reading it to string",
            source,
        })?;
        Self::from_yaml_str(&config_data)
    }

    /// Creates a new [`Config`] from a file `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - `path` has no file extension
    /// - `path` does not use one of the supported file extensions
    /// - creating a [`Config`] from the data fails
    /// - validating a [`Config`] created from the data fails
    pub fn from_file_path(path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        let path = path.as_ref();
        let extension = {
            let Some(extension) = path.extension() else {
                return Err(Error::MissingFileExtension {
                    path: path.to_path_buf(),
                }
                .into());
            };
            extension.to_string_lossy().to_string()
        };

        if !ConfigFileFormat::VARIANTS.contains(&extension.as_ref()) {
            return Err(Error::UnsupportedFileExtension {
                path: path.to_path_buf(),
                extension,
            }
            .into());
        }

        Self::from_yaml_file(path)
    }

    /// Creates a new [`Config`] from the first found Signstar configuration file path on the
    /// system.
    ///
    /// # Note
    ///
    /// Uses [`Config::first_existing_system_path`] to determine the first existing Signstar
    /// configuration file path.
    ///
    /// # Errors
    ///
    /// Returns an error if [`Config`] creation from the found path fails.
    pub fn from_system_path() -> Result<Self, crate::Error> {
        Self::from_yaml_file(Self::first_existing_system_path()?)
    }

    /// Serializes `self` as a YAML string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_yaml_string(&self) -> Result<String, crate::Error> {
        serde_saphyr::to_string(&self).map_err(|source| {
            Error::YamlSerialize {
                context: "serializing Signstar config",
                source,
            }
            .into()
        })
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

impl FromStr for Config {
    type Err = crate::Error;

    /// Creates a new [`Config`] from a string slice containing valid YAML.
    ///
    /// # Errors
    ///
    /// Returns an error if no [`Config`] can be created from `s`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Config::from_yaml_str(s)
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

/// The state of system users according to a Signstar configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemUserConfigState<'a> {
    pub(crate) system_user_data: HashSet<SystemUserData<'a>>,
}

impl<'a> From<&'a Config> for SystemUserConfigState<'a> {
    fn from(value: &'a Config) -> Self {
        Self {
            system_user_data: value.system_user_data(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, num::NonZeroUsize, thread::current};

    use insta::{assert_snapshot, with_settings};
    #[cfg(feature = "nethsm")]
    use nethsm::ConnectionSecurity;
    use pretty_assertions::assert_eq;
    use rstest::{fixture, rstest};
    use signstar_crypto::{AdministrativeSecretHandling, NonAdministrativeSecretHandling};
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    use signstar_crypto::{
        key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
        openpgp::OpenPgpUserIdList,
    };
    #[cfg(feature = "yubihsm2")]
    use signstar_yubihsm2::object::Domain;
    use tempfile::{NamedTempFile, TempDir};
    use testresult::TestResult;

    use super::*;
    use crate::config::{AuthorizedKeyEntry, SystemUserId, SystemUserMapping};
    #[cfg(feature = "nethsm")]
    use crate::nethsm::NetHsmMetricsUsers;

    const SNAPSHOT_PATH: &str = "fixtures/file/";

    /// Creates a default [`SystemConfig`] for testing purposes.
    #[fixture]
    fn default_system_config() -> TestResult<SystemConfig> {
        Ok(SystemConfig::new(
            1,
            AdministrativeSecretHandling::ShamirsSecretSharing {
                number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
            },
            NonAdministrativeSecretHandling::SystemdCreds,
            BTreeSet::from_iter([
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
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
                },
                SystemUserMapping::WireGuardDownload {
                    system_user: "wireguard-downloader".parse()?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                },
            ]),
        )?)
    }

    /// Creates a default [`NetHsmConfig`] for testing purposes.
    #[cfg(feature = "nethsm")]
    #[fixture]
    fn default_nethsm_config() -> TestResult<NetHsmConfig> {
        Ok(NetHsmConfig::new(
            BTreeSet::from_iter([
                Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
            ]),
            BTreeSet::from_iter([
                NetHsmUserMapping::Admin("admin".parse()?),
                NetHsmUserMapping::Backup{
                    backend_user: "backup".parse()?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                    system_user: "nethsm-backup-user".parse()?,
                },
                NetHsmUserMapping::HermeticMetrics {
                    backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                    system_user: "nethsm-hermetic-metrics-user".parse()?,
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
        )?)
    }

    /// Creates a default [`YubiHsm2Config`] for testing purposes.
    #[cfg(feature = "yubihsm2")]
    #[fixture]
    fn default_yubihsm2_config() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: "3".parse()?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: "2".parse()?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: "1".parse()?,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: "4".parse()?,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: "5".parse()?,
                    signing_key_id: "1".parse()?,
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
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            ]),
        )?)
    }

    /// Ensures, that [`Config::default_system_path`] always returns the same path.
    #[test]
    fn config_default_system_path() {
        assert_eq!(
            Config::default_system_path(),
            PathBuf::from("/usr/share/signstar/config.yaml")
        )
    }

    /// Ensures, that [`Config::list_config_file_paths`] always returns the same list of paths.
    #[test]
    fn config_list_config_file_paths() {
        assert_eq!(
            Config::list_config_file_paths(),
            vec![
                PathBuf::from("/usr/share/signstar/config.yaml"),
                PathBuf::from("/run/signstar/config.yaml"),
                PathBuf::from("/etc/signstar/config.yaml"),
            ]
        )
    }

    /// Ensures, that [`Config::from_file_path`] fails on missing file extensions.
    #[rstest]
    fn config_from_file_path_fails_on_missing_file_extension() -> TestResult {
        let temp_dir = TempDir::new()?;

        match Config::from_file_path(temp_dir.path().join("config")) {
            Ok(config) => panic!(
                "Should have failed to create a Config object, but succeeded instead: {config:?}"
            ),
            Err(crate::Error::Config(Error::MissingFileExtension { .. })) => {}
            Err(error) => panic!(
                "Should have failed with a ConfigError::MissingFileExtension, but failed with a different error instead: {error}"
            ),
        }

        Ok(())
    }

    /// Ensures, that [`Config::from_file_path`] fails on unsupported file extensions.
    #[rstest]
    fn config_from_file_path_fails_on_unsupported_file_extension() -> TestResult {
        let temp_file = NamedTempFile::with_suffix(".toml")?;

        match Config::from_file_path(temp_file.path()) {
            Ok(config) => panic!(
                "Should have failed to create a Config object, but succeeded instead: {config:?}"
            ),
            Err(crate::Error::Config(Error::UnsupportedFileExtension { .. })) => {}
            Err(error) => panic!(
                "Should have failed with a ConfigError::UnsupportedFileExtension, but failed with a different error instead: {error}"
            ),
        }

        Ok(())
    }

    /// Tests, that are only available when using no backend.
    #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
    mod no_backend {
        use std::collections::HashSet;

        use pretty_assertions::assert_eq;

        use super::*;
        use crate::config::{ConfigAuthorizedKeyEntries, ConfigSystemUserIds};

        /// Creates a default [`Config`] for testing purposes.
        #[fixture]
        fn default_config(default_system_config: TestResult<SystemConfig>) -> TestResult<Config> {
            Ok(ConfigBuilder::new(default_system_config?).finish()?)
        }

        /// Ensures, that [`Config::authorized_key_entries`] returns SSH authorized key entries
        /// correctly.
        #[rstest]
        fn config_authorized_key_entries(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<AuthorizedKeyEntry> = HashSet::from_iter([
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            ]);

            assert_eq!(
                config.authorized_key_entries(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Ensures, that [`Config::system_user_ids`] returns system user IDs correctly.
        #[rstest]
        fn config_system_user_ids(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<SystemUserId> = HashSet::from_iter([
                "share-holder1".parse()?,
                "share-holder2".parse()?,
                "share-holder3".parse()?,
                "wireguard-downloader".parse()?,
            ]);

            assert_eq!(
                config.system_user_ids(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }
    }

    /// Tests, that are only available when using the NetHSM (and no other) backend.
    #[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
    mod nethsm_backend {
        use pretty_assertions::assert_eq;

        use super::*;

        /// Creates a default [`Config`] for testing purposes.
        #[fixture]
        fn default_config(
            default_system_config: TestResult<SystemConfig>,
            default_nethsm_config: TestResult<NetHsmConfig>,
        ) -> TestResult<Config> {
            Ok(ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(default_nethsm_config?)
                .finish()?)
        }

        /// Ensures, that [`ConfigBuilder::finish`] fails on issues with overlapping data in
        /// configuration components.
        ///
        /// Here, a custom [`NetHsmConfig`] is staged together with a default [`SystemConfig`]
        /// (created by [`default_system_config`]) to create a failure scenario.
        #[rstest]
        #[case::two_duplicate_system_users_two_duplicate_ssh_public_keys(
            "Configuration with system-wide and NetHSM configuration has two duplicate system users and two duplicate SSH public keys",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
                    },
                    NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                        system_user: "share-holder2".parse()?,
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
                        system_user: "nethsm-signing-user".parse()?,
                        tag: "signing1".to_string(),
                    }
                ]),
            )?
        )]
        #[case::one_duplicate_system_user_two_duplicate_ssh_public_keys(
            "Configuration with system-wide and NetHSM configuration has one duplicate system user and two duplicate SSH public keys",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
                    },
                    NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
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
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "nethsm-signing-user".parse()?,
                        tag: "signing1".to_string(),
                    }
                ]),
            )?
        )]
        #[case::one_duplicate_system_user_one_duplicate_ssh_public_key(
            "Configuration with system-wide and NetHSM configuration has one duplicate system user and one duplicate SSH public key",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
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
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "nethsm-signing-user".parse()?,
                        tag: "signing1".to_string(),
                    }
                ]),
            )?
        )]
        #[case::one_duplicate_ssh_public_key(
            "Configuration with system-wide and NetHSM configuration has one duplicate SSH public key",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "nethsm-backup-user".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
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
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "nethsm-signing-user".parse()?,
                        tag: "signing1".to_string(),
                    }
                ]),
            )?
        )]
        #[case::one_duplicate_system_user(
            "Configuration with system-wide and NetHSM configuration has one duplicate system user",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
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
            )?
        )]
        fn config_builder_fails_validation(
            default_system_config: TestResult<SystemConfig>,
            #[case] description: &str,
            #[case] nethsm_config: NetHsmConfig,
        ) -> TestResult {
            let error_message = match ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(nethsm_config)
                .finish()
            {
                Err(error) => error.to_string(),
                Ok(config) => panic!(
                    "Expected to fail with Error::Validation, but succeeded instead: {}",
                    config.to_yaml_string()?
                ),
            };

            with_settings!({
                description => description,
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), error_message);
            });

            Ok(())
        }

        /// Ensures, that [`Config::nethsm`] returns the original input.
        #[rstest]
        fn config_nethsm(
            default_system_config: TestResult<SystemConfig>,
            default_nethsm_config: TestResult<NetHsmConfig>,
        ) -> TestResult {
            let nethsm_config = default_nethsm_config?;

            let config = ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(nethsm_config.clone())
                .finish()?;

            assert_eq!(
                &nethsm_config,
                config.nethsm().expect("a NetHsmConfig reference")
            );

            Ok(())
        }

        /// Ensures, that an optional [`UserBackendConnection`] can be retrieved from a [`Config`].
        #[rstest]
        #[case::nethsm_signing(
            "nethsm-signing-user",
            Some(UserBackendConnection::NetHsm {
                admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                    number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                    threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                },
                non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                connections: BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                mapping: NetHsmUserMapping::Signing {
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
            })
        )]
        #[case::none("foo", None)]
        fn config_user_backend_connection(
            default_config: TestResult<Config>,
            #[case] system_user: &str,
            #[case] expected_connection: Option<UserBackendConnection>,
        ) -> TestResult {
            let config = default_config?;
            assert_eq!(
                expected_connection,
                config.user_backend_connection(&system_user.parse()?)
            );

            Ok(())
        }

        /// Ensures, that [`Config::user_backend_connections`] returns the correct list of
        /// [`UserBackendConnection`] items according to a [`UserBackendConnectionFilter`].
        #[rstest]
        #[case::filter_all(
            UserBackendConnectionFilter::All,
            vec![
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Admin("admin".parse()?)
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "nethsm-backup-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                        system_user: "nethsm-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Signing {
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
                },
            ],
        )]
        #[case::filter_admin(
            UserBackendConnectionFilter::Admin,
            vec![
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Admin("admin".parse()?)
                },
            ],
        )]
        #[case::filter_non_admin(
            UserBackendConnectionFilter::NonAdmin,
            vec![
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "nethsm-backup-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                        system_user: "nethsm-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Signing {
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
                },
            ],
        )]
        fn config_user_backend_connections(
            default_config: TestResult<Config>,
            #[case] filter: UserBackendConnectionFilter,
            #[case] expected_connections: Vec<UserBackendConnection>,
        ) -> TestResult {
            let config = default_config?;

            assert_eq!(
                expected_connections,
                config.user_backend_connections(filter)
            );

            Ok(())
        }

        /// Ensures, that [`Config::authorized_key_entries`] returns SSH authorized key entries
        /// correctly.
        #[rstest]
        fn config_authorized_key_entries(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<AuthorizedKeyEntry> = HashSet::from_iter([
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
            ]);

            assert_eq!(
                config.authorized_key_entries(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Ensures, that [`Config::system_user_ids`] returns system user IDs correctly.
        #[rstest]
        fn config_system_user_ids(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<SystemUserId> = HashSet::from_iter([
                "share-holder1".parse()?,
                "share-holder2".parse()?,
                "share-holder3".parse()?,
                "wireguard-downloader".parse()?,
                "nethsm-backup-user".parse()?,
                "nethsm-hermetic-metrics-user".parse()?,
                "nethsm-metrics-user".parse()?,
                "nethsm-signing-user".parse()?,
            ]);

            assert_eq!(
                config.system_user_ids(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Ensures, that a [`Config`] object leads to a specific YAML output.
        ///
        /// In this particular case, a [`SystemConfig`] and a [`NetHsmConfig`] object are present.
        #[rstest]
        fn config_to_yaml_string(
            default_system_config: TestResult<SystemConfig>,
            default_nethsm_config: TestResult<NetHsmConfig>,
        ) -> TestResult {
            let config = ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(default_nethsm_config?)
                .finish()?;
            let config_str = config.to_yaml_string()?;

            with_settings!({
                description => "Configuration with system-wide and NetHSM configuration",
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), config_str);
            });

            Ok(())
        }

        /// Ensures, that a valid [`Config`] can be created from a YAML file and turned back into
        /// the same YAML string.
        ///
        /// The configuration file describes a [`SystemConfig`] and a [`NetHsmConfig`] object.
        #[rstest]
        fn roundtrip_yaml_config(
            #[files("../fixtures/config/nethsm_backend/*.yaml")] path: PathBuf,
        ) -> TestResult {
            let config_string = read_to_string(&path)?;
            let config = Config::from_file_path(&path)?;

            assert_eq!(config.to_yaml_string()?, config_string);

            Ok(())
        }

        /// Ensures, that [`AdministrativeSecretHandling`] and
        /// [`NonAdministrativeSecretHandling`]can be retrieved from a
        /// [`UserBackendConnection`].
        #[rstest]
        fn user_backend_connection_secret_handling(
            default_config: TestResult<Config>,
        ) -> TestResult {
            let config = default_config?;
            let admin_secret_handling = AdministrativeSecretHandling::ShamirsSecretSharing {
                number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
            };
            let non_admin_secret_handling = NonAdministrativeSecretHandling::SystemdCreds;

            let user_backend_connection = config
                .user_backend_connection(&"nethsm-signing-user".parse()?)
                .expect("there to be a mapping of the requested name");

            assert_eq!(
                user_backend_connection.admin_secret_handling(),
                admin_secret_handling
            );
            assert_eq!(
                user_backend_connection.non_admin_secret_handling(),
                non_admin_secret_handling
            );

            Ok(())
        }
    }

    /// Tests, that are only available when using the YubiHSM2 (and no other) backend.
    #[cfg(all(feature = "yubihsm2", not(feature = "nethsm")))]
    mod yubihsm2_backend {
        use pretty_assertions::assert_eq;

        use super::*;

        /// Creates a default [`Config`] for testing purposes.
        #[fixture]
        fn default_config(
            default_system_config: TestResult<SystemConfig>,
            default_yubihsm2_config: TestResult<YubiHsm2Config>,
        ) -> TestResult<Config> {
            Ok(ConfigBuilder::new(default_system_config?)
                .set_yubihsm2_config(default_yubihsm2_config?)
                .finish()?)
        }

        /// Ensures, that [`ConfigBuilder::finish`] fails on issues with overlapping data in
        /// configuration components.
        ///
        /// Here, a custom [`YubiHsm2Config`] is staged together with a default [`SystemConfig`]
        /// (created by [`default_system_config`]) to create a failure scenario.
        #[rstest]
        #[case::two_duplicate_system_users_two_duplicate_ssh_public_keys(
            "Configuration with system-wide and YubiHSM2 configuration has two duplicate system users and two duplicate SSH public keys",
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "share-holder2".parse()?,
                    },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                ]),
            )?
         )]
        #[case::one_duplicate_system_user_two_duplicate_ssh_public_keys(
            "Configuration with system-wide and YubiHSM2 configuration has one duplicate system user and two duplicate SSH public keys",
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                ]),
            )?
         )]
        #[case::one_duplicate_system_user_one_duplicate_ssh_public_key(
            "Configuration with system-wide and YubiHSM2 configuration has one duplicate system user and one duplicate SSH public key",
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                ]),
            )?
         )]
        #[case::one_duplicate_ssh_public_key(
            "Configuration with system-wide and YubiHSM2 configuration has one duplicate SSH public key",
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "yubihsm2-backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                ]),
            )?
         )]
        #[case::one_duplicate_system_user(
            "Configuration with system-wide and YubiHSM2 configuration has one duplicate system user",
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                ]),
            )?
         )]
        fn config_builder_fails_validation(
            default_system_config: TestResult<SystemConfig>,
            #[case] description: &str,
            #[case] yubihsm2_config: YubiHsm2Config,
        ) -> TestResult {
            let error_message = match ConfigBuilder::new(default_system_config?)
                .set_yubihsm2_config(yubihsm2_config)
                .finish()
            {
                Err(error) => error.to_string(),
                Ok(config) => panic!(
                    "Expected to fail with Error::Validation, but succeeded instead: {}",
                    config.to_yaml_string()?
                ),
            };

            with_settings!({
                description => description,
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), error_message);
            });

            Ok(())
        }

        /// Ensures, that [`Config::yubihsm2`] returns the original input.
        #[rstest]
        fn config_yubihsm2(
            default_system_config: TestResult<SystemConfig>,
            default_yubihsm2_config: TestResult<YubiHsm2Config>,
        ) -> TestResult {
            let yubihsm2_config = default_yubihsm2_config?;

            let config = ConfigBuilder::new(default_system_config?)
                .set_yubihsm2_config(yubihsm2_config.clone())
                .finish()?;

            assert_eq!(
                &yubihsm2_config,
                config.yubihsm2().expect("a YubiHsm2Config reference")
            );

            Ok(())
        }

        /// Ensures, that an optional [`UserBackendConnection`] can be retrieved from a [`Config`].
        #[rstest]
        #[case::yubihsm2_signing(
            "yubihsm2-signing-user",
            Some(UserBackendConnection::YubiHsm2 {
                admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                    number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                    threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                },
                non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                connections: BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                mapping: YubiHsm2UserMapping::Signing {
                    authentication_key_id: "5".parse()?,
                    signing_key_id: "1".parse()?,
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
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            })
        )]
        #[case::none("foo", None)]
        fn config_user_backend_connection(
            default_config: TestResult<Config>,
            #[case] system_user: &str,
            #[case] expected_connection: Option<UserBackendConnection>,
        ) -> TestResult {
            let config = default_config?;
            assert_eq!(
                expected_connection,
                config.user_backend_connection(&system_user.parse()?)
            );

            Ok(())
        }

        /// Ensures, that [`Config::user_backend_connections`] returns the correct list of
        /// [`UserBackendConnection`] items according to a [`UserBackendConnectionFilter`].
        #[rstest]
        #[case::filter_all(
            UserBackendConnectionFilter::All,
            vec![
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "yubihsm2-backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                },
            ],
        )]
        #[case::filter_admin(
            UserBackendConnectionFilter::Admin,
            vec![
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                },
            ],
        )]
        #[case::filter_non_admin(
            UserBackendConnectionFilter::NonAdmin,
            vec![
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "yubihsm2-backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                },
            ],
        )]
        fn config_user_backend_connections(
            default_config: TestResult<Config>,
            #[case] filter: UserBackendConnectionFilter,
            #[case] expected_connections: Vec<UserBackendConnection>,
        ) -> TestResult {
            let config = default_config?;

            assert_eq!(
                expected_connections,
                config.user_backend_connections(filter)
            );

            Ok(())
        }

        /// Ensures, that a [`Config`] object leads to a specific YAML output.
        ///
        /// In this particular case, a [`SystemConfig`] and a [`YubiHsm2Config`] object are present.
        #[rstest]
        fn config_to_yaml_string(
            default_system_config: TestResult<SystemConfig>,
            default_yubihsm2_config: TestResult<YubiHsm2Config>,
        ) -> TestResult {
            let config = ConfigBuilder::new(default_system_config?)
                .set_yubihsm2_config(default_yubihsm2_config?)
                .finish()?;
            let config_str = config.to_yaml_string()?;

            with_settings!({
                description => "Configuration with system-wide and YubiHSM2 configuration",
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), config_str);
            });

            Ok(())
        }

        /// Ensures, that [`Config::authorized_key_entries`] returns SSH authorized key entries
        /// correctly.
        #[rstest]
        fn config_authorized_key_entries(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<AuthorizedKeyEntry> = HashSet::from_iter([
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
            ]);

            assert_eq!(
                config.authorized_key_entries(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Ensures, that [`Config::system_user_ids`] returns system user IDs correctly.
        #[rstest]
        fn config_system_user_ids(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<SystemUserId> = HashSet::from_iter([
                "share-holder1".parse()?,
                "share-holder2".parse()?,
                "share-holder3".parse()?,
                "wireguard-downloader".parse()?,
                "yubihsm2-metrics-user".parse()?,
                "yubihsm2-backup-user".parse()?,
                "yubihsm2-hermetic-metrics-user".parse()?,
                "yubihsm2-signing-user".parse()?,
            ]);

            assert_eq!(
                config.system_user_ids(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Ensures, that a valid [`Config`] can be created from a YAML file and turned back into
        /// the same YAML string.
        ///
        /// The configuration file describes a [`SystemConfig`] and a [`YubiHsm2Config`] object.
        #[rstest]
        #[cfg(not(feature = "_yubihsm2-mockhsm"))]
        fn roundtrip_yaml_config(
            #[files("../fixtures/config/yubihsm2_backend/*.yaml")] path: PathBuf,
        ) -> TestResult {
            let config_string = read_to_string(&path)?;
            let config = Config::from_file_path(&path)?;

            assert_eq!(config.to_yaml_string()?, config_string);

            Ok(())
        }

        /// Ensures, that a valid [`Config`] can be created from a YAML file and turned back into
        /// the same YAML string.
        ///
        /// The configuration file describes a [`SystemConfig`] and a [`YubiHsm2Config`] object.
        #[rstest]
        #[cfg(feature = "_yubihsm2-mockhsm")]
        fn roundtrip_yaml_config_mockhsm(
            #[files("../fixtures/config/yubihsm2_mockhsm_backend/*.yaml")] path: PathBuf,
        ) -> TestResult {
            let config_string = read_to_string(&path)?;
            let config = Config::from_file_path(&path)?;

            assert_eq!(config.to_yaml_string()?, config_string);

            Ok(())
        }

        /// Ensures, that [`AdministrativeSecretHandling`] and
        /// [`NonAdministrativeSecretHandling`]can be retrieved from a
        /// [`UserBackendConnection`].
        #[rstest]
        fn user_backend_connection_secret_handling(
            default_config: TestResult<Config>,
        ) -> TestResult {
            let config = default_config?;
            let admin_secret_handling = AdministrativeSecretHandling::ShamirsSecretSharing {
                number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
            };
            let non_admin_secret_handling = NonAdministrativeSecretHandling::SystemdCreds;

            let user_backend_connection = config
                .user_backend_connection(&"yubihsm2-signing-user".parse()?)
                .expect("there to be a mapping of the requested name");

            assert_eq!(
                user_backend_connection.admin_secret_handling(),
                admin_secret_handling
            );
            assert_eq!(
                user_backend_connection.non_admin_secret_handling(),
                non_admin_secret_handling
            );

            Ok(())
        }
    }

    /// Tests, that are only available when using all available backends.
    #[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
    mod all_backends {
        use pretty_assertions::assert_eq;

        use super::*;

        /// Creates a default [`Config`] for testing purposes.
        #[fixture]
        fn default_config(
            default_system_config: TestResult<SystemConfig>,
            default_nethsm_config: TestResult<NetHsmConfig>,
            default_yubihsm2_config: TestResult<YubiHsm2Config>,
        ) -> TestResult<Config> {
            Ok(ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(default_nethsm_config?)
                .set_yubihsm2_config(default_yubihsm2_config?)
                .finish()?)
        }

        /// Ensures, that [`ConfigBuilder::finish`] fails on issues with overlapping data in
        /// configuration components.
        ///
        /// Here, custom [`NetHsmConfig`] and [`YubiHsm2Config`] objects are staged together with a
        /// default [`SystemConfig`] (created by [`default_system_config`]) to create a failure
        /// scenario.
        #[rstest]
        #[case::backend_overlap_duplicate_system_users_two_duplicate_ssh_public_keys(
            "Configuration with system-wide, NetHSM and YubiHSM2 configuration has two duplicate system users and two duplicate SSH public keys in the backends",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "backup-user".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
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
                        system_user: "nethsm-signing-user".parse()?,
                        tag: "nethsm-signing1".to_string(),
                    }
                ]),
            )?,
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                        system_user: "metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Backup {
                        authentication_key_id: "2".parse()?,
                        wrapping_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "backup-user".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
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
                        signing_key_id: "1".parse()?,
                        domain: Domain::One,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                        system_user: "yubihsm2-signing-user".parse()? }
                ]),
            )?,
        )]
        #[case::backend_overlap_one_duplicate_system_user(
            "Configuration with system-wide, NetHSM and YubiHSM2 configuration has one duplicate system user in the backends",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "backup-user".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
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
                        tag: "nethsm-signing1".to_string(),
                    }
                ]),
            )?,
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Backup {
                        authentication_key_id: "2".parse()?,
                        wrapping_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "backup-user".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
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
                        signing_key_id: "1".parse()?,
                        domain: Domain::One,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                        system_user: "yubihsm2-signing-user".parse()? }
                ]),
            )?,
        )]
        #[case::system_overlap_duplicate_system_users_two_duplicate_ssh_public_keys(
            "Configuration with system-wide, NetHSM and YubiHSM2 configuration has two duplicate system users and two duplicate SSH public keys in the system and the backends",
            NetHsmConfig::new(
                BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                BTreeSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                    },
                    NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                        system_user: "share-holder2".parse()?,
                    },
                    NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
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
                        tag: "nethsm-signing1".to_string(),
                    }
                ]),
            )?,
            YubiHsm2Config::new(
                BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                BTreeSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::Backup {
                        authentication_key_id: "2".parse()?,
                        wrapping_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                        system_user: "share-holder1".parse()?,
                    },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                        system_user: "share-holder2".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
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
                        signing_key_id: "1".parse()?,
                        domain: Domain::One,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                        system_user: "yubihsm2-signing-user".parse()? }
                ]),
            )?,
        )]
        fn config_fails_validation(
            default_system_config: TestResult<SystemConfig>,
            #[case] description: &str,
            #[case] nethsm_config: NetHsmConfig,
            #[case] yubihsm2_config: YubiHsm2Config,
        ) -> TestResult {
            let error_message = match ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(nethsm_config)
                .set_yubihsm2_config(yubihsm2_config)
                .finish()
            {
                Err(error) => error.to_string(),
                Ok(config) => panic!(
                    "Expected to fail with Error::Validation, but succeeded instead: {}",
                    config.to_yaml_string()?
                ),
            };

            with_settings!({
                description => description,
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), error_message);
            });

            Ok(())
        }

        /// Ensures, that an optional [`UserBackendConnection`] can be retrieved from a [`Config`].
        #[rstest]
        #[case::nethsm_signing(
            "nethsm-signing-user",
            Some(UserBackendConnection::NetHsm {
                admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                    number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                    threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                },
                non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                connections: BTreeSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                ]),
                mapping: NetHsmUserMapping::Signing {
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
            })
        )]
        #[case::yubihsm2_signing(
            "yubihsm2-signing-user",
            Some(UserBackendConnection::YubiHsm2 {
                admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                    number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                    threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                },
                non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                connections: BTreeSet::from_iter([
                    YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                ]),
                mapping: YubiHsm2UserMapping::Signing {
                    authentication_key_id: "5".parse()?,
                    signing_key_id: "1".parse()?,
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
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            })
        )]
        #[case::none("foo", None)]
        fn config_user_backend_connection(
            default_config: TestResult<Config>,
            #[case] system_user: &str,
            #[case] expected_connection: Option<UserBackendConnection>,
        ) -> TestResult {
            let config = default_config?;
            assert_eq!(
                expected_connection,
                config.user_backend_connection(&system_user.parse()?)
            );

            Ok(())
        }

        /// Ensures, that [`Config::user_backend_connections`] returns the correct list of
        /// [`UserBackendConnection`] items according to a [`UserBackendConnectionFilter`].
        #[rstest]
        #[case::filter_all(
            UserBackendConnectionFilter::All,
            vec![
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Admin("admin".parse()?)
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "nethsm-backup-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                        system_user: "nethsm-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Signing {
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
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "yubihsm2-backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                },
            ],
        )]
        #[case::filter_admin(
            UserBackendConnectionFilter::Admin,
            vec![
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Admin("admin".parse()?)
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                },
            ],
        )]
        #[case::filter_non_admin(
            UserBackendConnectionFilter::NonAdmin,
            vec![
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                        system_user: "nethsm-backup-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::HermeticMetrics {
                        backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
                        system_user: "nethsm-hermetic-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Metrics {
                        backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                        system_user: "nethsm-metrics-user".parse()?,
                    }
                },
                UserBackendConnection::NetHsm {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        Connection::new("https://nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
                        Connection::new("https://nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
                    ]),
                    mapping: NetHsmUserMapping::Signing {
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
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "yubihsm2-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                        system_user: "yubihsm2-backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                    },
                },
                UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: AdministrativeSecretHandling::ShamirsSecretSharing {
                        number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                        threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
                    },
                    non_admin_secret_handling: NonAdministrativeSecretHandling::SystemdCreds,
                    connections: BTreeSet::from_iter([
                        YubiHsm2Connection::Usb {serial_number: "0012345678".parse()? },
                        YubiHsm2Connection::Usb {serial_number: "0087654321".parse()? },
                    ]),
                    mapping: YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
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
                        system_user: "yubihsm2-signing-user".parse()?,
                        domain: Domain::One,
                    }
                },
            ],
        )]
        fn config_user_backend_connections(
            default_config: TestResult<Config>,
            #[case] filter: UserBackendConnectionFilter,
            #[case] expected_connections: Vec<UserBackendConnection>,
        ) -> TestResult {
            let config = default_config?;

            assert_eq!(
                expected_connections,
                config.user_backend_connections(filter)
            );

            Ok(())
        }

        /// Ensures, that a [`Config`] object leads to a specific YAML output.
        ///
        /// In this particular case, a [`SystemConfig`], a [`NetHsmConfig`] and a [`YubiHsm2Config`]
        /// object are present.
        #[rstest]
        fn config_to_yaml_string(
            default_system_config: TestResult<SystemConfig>,
            default_nethsm_config: TestResult<NetHsmConfig>,
            default_yubihsm2_config: TestResult<YubiHsm2Config>,
        ) -> TestResult {
            let config = ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(default_nethsm_config?)
                .set_yubihsm2_config(default_yubihsm2_config?)
                .finish()?;
            let config_str = config.to_yaml_string()?;

            with_settings!({
                description => "Configuration with system-wide, NetHSM and YubiHSM2 configuration",
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), config_str);
            });

            Ok(())
        }

        /// Ensures, that [`Config::authorized_key_entries`] returns SSH authorized key entries
        /// correctly.
        #[rstest]
        fn config_authorized_key_entries(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<AuthorizedKeyEntry> = HashSet::from_iter([
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
            ]);

            assert_eq!(
                config.authorized_key_entries(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Ensures, that [`Config::system_user_ids`] returns system user IDs correctly.
        #[rstest]
        fn config_system_user_ids(default_config: TestResult<Config>) -> TestResult {
            let config = default_config?;
            let expected: HashSet<SystemUserId> = HashSet::from_iter([
                "share-holder1".parse()?,
                "share-holder2".parse()?,
                "share-holder3".parse()?,
                "wireguard-downloader".parse()?,
                "nethsm-backup-user".parse()?,
                "nethsm-hermetic-metrics-user".parse()?,
                "nethsm-metrics-user".parse()?,
                "nethsm-signing-user".parse()?,
                "yubihsm2-metrics-user".parse()?,
                "yubihsm2-backup-user".parse()?,
                "yubihsm2-hermetic-metrics-user".parse()?,
                "yubihsm2-signing-user".parse()?,
            ]);

            assert_eq!(
                config.system_user_ids(),
                expected.iter().collect::<HashSet<_>>()
            );
            Ok(())
        }

        /// Create a [`Config`] using [`ConfigBuilder`].
        #[rstest]
        fn config_builder_new(
            default_system_config: TestResult<SystemConfig>,
            default_nethsm_config: TestResult<NetHsmConfig>,
            default_yubihsm2_config: TestResult<YubiHsm2Config>,
        ) -> TestResult {
            let _config = ConfigBuilder::new(default_system_config?)
                .set_nethsm_config(default_nethsm_config?)
                .set_yubihsm2_config(default_yubihsm2_config?)
                .finish()?;

            Ok(())
        }

        /// Ensures, that a valid [`Config`] can be created from a YAML file and turned back into
        /// the same YAML string.
        ///
        /// The configuration file describes a [`SystemConfig`], [`NetHsmConfig`] and a
        /// [`YubiHsm2Config`] object.
        #[rstest]
        fn roundtrip_yaml_config(
            #[files("../fixtures/config/all_backends/*.yaml")] path: PathBuf,
        ) -> TestResult {
            let config_string = read_to_string(&path)?;
            let config = Config::from_file_path(&path)?;

            assert_eq!(config.to_yaml_string()?, config_string);

            Ok(())
        }

        /// Ensures, that [`AdministrativeSecretHandling`] and
        /// [`NonAdministrativeSecretHandling`]can be retrieved from a
        /// [`UserBackendConnection`].
        #[rstest]
        fn user_backend_connection_secret_handling(
            default_config: TestResult<Config>,
        ) -> TestResult {
            let config = default_config?;
            let admin_secret_handling = AdministrativeSecretHandling::ShamirsSecretSharing {
                number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
                threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
            };
            let non_admin_secret_handling = NonAdministrativeSecretHandling::SystemdCreds;

            for user in ["nethsm-signing-user", "yubihsm2-signing-user"] {
                let user_backend_connection = config
                    .user_backend_connection(&user.parse()?)
                    .expect("there to be a mapping of the requested name");

                assert_eq!(
                    user_backend_connection.admin_secret_handling(),
                    admin_secret_handling
                );
                assert_eq!(
                    user_backend_connection.non_admin_secret_handling(),
                    non_admin_secret_handling
                );
            }

            Ok(())
        }
    }

    /// Tests, that are only available when using no backends.
    #[cfg(not(all(feature = "nethsm", feature = "yubihsm2")))]
    mod no_backends {
        use pretty_assertions::assert_eq;

        use super::*;

        /// Create a [`Config`] using [`ConfigBuilder`].
        #[rstest]
        fn config_builder_new(default_system_config: TestResult<SystemConfig>) -> TestResult {
            let _config = ConfigBuilder::new(default_system_config?).finish()?;

            Ok(())
        }

        /// Ensures that a reference to the [`SystemConfig`] can be retrieved from [`Config`].
        #[rstest]
        fn config_system(default_system_config: TestResult<SystemConfig>) -> TestResult {
            let system_config = default_system_config?;
            let config = ConfigBuilder::new(system_config.clone()).finish()?;
            assert_eq!(config.system(), &system_config);

            Ok(())
        }

        /// Ensures, that a [`Config`] object leads to a specific YAML output.
        ///
        /// In this particular case, only a [`SystemConfig`] object are present.
        #[rstest]
        fn config_to_yaml_string(default_system_config: TestResult<SystemConfig>) -> TestResult {
            let config = ConfigBuilder::new(default_system_config?).finish()?;
            let config_str = config.to_yaml_string()?;

            with_settings!({
                description => "Configuration with system-wide, NetHSM and YubiHSM2 configuration",
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), config_str);
            });

            Ok(())
        }

        /// Ensures, that a valid [`Config`] can be created from a YAML file and turned back into
        /// the same YAML string.
        ///
        /// The configuration file only describes a [`SystemConfig`] object.
        #[rstest]
        fn roundtrip_yaml_config(
            #[files("../fixtures/config/no_backend/*.yaml")] path: PathBuf,
        ) -> TestResult {
            let config_string = read_to_string(&path)?;
            let config = Config::from_file_path(&path)?;

            assert_eq!(config.to_yaml_string()?, config_string);

            Ok(())
        }
    }
}
