use std::collections::HashSet;

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{Connection, KeyId, NamespaceId, SigningKeySetup, UserId, UserRole};
use serde::{Deserialize, Serialize};

use crate::{
    AdministrativeSecretHandling,
    AuthorizedKeyEntry,
    AuthorizedKeyEntryList,
    HermeticParallelConfig,
    NonAdministrativeSecretHandling,
    SystemUserId,
    SystemWideUserId,
};

/// Errors related to mapping
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A duplicate top-level [`KeyId`]
    #[error("Duplicate top-level NetHsm key {key}")]
    DuplicateKey { key: KeyId },

    /// A duplicate namespaced [`KeyId`]
    #[error("Duplicate NetHsm key {key} in namespace {namespace}")]
    DuplicateKeyInNamespace { namespace: String, key: KeyId },

    /// A duplicate [`UserId`]
    #[error("Duplicate NetHsm user {nethsm_user}")]
    DuplicateNetHsmUser { nethsm_user: UserId },

    /// A [`UserId`] is used both for a user in the [`Metrics`][`nethsm::UserRole::Metrics`] and
    /// [`Operator`][`nethsm::UserRole::Operator`] role
    #[error("The NetHsm user {metrics_user} is both in the Metrics and Operator role!")]
    MetricsAlsoOperator { metrics_user: SystemWideUserId },
}

/// A set of users with unique [`UserId`]s, used for metrics retrieval
///
/// This struct tracks a user that is intended for the use in the
/// [`Metrics`][`nethsm::UserRole::Metrics`] role and a list of users, that are intended to be used
/// in the [`Operator`][`nethsm::UserRole::Operator`] role.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
pub struct NetHsmMetricsUsers {
    metrics_user: SystemWideUserId,
    operator_users: Vec<UserId>,
}

impl NetHsmMetricsUsers {
    /// Creates a new [`NetHsmMetricsUsers`]
    ///
    /// # Error
    ///
    /// Returns an error, if the provided [`UserId`] of the `metrics_user` is duplicated in the
    /// provided `operator_users`.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// // this fails because there are duplicate UserIds
    /// assert!(
    ///     NetHsmMetricsUsers::new(
    ///         "metrics1".parse()?,
    ///         vec!["metrics1".parse()?, "user2".parse()?,],
    ///     )
    ///     .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(metrics_user: SystemWideUserId, operator_users: Vec<UserId>) -> Result<Self, Error> {
        // prevent duplicate metrics and operator users
        if operator_users.contains(&metrics_user.clone().into()) {
            return Err(Error::MetricsAlsoOperator { metrics_user });
        }

        Ok(Self {
            metrics_user,
            operator_users,
        })
    }

    /// Returns all tracked [`UserId`]s of the [`NetHsmMetricsUsers`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    /// use nethsm_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm_metrics_users = NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// assert_eq!(
    ///     nethsm_metrics_users.get_users(),
    ///     vec![
    ///         UserId::new("metrics1".to_string())?,
    ///         UserId::new("user1".to_string())?,
    ///         UserId::new("user2".to_string())?
    ///     ]
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_users(&self) -> Vec<UserId> {
        [
            vec![self.metrics_user.clone().into()],
            self.operator_users.clone(),
        ]
        .concat()
    }

    /// Returns all tracked [`UserId`]s and their respective [`UserRole`].
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{UserId, UserRole};
    /// use nethsm_config::NetHsmMetricsUsers;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm_metrics_users = NetHsmMetricsUsers::new(
    ///     "metrics1".parse()?,
    ///     vec!["user1".parse()?, "user2".parse()?],
    /// )?;
    ///
    /// assert_eq!(
    ///     nethsm_metrics_users.get_users_and_roles(),
    ///     vec![
    ///         (UserId::new("metrics1".to_string())?, UserRole::Metrics),
    ///         (UserId::new("user1".to_string())?, UserRole::Operator),
    ///         (UserId::new("user2".to_string())?, UserRole::Operator)
    ///     ]
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_users_and_roles(&self) -> Vec<(UserId, UserRole)> {
        [
            vec![(self.metrics_user.clone().into(), UserRole::Metrics)],
            self.operator_users
                .iter()
                .map(|user| (user.clone(), UserRole::Operator))
                .collect(),
        ]
        .concat()
    }
}

/// User mapping between system users and [`NetHsm`][`nethsm::NetHsm`] users
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Serialize)]
pub enum UserMapping {
    /// A NetHsm user in the Administrator role, without a system user mapped to it
    #[serde(rename = "nethsm_only_admin")]
    NetHsmOnlyAdmin(UserId),

    /// A system user, with SSH access, mapped to a system-wide [`NetHsm`][`nethsm::NetHsm`] user
    /// in the Backup role
    #[serde(rename = "system_nethsm_backup")]
    SystemNetHsmBackup {
        nethsm_user: SystemWideUserId,
        ssh_authorized_key: AuthorizedKeyEntry,
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a system-wide [`NetHsm`][`nethsm::NetHsm`] user
    /// in the Metrics role and `n` users in the Operator role with read-only access to zero or
    /// more keys
    #[serde(rename = "system_nethsm_metrics")]
    SystemNetHsmMetrics {
        nethsm_users: NetHsmMetricsUsers,
        ssh_authorized_key: AuthorizedKeyEntry,
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a [`NetHsm`][`nethsm::NetHsm`] user in the
    /// Operator role with access to a single signing key.
    ///
    /// Signing key and NetHSM user are mapped using a tag.
    #[serde(rename = "system_nethsm_operator_signing")]
    SystemNetHsmOperatorSigning {
        nethsm_user: UserId,
        nethsm_key_setup: SigningKeySetup,
        ssh_authorized_key: AuthorizedKeyEntry,
        system_user: SystemUserId,
        tag: String,
    },

    /// A system user, without SSH access, mapped to a system-wide [`NetHsm`][`nethsm::NetHsm`]
    /// user in the Metrics role and one or more NetHsm users in the Operator role with
    /// read-only access to zero or more keys
    #[serde(rename = "hermetic_system_nethsm_metrics")]
    HermeticSystemNetHsmMetrics {
        nethsm_users: NetHsmMetricsUsers,
        system_user: SystemUserId,
    },

    /// A system user, with SSH access for one or more SSH keys, not mapped to any NetHsm user,
    /// used for downloading shares of a shared secret
    #[serde(rename = "system_only_share_download")]
    SystemOnlyShareDownload {
        system_user: SystemUserId,
        ssh_authorized_keys: AuthorizedKeyEntryList,
    },

    /// A system user, with SSH access for one or more SSH keys, not mapped to any NetHsm user,
    /// used for uploading shares of a shared secret
    #[serde(rename = "system_only_share_upload")]
    SystemOnlyShareUpload {
        system_user: SystemUserId,
        ssh_authorized_keys: AuthorizedKeyEntryList,
    },

    /// A system user, with SSH access for one or more SSH keys, not mapped to any NetHsm user,
    /// used for downloading WireGuard configuration
    #[serde(rename = "system_only_wireguard_download")]
    SystemOnlyWireGuardDownload {
        system_user: SystemUserId,
        ssh_authorized_keys: AuthorizedKeyEntryList,
    },
}

impl UserMapping {
    /// Returns the optional system user of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::{AuthorizedKeyEntryList, SystemUserId, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?])?,
    /// };
    /// assert_eq!(mapping.get_system_user(), Some(&SystemUserId::new("user1".to_string())?));
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert_eq!(mapping.get_system_user(), None);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_system_user(&self) -> Option<&SystemUserId> {
        match self {
            UserMapping::NetHsmOnlyAdmin(_) => None,
            UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                ssh_authorized_key: _,
                system_user,
            }
            | UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: _,
                nethsm_key_setup: _,
                ssh_authorized_key: _,
                system_user,
                tag: _,
            }
            | UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                ssh_authorized_key: _,
                system_user,
            }
            | UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: _,
                system_user,
            }
            | UserMapping::SystemOnlyShareDownload {
                system_user,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user,
                ssh_authorized_keys: _,
            } => Some(system_user),
        }
    }

    /// Returns the NetHsm users of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    /// use nethsm_config::{AuthorizedKeyEntryList, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?])?,
    /// };
    /// assert!(mapping.get_nethsm_users().is_empty());
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert_eq!(mapping.get_nethsm_users(), vec![UserId::new("user1".to_string())?]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_nethsm_users(&self) -> Vec<UserId> {
        match self {
            UserMapping::SystemNetHsmBackup {
                nethsm_user,
                system_user: _,
                ssh_authorized_key: _,
            } => vec![nethsm_user.clone().into()],
            UserMapping::NetHsmOnlyAdmin(nethsm_user)
            | UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key: _,
                tag: _,
            } => vec![nethsm_user.clone()],
            UserMapping::SystemNetHsmMetrics {
                nethsm_users,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users,
                system_user: _,
            } => nethsm_users.get_users(),
            UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_keys: _,
            } => vec![],
        }
    }

    /// Returns the SSH authorized keys of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm_config::{AuthorizedKeyEntry, AuthorizedKeyEntryList, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?])?,
    /// };
    /// assert_eq!(mapping.get_ssh_authorized_keys(), vec![AuthorizedKeyEntry::new("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".to_string())?]);
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert_eq!(mapping.get_ssh_authorized_keys(), vec![]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_ssh_authorized_keys(&self) -> Vec<AuthorizedKeyEntry> {
        match self {
            UserMapping::NetHsmOnlyAdmin(_) => vec![],
            UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: _,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key,
                tag: _,
            } => vec![ssh_authorized_key.clone()],
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
                ssh_authorized_key,
            } => vec![ssh_authorized_key.clone()],
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
            } => vec![],
            UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_keys,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_keys,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_keys,
            } => ssh_authorized_keys.into(),
        }
    }

    /// Returns all used [`KeyId`]s of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, KeyId, OpenPgpUserIdList, SigningKeySetup};
    /// use nethsm_config::{AuthorizedKeyEntryList, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning {
    ///     nethsm_user: "user1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
    ///         "key1".parse()?,
    ///         "Curve25519".parse()?,
    ///         vec!["EdDsaSignature".parse()?],
    ///         None,
    ///         "EdDsa".parse()?,
    ///         CryptographicKeyContext::OpenPgp{
    ///             user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
    ///             version: "v4".parse()?,
    ///         },
    ///     )?,
    ///     system_user: "ssh-user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    ///     tag: "tag1".to_string(),
    /// };
    /// assert_eq!(mapping.get_key_ids(None), vec![KeyId::new("key1".to_string())?]);
    ///
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?])?,
    /// };
    /// assert_eq!(mapping.get_key_ids(None), vec![]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_key_ids(&self, namespace: Option<&NamespaceId>) -> Vec<KeyId> {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                nethsm_key_setup,
                system_user: _,
                ssh_authorized_key: _,
                tag: _,
            } => {
                if nethsm_user.namespace() == namespace {
                    vec![nethsm_key_setup.get_key_id()]
                } else {
                    vec![]
                }
            }
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
            }
            | UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_keys: _,
            } => vec![],
        }
    }

    /// Returns tags for keys and users
    ///
    /// Tags can be filtered by [namespace] by providing [`Some`] `namespace`.
    /// Providing [`None`] implies that the context is system-wide.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, OpenPgpUserIdList, SigningKeySetup};
    /// use nethsm_config::{AuthorizedKeyEntryList, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?])?,
    /// };
    /// assert!(mapping.get_tags(None).is_empty());
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert!(mapping.get_tags(None).is_empty());
    ///
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning{
    ///     nethsm_user: "ns1~user1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
    ///         "key1".parse()?,
    ///         "Curve25519".parse()?,
    ///         vec!["EdDsaSignature".parse()?],
    ///         None,
    ///         "EdDsa".parse()?,
    ///         CryptographicKeyContext::OpenPgp{
    ///             user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
    ///             version: "4".parse()?,
    ///     })?,
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    ///     tag: "tag1".to_string(),
    /// };
    /// assert!(mapping.get_tags(None).is_empty());
    /// assert_eq!(mapping.get_tags(Some(&"ns1".parse()?)), vec!["tag1"]);
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    pub fn get_tags(&self, namespace: Option<&NamespaceId>) -> Vec<&str> {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key: _,
                tag,
            } => {
                if nethsm_user.namespace() == namespace {
                    vec![tag.as_str()]
                } else {
                    vec![]
                }
            }
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
            }
            | UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_keys: _,
            } => vec![],
        }
    }

    /// Returns all [`NetHsm`][`nethsm::NetHsm`] [namespaces] of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, OpenPgpUserIdList, SigningKeySetup};
    /// use nethsm_config::{AuthorizedKeyEntryList, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_keys: AuthorizedKeyEntryList::new(vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?])?,
    /// };
    /// assert!(mapping.get_namespaces().is_empty());
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert!(mapping.get_namespaces().is_empty());
    ///
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning{
    ///     nethsm_user: "ns1~user1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
    ///         "key1".parse()?,
    ///         "Curve25519".parse()?,
    ///         vec!["EdDsaSignature".parse()?],
    ///         None,
    ///         "EdDsa".parse()?,
    ///         CryptographicKeyContext::OpenPgp{
    ///             user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
    ///             version: "4".parse()?,
    ///     })?,
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    ///     tag: "tag1".to_string(),
    /// };
    /// assert_eq!(mapping.get_namespaces(), vec!["ns1".parse()?]);
    /// # Ok(())
    /// # }
    /// ```
    /// [namespaces]: https://docs.nitrokey.com/nethsm/administration#namespaces
    pub fn get_namespaces(&self) -> Vec<NamespaceId> {
        match self {
            UserMapping::NetHsmOnlyAdmin(nethsm_user)
            | UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key: _,
                tag: _,
            } => {
                if let Some(namespace) = nethsm_user.namespace() {
                    vec![namespace.clone()]
                } else {
                    vec![]
                }
            }
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users,
                system_user: _,
            }
            | UserMapping::SystemNetHsmMetrics {
                nethsm_users,
                system_user: _,
                ssh_authorized_key: _,
            } => nethsm_users
                .get_users()
                .iter()
                .filter_map(|user_id| user_id.namespace())
                .cloned()
                .collect(),
            UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_keys: _,
            } => vec![],
        }
    }

    /// Returns whether the mapping has both system and [`NetHsm`] users.
    ///
    /// Returns `true` if the `self` has at least one system and one [`NetHsm`] user, and `false`
    /// otherwise.
    pub fn has_system_and_nethsm_user(&self) -> bool {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: _,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key: _,
                tag: _,
            }
            | UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
            }
            | UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
                ssh_authorized_key: _,
            }
            | UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                system_user: _,
                ssh_authorized_key: _,
            } => true,
            UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_keys: _,
            }
            | UserMapping::NetHsmOnlyAdmin(_) => false,
        }
    }
}

/// A [`UserMapping`] centric view of a [`HermeticParallelConfig`].
///
/// Wraps a single [`UserMapping`], as well as the system-wide [`AdministrativeSecretHandling`],
/// [`NonAdministrativeSecretHandling`] and [`Connection`]s.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtendedUserMapping {
    admin_secret_handling: AdministrativeSecretHandling,
    non_admin_secret_handling: NonAdministrativeSecretHandling,
    connections: HashSet<Connection>,
    user_mapping: UserMapping,
}

impl ExtendedUserMapping {
    /// Creates a new [`ExtendedUserMapping`].
    pub fn new(
        admin_secret_handling: AdministrativeSecretHandling,
        non_admin_secret_handling: NonAdministrativeSecretHandling,
        connections: HashSet<Connection>,
        user_mapping: UserMapping,
    ) -> Self {
        Self {
            admin_secret_handling,
            non_admin_secret_handling,
            connections,
            user_mapping,
        }
    }

    /// Returns the [`AdministrativeSecretHandling`].
    pub fn get_admin_secret_handling(&self) -> AdministrativeSecretHandling {
        self.admin_secret_handling
    }

    /// Returns the [`Connection`]s.
    pub fn get_connections(&self) -> HashSet<Connection> {
        self.connections.clone()
    }

    /// Returns the [`NonAdministrativeSecretHandling`].
    pub fn get_non_admin_secret_handling(&self) -> NonAdministrativeSecretHandling {
        self.non_admin_secret_handling
    }

    /// Returns the [`UserMapping`].
    pub fn get_user_mapping(&self) -> &UserMapping {
        &self.user_mapping
    }
}

impl From<HermeticParallelConfig> for Vec<ExtendedUserMapping> {
    /// Creates a `Vec` of [`ExtendedUserMapping`] from a [`HermeticParallelConfig`].
    ///
    /// A [`UserMapping`] can not be aware of credentials if it does not track at least one
    /// [`SystemUserId`] and one [`UserId`]. Therefore only those [`UserMapping`]s for which
    /// [`has_system_and_nethsm_user`](UserMapping::has_system_and_nethsm_user) returns `true` are
    /// returned.
    fn from(value: HermeticParallelConfig) -> Self {
        value
            .iter_user_mappings()
            .filter_map(|mapping| {
                if mapping.has_system_and_nethsm_user() {
                    Some(ExtendedUserMapping {
                        admin_secret_handling: value.get_administrative_secret_handling(),
                        non_admin_secret_handling: value.get_non_administrative_secret_handling(),
                        connections: value.iter_connections().cloned().collect(),
                        user_mapping: mapping.clone(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}
