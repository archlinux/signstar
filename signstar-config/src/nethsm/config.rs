//! [`NetHsm`] specific integration for the [`crate::config`] module.

use std::collections::HashSet;

use garde::Validate;
#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{
    Connection,
    FullCredentials,
    KeyId,
    NamespaceId,
    Passphrase,
    SystemWideUserId,
    UserId,
    UserRole,
};
use serde::{Deserialize, Serialize};
use signstar_crypto::{key::SigningKeySetup, traits::UserWithPassphrase};

use crate::{
    AuthorizedKeyEntry,
    SystemUserId,
    config::{
        BackendDomainFilter,
        BackendKeyIdFilter,
        BackendUserIdFilter,
        BackendUserIdKind,
        ConfigAuthorizedKeyEntries,
        ConfigSystemUserIds,
        MappingAuthorizedKeyEntry,
        MappingBackendDomain,
        MappingBackendKeyId,
        MappingBackendUserIds,
        MappingBackendUserSecrets,
        MappingSystemUserId,
        duplicate_authorized_keys,
        duplicate_backend_user_ids,
        duplicate_domains,
        duplicate_key_ids,
        duplicate_system_user_ids,
        ordered_set,
    },
};

/// An error that may occur when using NetHsm config objects.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A [`UserId`] is used both for a user in the [`Metrics`][`nethsm::UserRole::Metrics`] and
    /// [`Operator`][`nethsm::UserRole::Operator`] role.
    #[error("The NetHSM user {metrics_user} is both in the Metrics and Operator role!")]
    MetricsAlsoOperator {
        /// The system-wide User ID of a NetHSM user that is both in the
        /// [`Metrics`][`nethsm::UserRole::Metrics`] and
        /// [`Operator`][`nethsm::UserRole::Operator`] role.
        metrics_user: SystemWideUserId,
    },

    /// A NetHSM [`UserId`] is not found.
    #[error("The NetHSM user {user} cannot be found")]
    UserIdNotFound {
        /// The name of the NetHSM user that cannot be found.
        user: String,
    },
}

/// A filter for retrieving information about users and keys.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FilterUserKeys {
    /// Consider both system-wide and namespaced users and keys.
    All,

    /// Only consider users and keys that are in a namespace.
    Namespaced,

    /// Only consider users and keys that match a specific [`NamespaceId`].
    Namespace(NamespaceId),

    /// Only consider system-wide users and keys.
    SystemWide,

    /// Only consider users and keys that match a specific tag.
    Tag(String),
}

/// A set of users with unique [`UserId`]s, used for metrics retrieval
///
/// This struct tracks a user that is intended for the use in the
/// [`Metrics`][`nethsm::UserRole::Metrics`] role and a list of users, that are intended to be used
/// in the [`Operator`][`nethsm::UserRole::Operator`] role.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
    /// use signstar_config::NetHsmMetricsUsers;
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
    pub fn new(
        metrics_user: SystemWideUserId,
        operator_users: Vec<UserId>,
    ) -> Result<Self, crate::Error> {
        // prevent duplicate metrics and operator users
        if operator_users.contains(metrics_user.as_ref()) {
            return Err(Error::MetricsAlsoOperator { metrics_user }.into());
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
    /// use signstar_config::NetHsmMetricsUsers;
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
    /// use signstar_config::NetHsmMetricsUsers;
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

/// Data about a NetHSM user.
#[derive(Clone, Debug)]
pub struct NetHsmUserData {
    /// The name of the user.
    pub user: UserId,

    /// The role of the user.
    pub role: UserRole,

    /// The optional tag assigned to the user.
    pub tag: Option<String>,
}

/// A filter for retrieving information about users and keys.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum NetHsmUserKeysFilter {
    /// Consider both system-wide and namespaced users and keys.
    All,

    /// Only consider users and keys that are in a namespace.
    Namespaced,

    /// Only consider system-wide users and keys.
    SystemWide,
}

/// Data about a NetHSM signing user associated with a key.
#[derive(Clone, Debug)]
pub struct NetHsmUserKeyData {
    /// The name of the user.
    pub user: UserId,

    /// The key associated with the user.
    pub key_id: KeyId,

    /// The setup of the key.
    pub key_setup: SigningKeySetup,

    /// The tag assigned to the user and the key.
    pub tag: String,
}

/// User and data mapping between system users and NetHSM users.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetHsmUserMapping {
    /// A NetHsm user in the Administrator role, without a system user mapped to it.
    Admin(UserId),

    /// A system user, with SSH access, mapped to a system-wide NetHSM user in the Backup role.
    Backup {
        /// The name of the NetHSM user.
        backend_user: SystemWideUserId,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, without SSH access, mapped to a system-wide NetHSM
    /// user in the Metrics role and one or more NetHsm users in the Operator role with
    /// read-only access to zero or more keys
    HermeticMetrics {
        /// The NetHSM users in the [`Metrics`][`UserRole::Metrics`] and
        /// [`operator`][`UserRole::Operator`] role.
        backend_users: NetHsmMetricsUsers,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a system-wide NetHSM user
    /// in the Metrics role and `n` users in the Operator role with read-only access to zero or
    /// more keys
    Metrics {
        /// The NetHSM users in the [`Metrics`][`UserRole::Metrics`] and
        /// [`operator`][`UserRole::Operator`] role.
        backend_users: NetHsmMetricsUsers,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a NetHSM user in the
    /// Operator role with access to a single signing key.
    ///
    /// Signing key and NetHSM user are mapped using a tag.
    Signing {
        /// The name of the NetHSM user.
        backend_user: UserId,
        /// The ID of the NetHSM key.
        signing_key_id: KeyId,
        /// The setup of a NetHSM key.
        key_setup: SigningKeySetup,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
        /// The tag used for the user and the signing key on the NetHSM.
        tag: String,
    },
}

impl NetHsmUserMapping {
    /// Returns the list of [`NamespaceId`]s associated with this [`NetHsmUserMapping`].
    pub fn namespaces(&self) -> Vec<&NamespaceId> {
        match self {
            Self::Admin(backend_user) | Self::Signing { backend_user, .. } => {
                if let Some(namespace) = backend_user.namespace() {
                    vec![namespace]
                } else {
                    Vec::new()
                }
            }
            Self::Backup { .. } => Vec::new(),
            Self::HermeticMetrics { backend_users, .. } | Self::Metrics { backend_users, .. } => {
                backend_users
                    .operator_users
                    .iter()
                    .filter_map(|user_id| user_id.namespace())
                    .collect::<Vec<_>>()
            }
        }
    }

    /// Returns the optional tag used in the [`NetHsmUserMapping`].
    ///
    /// # Note
    ///
    /// Only [`NetHsmUserMapping::Signing`] can have a tag.
    pub fn tag(&self, namespace: Option<&NamespaceId>) -> Option<&str> {
        match self {
            Self::Signing {
                backend_user, tag, ..
            } => {
                if namespace == backend_user.namespace() {
                    Some(tag.as_str())
                } else {
                    None
                }
            }
            Self::Admin(_)
            | Self::Backup { .. }
            | Self::HermeticMetrics { .. }
            | Self::Metrics { .. } => None,
        }
    }

    /// Returns the list of [`UserId`] objects associated with this [`NetHsmUserMapping`].
    pub fn nethsm_user_ids(&self) -> Vec<UserId> {
        match self {
            Self::Admin(user_id) => vec![user_id.clone()],
            Self::Backup { backend_user, .. } => vec![backend_user.as_ref().clone()],
            Self::Metrics { backend_users, .. } | Self::HermeticMetrics { backend_users, .. } => {
                backend_users.get_users()
            }
            Self::Signing { backend_user, .. } => vec![backend_user.clone()],
        }
    }

    /// Returns the list of [`NetHsmUserData`] objects associated with this [`NetHsmUserMapping`].
    pub fn nethsm_user_data(&self) -> Vec<NetHsmUserData> {
        match self {
            Self::Admin(user_id) => vec![NetHsmUserData {
                user: user_id.clone(),
                role: UserRole::Administrator,
                tag: None,
            }],
            Self::Backup { backend_user, .. } => {
                vec![NetHsmUserData {
                    user: backend_user.as_ref().clone(),
                    role: UserRole::Backup,
                    tag: None,
                }]
            }
            Self::Metrics { backend_users, .. } | Self::HermeticMetrics { backend_users, .. } => {
                let mut users = backend_users
                    .operator_users
                    .iter()
                    .map(|user_id| NetHsmUserData {
                        user: user_id.clone(),
                        role: UserRole::Operator,
                        tag: None,
                    })
                    .collect::<Vec<_>>();
                users.push(NetHsmUserData {
                    user: backend_users.metrics_user.as_ref().clone(),
                    role: UserRole::Metrics,
                    tag: None,
                });
                users
            }
            Self::Signing {
                backend_user, tag, ..
            } => vec![NetHsmUserData {
                user: backend_user.clone(),
                role: UserRole::Operator,
                tag: Some(tag.clone()),
            }],
        }
    }

    /// Returns a filtered list of [`NetHsmUserKeyData`] objects from this [`NetHsmUserMapping`].
    ///
    /// Based on a [`NetHsmUserKeysFilter`] it is possible to target only namespaced or system-wide,
    /// or all user mappings that have associated key configs.
    pub fn nethsm_user_key_data(&self, filter: NetHsmUserKeysFilter) -> Option<NetHsmUserKeyData> {
        match self {
            Self::Admin(_)
            | Self::Backup { .. }
            | Self::Metrics { .. }
            | Self::HermeticMetrics { .. } => None,
            Self::Signing {
                backend_user,
                signing_key_id,
                key_setup,
                tag,
                ..
            } => {
                if matches!(filter, NetHsmUserKeysFilter::All)
                    || (matches!(filter, NetHsmUserKeysFilter::Namespaced)
                        && backend_user.is_namespaced())
                    || (matches!(filter, NetHsmUserKeysFilter::SystemWide)
                        && !backend_user.is_namespaced())
                {
                    Some(NetHsmUserKeyData {
                        user: backend_user.clone(),
                        key_id: signing_key_id.clone(),
                        key_setup: key_setup.clone(),
                        tag: tag.clone(),
                    })
                } else {
                    None
                }
            }
        }
    }
}

impl MappingSystemUserId for NetHsmUserMapping {
    fn system_user_id(&self) -> Option<&SystemUserId> {
        match self {
            Self::Admin(_) => None,
            Self::Backup { system_user, .. }
            | Self::Metrics { system_user, .. }
            | Self::HermeticMetrics { system_user, .. }
            | Self::Signing { system_user, .. } => Some(system_user),
        }
    }
}

impl MappingAuthorizedKeyEntry for NetHsmUserMapping {
    fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry> {
        match self {
            Self::Admin(_) | Self::HermeticMetrics { .. } => None,
            Self::Backup {
                ssh_authorized_key, ..
            }
            | Self::Metrics {
                ssh_authorized_key, ..
            }
            | Self::Signing {
                ssh_authorized_key, ..
            } => Some(ssh_authorized_key),
        }
    }
}

impl MappingBackendUserIds for NetHsmUserMapping {
    fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String> {
        match self {
            Self::Admin(user_id) => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Admin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![user_id.to_string()])
                } else {
                    None
                }
            }
            Self::Backup { backend_user, .. } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Backup)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![backend_user.to_string()])
                } else {
                    None
                }
            }
            Self::Metrics { backend_users, .. } | Self::HermeticMetrics { backend_users, .. } => {
                match filter.backend_user_id_kind {
                    BackendUserIdKind::Admin
                    | BackendUserIdKind::Backup
                    | BackendUserIdKind::Signing => None,
                    BackendUserIdKind::Metrics => {
                        Some(vec![backend_users.metrics_user.to_string()])
                    }
                    BackendUserIdKind::NonAdmin | BackendUserIdKind::Any => Some(
                        backend_users
                            .get_users()
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                    ),
                    BackendUserIdKind::Observer => Some(
                        backend_users
                            .operator_users
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                    ),
                }
            }
            Self::Signing { backend_user, .. } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Signing)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![backend_user.to_string()])
                } else {
                    None
                }
            }
        }
        .unwrap_or_default()
    }

    fn backend_user_with_passphrase(
        &self,
        name: &str,
        passphrase: Passphrase,
    ) -> Result<Box<dyn UserWithPassphrase>, crate::Error> {
        for user in self.nethsm_user_ids() {
            if user.to_string() == name {
                return Ok(Box::new(FullCredentials::new(user, passphrase)));
            }
        }

        Err(Error::UserIdNotFound {
            user: name.to_string(),
        }
        .into())
    }

    fn backend_users_with_new_passphrase(
        &self,
        filter: BackendUserIdFilter,
    ) -> Vec<Box<dyn UserWithPassphrase>> {
        if let Some(backend_user_ids) = match self {
            Self::Admin(user_id) => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Admin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![user_id.clone()])
                } else {
                    None
                }
            }
            Self::Backup { backend_user, .. } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Backup)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![UserId::from(backend_user.clone())])
                } else {
                    None
                }
            }
            Self::Metrics { backend_users, .. } | Self::HermeticMetrics { backend_users, .. } => {
                match filter.backend_user_id_kind {
                    BackendUserIdKind::Admin
                    | BackendUserIdKind::Backup
                    | BackendUserIdKind::Signing => None,
                    BackendUserIdKind::Metrics => {
                        Some(vec![backend_users.metrics_user.as_ref().clone()])
                    }
                    BackendUserIdKind::NonAdmin | BackendUserIdKind::Any => {
                        Some(backend_users.get_users().to_vec())
                    }
                    BackendUserIdKind::Observer => Some(backend_users.operator_users.to_vec()),
                }
            }
            Self::Signing { backend_user, .. } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Signing)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![backend_user.clone()])
                } else {
                    None
                }
            }
        } {
            backend_user_ids
                .into_iter()
                .map(|backend_user_id| {
                    Box::new(FullCredentials::new(
                        backend_user_id,
                        Passphrase::generate(None),
                    )) as Box<dyn UserWithPassphrase>
                })
                .collect()
        } else {
            Vec::new()
        }
    }
}

/// A filter for filtering sets of key IDs used in a NetHSM.
#[derive(Clone, Debug)]
pub struct NetHsmBackendKeyIdFilter<'a> {
    pub namespace: Option<&'a NamespaceId>,
}

impl<'a> BackendKeyIdFilter for NetHsmBackendKeyIdFilter<'a> {}

impl<'a> MappingBackendKeyId<NetHsmBackendKeyIdFilter<'a>> for NetHsmUserMapping {
    fn backend_key_id(&self, filter: &NetHsmBackendKeyIdFilter<'a>) -> Option<String> {
        match self {
            Self::Admin(_)
            | Self::Backup { .. }
            | Self::HermeticMetrics { .. }
            | Self::Metrics { .. } => None,
            Self::Signing {
                backend_user,
                signing_key_id,
                ..
            } => {
                if filter.namespace == backend_user.namespace() {
                    Some(signing_key_id.to_string())
                } else {
                    None
                }
            }
        }
    }
}

impl MappingBackendUserSecrets for NetHsmUserMapping {}

/// A filter for filtering sets of tags used in a NetHSM.
#[derive(Clone, Debug)]
pub struct NetHsmConfigDomainFilter<'a> {
    /// An optional [`NamespaceId`] that is used to filter a [`NetHsmUserMapping`] by when
    /// searching for tags.
    pub namespace: Option<&'a NamespaceId>,
}

impl<'a> BackendDomainFilter for NetHsmConfigDomainFilter<'a> {}

impl<'a> MappingBackendDomain<NetHsmConfigDomainFilter<'a>> for NetHsmUserMapping {
    /// Returns the optional tag of the [`NetHsmUserMapping`].
    ///
    /// # Note
    ///
    /// Delegates to [`NetHsmUserMapping::tag`].
    fn backend_domain(&self, filter: Option<&NetHsmConfigDomainFilter>) -> Option<String> {
        let filter = if let Some(filter) = filter {
            filter.namespace
        } else {
            None
        };

        self.tag(filter).map(ToString::to_string)
    }
}

/// Validates a set of [`Connection`] objects.
///
/// Ensures that `value` is not empty and does not contain one or more [`Connection`]s with
/// duplicate URLs.
///
/// # Note
///
/// [`Connection`] derives [`Eq`]/[`PartialEq`] and [`Ord`]/[`PartialOrd`], which allows several
/// items with the same URL but differing TLS settings. However, in a configuration file we
/// generally never want to use the same device with differing TLS settings, as those devices are
/// used in a round-robin fashion.
///
/// # Errors
///
/// Returns an error if `value` is empty or contains one or more [`Connection`]s with duplicate
/// URLs.
fn validate_nethsm_config_connections(value: &HashSet<Connection>, _context: &()) -> garde::Result {
    if value.is_empty() {
        return Err(garde::Error::new("contains no connections"));
    }

    let urls = value
        .iter()
        .map(|connection| connection.url())
        .collect::<Vec<_>>();
    let duplicates = {
        let mut duplicates = HashSet::new();

        for url in urls.iter() {
            if urls.iter().filter(|list_url| url == *list_url).count() > 1 {
                duplicates.insert(url);
            }
        }
        let mut duplicates = Vec::from_iter(duplicates);
        duplicates.sort();
        duplicates
    };

    if !duplicates.is_empty() {
        return Err(garde::Error::new(format!(
            "contains the duplicate URL{} {}",
            if duplicates.len() > 1 { "s" } else { "" },
            duplicates
                .iter()
                .map(|url| format!("\"{url}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    Ok(())
}

/// Validates a set of [`NetHsmUserMapping`] objects.
///
/// Ensures that `value` is not empty.
///
/// Further ensures that there are no
///
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
/// - missing system-wide administrator backend users
/// - duplicate backend users
/// - duplicate system-wide signing key IDs
/// - duplicate system-wide tags
/// - duplicate wrapping key IDs
/// - missing namespaced administrator backend users
/// - duplicate namespaced signing key IDs
/// - duplicate namespaced tags
///
/// # Errors
///
/// Returns an error if there are
///
/// - no items in `value`
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
/// - missing system-wide administrator backend users
/// - duplicate backend users
/// - duplicate system-wide signing key IDs
/// - duplicate system-wide tags
/// - duplicate wrapping key IDs
/// - missing namespaced administrator backend users
/// - duplicate namespaced signing key IDs
/// - duplicate namespaced tags
fn validate_nethsm_config_mappings(
    value: &HashSet<NetHsmUserMapping>,
    _context: &(),
) -> garde::Result {
    if value.is_empty() {
        return Err(garde::Error::new("contains no user mappings"));
    }

    // Collect all duplicate system user IDs.
    let duplicate_system_user_ids = duplicate_system_user_ids(value);

    // Collect all duplicate SSH public keys used as authorized_keys.
    let duplicate_authorized_keys = duplicate_authorized_keys(value);

    // Check whether there is at least one system-wide backend administrator.
    let missing_system_wide_admin = {
        let num_system_admins = value
            .iter()
            .filter_map(|mapping| {
                if let NetHsmUserMapping::Admin(user_id) = mapping
                    && !user_id.is_namespaced()
                {
                    Some(user_id)
                } else {
                    None
                }
            })
            .count();

        if num_system_admins == 0 {
            Some("no system-wide administrator user".to_string())
        } else {
            None
        }
    };

    // Collect all duplicate backend user IDs.
    let duplicate_backend_user_ids = duplicate_backend_user_ids(value);

    // Collect all duplicate system-wide key IDs.
    let duplicate_system_wide_key_ids = duplicate_key_ids(
        value,
        &NetHsmBackendKeyIdFilter { namespace: None },
        Some(" system-wide".to_string()),
    );

    // Collect all duplicate system-wide tags.
    let duplicate_system_wide_tags =
        duplicate_domains(value, None, Some(" system-wide".to_string()), Some("tag"));

    // Collect all namespace IDs.
    let all_namespaces = {
        let mut all_namespaces = Vec::from_iter(
            value
                .iter()
                .flat_map(|mapping| mapping.namespaces())
                .collect::<HashSet<_>>(),
        );
        all_namespaces.sort();
        all_namespaces
    };

    // Collect all namespace IDs without an admin user.
    let namespaces_without_admin = {
        let mut all_namespaces: HashSet<&NamespaceId> = HashSet::from_iter(all_namespaces.clone());

        for mapping in value.iter() {
            if let NetHsmUserMapping::Admin(user_id) = mapping
                && let Some(namespace) = user_id.namespace()
            {
                all_namespaces.remove(namespace);
            }
        }

        if all_namespaces.is_empty() {
            None
        } else {
            let mut namespaces_without_admin = all_namespaces
                .iter()
                .map(|namespace| format!("\"{namespace}\""))
                .collect::<Vec<_>>();
            namespaces_without_admin.sort();
            Some(format!(
                "the namespace{} {} without an administrator user",
                if namespaces_without_admin.len() > 1 {
                    "s"
                } else {
                    ""
                },
                namespaces_without_admin.join(", ")
            ))
        }
    };

    // Collect all duplicate namespaced key IDs.
    let duplicate_namespaced_key_ids = {
        let mut all_duplicates = Vec::new();

        for namespace in all_namespaces.iter() {
            let mut duplicates = duplicate_key_ids(
                value,
                &NetHsmBackendKeyIdFilter {
                    namespace: Some(namespace),
                },
                Some(format!(" \"{namespace}\" namespaced")),
            );
            if let Some(message) = duplicates.take() {
                all_duplicates.push(message)
            }
        }

        if all_duplicates.is_empty() {
            None
        } else {
            Some(all_duplicates.join("\n"))
        }
    };

    // Collect all duplicate namespaced tags.
    let duplicate_namespaced_tags = {
        let mut all_duplicates = Vec::new();

        for namespace in all_namespaces.iter() {
            let mut duplicates = duplicate_domains(
                value,
                Some(&NetHsmConfigDomainFilter {
                    namespace: Some(namespace),
                }),
                Some(format!(" \"{namespace}\" namespaced")),
                Some("tag"),
            );
            if let Some(message) = duplicates.take() {
                all_duplicates.push(message)
            }
        }

        if all_duplicates.is_empty() {
            None
        } else {
            Some(all_duplicates.join("\n"))
        }
    };

    let messages = [
        duplicate_system_user_ids,
        duplicate_authorized_keys,
        missing_system_wide_admin,
        duplicate_backend_user_ids,
        duplicate_system_wide_key_ids,
        duplicate_system_wide_tags,
        namespaces_without_admin,
        duplicate_namespaced_key_ids,
        duplicate_namespaced_tags,
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

/// The configuration items for a NetHSM.
///
/// Tracks a set of connections to a NetHSM backend and user mappings that are present on each of
/// them.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct NetHsmConfig {
    #[serde(serialize_with = "ordered_set", default)]
    #[garde(custom(validate_nethsm_config_connections))]
    connections: HashSet<Connection>,

    #[serde(serialize_with = "ordered_set", default)]
    #[garde(custom(validate_nethsm_config_mappings))]
    mappings: HashSet<NetHsmUserMapping>,
}

impl NetHsmConfig {
    /// Creates a new [`NetHsmConfig`] from a set of [`Connection`] and a set of
    /// [`NetHsmUserMapping`] items.
    pub fn new(
        connections: HashSet<Connection>,
        mappings: HashSet<NetHsmUserMapping>,
    ) -> Result<Self, crate::Error> {
        let config = Self {
            connections,
            mappings,
        };

        config
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "validating a NetHSM specific configuration item".to_string(),
                source,
            })?;

        Ok(config)
    }

    /// Returns a reference to the set of [`Connection`] objects.
    pub fn connections(&self) -> &HashSet<Connection> {
        &self.connections
    }

    /// Returns a reference to the set of [`NetHsmUserMapping`] objects.
    pub fn mappings(&self) -> &HashSet<NetHsmUserMapping> {
        &self.mappings
    }
}

impl ConfigAuthorizedKeyEntries for NetHsmConfig {
    fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry> {
        self.mappings
            .iter()
            .filter_map(|mapping| mapping.authorized_key_entry())
            .collect()
    }
}

impl ConfigSystemUserIds for NetHsmConfig {
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
    use signstar_crypto::{
        key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
        openpgp::OpenPgpUserIdList,
    };
    use testresult::TestResult;

    use super::*;

    const SNAPSHOT_PATH: &str = "fixtures/nethsm_config/";

    #[test]
    fn nethsm_metrics_users_succeeds() -> TestResult {
        NetHsmMetricsUsers::new(
            SystemWideUserId::new("metrics".to_string())?,
            vec![
                UserId::new("operator".to_string())?,
                UserId::new("ns1~operator".to_string())?,
            ],
        )?;
        Ok(())
    }

    #[test]
    fn nethsm_metrics_users_fails() -> TestResult {
        if let Ok(user) = NetHsmMetricsUsers::new(
            SystemWideUserId::new("metrics".to_string())?,
            vec![
                UserId::new("metrics".to_string())?,
                UserId::new("ns1~operator".to_string())?,
            ],
        ) {
            panic!("Succeeded creating a NetHsmMetricsUsers, but should have failed:\n{user:?}")
        }
        Ok(())
    }

    #[test]
    fn nethsm_config_new_succeeds() -> TestResult {
        let _config = NetHsmConfig::new(
                HashSet::from_iter([
                    Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
                    Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
                ]),
                HashSet::from_iter([
                    NetHsmUserMapping::Admin("admin".parse()?),
                    NetHsmUserMapping::Backup{
                        backend_user: "backup".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
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
            )?;

        Ok(())
    }

    #[rstest]
    #[case::no_connection(
        "Error message for NetHsmConfig::new with no backend connection",
        HashSet::new(),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
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
    )]
    #[case::duplicate_connection_url(
        "Error message for NetHsmConfig::new with two duplicate connection URLs",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?, nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm1.example.org/".parse()?, nethsm::ConnectionSecurity::Native),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
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
    )]
    #[case::no_mappings(
        "Error message for NetHsmConfig::new with no user mappings",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::new(),
    )]
    #[case::duplicate_system_user_ids(
        "Error message for NetHsmConfig::new with two duplicate system user IDs",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "backup-user".parse()?,
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
    )]
    #[case::duplicate_ssh_public_keys(
        "Error message for NetHsmConfig::new with two duplicate SSH public keys as authorized keys",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user2@other-host".parse()?,
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
    )]
    #[case::missing_system_wide_administrator(
        "Error message for NetHsmConfig::new with a system-wide administrator missing",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
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
    )]
    #[case::duplicate_system_wide_backend_user_ids(
        "Error message for NetHsmConfig::new with two duplicate system-wide backend user IDs",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Admin("backup".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
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
    )]
    #[case::duplicate_namespaced_backend_user_ids(
        "Error message for NetHsmConfig::new with two duplicate namespaced backend user IDs",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Admin("ns1~admin".parse()?),
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
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
                system_user: "ns1-signing-user1".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
                signing_key_id: "signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "ns1-signing-user2".parse()?,
                tag: "signing2".to_string(),
            }
        ]),
    )]
    #[case::duplicate_system_wide_key_ids(
        "Error message for NetHsmConfig::new with two duplicate system-wide key IDs",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            NetHsmUserMapping::Signing {
                backend_user: "signing1".parse()?,
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
            },
            NetHsmUserMapping::Signing {
                backend_user: "signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "signing-user2".parse()?,
                tag: "signing2".to_string(),
            }
        ]),
    )]
    #[case::duplicate_system_wide_tags(
        "Error message for NetHsmConfig::new with two duplicate system-wide tags",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            NetHsmUserMapping::Signing {
                backend_user: "signing1".parse()?,
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
            },
            NetHsmUserMapping::Signing {
                backend_user: "signing2".parse()?,
                signing_key_id: "signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "signing-user2".parse()?,
                tag: "signing1".to_string(),
            }
        ]),
    )]
    #[case::missing_namespace_administrator(
        "Error message for NetHsmConfig::new with a missing namespace administrator",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
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
                system_user: "ns1-signing-user".parse()?,
                tag: "signing1".to_string(),
            },
        ]),
    )]
    #[case::duplicate_namespace_key_ids(
        "Error message for NetHsmConfig::new with two duplicate namespaced key IDs",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Admin("ns1~admin".parse()?),
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
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
                system_user: "ns1-signing-user".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "ns1-signing-user2".parse()?,
                tag: "signing2".to_string(),
            }
        ]),
    )]
    #[case::duplicate_namespace_tags(
        "Error message for NetHsmConfig::new with two duplicate namespaced tags",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm2.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Admin("ns1~admin".parse()?),
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
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
                system_user: "ns1-signing-user".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing2".parse()?,
                signing_key_id: "signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "ns1-signing-user2".parse()?,
                tag: "signing1".to_string(),
            }
        ]),
    )]
    #[case::all_the_issues(
        "Error message for NetHsmConfig::new with multiple validation issues (connections and mappings)",
        HashSet::from_iter([
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Unsafe),
            Connection::new("https://nethsm1.example.org/".parse()?,nethsm::ConnectionSecurity::Native),
        ]),
        HashSet::from_iter([
            NetHsmUserMapping::Signing {
                backend_user: "signing1".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
                system_user: "ns1-signing-user1".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "signing1".parse()?,
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
                system_user: "ns1-signing-user1".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
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
                system_user: "ns1-signing-user1".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing1".parse()?,
                signing_key_id: "signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "ns1-signing-user2".parse()?,
                tag: "signing1".to_string(),
            },
            NetHsmUserMapping::Signing {
                backend_user: "ns1~signing2".parse()?,
                signing_key_id: "signing2".parse()?,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "ns1-signing-user1".parse()?,
                tag: "signing1".to_string(),
            },
        ]),
    )]
    fn nethsm_config_new_fails_validation(
        #[case] description: &str,
        #[case] connections: HashSet<Connection>,
        #[case] mappings: HashSet<NetHsmUserMapping>,
    ) -> TestResult {
        let error_msg = match NetHsmConfig::new(connections, mappings) {
            Err(crate::Error::Validation { source, .. }) => source.to_string(),
            Ok(config) => {
                panic!("Expected to fail with Error::Validation, but succeeded instead: {config:?}")
            }
            Err(error) => panic!(
                "Expected to fail with Error::Validation, but failed with a different error instead: {error}"
            ),
        };

        with_settings!({
            description => description,
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), error_msg);
        });
        Ok(())
    }
}
