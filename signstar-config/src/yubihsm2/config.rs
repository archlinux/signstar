//! YubiHSM2 specific integration for the [`crate::config`] module.
#![cfg(feature = "yubihsm2")]

use std::{
    collections::HashSet,
    fmt::Display,
    num::{NonZeroU8, NonZeroU16, NonZeroUsize},
    str::FromStr,
};

use garde::Validate;
use serde::{Deserialize, Serialize};
use signstar_crypto::{key::SigningKeySetup, passphrase::Passphrase, traits::UserWithPassphrase};
use signstar_yubihsm2::{Credentials, yubihsm::Domain};

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
    yubihsm2::backend::YubiHsmConnection,
};

/// An error that may occur when using YubiHSM2 config objects.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An authentication key ID does not match an expectation.
    #[error("Expected the YubiHSM2 authentication key ID {expected}, but found {actual} instead")]
    AuthenticationKeyIdMismatch {
        /// The expected authentication key ID.
        expected: String,

        /// The actually found authentication key ID.
        actual: String,
    },

    /// An invalid key domain.
    #[error("Error while constructing a YubiHSM2 key domain from {key_domain}, because {reason}")]
    InvalidDomain {
        /// The reason why the key domain is invalid.
        ///
        /// This is meant to complete the sentence "Error while constructing a YubiHSM2 key domain
        /// from {key_domain}, because ".
        reason: String,

        /// The invalid key domain.
        key_domain: String,
    },
}

/// The configuration representation of a YubiHSM2 domain.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct YubiHsm2Domain(NonZeroU8);

impl YubiHsm2Domain {
    /// Creates a new [`YubiHsm2Domain`] from a [`NonZeroU16`].
    pub fn new(num: NonZeroU8) -> Result<Self, crate::Error> {
        if num.get() > 16 {
            return Err(Error::InvalidDomain {
                reason: "a domain must be a number from 1-16".to_string(),
                key_domain: num.to_string(),
            }
            .into());
        }

        Ok(Self(num))
    }

    /// Returns the inner [`NonZeroU16`].
    pub fn get(&self) -> NonZeroU8 {
        self.0
    }
}

impl AsRef<NonZeroU8> for YubiHsm2Domain {
    fn as_ref(&self) -> &NonZeroU8 {
        &self.0
    }
}

impl Display for YubiHsm2Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl TryFrom<NonZeroU8> for YubiHsm2Domain {
    type Error = crate::Error;

    fn try_from(value: NonZeroU8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<NonZeroU16> for YubiHsm2Domain {
    type Error = crate::Error;

    fn try_from(value: NonZeroU16) -> Result<Self, Self::Error> {
        Self::try_from(
            NonZeroU8::try_from(value).map_err(|source| Error::InvalidDomain {
                reason: source.to_string(),
                key_domain: value.to_string(),
            })?,
        )
    }
}

impl TryFrom<NonZeroUsize> for YubiHsm2Domain {
    type Error = crate::Error;

    fn try_from(value: NonZeroUsize) -> Result<Self, Self::Error> {
        Self::try_from(
            NonZeroU8::try_from(value).map_err(|source| Error::InvalidDomain {
                reason: source.to_string(),
                key_domain: value.to_string(),
            })?,
        )
    }
}

impl TryFrom<usize> for YubiHsm2Domain {
    type Error = crate::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_from(
            NonZeroUsize::try_from(value).map_err(|source| Error::InvalidDomain {
                reason: source.to_string(),
                key_domain: value.to_string(),
            })?,
        )
    }
}

impl FromStr for YubiHsm2Domain {
    type Err = crate::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let num = NonZeroU8::from_str(s).map_err(|source| Error::InvalidDomain {
            reason: source.to_string(),
            key_domain: s.to_string(),
        })?;
        Self::new(num)
    }
}

impl From<YubiHsm2Domain> for Domain {
    fn from(value: YubiHsm2Domain) -> Self {
        match value.get().get() {
            1 => Domain::DOM1,
            2 => Domain::DOM2,
            3 => Domain::DOM3,
            4 => Domain::DOM4,
            5 => Domain::DOM5,
            6 => Domain::DOM6,
            7 => Domain::DOM7,
            8 => Domain::DOM8,
            9 => Domain::DOM9,
            10 => Domain::DOM10,
            11 => Domain::DOM11,
            12 => Domain::DOM12,
            13 => Domain::DOM13,
            14 => Domain::DOM14,
            15 => Domain::DOM15,
            16 => Domain::DOM16,
            _ => unreachable!(),
        }
    }
}

/// User and data mapping between system users and YubiHSM2 users.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum YubiHsm2UserMapping {
    /// A YubiHSM2 user in the administrator role, without a system user mapped to it.
    ///
    /// Tracks an [authentication key object] with a specific `authentication_key_id`.
    ///
    /// # Note
    ///
    /// This variant implies, that the created [authentication key object] has all relevant
    /// [capabilities] necessary for the creation of users and keys and to restore from backup,
    /// i.e.:
    ///
    /// - "delete-asymmetric-key"
    /// - "generate-asymmetric-key"
    /// - "put-asymmetric-key"
    /// - "delete-authen-tication-key"
    /// - "put-authentication-key"
    /// - "change-authentication-key"
    /// - "get-option"
    /// - "set-option"
    /// - "delete-hmac-key"
    /// - "generate-hmac-key"
    /// - "put-mac-key"
    /// - "sign-hmac"
    /// - "verify-hmac"
    /// - "delete-opaque"
    /// - "generate-opaque"
    /// - "get-opaque"
    /// - "put-opaque"
    /// - "reset-device"
    /// - "delete-template"
    /// - "get-template"
    /// - "put-template"
    /// - "delete-wrap-key"
    /// - "exportable-under-wrap"
    /// - "generate-wrap-key"
    /// - "import-wrapped"
    /// - "put-wrap-key"
    /// - "unwrap-data"
    /// - "wrap-data"
    /// - "put-public-wrap-key"
    /// - "delete-public-wrap-key"
    /// - "generate-symmetric-key"
    /// - "put-symmetric-key"
    /// - "delete-symmetric-key"
    ///
    /// Further, it is assumed that the [authentication key object] is added to all [domains].
    ///
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    /// [domains]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
    Admin {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: u16,
    },

    /// A system user, with SSH access, mapped to a YubiHSM2 authentication key.
    ///
    /// This variant tracks
    ///
    /// - an [authentication key object] with a specific `authentication_key_id`
    /// - an SSH authorized key with a specific `ssh_authorized_key`
    /// - a system user ID using `system_user`
    ///
    /// Its data is used to create relevant system and backend users for the retrieval of audit logs
    /// over the network, made available by the YubiHSM2.
    ///
    /// # Note
    ///
    /// This variant implies, that the created [authentication key object] has all relevant
    /// [capabilities] for audit log retrieval (i.e. "get-log-entries").
    ///
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    AuditLog {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: u16,

        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,

        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A mapping used for the creation of YubiHSM2 backups.
    ///
    /// This variant tracks
    ///
    /// - an [authentication key object] with a specific `authentication_key_id`
    /// - a [wrap key object] with a specific `wrapping_key_id`
    /// - an SSH authorized key with a specific `ssh_authorized_key`
    /// - a system user ID using `system_user`
    ///
    /// Its data is used to create relevant system and backend users for the creation of backups of
    /// all keys (including [authentication key object]s) and non-key material (e.g. OpenPGP
    /// certificates) of a YubiHSM2.
    ///
    /// # Note
    ///
    /// This variant implies, that the created [authentication key object] has all relevant
    /// [capabilities] for backup related actions (i.e. "export-wrapped", "wrap-data").
    ///
    /// Further, it is assumed that both the [authentication key object] and [wrap key object] are
    /// added to all [domains].
    ///
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    /// [domains]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
    /// [wrap key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#hsm2-wrap-key-obj
    Backup {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        ///
        /// This represents an [authentication key object].
        ///
        /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
        authentication_key_id: u16,

        /// The identifier of the wrapping key in the YubiHSM2 backend.
        ///
        /// This identifies the encryption key used for wrapping backups of all keys of the
        /// YubiHSM2.
        ///
        /// # Note
        ///
        /// The wrapping key is automatically added to all [domains].
        ///
        /// [domains]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
        wrapping_key_id: u16,

        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,

        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, without SSH access, mapped to a YubiHSM2 authentication key for collecting
    /// audit logs.
    ///
    /// This variant tracks
    ///
    /// - an [authentication key object] with a specific `authentication_key_id`
    /// - a system user ID using `system_user`
    ///
    /// Its data is used to create relevant system and backend users for the retrieval of audit logs
    /// made available by the YubiHSM2.
    ///
    /// # Note
    ///
    /// This variant implies, that the created [authentication key object] has all relevant
    /// [capabilities] for audit log retrieval (i.e. "get-log-entries").
    ///
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    HermeticAuditLog {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: u16,

        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a YubiHSM2 user in the
    /// Operator role with access to a single signing key.
    ///
    /// This variant tracks
    ///
    /// - an [authentication key object] identified by an `authentication_key_id`
    /// - a [domain] (`domain`) assigned to both objects identified by `authentication_key_id` and
    ///   `signing_key_id`
    /// - a [`SigningKeySetup`] using `key_setup`
    /// - an [asymmetric key object] identified by a `signing_key_id`
    /// - an SSH authorized key (`ssh_authorized_key`) for a `system_user`
    /// - a system user ID (`system_user`)
    ///
    /// Its data is used to create relevant system and backend users for the creation of backups of
    /// all keys (including [authentication key object]s) and non-key material (e.g. OpenPGP
    /// certificates) of a YubiHSM2.
    ///
    /// # Note
    ///
    /// This variant implies, that the created [authentication key object] has all relevant
    /// [capabilities] for signing with the [asymmetric key object] (i.e. "sign-ecdsa",
    /// "sign-eddsa", "sign-pkcs" and "sign-pss").
    ///
    /// Further, it is assumed that both the [authentication key object] and [asymmetric key object]
    /// are added to the single [domain] `domain`.
    ///
    /// [asymmetric key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#asymmetric-key-object
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    /// [domain]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
    Signing {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: u16,

        /// The setup of a YubiHSM2 key.
        key_setup: SigningKeySetup,

        /// The [domain] the signing and authentication key belong to.
        ///
        /// [domain]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
        domain: YubiHsm2Domain,

        /// The identifier of the signing key in the YubiHSM2 backend.
        signing_key_id: u16,

        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,

        /// The name of the system user.
        system_user: SystemUserId,
    },
}

impl YubiHsm2UserMapping {
    /// Returns the optional [`YubiHsm2Domain`] of the [`YubiHsm2UserMapping`].
    pub fn domain(&self) -> Option<&YubiHsm2Domain> {
        match self {
            Self::Admin { .. }
            | Self::Backup { .. }
            | Self::AuditLog { .. }
            | Self::HermeticAuditLog { .. } => None,
            Self::Signing {
                domain: key_domain, ..
            } => Some(key_domain),
        }
    }

    /// Returns the authentication key ID of the [`YubiHsm2UserMapping`].
    pub fn backend_user_id(&self) -> u16 {
        match self {
            Self::Admin {
                authentication_key_id,
            }
            | Self::AuditLog {
                authentication_key_id,
                ..
            }
            | Self::Backup {
                authentication_key_id,
                ..
            }
            | Self::HermeticAuditLog {
                authentication_key_id,
                ..
            }
            | Self::Signing {
                authentication_key_id,
                ..
            } => *authentication_key_id,
        }
    }
}

impl MappingSystemUserId for YubiHsm2UserMapping {
    fn system_user_id(&self) -> Option<&SystemUserId> {
        match self {
            Self::Admin { .. } => None,
            Self::AuditLog { system_user, .. }
            | Self::Backup { system_user, .. }
            | Self::HermeticAuditLog { system_user, .. }
            | Self::Signing { system_user, .. } => Some(system_user),
        }
    }
}

impl MappingBackendUserIds for YubiHsm2UserMapping {
    fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String> {
        match self {
            Self::Admin {
                authentication_key_id,
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Admin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![authentication_key_id.to_string()])
                } else {
                    None
                }
            }
            Self::AuditLog {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Metrics)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![authentication_key_id.to_string()])
                } else {
                    None
                }
            }
            Self::Backup {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Backup)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![authentication_key_id.to_string()])
                } else {
                    None
                }
            }
            Self::HermeticAuditLog {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Metrics)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![authentication_key_id.to_string()])
                } else {
                    None
                }
            }
            Self::Signing {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Signing)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(vec![authentication_key_id.to_string()])
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
        let backend_user_id = self.backend_user_id();
        if backend_user_id.to_string() != name {
            return Err(Error::AuthenticationKeyIdMismatch {
                expected: name.to_string(),
                actual: backend_user_id.to_string(),
            }
            .into());
        }

        Ok(Box::new(Credentials::new(backend_user_id, passphrase)))
    }

    fn backend_users_with_new_passphrase(
        &self,
        filter: BackendUserIdFilter,
    ) -> Vec<Box<dyn UserWithPassphrase>> {
        if let Some(authentication_key_id) = match self {
            Self::Admin {
                authentication_key_id,
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Admin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(authentication_key_id)
                } else {
                    None
                }
            }
            Self::AuditLog {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Metrics)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(authentication_key_id)
                } else {
                    None
                }
            }
            Self::Backup {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Backup)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(authentication_key_id)
                } else {
                    None
                }
            }
            Self::HermeticAuditLog {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Metrics)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(authentication_key_id)
                } else {
                    None
                }
            }
            Self::Signing {
                authentication_key_id,
                ..
            } => {
                if matches!(filter.backend_user_id_kind, BackendUserIdKind::Signing)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::NonAdmin)
                    || matches!(filter.backend_user_id_kind, BackendUserIdKind::Any)
                {
                    Some(authentication_key_id)
                } else {
                    None
                }
            }
        } {
            vec![Box::new(Credentials::new(
                *authentication_key_id,
                Passphrase::generate(None),
            ))]
        } else {
            Vec::new()
        }
    }
}

impl MappingAuthorizedKeyEntry for YubiHsm2UserMapping {
    fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry> {
        match self {
            Self::Admin { .. } | Self::HermeticAuditLog { .. } => None,
            Self::AuditLog {
                ssh_authorized_key, ..
            }
            | Self::Backup {
                ssh_authorized_key, ..
            }
            | Self::Signing {
                ssh_authorized_key, ..
            } => Some(ssh_authorized_key),
        }
    }
}

/// A filter for filtering sets of tags used in a NetHSM.
#[derive(Clone, Copy, Debug)]
pub struct YubiHsm2DomainFilter {}

impl BackendDomainFilter for YubiHsm2DomainFilter {}

impl MappingBackendDomain<YubiHsm2DomainFilter> for YubiHsm2UserMapping {
    fn backend_domain(&self, _filter: Option<&YubiHsm2DomainFilter>) -> Option<String> {
        self.domain().map(|domain| domain.as_ref().to_string())
    }
}

/// An understood key [object type].
///
/// # Note
///
/// Only a subset of all [object types][object type] are supported.
///
/// [object type]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#object-type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyObjectType {
    /// An [asymmetric key object].
    ///
    /// [asymmetric key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#hsm2-asymmetric-key-obj
    Signing,

    /// A [wrap key object].
    ///
    /// [wrap key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#hsm2-wrap-key-obj
    Wrapping,
}

/// A filter when search for key IDs in the [`YubiHsm2Config`].
#[derive(Clone, Debug)]
pub struct YubiHsm2BackendKeyIdFilter {
    /// The key object type to look for.
    ///
    /// [object type]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#object-type
    pub key_type: KeyObjectType,

    /// The optional [domain] to match the mapping against.
    ///
    /// [domain]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
    pub key_domain: Option<YubiHsm2Domain>,
}

impl BackendKeyIdFilter for YubiHsm2BackendKeyIdFilter {}

impl MappingBackendKeyId<YubiHsm2BackendKeyIdFilter> for YubiHsm2UserMapping {
    fn backend_key_id(&self, filter: &YubiHsm2BackendKeyIdFilter) -> Option<String> {
        match self {
            Self::Admin { .. } | Self::AuditLog { .. } | Self::HermeticAuditLog { .. } => None,
            Self::Backup {
                wrapping_key_id, ..
            } => {
                if filter.key_type == KeyObjectType::Wrapping {
                    // NOTE: Implicitly, wrapping key objects are in all domains.
                    Some(wrapping_key_id.to_string())
                } else {
                    None
                }
            }
            Self::Signing {
                signing_key_id,
                domain: key_domain,
                ..
            } => {
                if filter.key_type == KeyObjectType::Signing {
                    if let Some(filter_key_domain) = filter.key_domain {
                        if &filter_key_domain == key_domain {
                            Some(signing_key_id.to_string())
                        } else {
                            None
                        }
                    } else {
                        Some(signing_key_id.to_string())
                    }
                } else {
                    None
                }
            }
        }
    }
}

impl MappingBackendUserSecrets for YubiHsm2UserMapping {}

/// Validates a set of [`YubiHsmConnection`] objects.
///
/// Ensures that `value` is not empty.
///
/// # Errors
///
/// Returns an error if `value` is empty.
fn validate_yubihsm2_config_connections(
    value: &HashSet<YubiHsmConnection>,
    _context: &(),
) -> garde::Result {
    if value.is_empty() {
        return Err(garde::Error::new("contains no connections".to_string()));
    }

    Ok(())
}

/// Validates a set of [`YubiHsm2UserMapping`] objects.
///
/// Ensures that `value` is not empty.
///
/// Further ensures that there are no
///
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
/// - missing administrator backend users
/// - duplicate backend users
/// - duplicate signing key IDs
/// - duplicate wrapping key IDs
/// - duplicate domains
///
/// # Errors
///
/// Returns an error if there are
///
/// - no items in `value`
/// - duplicate system users
/// - duplicate SSH authorized keys (by comparing the actual SSH public keys)
/// - missing administrator backend users
/// - duplicate backend users
/// - duplicate signing key IDs
/// - duplicate wrapping key IDs
/// - duplicate domains
fn validate_yubihsm2_config_mappings(
    value: &HashSet<YubiHsm2UserMapping>,
    _context: &(),
) -> garde::Result {
    if value.is_empty() {
        return Err(garde::Error::new("contains no user mappings".to_string()));
    }

    // Collect all duplicate system user IDs.
    let duplicate_system_user_ids = duplicate_system_user_ids(value);

    // Collect all duplicate SSH public keys used as authorized_keys.
    let duplicate_authorized_keys = duplicate_authorized_keys(value);

    // Check whether there is at least one backend administrator.
    let missing_admin = {
        let num_system_admins = value
            .iter()
            .filter_map(|mapping| {
                if let YubiHsm2UserMapping::Admin {
                    authentication_key_id,
                } = mapping
                {
                    Some(authentication_key_id)
                } else {
                    None
                }
            })
            .count();

        if num_system_admins == 0 {
            Some("no administrator user".to_string())
        } else {
            None
        }
    };

    // Collect all duplicate backend user IDs.
    let duplicate_backend_user_ids = duplicate_backend_user_ids(value);

    // Collect all duplicate signing key IDs.
    let duplicate_signing_key_ids = duplicate_key_ids(
        value,
        &YubiHsm2BackendKeyIdFilter {
            key_type: KeyObjectType::Signing,
            key_domain: None,
        },
        Some(" signing".to_string()),
    );

    // Collect all duplicate wrapping (backup) key IDs.
    let duplicate_wrapping_key_ids = duplicate_key_ids(
        value,
        &YubiHsm2BackendKeyIdFilter {
            key_type: KeyObjectType::Wrapping,
            key_domain: None,
        },
        Some(" wrapping".to_string()),
    );

    // Collect all duplicate domains.
    let duplicate_domains = duplicate_domains(value, None, None, None);

    let messages = [
        duplicate_system_user_ids,
        duplicate_authorized_keys,
        missing_admin,
        duplicate_backend_user_ids,
        duplicate_signing_key_ids,
        duplicate_wrapping_key_ids,
        duplicate_domains,
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

/// The configuration items for a YubiHSM2 backend.
///
/// Tracks a set of connections to a YubiHSM2 backend and user mappings that are present on each of
/// them.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct YubiHsm2Config {
    /// A set of connections to YubiHSM2 backends.
    #[serde(serialize_with = "ordered_set", default)]
    #[garde(custom(validate_yubihsm2_config_connections))]
    connections: HashSet<YubiHsmConnection>,

    /// User mappings present in each YubiHSM2 backend.
    #[serde(serialize_with = "ordered_set", default)]
    #[garde(custom(validate_yubihsm2_config_mappings))]
    mappings: HashSet<YubiHsm2UserMapping>,
}

impl YubiHsm2Config {
    /// Creates a new [`YubiHsm2Config`] from a set of [`YubiHsmConnection`] and a set of
    /// [`YubiHsm2UserMapping`] items.
    pub fn new(
        connections: HashSet<YubiHsmConnection>,
        mappings: HashSet<YubiHsm2UserMapping>,
    ) -> Result<Self, crate::Error> {
        let config = Self {
            connections,
            mappings,
        };
        config
            .validate()
            .map_err(|source| crate::Error::Validation {
                context: "validating a YubiHSM2 specific configuration item".to_string(),
                source,
            })?;

        Ok(config)
    }

    /// Returns a reference to the set of [`YubiHsmConnection`] objects.
    pub fn connections(&self) -> &HashSet<YubiHsmConnection> {
        &self.connections
    }

    /// Returns a reference to the set of [`YubiHsm2UserMapping`] objects.
    pub fn mappings(&self) -> &HashSet<YubiHsm2UserMapping> {
        &self.mappings
    }
}

impl ConfigAuthorizedKeyEntries for YubiHsm2Config {
    fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry> {
        self.mappings
            .iter()
            .filter_map(|mapping| mapping.authorized_key_entry())
            .collect()
    }
}

impl ConfigSystemUserIds for YubiHsm2Config {
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

    const SNAPSHOT_PATH: &str = "fixtures/yubihsm2_config/";

    #[test]
    fn yubihsm2_config_new_succeeds() -> TestResult {
        let _config = YubiHsm2Config::new(
                HashSet::from_iter([
                    YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
                    YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
                ]),
                HashSet::from_iter([
                    YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: 2,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                        system_user: "backup-user".parse()?,
                        wrapping_key_id: 1,
                    },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: 3,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: 4,
                        signing_key_id: 1,
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
                        domain: 1.try_into()?,
                    }
                ]),
            )?;

        Ok(())
    }

    #[rstest]
    #[case::no_connection(
        "Error message for YubiHsm2Config::new with no connection",
        HashSet::new(),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 4,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            }
        ]),
    )]
    #[case::no_mappings(
        "Error message for YubiHsm2Config::new with no user mappings",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::new(),
    )]
    #[case::duplicate_system_user_ids(
        "Error message for YubiHsm2Config::new with two duplicate system user IDs",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 4,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            }
        ]),
    )]
    #[case::duplicate_ssh_public_keys(
        "Error message for YubiHsm2Config::new with two duplicate SSH public keys as authorized keys",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 4,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            }
        ]),
    )]
    #[case::no_administrator(
        "Error message for YubiHsm2Config::new with no administrator",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 4,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            }
        ]),
    )]
    #[case::duplicate_backend_user_ids(
        "Error message for YubiHsm2Config::new with two duplicate backend user IDs",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 3,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            }
        ]),
    )]
    #[case::duplicate_signing_key_ids(
        "Error message for YubiHsm2Config::new with two duplicate signing key IDs",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 4,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 5,
                signing_key_id: 1,
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
                domain: 2.try_into()?,
            },
        ]),
    )]
    #[case::duplicate_wrapping_key_ids(
        "Error message for YubiHsm2Config::new with two duplicate wrapping key IDs",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "backup-user2".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 4,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 5,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            },
        ]),
    )]
    #[case::duplicate_domains(
        "Error message for YubiHsm2Config::new with two duplicate domains",
        HashSet::from_iter([
            YubiHsmConnection::Usb {serial_number: "0012345678".parse()? },
            YubiHsmConnection::Usb {serial_number: "0087654321".parse()? },
        ]),
        HashSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 4,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 5,
                signing_key_id: 2,
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
                domain: 1.try_into()?,
            },
        ]),
    )]
    #[case::all_the_issues(
        "Error message for YubiHsm2Config::new with multiple validation issues (connections and mappings)",
        HashSet::new(),
        HashSet::from_iter([
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 2,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: 1,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: 3,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-backupuser".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 5,
                signing_key_id: 1,
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
                domain: 1.try_into()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: 5,
                signing_key_id: 1,
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
                system_user: "signing-user2".parse()?,
                domain: 1.try_into()?,
            },
        ]),
    )]
    fn yubihsm2_config_new_fails_validation(
        #[case] description: &str,
        #[case] connections: HashSet<YubiHsmConnection>,
        #[case] mappings: HashSet<YubiHsm2UserMapping>,
    ) -> TestResult {
        let error_msg = match YubiHsm2Config::new(connections, mappings) {
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
