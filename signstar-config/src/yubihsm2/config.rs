//! YubiHSM2 specific integration for the [`crate::config`] module.
#![cfg(feature = "yubihsm2")]

use std::{
    collections::{BTreeSet, HashSet},
    fmt::Display,
};

use garde::Validate;
use serde::{Deserialize, Serialize};
use signstar_crypto::{key::SigningKeySetup, passphrase::Passphrase, traits::UserWithPassphrase};
use signstar_yubihsm2::{
    Connection,
    Credentials,
    object::{Capabilities, Capability, Domain, Domains, Id},
    yubihsm::Code,
};

use crate::{
    config::{
        AuthorizedKeyEntry,
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
        SystemUserData,
        SystemUserId,
        duplicate_authorized_keys,
        duplicate_backend_user_ids,
        duplicate_domains,
        duplicate_key_ids,
        duplicate_system_user_ids,
    },
    state::{StateOrigin, StateOriginInfo},
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
    /// [capabilities] necessary for the creation of users and keys and to restore from backup
    /// (see [`YubiHsm2UserMapping::CAP_ADMIN`] for details).
    ///
    /// Further, it is assumed that the [authentication key object] is added to all [domains].
    ///
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    /// [domains]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
    Admin {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: Id,
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
    /// [capabilities] for audit log retrieval (see [`YubiHsm2UserMapping::CAP_AUDIT_LOG`] for
    /// details).
    ///
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    AuditLog {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: Id,

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
    /// [capabilities] for backup related actions (see [`YubiHsm2UserMapping::CAP_BACKUP`] for
    /// details).
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
        authentication_key_id: Id,

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
        wrapping_key_id: Id,

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
    /// [capabilities] for audit log retrieval (see [`YubiHsm2UserMapping::CAP_HERMETIC_AUDIT_LOG`]
    /// for details).
    ///
    /// [authentication key object]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    HermeticAuditLog {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: Id,

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
    /// [capabilities] for signing with the [asymmetric key object] (see
    /// [`YubiHsm2UserMapping::CAP_SIGNING`] for details).
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
        authentication_key_id: Id,

        /// The setup of a YubiHSM2 key.
        key_setup: SigningKeySetup,

        /// The [domain] the signing and authentication key belong to.
        ///
        /// [domain]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains
        domain: Domain,

        /// The identifier of the signing key in the YubiHSM2 backend.
        signing_key_id: Id,

        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,

        /// The name of the system user.
        system_user: SystemUserId,
    },
}

impl YubiHsm2UserMapping {
    /// The list of [`Capability`] items required for [`YubiHsm2UserMapping::Admin`].
    ///
    /// Each item relates to a [capability] of the YubiHSM2 device:
    ///
    /// - `change-authentication-key`
    /// - `delete-asymmetric-key`
    /// - `delete-authentication-key`
    /// - `delete-hmac-key`
    /// - `delete-opaque`
    /// - `delete-template`
    /// - `delete-wrap-key`
    /// - `exportable-under-wrap`
    /// - `generate-asymmetric-key`
    /// - `generate-hmac-key`
    /// - `generate-wrap-key`
    /// - `get-opaque`
    /// - `get-option`
    /// - `get-template`
    /// - `import-wrapped`
    /// - `put-asymmetric-key`
    /// - `put-authentication-key`
    /// - `put-mac-key`
    /// - `put-opaque`
    /// - `put-template`
    /// - `put-wrap-key`
    /// - `reset-device`
    /// - `set-option`
    /// - `sign-hmac`
    /// - `unwrap-data`
    /// - `verify-hmac`
    /// - `wrap-data`
    ///
    /// [capability]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    pub const CAP_ADMIN: &[Capability] = &[
        Capability::ChangeAuthenticationKey,
        Capability::DeleteAsymmetricKey,
        Capability::DeleteAuthenticationKey,
        Capability::DeleteHmacKey,
        Capability::DeleteOpaque,
        Capability::DeleteTemplate,
        Capability::DeleteWrapKey,
        Capability::ExportableUnderWrap,
        Capability::GenerateAsymmetricKey,
        Capability::GenerateHmacKey,
        Capability::GenerateWrapKey,
        Capability::GetOpaque,
        Capability::GetOption,
        Capability::GetTemplate,
        Capability::ImportWrapped,
        Capability::PutAsymmetricKey,
        Capability::PutAuthenticationKey,
        Capability::PutHmacKey,
        Capability::PutOpaque,
        Capability::SetOption,
        Capability::PutTemplate,
        Capability::PutWrapKey,
        Capability::ResetDevice,
        Capability::SignHmac,
        Capability::UnwrapData,
        Capability::VerifyHmac,
        Capability::WrapData,
    ];

    /// The list of [`Capability`] items required for [`YubiHsm2UserMapping::AuditLog`].
    ///
    /// Each item relates to a [capability] of the YubiHSM2 device:
    ///
    /// - `get-log-entries`
    ///
    /// [capability]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    pub const CAP_AUDIT_LOG: &[Capability] = &[Capability::GetLogEntries];

    /// The list of [`Capability`] items required for [`YubiHsm2UserMapping::Backup`].
    ///
    /// Each item relates to a [capability] of the YubiHSM2 device:
    ///
    /// - `export-wrapped`
    ///
    /// [capability]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    pub const CAP_BACKUP: &[Capability] = &[Capability::ExportWrapped];

    /// The list of [`Capability`] items required for [`YubiHsm2UserMapping::HermeticAuditLog`].
    ///
    /// Each item relates to a [capability] of the YubiHSM2 device:
    ///
    /// - `get-log-entries`
    ///
    /// [capability]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    pub const CAP_HERMETIC_AUDIT_LOG: &[Capability] = &[Capability::GetLogEntries];

    /// The list of [`Capability`] items required for [`YubiHsm2UserMapping::Signing`].
    ///
    /// Each item relates to a [capability] of the YubiHSM2 device:
    ///
    /// - `sign-eddsa`
    ///
    /// [capability]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    pub const CAP_SIGNING: &[Capability] = &[Capability::SignEddsa];

    /// Returns the optional [`Domains`] of the [`YubiHsm2UserMapping`].
    pub fn domains(&self) -> Option<Domains> {
        match self {
            Self::Admin { .. } | Self::Backup { .. } => Some(Domains::all()),
            Self::AuditLog { .. } | Self::HermeticAuditLog { .. } => None,
            Self::Signing {
                domain: key_domain, ..
            } => Some(Domains::from(*key_domain)),
        }
    }

    /// Returns the authentication key ID of the [`YubiHsm2UserMapping`].
    pub fn backend_user_id(&self) -> Id {
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

    /// Returns the [`Capabilities`] required by a variant.
    ///
    /// Each variant tracks a different set of [capabilities].
    /// The return value of this function combines each item from that set in a single value.
    ///
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    pub fn capabilities(&self) -> Capabilities {
        Capabilities::from(match self {
            Self::Admin { .. } => Self::CAP_ADMIN,
            Self::AuditLog { .. } => Self::CAP_AUDIT_LOG,
            Self::Backup { .. } => Self::CAP_BACKUP,
            Self::HermeticAuditLog { .. } => Self::CAP_HERMETIC_AUDIT_LOG,
            Self::Signing { .. } => Self::CAP_SIGNING,
        })
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
                if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
                    .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::Metrics,
                    BackendUserIdKind::NonAdmin,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::Backup,
                    BackendUserIdKind::NonAdmin,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::Metrics,
                    BackendUserIdKind::NonAdmin,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::NonAdmin,
                    BackendUserIdKind::Signing,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
                    .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::Metrics,
                    BackendUserIdKind::NonAdmin,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::Backup,
                    BackendUserIdKind::NonAdmin,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::Metrics,
                    BackendUserIdKind::NonAdmin,
                ]
                .contains(&filter.backend_user_id_kind)
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
                if [
                    BackendUserIdKind::Any,
                    BackendUserIdKind::NonAdmin,
                    BackendUserIdKind::Signing,
                ]
                .contains(&filter.backend_user_id_kind)
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

impl<'a> From<&'a YubiHsm2UserMapping> for SystemUserData<'a> {
    fn from(value: &'a YubiHsm2UserMapping) -> Self {
        match value {
            YubiHsm2UserMapping::Admin { .. } => Self::BackendAdmin {
                system_user: SystemUserId::root(),
            },
            YubiHsm2UserMapping::AuditLog {
                ssh_authorized_key,
                system_user,
                ..
            } => Self::BackendMetrics {
                system_user,
                ssh_authorized_key,
            },
            YubiHsm2UserMapping::Backup {
                ssh_authorized_key,
                system_user,
                ..
            } => Self::BackendBackup {
                system_user,
                ssh_authorized_key,
            },
            YubiHsm2UserMapping::HermeticAuditLog { system_user, .. } => {
                Self::BackendHermeticMetrics { system_user }
            }
            YubiHsm2UserMapping::Signing {
                ssh_authorized_key,
                system_user,
                ..
            } => Self::BackendSign {
                system_user,
                ssh_authorized_key,
            },
        }
    }
}

/// A filter for filtering sets of tags used in a YubiHSM2.
#[derive(Clone, Copy, Debug)]
pub struct YubiHsm2DomainFilter {}

impl BackendDomainFilter for YubiHsm2DomainFilter {}

impl MappingBackendDomain<YubiHsm2DomainFilter> for YubiHsm2UserMapping {
    fn backend_domain(&self, _filter: Option<&YubiHsm2DomainFilter>) -> Option<String> {
        self.domains().map(|domains| domains.bits().to_string())
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
    pub key_domain: Option<Domain>,
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

/// Validates a set of [`Connection`] objects.
///
/// Ensures that `value` is not empty.
///
/// # Errors
///
/// Returns an error if `value` is empty.
fn validate_yubihsm2_config_connections(
    value: &BTreeSet<Connection>,
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
    value: &BTreeSet<YubiHsm2UserMapping>,
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
    //
    // NOTE: We are not looking for duplicate domains in `YubiHsm2Mapping::Admin` and
    // `YubiHsm2Mapping::Backup`, as those are (implicitly) always in all domains.
    let duplicate_domains = duplicate_domains(
        &value
            .iter()
            .filter(|mapping| {
                !matches!(mapping, YubiHsm2UserMapping::Admin { .. })
                    && !matches!(mapping, YubiHsm2UserMapping::Backup { .. })
            })
            .collect::<BTreeSet<_>>(),
        None,
        None,
        None,
    );

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
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Validate)]
#[serde(rename_all = "snake_case")]
pub struct YubiHsm2Config {
    /// A set of connections to YubiHSM2 backends.
    #[garde(custom(validate_yubihsm2_config_connections))]
    connections: BTreeSet<Connection>,

    /// User mappings present in each YubiHSM2 backend.
    #[garde(custom(validate_yubihsm2_config_mappings))]
    mappings: BTreeSet<YubiHsm2UserMapping>,
}

impl YubiHsm2Config {
    /// The list of [YubiHSM2 commands] that should be tracked in the audit log.
    ///
    /// [YubiHSM2 commands]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html
    pub const AUDIT_COMMANDS: &[Code] = &[
        Code::AuthenticateSession,
        Code::ChangeAuthenticationKey,
        Code::CloseSession,
        Code::CreateSession,
        Code::DeleteObject,
        Code::ExportWrapped,
        Code::GetObjectInfo,
        Code::GetLogEntries,
        Code::GetOpaqueObject,
        Code::GetOption,
        Code::GetPublicKey,
        Code::GetStorageInfo,
        Code::HsmInitialization,
        Code::ImportWrapped,
        Code::PutOpaqueObject,
        Code::PutWrapKey,
        Code::ResetDevice,
        Code::SetOption,
        Code::SignAttestationCertificate,
        Code::SignEddsa,
    ];

    /// Creates a new [`YubiHsm2Config`] from a set of [`Connection`] and a set of
    /// [`YubiHsm2UserMapping`] items.
    pub fn new(
        connections: BTreeSet<Connection>,
        mappings: BTreeSet<YubiHsm2UserMapping>,
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

    /// Returns a reference to the set of [`Connection`] objects.
    pub fn connections(&self) -> &BTreeSet<Connection> {
        &self.connections
    }

    /// Returns a reference to the set of [`YubiHsm2UserMapping`] objects.
    pub fn mappings(&self) -> &BTreeSet<YubiHsm2UserMapping> {
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

/// Data about a YubiHSM2 user.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct YubiHsm2ConfigUserData {
    /// The ID of the authentication key.
    pub authentication_key_id: Id,

    /// The capabilities of the authentication key.
    pub capabilities: Capabilities,

    /// The optional domains of the authentication key.
    pub domains: Option<Domains>,
}

impl Display for YubiHsm2ConfigUserData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (capabilities: {}",
            self.authentication_key_id, self.capabilities
        )?;
        if let Some(domains) = self.domains.as_ref() {
            write!(f, "; domains: {domains}")?;
        }
        write!(f, ")")?;

        Ok(())
    }
}

/// Data about a YubiHSM2 signing user associated with a signing key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct YubiHsm2ConfigUserKeyData<'config> {
    /// The ID of the signing key.
    pub signing_key_id: &'config Id,

    /// The ID of the authentication key.
    pub authentication_key_id: &'config Id,

    /// The capabilities of the signing key.
    pub capabilities: Capabilities,

    /// The domain of the signing key.
    pub domain: &'config Domain,

    /// The setup of the signing key.
    pub key_setup: &'config SigningKeySetup,
}

impl<'config> Display for YubiHsm2ConfigUserKeyData<'config> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (authentication: {}; capabilities: {}; domain: {}; ",
            self.signing_key_id, self.authentication_key_id, self.capabilities, self.domain,
        )?;
        write!(f, "type: {}; ", self.key_setup.key_type())?;
        write!(
            f,
            "mechanisms: {}; ",
            self.key_setup
                .key_mechanisms()
                .iter()
                .map(|mechanism| mechanism.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )?;
        write!(f, "context: {}", self.key_setup.key_context())?;
        write!(f, ")")?;

        Ok(())
    }
}

/// The state of a YubiHSM2 configuration.
///
/// Tracks the available backend authentication keys, their capabilities and domains, as well as the
/// signing key setups associated with those authentication keys.
#[derive(Debug)]
pub struct YubiHsm2ConfigState<'config> {
    /// The user states.
    pub user_data: Vec<YubiHsm2ConfigUserData>,

    /// The key states.
    pub key_data: Vec<YubiHsm2ConfigUserKeyData<'config>>,
}

impl<'config> YubiHsm2ConfigState<'config> {
    /// The name of the origin for the state.
    pub const STATE_NAME: &'static str = "YubiHSM2 config";
}

impl<'config> From<&'config YubiHsm2Config> for YubiHsm2ConfigState<'config> {
    /// Creates a new [`YubiHsm2ConfigState`] from a [`YubiHsm2Config`].
    fn from(value: &'config YubiHsm2Config) -> Self {
        let mut user_data = Vec::new();
        let mut key_data = Vec::new();

        for mapping in value.mappings() {
            if let YubiHsm2UserMapping::Signing {
                authentication_key_id,
                key_setup,
                domain,
                signing_key_id,
                ..
            } = mapping
            {
                key_data.push(YubiHsm2ConfigUserKeyData {
                    signing_key_id,
                    authentication_key_id,
                    capabilities: mapping.capabilities(),
                    domain,
                    key_setup,
                })
            }

            user_data.push(YubiHsm2ConfigUserData {
                authentication_key_id: mapping.backend_user_id(),
                capabilities: mapping.capabilities(),
                domains: mapping.domains(),
            })
        }

        Self {
            user_data,
            key_data,
        }
    }
}

impl<'config> StateOriginInfo for YubiHsm2ConfigState<'config> {
    fn state_name(&self) -> &str {
        Self::STATE_NAME
    }

    fn state_origin(&self) -> StateOrigin {
        StateOrigin::Backend
    }
}

#[cfg(test)]
mod tests {
    use std::thread::current;

    use insta::{assert_snapshot, with_settings};
    use log::{LevelFilter, debug};
    use rstest::{fixture, rstest};
    use signstar_common::logging::setup_logging;
    use signstar_crypto::{
        key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
        openpgp::OpenPgpUserIdList,
    };
    use testresult::TestResult;

    use super::*;

    const SNAPSHOT_PATH: &str = "fixtures/yubihsm2_config/";

    #[rstest]
    #[case::admin(YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? })]
    #[case::audit_log(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
    )]
    #[case::backup(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
    )]
    #[case::hermetic_audit_log(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
    )]
    #[case::signing(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        }
    )]
    fn yubihsm2_user_mapping_backend_user_id(#[case] mapping: YubiHsm2UserMapping) -> TestResult {
        let id: Id = "1".parse()?;
        assert_eq!(mapping.backend_user_id(), id);

        Ok(())
    }

    /// Ensures that [`YubiHsm2UserMapping::capability`] works as intended.
    #[rstest]
    #[case::admin(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        YubiHsm2UserMapping::CAP_ADMIN,
    )]
    #[case::audit_log(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        YubiHsm2UserMapping::CAP_AUDIT_LOG,
    )]
    #[case::backup(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        YubiHsm2UserMapping::CAP_BACKUP,
    )]
    #[case::hermetic_audit_log(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        YubiHsm2UserMapping::CAP_HERMETIC_AUDIT_LOG,
    )]
    #[case::signing(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        YubiHsm2UserMapping::CAP_SIGNING,
    )]
    fn yubihsm2_user_mapping_capability(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] expected: &[Capability],
    ) -> TestResult {
        let expected = Capabilities::from(expected);
        assert_eq!(mapping.capabilities(), expected);

        Ok(())
    }

    #[rstest]
    #[case::admin_filter_admin(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::admin_filter_any(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::audit_log_filter_metrics(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::audit_log_filter_any(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::audit_log_filter_non_admin(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::backup_filter_backup(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::backup_filter_any(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::backup_filter_non_admin(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::hermetic_audit_log_filter_metrics(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::hermetic_audit_log_filter_any(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::hermetic_audit_log_filter_non_admin(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::signing_filter_signing(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::signing_filter_any(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::signing_filter_non_admin(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    fn yubihsm2_user_mapping_backend_user_ids_filter_matches(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] filter: BackendUserIdFilter,
    ) -> TestResult {
        assert_eq!(mapping.backend_user_ids(filter), vec!["1".to_string()]);

        Ok(())
    }

    #[rstest]
    #[case::admin_filter_non_admin(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::admin_filter_backup(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::admin_filter_metrics(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::admin_filter_observer(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::admin_filter_signing(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::audit_log_filter_admin(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::audit_log_filter_backup(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::audit_log_filter_observer(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::audit_log_filter_signing(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::backup_filter_admin(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::backup_filter_metrics(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::backup_filter_observer(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::backup_filter_signing(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::hermetic_audit_log_filter_admin(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::hermetic_audit_log_filter_backup(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::hermetic_audit_log_filter_observer(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::hermetic_audit_log_filter_signing(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::signing_filter_admin(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::signing_filter_backup(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::signing_filter_metrics(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::signing_filter_observer(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    fn yubihsm2_user_mapping_backend_user_ids_filter_mismatches(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] filter: BackendUserIdFilter,
    ) -> TestResult {
        assert!(mapping.backend_user_ids(filter).is_empty());

        Ok(())
    }

    #[test]
    fn yubihsm2_user_mapping_backend_user_with_passphrase_succeeds() -> TestResult {
        let mapping = YubiHsm2UserMapping::Admin {
            authentication_key_id: "1".parse()?,
        };
        let passphrase = Passphrase::generate(None);
        let creds = mapping.backend_user_with_passphrase("1", passphrase.clone())?;

        assert_eq!(creds.user(), "1");
        assert_eq!(
            creds.passphrase().expose_borrowed(),
            passphrase.expose_borrowed()
        );

        Ok(())
    }

    #[test]
    fn yubihsm2_user_mapping_backend_user_with_passphrase_fails() -> TestResult {
        let mapping = YubiHsm2UserMapping::Admin {
            authentication_key_id: "1".parse()?,
        };
        assert!(
            mapping
                .backend_user_with_passphrase("2", Passphrase::generate(None))
                .is_err()
        );

        Ok(())
    }

    #[rstest]
    #[case::admin_filter_admin(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::admin_filter_any(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::audit_log_filter_metrics(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::audit_log_filter_any(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::audit_log_filter_non_admin(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::backup_filter_backup(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::backup_filter_any(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::backup_filter_non_admin(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::hermetic_audit_log_filter_metrics(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::hermetic_audit_log_filter_any(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::hermetic_audit_log_filter_non_admin(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::signing_filter_signing(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::signing_filter_any(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any },
    )]
    #[case::signing_filter_non_admin(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    fn yubihsm2_user_mapping_backend_users_with_new_passphrase_filter_matches(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] filter: BackendUserIdFilter,
    ) -> TestResult {
        let creds = mapping.backend_users_with_new_passphrase(filter);
        assert!(creds.first().is_some_and(|creds| creds.user() == "1"));

        Ok(())
    }

    #[rstest]
    #[case::admin_filter_non_admin(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin },
    )]
    #[case::admin_filter_backup(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::admin_filter_metrics(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::admin_filter_observer(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::admin_filter_signing(
        YubiHsm2UserMapping::Admin{ authentication_key_id: "1".parse()? },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::audit_log_filter_admin(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::audit_log_filter_backup(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::audit_log_filter_observer(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::audit_log_filter_signing(
        YubiHsm2UserMapping::AuditLog {
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::backup_filter_admin(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::backup_filter_metrics(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::backup_filter_observer(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::backup_filter_signing(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::hermetic_audit_log_filter_admin(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::hermetic_audit_log_filter_backup(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::hermetic_audit_log_filter_observer(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    #[case::hermetic_audit_log_filter_signing(
        YubiHsm2UserMapping::HermeticAuditLog {
            authentication_key_id: "1".parse()?,
            system_user: "metrics-user".parse()?,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing },
    )]
    #[case::signing_filter_admin(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin },
    )]
    #[case::signing_filter_backup(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup },
    )]
    #[case::signing_filter_metrics(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics },
    )]
    #[case::signing_filter_observer(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer },
    )]
    fn yubihsm2_user_mapping_backend_users_with_new_passphrase_filter_mismatches(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] filter: BackendUserIdFilter,
    ) -> TestResult {
        assert!(mapping.backend_users_with_new_passphrase(filter).is_empty());

        Ok(())
    }

    #[rstest]
    #[case::backup_filter_wrapping_no_domain(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Wrapping, key_domain: None },
    )]
    #[case::backup_filter_wrapping_some_domain(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Wrapping, key_domain: Some(Domain::One) },
    )]
    #[case::signing_filter_signing_matching_domain(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Signing, key_domain: Some(Domain::One) },
    )]
    fn yubihsm2_user_mapping_backend_key_id_filter_matches(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] filter: YubiHsm2BackendKeyIdFilter,
    ) -> TestResult {
        assert!(mapping.backend_key_id(&filter).is_some_and(|id| id == "1"));

        Ok(())
    }

    #[rstest]
    #[case::backup_filter_signing_no_domain(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Signing, key_domain: None },
    )]
    #[case::backup_filter_signing_some_domain(
        YubiHsm2UserMapping::Backup{
            authentication_key_id: "1".parse()?,
            ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
            system_user: "backup-user".parse()?,
            wrapping_key_id: "1".parse()?,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Signing, key_domain: Some(Domain::One) },
    )]
    #[case::signing_filter_signing_wrong_domain(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Signing, key_domain: Some(Domain::Two) },
    )]
    #[case::signing_filter_wrapping_same_domain(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Wrapping, key_domain: Some(Domain::One) },
    )]
    #[case::signing_filter_wrapping_wrong_domain(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Wrapping, key_domain: Some(Domain::Two) },
    )]
    #[case::signing_filter_wrapping_no_domain(
        YubiHsm2UserMapping::Signing {
            authentication_key_id: "1".parse()?,
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
            system_user: "signing-user".parse()?,
            domain: Domain::One,
        },
        YubiHsm2BackendKeyIdFilter{ key_type: KeyObjectType::Wrapping, key_domain: None },
    )]
    fn yubihsm2_user_mapping_backend_key_id_filter_mismatches(
        #[case] mapping: YubiHsm2UserMapping,
        #[case] filter: YubiHsm2BackendKeyIdFilter,
    ) -> TestResult {
        assert!(mapping.backend_key_id(&filter).is_none());

        Ok(())
    }

    #[fixture]
    fn yubihsm2_yubihsm_connections() -> TestResult<[Connection; 2]> {
        Ok([
            Connection::Usb {
                serial_number: "0012345678".parse()?,
            },
            Connection::Usb {
                serial_number: "0087654321".parse()?,
            },
        ])
    }

    #[fixture]
    fn yubihsm2_mappings() -> TestResult<[YubiHsm2UserMapping; 5]> {
        Ok([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                        system_user: "backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "hermetic-metrics".parse()?,
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
                        system_user: "signing-user".parse()?,
                        domain: Domain::One,
                    }
                ])
    }

    #[fixture]
    fn yubihsm2_config(
        yubihsm2_yubihsm_connections: TestResult<[Connection; 2]>,
        yubihsm2_mappings: TestResult<[YubiHsm2UserMapping; 5]>,
    ) -> TestResult<YubiHsm2Config> {
        let yubihsm2_yubihsm_connections = yubihsm2_yubihsm_connections?;
        let yubihsm2_mappings = yubihsm2_mappings?;
        let config = YubiHsm2Config::new(
            BTreeSet::from_iter(yubihsm2_yubihsm_connections),
            BTreeSet::from_iter(yubihsm2_mappings),
        )?;

        Ok(config)
    }

    #[rstest]
    fn yubihsm2_config_connections(
        yubihsm2_yubihsm_connections: TestResult<[Connection; 2]>,
        yubihsm2_config: TestResult<YubiHsm2Config>,
    ) -> TestResult {
        let yubihsm2_config = yubihsm2_config?;
        let yubihsm2_yubihsm_connections = yubihsm2_yubihsm_connections?;
        let connections = yubihsm2_config.connections();

        assert_eq!(connections.len(), 2);
        assert!(
            connections
                .first()
                .is_some_and(|connection| connection == &yubihsm2_yubihsm_connections[0]),
        );
        assert!(
            connections
                .last()
                .is_some_and(|connection| connection == &yubihsm2_yubihsm_connections[1]),
        );

        Ok(())
    }

    #[rstest]
    fn yubihsm2_config_mappings(
        yubihsm2_mappings: TestResult<[YubiHsm2UserMapping; 5]>,
        yubihsm2_config: TestResult<YubiHsm2Config>,
    ) -> TestResult {
        let yubihsm2_config = yubihsm2_config?;
        let yubihsm2_mappings = yubihsm2_mappings?;
        let mappings = yubihsm2_config.mappings();

        assert_eq!(mappings.len(), 5);
        for mapping in yubihsm2_mappings.iter() {
            assert!(mappings.contains(mapping));
        }

        Ok(())
    }

    #[rstest]
    fn yubihsm2_config_authorized_key_entries(
        yubihsm2_mappings: TestResult<[YubiHsm2UserMapping; 5]>,
        yubihsm2_config: TestResult<YubiHsm2Config>,
    ) -> TestResult {
        let yubihsm2_config = yubihsm2_config?;
        let authorized_key_entries = yubihsm2_config.authorized_key_entries();

        let yubihsm2_mappings = yubihsm2_mappings?;
        let initial_entries = yubihsm2_mappings
            .iter()
            .filter_map(|mapping| mapping.authorized_key_entry())
            .collect::<HashSet<_>>();

        assert_eq!(initial_entries, authorized_key_entries);

        Ok(())
    }

    #[rstest]
    fn yubihsm2_config_system_user_ids(
        yubihsm2_mappings: TestResult<[YubiHsm2UserMapping; 5]>,
        yubihsm2_config: TestResult<YubiHsm2Config>,
    ) -> TestResult {
        let yubihsm2_config = yubihsm2_config?;
        let system_user_ids = yubihsm2_config.system_user_ids();

        let yubihsm2_mappings = yubihsm2_mappings?;
        let initial_entries = yubihsm2_mappings
            .iter()
            .filter_map(|mapping| mapping.system_user_id())
            .collect::<HashSet<_>>();

        assert_eq!(initial_entries, system_user_ids);

        Ok(())
    }

    #[rstest]
    #[case::no_connection(
        "Error message for YubiHsm2Config::new with no connection",
        BTreeSet::new(),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "4".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            }
        ]),
    )]
    #[case::no_mappings(
        "Error message for YubiHsm2Config::new with no user mappings",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::new(),
    )]
    #[case::duplicate_system_user_ids(
        "Error message for YubiHsm2Config::new with two duplicate system user IDs",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "4".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            }
        ]),
    )]
    #[case::duplicate_ssh_public_keys(
        "Error message for YubiHsm2Config::new with two duplicate SSH public keys as authorized keys",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "4".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            }
        ]),
    )]
    #[case::no_administrator(
        "Error message for YubiHsm2Config::new with no administrator",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "4".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            }
        ]),
    )]
    #[case::duplicate_backend_user_ids(
        "Error message for YubiHsm2Config::new with two duplicate backend user IDs",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "3".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            }
        ]),
    )]
    #[case::duplicate_signing_key_ids(
        "Error message for YubiHsm2Config::new with two duplicate signing key IDs",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "4".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
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
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "signing-user2".parse()?,
                domain: Domain::Two,
            },
        ]),
    )]
    #[case::duplicate_wrapping_key_ids(
        "Error message for YubiHsm2Config::new with two duplicate wrapping key IDs",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "backup-user2".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "4".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            },
        ]),
    )]
    #[case::duplicate_domains(
        "Error message for YubiHsm2Config::new with two duplicate domains",
        BTreeSet::from_iter([
            Connection::Usb {serial_number: "0012345678".parse()? },
            Connection::Usb {serial_number: "0087654321".parse()? },
        ]),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-user".parse()?,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "4".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
            },
            YubiHsm2UserMapping::Signing {
                authentication_key_id: "5".parse()?,
                signing_key_id: "2".parse()?,
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
                domain: Domain::One,
            },
        ]),
    )]
    #[case::all_the_issues(
        "Error message for YubiHsm2Config::new with multiple validation issues (connections and mappings)",
        BTreeSet::new(),
        BTreeSet::from_iter([
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "2".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::Backup{
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
                system_user: "backup-user".parse()?,
                wrapping_key_id: "1".parse()?,
            },
            YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "3".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "metrics-backupuser".parse()?,
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
                system_user: "signing-user".parse()?,
                domain: Domain::One,
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
                system_user: "signing-user2".parse()?,
                domain: Domain::One,
            },
        ]),
    )]
    fn yubihsm2_config_new_fails_validation(
        #[case] description: &str,
        #[case] connections: BTreeSet<Connection>,
        #[case] mappings: BTreeSet<YubiHsm2UserMapping>,
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

    /// Ensures that [`YubiHsm2ConfigUserData`] is displayed correctly.
    #[rstest]
    #[case::single_cap_single_domain(
        Capabilities::from(vec![Capability::SignEddsa].as_slice()),
        Some(Domains::from(vec![Domain::One].as_slice())),
        "1 (capabilities: sign-eddsa; domains: 1)"
    )]
    #[case::single_cap_no_domain(
        Capabilities::from(vec![Capability::SignEddsa].as_slice()),
        None,
        "1 (capabilities: sign-eddsa)"
    )]
    #[case::multi_cap_multi_domain(
        Capabilities::from(vec![Capability::SignEddsa, Capability::SignEcdsa].as_slice()),
        Some(Domains::from(vec![Domain::One, Domain::Two].as_slice())),
        "1 (capabilities: sign-ecdsa, sign-eddsa; domains: 1, 2)"
    )]
    #[case::multi_cap_single_domain(
        Capabilities::from(vec![Capability::SignEddsa, Capability::SignEcdsa].as_slice()),
        Some(Domains::from(vec![Domain::One].as_slice())),
        "1 (capabilities: sign-ecdsa, sign-eddsa; domains: 1)"
    )]
    #[case::multi_cap_no_domain(
        Capabilities::from(vec![Capability::SignEddsa, Capability::SignEcdsa].as_slice()),
        None,
        "1 (capabilities: sign-ecdsa, sign-eddsa)"
    )]
    fn yubihsm2_config_user_data_display(
        #[case] capabilities: Capabilities,
        #[case] domains: Option<Domains>,
        #[case] display: &str,
    ) -> TestResult {
        let data = YubiHsm2ConfigUserData {
            authentication_key_id: "1".parse()?,
            capabilities,
            domains,
        };

        assert_eq!(format!("{data}"), display);

        Ok(())
    }

    /// Ensures that [`YubiHsm2ConfigState`] can be created from [`YubiHsm2Config`].
    #[rstest]
    fn yubihsm2_config_state_from_yubihsm_config(
        yubihsm2_config: TestResult<YubiHsm2Config>,
        yubihsm2_mappings: TestResult<[YubiHsm2UserMapping; 5]>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let yubihsm2_config = yubihsm2_config?;
        let yubihsm2_mappings = yubihsm2_mappings?;
        let state = YubiHsm2ConfigState::from(&yubihsm2_config);

        for authentication_key_id in yubihsm2_mappings
            .iter()
            .map(|mapping| mapping.backend_user_id())
        {
            debug!(
                "Ensuring that the YubiHSM2 authentication key ID {authentication_key_id} can be found in the YubiHSM2 config state."
            );
            assert!(
                state
                    .user_data
                    .iter()
                    .any(|user_data| user_data.authentication_key_id == authentication_key_id)
            );
        }

        for (authentication_key_id, signing_key_id) in
            yubihsm2_mappings.iter().filter_map(|mapping| {
                if let YubiHsm2UserMapping::Signing {
                    authentication_key_id,
                    signing_key_id,
                    ..
                } = mapping
                {
                    Some((authentication_key_id, signing_key_id))
                } else {
                    None
                }
            })
        {
            debug!(
                "Ensuring that the YubiHSM2 authentication key ID {authentication_key_id} and signing key ID {signing_key_id} can be found in the YubiHSM2 config state."
            );
            assert!(
                state
                    .key_data
                    .iter()
                    .any(|data| data.authentication_key_id == authentication_key_id
                        && data.signing_key_id == signing_key_id)
            );
        }

        Ok(())
    }
}
