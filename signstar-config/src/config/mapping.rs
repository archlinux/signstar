//! User mapping for [`SignstarConfig`].

use std::{
    collections::HashSet,
    fs::{File, Permissions, create_dir_all, read_to_string, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use log::info;
use nethsm::{FullCredentials, KeyId, NamespaceId, Passphrase, SystemWideUserId, UserId, UserRole};
use serde::{Deserialize, Serialize};
use signstar_common::{
    common::SECRET_FILE_MODE,
    system_user::{
        get_home_base_dir_path,
        get_plaintext_secret_file,
        get_systemd_creds_secret_file,
        get_user_secrets_dir,
    },
};
use signstar_crypto::{key::SigningKeySetup, traits::UserWithPassphrase};

use crate::{
    AdministrativeSecretHandling,
    AuthorizedKeyEntry,
    CredentialsLoading,
    CredentialsLoadingError,
    CredentialsLoadingErrors,
    Error,
    NonAdministrativeSecretHandling,
    SignstarConfig,
    SystemUserId,
    config::base::BackendConnection,
    nethsm::config::{FilterUserKeys, NetHsmMetricsUsers},
    utils::{
        fail_if_not_root,
        fail_if_root,
        get_command,
        get_current_system_user,
        get_system_user_pair,
        match_current_system_user,
    },
};

/// The kind of backend user.
///
/// This distinguishes between the different access rights levels (i.e. administrative and
/// non-administrative) of a backend user.
#[derive(Clone, Copy, Debug, Default)]
pub enum BackendUserKind {
    /// Administrative user.
    Admin,
    /// Non-administrative user.
    #[default]
    NonAdmin,
}

/// A filter for [`UserMapping`] variants.
#[derive(Clone, Debug, Default)]
pub struct UserMappingFilter {
    /// The kind of backend user.
    pub backend_user_kind: BackendUserKind,
}

/// User and data mapping between system users and HSM users.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum UserMapping {
    /// A NetHsm user in the Administrator role, without a system user mapped to it
    #[serde(rename = "nethsm_only_admin")]
    NetHsmOnlyAdmin(UserId),

    /// A system user, with SSH access, mapped to a system-wide NetHSM user in the Backup role.
    #[serde(rename = "system_nethsm_backup")]
    SystemNetHsmBackup {
        /// The name of the NetHSM user.
        nethsm_user: SystemWideUserId,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a YubiHSM2 authentication key.
    ///
    /// # Note
    ///
    /// This variant implies, that the created user should have all [capabilities] for backup
    /// related actions (i.e. "export-wrapped", "wrap-data").
    ///
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    #[cfg(feature = "yubihsm2")]
    #[serde(rename = "system_yubihsm2_backup")]
    SystemYubiHsm2Backup {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: u16,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a system-wide NetHSM user
    /// in the Metrics role and `n` users in the Operator role with read-only access to zero or
    /// more keys
    #[serde(rename = "system_nethsm_metrics")]
    SystemNetHsmMetrics {
        /// The NetHSM users in the [`Metrics`][`UserRole::Metrics`] and
        /// [`operator`][`UserRole::Operator`] role.
        nethsm_users: NetHsmMetricsUsers,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, mapped to a NetHSM user in the
    /// Operator role with access to a single signing key.
    ///
    /// Signing key and NetHSM user are mapped using a tag.
    #[serde(rename = "system_nethsm_operator_signing")]
    SystemNetHsmOperatorSigning {
        /// The name of the NetHSM user.
        nethsm_user: UserId,
        /// The ID of the NetHSM key.
        key_id: KeyId,
        /// The setup of a NetHSM key.
        nethsm_key_setup: SigningKeySetup,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
        /// The tag used for the user and the signing key on the NetHSM.
        tag: String,
    },

    /// A system user, with SSH access, mapped to a YubiHSM2 user in the
    /// Operator role with access to a single signing key.
    ///
    /// Signing key and YubiHSM user are mapped using a permission.
    ///
    /// # Note
    ///
    /// This variant implies, that the created user should have all [capabilities] for signatures
    /// (i.e. "sign-ecdsa", "sign-eddsa", "sign-pkcs" and "sign-pss").
    ///
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    #[cfg(feature = "yubihsm2")]
    #[serde(rename = "system_yubihsm_operator_signing")]
    SystemYubiHsmOperatorSigning {
        /// The identifier of the authentication key used to create a session with the YubiHSM2.
        authentication_key_id: u16,
        /// The setup of a YubiHSM2 key.
        backend_key_setup: SigningKeySetup,
        /// The identifier of the key in the YubiHSM2 backend.
        backend_key_id: u16,
        /// The domain the backend key belongs to.
        backend_key_domain: usize,
        /// The SSH public key used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, without SSH access, mapped to a system-wide NetHSM
    /// user in the Metrics role and one or more NetHsm users in the Operator role with
    /// read-only access to zero or more keys
    #[serde(rename = "hermetic_system_nethsm_metrics")]
    HermeticSystemNetHsmMetrics {
        /// The NetHSM users in the [`Metrics`][`UserRole::Metrics`] and
        /// [`operator`][`UserRole::Operator`] role.
        nethsm_users: NetHsmMetricsUsers,
        /// The name of the system user.
        system_user: SystemUserId,
    },

    /// A system user, with SSH access, not mapped to any backend user, that is used for downloading
    /// shares of a shared secret.
    #[serde(rename = "system_only_share_download")]
    SystemOnlyShareDownload {
        /// The name of the system user.
        system_user: SystemUserId,
        /// The list of SSH public keys used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
    },

    /// A system user, with SSH access, not mapped to any backend user, that is used for uploading
    /// shares of a shared secret.
    #[serde(rename = "system_only_share_upload")]
    SystemOnlyShareUpload {
        /// The name of the system user.
        system_user: SystemUserId,
        /// The list of SSH public keys used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
    },

    /// A system user, with SSH access, not mapped to any backend user, that is used for downloading
    /// the WireGuard configuration of the host.
    #[serde(rename = "system_only_wireguard_download")]
    SystemOnlyWireGuardDownload {
        /// The name of the system user.
        system_user: SystemUserId,
        /// The list of SSH public keys used for connecting to the `system_user`.
        ssh_authorized_key: AuthorizedKeyEntry,
    },

    /// A YubiHSM 2 user in the administrator role, without a system user mapped to it.
    ///
    /// Wraps a [`u16`] which represents the [authentication key ID] on the HSM backend.
    ///
    /// # Note
    ///
    /// This variant implies, that the created user should have all [capabilities] necessary for the
    /// creation of users and keys and restore from backup, i.e.:
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
    /// [authentication key ID]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#authentication-key-object
    /// [capabilities]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#capability-protocol-details
    #[cfg(feature = "yubihsm2")]
    #[serde(rename = "yubihsm_only_admin")]
    YubiHsmOnlyAdmin(u16),
}

impl UserMapping {
    /// Returns the optional system user of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_config::{SystemUserId, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
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
                key_id: _,
                nethsm_key_setup: _,
                ssh_authorized_key: _,
                system_user,
                ..
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
            | UserMapping::SystemOnlyShareDownload { system_user, .. }
            | UserMapping::SystemOnlyShareUpload { system_user, .. }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user,
                ssh_authorized_key: _,
            } => Some(system_user),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_) => None,
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: _,
                backend_key_setup: _,
                backend_key_id: _,
                backend_key_domain: _,
                system_user,
                ..
            }
            | UserMapping::SystemYubiHsm2Backup { system_user, .. } => Some(system_user),
        }
    }

    /// Returns the backend users of the mapping.
    ///
    /// Returns a [`Vec`] of [`String`] containing all backend user names.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::{key::{CryptographicKeyContext, SigningKeySetup}, openpgp::OpenPgpUserIdList};
    /// use signstar_config::{BackendUserKind, UserMapping, UserMappingFilter};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning {
    ///     nethsm_user: "user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// assert_eq!(vec!["user1".to_string()], mapping.backend_users(UserMappingFilter::default()));
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert_eq!(vec!["user1".to_string()], mapping.backend_users(UserMappingFilter{ backend_user_kind: BackendUserKind::Admin }));
    /// # Ok(())
    /// # }
    /// ```
    pub fn backend_users(&self, filter: UserMappingFilter) -> Vec<String> {
        match self {
            UserMapping::NetHsmOnlyAdmin(user_id) => match filter.backend_user_kind {
                BackendUserKind::Admin => vec![user_id.to_string()],
                BackendUserKind::NonAdmin => Vec::new(),
            },
            UserMapping::SystemNetHsmBackup { nethsm_user, .. } => match filter.backend_user_kind {
                BackendUserKind::Admin => Vec::new(),
                BackendUserKind::NonAdmin => vec![nethsm_user.to_string()],
            },
            UserMapping::HermeticSystemNetHsmMetrics { nethsm_users, .. }
            | UserMapping::SystemNetHsmMetrics { nethsm_users, .. } => {
                match filter.backend_user_kind {
                    BackendUserKind::Admin => Vec::new(),
                    BackendUserKind::NonAdmin => nethsm_users
                        .get_users()
                        .iter()
                        .map(|user| user.to_string())
                        .collect(),
                }
            }
            UserMapping::SystemNetHsmOperatorSigning { nethsm_user, .. } => {
                match filter.backend_user_kind {
                    BackendUserKind::Admin => Vec::new(),
                    BackendUserKind::NonAdmin => vec![nethsm_user.to_string()],
                }
            }
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(admin) => match filter.backend_user_kind {
                BackendUserKind::Admin => vec![admin.to_string()],
                BackendUserKind::NonAdmin => Vec::new(),
            },
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id,
                ..
            }
            | UserMapping::SystemYubiHsm2Backup {
                authentication_key_id,
                ..
            } => match filter.backend_user_kind {
                BackendUserKind::Admin => Vec::new(),
                BackendUserKind::NonAdmin => vec![authentication_key_id.to_string()],
            },
        }
    }

    /// Returns the backend users of the mapping with new passphrases based on a `filter`.
    ///
    /// Returns a [`Vec`] of implementations of the [`UserWithPassphrase`] trait.
    /// For each returned backend user a new [`Passphrase`] is generated using the default settings
    /// of [`Passphrase::generate`].
    ///
    /// With a [`UserMappingFilter`] it is possible to target specific kinds of backend users.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::{key::{CryptographicKeyContext, SigningKeySetup}, openpgp::OpenPgpUserIdList};
    /// use signstar_config::{UserMapping, UserMappingFilter};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning {
    ///     nethsm_user: "user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// let creds = mapping.backend_users_with_new_passphrase(UserMappingFilter::default());
    /// println!("{creds:?}");
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// let creds = mapping.backend_users_with_new_passphrase(UserMappingFilter::default());
    /// println!("{creds:?}");
    /// # Ok(())
    /// # }
    /// ```
    pub fn backend_users_with_new_passphrase(
        &self,
        filter: UserMappingFilter,
    ) -> Vec<Box<dyn UserWithPassphrase>> {
        match self {
            UserMapping::NetHsmOnlyAdmin(user_id) => match filter.backend_user_kind {
                BackendUserKind::Admin => vec![Box::new(nethsm::FullCredentials::new(
                    user_id.clone(),
                    Passphrase::generate(None),
                ))],
                BackendUserKind::NonAdmin => Vec::new(),
            },
            UserMapping::SystemNetHsmBackup { nethsm_user, .. } => match filter.backend_user_kind {
                BackendUserKind::Admin => Vec::new(),
                BackendUserKind::NonAdmin => vec![Box::new(nethsm::FullCredentials::new(
                    nethsm_user.as_ref().clone(),
                    Passphrase::generate(None),
                ))],
            },
            UserMapping::HermeticSystemNetHsmMetrics { nethsm_users, .. }
            | UserMapping::SystemNetHsmMetrics { nethsm_users, .. } => {
                match filter.backend_user_kind {
                    BackendUserKind::Admin => Vec::new(),
                    BackendUserKind::NonAdmin => nethsm_users
                        .get_users()
                        .iter()
                        .map(|user| {
                            Box::new(FullCredentials::new(
                                user.clone(),
                                Passphrase::generate(None),
                            )) as Box<dyn UserWithPassphrase>
                        })
                        .collect(),
                }
            }
            UserMapping::SystemNetHsmOperatorSigning { nethsm_user, .. } => {
                match filter.backend_user_kind {
                    BackendUserKind::Admin => Vec::new(),
                    BackendUserKind::NonAdmin => vec![Box::new(nethsm::FullCredentials::new(
                        nethsm_user.clone(),
                        Passphrase::generate(None),
                    ))],
                }
            }
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(admin) => match filter.backend_user_kind {
                BackendUserKind::Admin => vec![Box::new(signstar_yubihsm2::Credentials::new(
                    *admin,
                    Passphrase::generate(None),
                ))],
                BackendUserKind::NonAdmin => Vec::new(),
            },
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id,
                ..
            }
            | UserMapping::SystemYubiHsm2Backup {
                authentication_key_id,
                ..
            } => match filter.backend_user_kind {
                BackendUserKind::Admin => Vec::new(),
                BackendUserKind::NonAdmin => vec![Box::new(signstar_yubihsm2::Credentials::new(
                    *authentication_key_id,
                    Passphrase::generate(None),
                ))],
            },
        }
    }

    /// Returns the NetHSM users of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    /// use signstar_config::UserMapping;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
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
            UserMapping::SystemNetHsmBackup { nethsm_user, .. } => vec![nethsm_user.clone().into()],
            UserMapping::NetHsmOnlyAdmin(nethsm_user)
            | UserMapping::SystemNetHsmOperatorSigning { nethsm_user, .. } => {
                vec![nethsm_user.clone()]
            }
            UserMapping::SystemNetHsmMetrics { nethsm_users, .. }
            | UserMapping::HermeticSystemNetHsmMetrics { nethsm_users, .. } => {
                nethsm_users.get_users()
            }
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
        }
    }

    /// Returns the list of all tracked [`UserId`]s and their respective [`UserRole`]s.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{UserId, UserRole};
    /// use signstar_config::UserMapping;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    /// };
    /// assert!(mapping.get_nethsm_users_and_roles().is_empty());
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert_eq!(mapping.get_nethsm_users_and_roles(), vec![(UserId::new("user1".to_string())?, UserRole::Administrator)]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_nethsm_users_and_roles(&self) -> Vec<(UserId, UserRole)> {
        match self {
            UserMapping::SystemNetHsmBackup { nethsm_user, .. } => {
                vec![(nethsm_user.clone().into(), UserRole::Backup)]
            }
            UserMapping::NetHsmOnlyAdmin(nethsm_user) => {
                vec![(nethsm_user.clone(), UserRole::Administrator)]
            }
            UserMapping::SystemNetHsmOperatorSigning { nethsm_user, .. } => {
                vec![(nethsm_user.clone(), UserRole::Operator)]
            }
            UserMapping::SystemNetHsmMetrics { nethsm_users, .. }
            | UserMapping::HermeticSystemNetHsmMetrics { nethsm_users, .. } => {
                nethsm_users.get_users_and_roles()
            }
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
        }
    }

    /// Returns a list of tuples containing [`UserId`], [`UserRole`] and a list of tags.
    ///
    /// # Note
    ///
    /// Certain variants of [`UserMapping`] such as [`UserMapping::SystemOnlyShareDownload`],
    /// [`UserMapping::SystemOnlyShareUpload`] and [`UserMapping::SystemOnlyWireGuardDownload`]
    /// always return an empty [`Vec`] because they do not track backend users.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, OpenPgpUserIdList, UserId, UserRole};
    /// use signstar_crypto::key::SigningKeySetup;
    /// use signstar_config::{AuthorizedKeyEntry, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning {
    ///     nethsm_user: "user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// assert_eq!(
    ///     mapping.get_nethsm_user_role_and_tags(),
    ///     vec![(UserId::new("user1".to_string())?, UserRole::Operator, vec!["tag1".to_string()])]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_nethsm_user_role_and_tags(&self) -> Vec<(UserId, UserRole, Vec<String>)> {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                key_id: _,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key: _,
                tag,
            } => vec![(
                nethsm_user.clone(),
                UserRole::Operator,
                vec![tag.to_string()],
            )],
            UserMapping::SystemNetHsmBackup { nethsm_user, .. } => {
                vec![(nethsm_user.clone().into(), UserRole::Backup, Vec::new())]
            }
            UserMapping::NetHsmOnlyAdmin(user_id) => {
                vec![(user_id.clone(), UserRole::Administrator, Vec::new())]
            }
            UserMapping::SystemNetHsmMetrics { nethsm_users, .. } => nethsm_users
                .get_users_and_roles()
                .iter()
                .map(|(user, role)| (user.clone(), *role, Vec::new()))
                .collect(),
            UserMapping::HermeticSystemNetHsmMetrics { nethsm_users, .. } => nethsm_users
                .get_users_and_roles()
                .iter()
                .map(|(user, role)| (user.clone(), *role, Vec::new()))
                .collect(),
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
        }
    }

    /// Returns the SSH authorized key of the mapping if it exists.
    ///
    /// Returns [`None`] if the mapping does not have an SSH authorized key.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use signstar_config::{AuthorizedKeyEntry, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    /// };
    /// assert_eq!(mapping.get_ssh_authorized_key(), Some(&AuthorizedKeyEntry::from_str("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host")?));
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert_eq!(mapping.get_ssh_authorized_key(), None);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_ssh_authorized_key(&self) -> Option<&AuthorizedKeyEntry> {
        match self {
            UserMapping::NetHsmOnlyAdmin(_) | UserMapping::HermeticSystemNetHsmMetrics { .. } => {
                None
            }
            UserMapping::SystemNetHsmBackup {
                nethsm_user: _,
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemNetHsmMetrics {
                nethsm_users: _,
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemOnlyShareDownload {
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemOnlyShareUpload {
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemOnlyWireGuardDownload {
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: _,
                key_id: _,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key,
                ..
            } => Some(ssh_authorized_key),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_) => None,
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: _,
                backend_key_setup: _,
                backend_key_id: _,
                backend_key_domain: _,
                system_user: _,
                ssh_authorized_key,
            }
            | UserMapping::SystemYubiHsm2Backup {
                ssh_authorized_key, ..
            } => Some(ssh_authorized_key),
        }
    }

    /// Returns all used [`KeyId`]s of the mapping
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, KeyId, OpenPgpUserIdList};
    /// use signstar_crypto::key::SigningKeySetup;
    /// use signstar_config::{AuthorizedKeyEntry, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning {
    ///     nethsm_user: "user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// assert_eq!(mapping.get_nethsm_key_ids(None), vec![KeyId::new("key1".to_string())?]);
    ///
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    /// };
    /// assert_eq!(mapping.get_nethsm_key_ids(None), Vec::new());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_nethsm_key_ids(&self, namespace: Option<&NamespaceId>) -> Vec<KeyId> {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                key_id,
                ..
            } => {
                if nethsm_user.namespace() == namespace {
                    vec![key_id.clone()]
                } else {
                    Vec::new()
                }
            }
            UserMapping::SystemNetHsmMetrics { .. }
            | UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::HermeticSystemNetHsmMetrics { .. }
            | UserMapping::SystemNetHsmBackup { .. }
            | UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
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
    /// use nethsm::{CryptographicKeyContext, OpenPgpUserIdList};
    /// use signstar_crypto::key::SigningKeySetup;
    /// use signstar_config::UserMapping;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    /// };
    /// assert!(mapping.get_nethsm_tags(None).is_empty());
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert!(mapping.get_nethsm_tags(None).is_empty());
    ///
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning{
    ///     nethsm_user: "ns1~user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// assert!(mapping.get_nethsm_tags(None).is_empty());
    /// assert_eq!(mapping.get_nethsm_tags(Some(&"ns1".parse()?)), vec!["tag1"]);
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    pub fn get_nethsm_tags(&self, namespace: Option<&NamespaceId>) -> Vec<&str> {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                key_id: _,
                nethsm_key_setup: _,
                system_user: _,
                ssh_authorized_key: _,
                tag,
            } => {
                if nethsm_user.namespace() == namespace {
                    vec![tag.as_str()]
                } else {
                    Vec::new()
                }
            }
            UserMapping::SystemNetHsmMetrics { .. }
            | UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::HermeticSystemNetHsmMetrics { .. }
            | UserMapping::SystemNetHsmBackup { .. }
            | UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
        }
    }

    /// Returns a list of tuples of [`UserId`], [`KeyId`], [`SigningKeySetup`] and tag for the
    /// mapping.
    ///
    /// Using a `filter` (see [`FilterUserKeys`]) it is possible to have only a subset of the
    /// available tuples be returned:
    ///
    /// - [`FilterUserKeys::All`]: Returns all available tuples.
    /// - [`FilterUserKeys::Namespaced`]: Returns tuples that match [`UserId`]s with a namespace.
    /// - [`FilterUserKeys::Namespace`]: Returns tuples that match [`UserId`]s with a specific
    ///   namespace.
    /// - [`FilterUserKeys::SystemWide`]: Returns tuples that match [`UserId`]s without a namespace.
    /// - [`FilterUserKeys::Namespace`]: Returns tuples that match a specific tag.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, KeyId, OpenPgpUserIdList, UserId};
    /// use signstar_crypto::key::SigningKeySetup;
    /// use signstar_config::{FilterUserKeys, UserMapping};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning {
    ///     nethsm_user: "user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// assert_eq!(
    ///     mapping.get_nethsm_user_key_and_tag(FilterUserKeys::All),
    ///     vec![(
    ///         "user1".parse()?,
    ///         "key1".parse()?,
    ///         SigningKeySetup::new(
    ///             "Curve25519".parse()?,
    ///             vec!["EdDsaSignature".parse()?],
    ///             None,
    ///             "EdDsa".parse()?,
    ///             CryptographicKeyContext::OpenPgp{
    ///                 user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
    ///                 version: "v4".parse()?,
    ///             },
    ///         )?,
    ///         "tag1".to_string(),
    ///     )]
    /// );
    /// assert_eq!(mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespace("test".parse()?)), Vec::new());
    /// assert_eq!(mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Tag("tag2".parse()?)), Vec::new());
    ///
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    /// };
    /// assert_eq!(mapping.get_nethsm_user_key_and_tag(FilterUserKeys::All), Vec::new());
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_nethsm_user_key_and_tag(
        &self,
        filter: FilterUserKeys,
    ) -> Vec<(UserId, KeyId, SigningKeySetup, String)> {
        match self {
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user,
                key_id,
                nethsm_key_setup,
                system_user: _,
                ssh_authorized_key: _,
                tag,
            } => match filter {
                FilterUserKeys::All => {
                    vec![(
                        nethsm_user.clone(),
                        key_id.clone(),
                        nethsm_key_setup.clone(),
                        tag.clone(),
                    )]
                }
                FilterUserKeys::Namespaced => {
                    if nethsm_user.is_namespaced() {
                        vec![(
                            nethsm_user.clone(),
                            key_id.clone(),
                            nethsm_key_setup.clone(),
                            tag.clone(),
                        )]
                    } else {
                        Vec::new()
                    }
                }
                FilterUserKeys::Namespace(namespace) => {
                    if Some(&namespace) == nethsm_user.namespace() {
                        vec![(
                            nethsm_user.clone(),
                            key_id.clone(),
                            nethsm_key_setup.clone(),
                            tag.clone(),
                        )]
                    } else {
                        Vec::new()
                    }
                }
                FilterUserKeys::SystemWide => {
                    if !nethsm_user.is_namespaced() {
                        vec![(
                            nethsm_user.clone(),
                            key_id.clone(),
                            nethsm_key_setup.clone(),
                            tag.clone(),
                        )]
                    } else {
                        Vec::new()
                    }
                }
                FilterUserKeys::Tag(filter_tag) => {
                    if &filter_tag == tag {
                        vec![(
                            nethsm_user.clone(),
                            key_id.clone(),
                            nethsm_key_setup.clone(),
                            tag.clone(),
                        )]
                    } else {
                        Vec::new()
                    }
                }
            },
            UserMapping::SystemNetHsmMetrics { .. }
            | UserMapping::NetHsmOnlyAdmin(_)
            | UserMapping::HermeticSystemNetHsmMetrics { .. }
            | UserMapping::SystemNetHsmBackup { .. }
            | UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
        }
    }

    /// Returns all NetHSM [namespaces] of the mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{CryptographicKeyContext, OpenPgpUserIdList};
    /// use signstar_crypto::key::SigningKeySetup;
    /// use signstar_config::UserMapping;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let mapping = UserMapping::SystemOnlyShareDownload {
    ///     system_user: "user1".parse()?,
    ///     ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
    /// };
    /// assert!(mapping.get_nethsm_namespaces().is_empty());
    ///
    /// let mapping = UserMapping::NetHsmOnlyAdmin("user1".parse()?);
    /// assert!(mapping.get_nethsm_namespaces().is_empty());
    ///
    /// let mapping = UserMapping::SystemNetHsmOperatorSigning{
    ///     nethsm_user: "ns1~user1".parse()?,
    ///     key_id: "key1".parse()?,
    ///     nethsm_key_setup: SigningKeySetup::new(
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
    /// assert_eq!(mapping.get_nethsm_namespaces(), vec!["ns1".parse()?]);
    /// # Ok(())
    /// # }
    /// ```
    /// [namespaces]: https://docs.nitrokey.com/nethsm/administration#namespaces
    pub fn get_nethsm_namespaces(&self) -> Vec<NamespaceId> {
        match self {
            UserMapping::NetHsmOnlyAdmin(nethsm_user)
            | UserMapping::SystemNetHsmOperatorSigning { nethsm_user, .. } => {
                if let Some(namespace) = nethsm_user.namespace() {
                    vec![namespace.clone()]
                } else {
                    Vec::new()
                }
            }
            UserMapping::HermeticSystemNetHsmMetrics { nethsm_users, .. }
            | UserMapping::SystemNetHsmMetrics { nethsm_users, .. } => nethsm_users
                .get_users()
                .iter()
                .filter_map(|user_id| user_id.namespace())
                .cloned()
                .collect(),
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemNetHsmBackup { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. } => Vec::new(),
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_)
            | UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => Vec::new(),
        }
    }

    /// Returns whether the mapping has both system and HSM backend users.
    ///
    /// Returns `true` if the `self` has at least one system and one HSM backend user, and `false`
    /// otherwise.
    pub fn has_system_and_backend_user(&self) -> bool {
        match self {
            UserMapping::SystemNetHsmOperatorSigning { .. }
            | UserMapping::HermeticSystemNetHsmMetrics { .. }
            | UserMapping::SystemNetHsmMetrics { .. }
            | UserMapping::SystemNetHsmBackup { .. } => true,
            #[cfg(feature = "yubihsm2")]
            UserMapping::YubiHsmOnlyAdmin(_) => false,
            #[cfg(feature = "yubihsm2")]
            UserMapping::SystemYubiHsm2Backup { .. }
            | UserMapping::SystemYubiHsmOperatorSigning { .. } => true,
            UserMapping::SystemOnlyShareDownload { .. }
            | UserMapping::SystemOnlyShareUpload { .. }
            | UserMapping::SystemOnlyWireGuardDownload { .. }
            | UserMapping::NetHsmOnlyAdmin(_) => false,
        }
    }
}

/// Checks the accessibility of a secrets file.
///
/// Checks whether file at `path`
///
/// - exists,
/// - is a file,
/// - has accessible metadata,
/// - and has the file mode [`SECRET_FILE_MODE`].
///
/// # Errors
///
/// Returns an error, if the file at `path`
///
/// - does not exist,
/// - is not a file,
/// - does not have accessible metadata,
/// - or has a file mode other than [`SECRET_FILE_MODE`].
pub(crate) fn check_secrets_file(path: impl AsRef<Path>) -> Result<(), Error> {
    let path = path.as_ref();

    // check if a path exists
    if !path.exists() {
        return Err(crate::non_admin_credentials::Error::SecretsFileMissing {
            path: path.to_path_buf(),
        }
        .into());
    }

    // check if this is a file
    if !path.is_file() {
        return Err(Error::NonAdminSecretHandling(
            crate::non_admin_credentials::Error::SecretsFileNotAFile {
                path: path.to_path_buf(),
            },
        ));
    }

    // check for correct permissions
    match path.metadata() {
        Ok(metadata) => {
            let mode = metadata.permissions().mode();
            if mode != SECRET_FILE_MODE {
                return Err(Error::NonAdminSecretHandling(
                    crate::non_admin_credentials::Error::SecretsFilePermissions {
                        path: path.to_path_buf(),
                        mode,
                    },
                ));
            }
        }
        Err(source) => {
            return Err(Error::NonAdminSecretHandling(
                crate::non_admin_credentials::Error::SecretsFileMetadata {
                    path: path.to_path_buf(),
                    source,
                },
            ));
        }
    }

    Ok(())
}

/// A [`UserMapping`] centric view of a [`SignstarConfig`].
///
/// Wraps a single [`UserMapping`], as well as the system-wide [`AdministrativeSecretHandling`],
/// [`NonAdministrativeSecretHandling`] and [`BackendConnection`]s.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExtendedUserMapping {
    admin_secret_handling: AdministrativeSecretHandling,
    non_admin_secret_handling: NonAdministrativeSecretHandling,
    connections: HashSet<BackendConnection>,
    user_mapping: UserMapping,
}

impl ExtendedUserMapping {
    /// Creates a new [`ExtendedUserMapping`].
    pub fn new(
        admin_secret_handling: AdministrativeSecretHandling,
        non_admin_secret_handling: NonAdministrativeSecretHandling,
        connections: HashSet<BackendConnection>,
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

    /// Returns the [`BackendConnection`]s.
    pub fn get_connections(&self) -> HashSet<BackendConnection> {
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

    /// Loads credentials for each backend user associated with a [`SystemUserId`].
    ///
    /// The [`SystemUserId`] of the mapping must be equal to the current system user calling this
    /// function.
    /// Relies on [`get_plaintext_secret_file`] and [`get_systemd_creds_secret_file`] to retrieve
    /// the specific path to a secrets file for each backend user name mapped to a [`SystemUserId`].
    ///
    /// Returns a [`CredentialsLoading`], which may contain critical errors related to loading a
    /// passphrase from a secrets file for each available backend user.
    ///
    /// # Note
    ///
    /// The caller is expected to handle any errors tracked in the returned object based on context.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the [`ExtendedUserMapping`] provides no [`SystemUserId`],
    /// - no system user equal to the [`SystemUserId`] exists,
    /// - the [`SystemUserId`] is not equal to the currently calling system user,
    /// - or the [systemd-creds] command is not available when trying to decrypt secrets.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn load_credentials(&self) -> Result<CredentialsLoading, Error> {
        // Retrieve required SystemUserId and User and compare with current User.
        let (system_user, user) = get_system_user_pair(self)?;
        let current_system_user = get_current_system_user()?;

        // fail if running as root
        fail_if_root(&current_system_user)?;
        match_current_system_user(&current_system_user, &user)?;

        let secret_handling = self.get_non_admin_secret_handling();
        let mut credentials: Vec<Box<dyn UserWithPassphrase>> = Vec::new();
        let mut errors = Vec::new();

        // Iterate over the names of non-administrative backend users of the mapping.
        for name in self.get_user_mapping().backend_users(UserMappingFilter {
            backend_user_kind: BackendUserKind::NonAdmin,
        }) {
            let secrets_file = match secret_handling {
                NonAdministrativeSecretHandling::Plaintext => {
                    get_plaintext_secret_file(system_user.as_ref(), &name)
                }
                NonAdministrativeSecretHandling::SystemdCreds => {
                    get_systemd_creds_secret_file(system_user.as_ref(), &name)
                }
            };
            info!(
                "Load secret for system user {system_user} and backend user {name} from file: {secrets_file:?}"
            );
            // Ensure the secrets file has correct ownership and permissions.
            if let Err(error) = check_secrets_file(secrets_file.as_path()) {
                errors.push(CredentialsLoadingError::new(name.clone(), error));
                continue;
            };

            let passphrase = match secret_handling {
                // Read from plaintext secrets file.
                NonAdministrativeSecretHandling::Plaintext => {
                    // get passphrase or error
                    match read_to_string(&secrets_file).map_err(|source| {
                        Error::NonAdminSecretHandling(
                            crate::non_admin_credentials::Error::SecretsFileRead {
                                path: secrets_file,
                                source,
                            },
                        )
                    }) {
                        Ok(passphrase) => Passphrase::new(passphrase),
                        Err(error) => {
                            errors.push(CredentialsLoadingError::new(name.clone(), error));
                            continue;
                        }
                    }
                }
                // Read from systemd-creds encrypted secrets file.
                NonAdministrativeSecretHandling::SystemdCreds => {
                    // Decrypt secret using systemd-creds.
                    let creds_command = get_command("systemd-creds")?;
                    let mut command = Command::new(creds_command);
                    let command = command
                        .arg("--user")
                        .arg("decrypt")
                        .arg(&secrets_file)
                        .arg("-");
                    match command.output().map_err(|source| Error::CommandExec {
                        command: format!("{command:?}"),
                        source,
                    }) {
                        Ok(command_output) => {
                            // fail if decryption did not result in a successful status code
                            if !command_output.status.success() {
                                errors.push(CredentialsLoadingError::new(
                                    name.clone(),
                                    Error::CommandNonZero {
                                        command: format!("{command:?}"),
                                        exit_status: command_output.status,
                                        stderr: String::from_utf8_lossy(&command_output.stderr)
                                            .into_owned(),
                                    },
                                ));
                                continue;
                            }

                            let creds = match String::from_utf8(command_output.stdout) {
                                Ok(creds) => creds,
                                Err(source) => {
                                    errors.push(CredentialsLoadingError::new(
                                        name.clone(),
                                        Error::Utf8String {
                                            path: secrets_file,
                                            context: format!(
                                                "converting stdout of {command:?} to string"
                                            ),
                                            source,
                                        },
                                    ));
                                    continue;
                                }
                            };

                            Passphrase::new(creds)
                        }
                        Err(error) => {
                            errors.push(CredentialsLoadingError::new(name.clone(), error));
                            continue;
                        }
                    }
                }
            };

            // Add the credentials to the output.
            //
            // NOTE: Some UserMappings do not have non-administrative backend users and are only
            // matched to allow for variants behind dedicated features to be addressed properly.
            match self.get_user_mapping() {
                // NOTE: This is a no-op, because an admin user's credentials are not persisted the
                // same way as those of a non-admin user.
                UserMapping::NetHsmOnlyAdmin(_) => {}
                // NOTE: This is a no-op, as these mappings have no backend user.
                UserMapping::SystemOnlyShareDownload { .. }
                | UserMapping::SystemOnlyShareUpload { .. }
                | UserMapping::SystemOnlyWireGuardDownload { .. } => {}
                UserMapping::SystemNetHsmBackup { .. }
                | UserMapping::SystemNetHsmMetrics { .. }
                | UserMapping::SystemNetHsmOperatorSigning { .. }
                | UserMapping::HermeticSystemNetHsmMetrics { .. } => {
                    credentials.push(Box::new(FullCredentials::new(
                        // NOTE: It is not possible to actually trigger this error, as we are
                        // deriving `name` from a `UserId` in this case.
                        UserId::new(name)
                            .map_err(|source| Error::NetHsm(nethsm::Error::User(source)))?,
                        passphrase,
                    )));
                }
                #[cfg(feature = "yubihsm2")]
                UserMapping::YubiHsmOnlyAdmin(_) => {}
                #[cfg(feature = "yubihsm2")]
                UserMapping::SystemYubiHsmOperatorSigning {
                    authentication_key_id,
                    ..
                }
                | UserMapping::SystemYubiHsm2Backup {
                    authentication_key_id,
                    ..
                } => credentials.push(Box::new(signstar_yubihsm2::Credentials::new(
                    *authentication_key_id,
                    passphrase,
                ))),
            }
        }

        Ok(CredentialsLoading::new(
            self.clone(),
            credentials,
            CredentialsLoadingErrors::new(errors),
        ))
    }

    /// Creates secrets directories for all non-administrative mappings.
    ///
    /// Matches the [`SystemUserId`] in a mapping with an actual user on the system.
    /// Creates the passphrase directory for the user and ensures correct ownership of it and all
    /// parent directories up until the user's home directory.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - no system user is available in the mapping,
    /// - the system user of the mapping is not available on the system,
    /// - the directory could not be created,
    /// - the ownership of any directory between the user's home and the passphrase directory can
    ///   not be changed.
    pub fn create_secrets_dir(&self) -> Result<(), Error> {
        // Retrieve required SystemUserId and User and compare with current User.
        let (system_user, user) = get_system_user_pair(self)?;

        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        // get and create the user's passphrase directory
        let secrets_dir = get_user_secrets_dir(system_user.as_ref());
        create_dir_all(&secrets_dir).map_err(|source| {
            crate::non_admin_credentials::Error::SecretsDirCreate {
                path: secrets_dir.clone(),
                system_user: system_user.clone(),
                source,
            }
        })?;

        // Recursively chown all directories to the user and group, until `HOME_BASE_DIR` is
        // reached.
        let home_dir = get_home_base_dir_path().join(PathBuf::from(system_user.as_ref()));
        let mut chown_dir = secrets_dir.clone();
        while chown_dir != home_dir {
            chown(&chown_dir, Some(user.uid.as_raw()), Some(user.gid.as_raw())).map_err(
                |source| Error::Chown {
                    path: chown_dir.to_path_buf(),
                    user: system_user.to_string(),
                    source,
                },
            )?;
            if let Some(parent) = &chown_dir.parent() {
                chown_dir = parent.to_path_buf()
            } else {
                break;
            }
        }

        Ok(())
    }

    /// Creates passphrases for all non-administrative mappings.
    ///
    /// If the targeted [`UserMapping`] is that of non-administrative backend user(s), a new random
    /// passphrase (see [`Passphrase::generate`]) is created for each of those backend user(s).
    /// Each passphrase is written to disk and finally the list of credentials are returned.
    ///
    /// - If `self` is configured to use [`NonAdministrativeSecretHandling::Plaintext`], the
    ///   passphrase is stored in a secrets file, defined by [`get_plaintext_secret_file`].
    /// - If `self` is configured to use [`NonAdministrativeSecretHandling::SystemdCreds`], the
    ///   passphrase is encrypted using [systemd-creds] and stored in a secrets file, defined by
    ///   [`get_systemd_creds_secret_file`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the targeted system user does not exist in the mapping or on the system,
    /// - the function is called using a non-root user,
    /// - the [systemd-creds] command is not available when trying to encrypt the passphrase,
    /// - the encryption of the passphrase using [systemd-creds] fails,
    /// - the secrets file can not be created,
    /// - the secrets file can not be written to,
    /// - or the ownership and permissions of the secrets file can not be changed.
    ///
    /// [systemd-creds]: https://man.archlinux.org/man/systemd-creds.1
    pub fn create_non_administrative_secrets(
        &self,
    ) -> Result<Vec<Box<dyn UserWithPassphrase>>, Error> {
        // Retrieve required SystemUserId and User.
        let (system_user, user) = get_system_user_pair(self)?;

        // fail if not running as root
        fail_if_not_root(&get_current_system_user()?)?;

        let secret_handling = self.get_non_admin_secret_handling();
        // Get credentials for all backend users (with newly generated passphrases).
        let credentials =
            self.get_user_mapping()
                .backend_users_with_new_passphrase(UserMappingFilter {
                    backend_user_kind: BackendUserKind::NonAdmin,
                });

        // Write the passphrase for each set of credentials to disk.
        for creds in credentials.iter() {
            let secrets_file = match secret_handling {
                NonAdministrativeSecretHandling::Plaintext => {
                    get_plaintext_secret_file(system_user.as_ref(), &creds.user())
                }
                NonAdministrativeSecretHandling::SystemdCreds => {
                    get_systemd_creds_secret_file(system_user.as_ref(), &creds.user())
                }
            };

            info!(
                "Create secret for system user {system_user} and backend user {} in file: {secrets_file:?}",
                creds.user()
            );
            let secret = {
                // Create credentials files depending on secret handling
                match secret_handling {
                    NonAdministrativeSecretHandling::Plaintext => {
                        creds.passphrase().expose_borrowed().as_bytes().to_vec()
                    }
                    NonAdministrativeSecretHandling::SystemdCreds => {
                        // Create systemd-creds encrypted secret.
                        let creds_command = get_command("systemd-creds")?;
                        let mut command = Command::new(creds_command);
                        let command = command
                            .arg("--user")
                            .arg("--name=")
                            .arg("--uid")
                            .arg(system_user.as_ref())
                            .arg("encrypt")
                            .arg("-")
                            .arg("-")
                            .stdin(Stdio::piped())
                            .stdout(Stdio::piped())
                            .stderr(Stdio::piped());
                        let mut command_child =
                            command.spawn().map_err(|source| Error::CommandBackground {
                                command: format!("{command:?}"),
                                source,
                            })?;

                        // write to stdin
                        command_child
                            .stdin
                            .take()
                            .ok_or(Error::CommandAttachToStdin {
                                command: format!("{command:?}"),
                            })?
                            .write_all(creds.passphrase().expose_borrowed().as_bytes())
                            .map_err(|source| Error::CommandWriteToStdin {
                                command: format!("{command:?}"),
                                source,
                            })?;

                        let command_output =
                            command_child.wait_with_output().map_err(|source| {
                                Error::CommandExec {
                                    command: format!("{command:?}"),
                                    source,
                                }
                            })?;

                        if !command_output.status.success() {
                            return Err(Error::CommandNonZero {
                                command: format!("{command:?}"),
                                exit_status: command_output.status,
                                stderr: String::from_utf8_lossy(&command_output.stderr)
                                    .into_owned(),
                            });
                        }
                        command_output.stdout
                    }
                }
            };

            // Write secret to file and adjust permission and ownership of file.
            let mut file = File::create(secrets_file.as_path()).map_err(|source| {
                {
                    crate::non_admin_credentials::Error::SecretsFileCreate {
                        path: secrets_file.clone(),
                        system_user: system_user.clone(),
                        source,
                    }
                }
            })?;
            file.write_all(&secret).map_err(|source| {
                crate::non_admin_credentials::Error::SecretsFileWrite {
                    path: secrets_file.clone(),
                    system_user: system_user.clone(),
                    source,
                }
            })?;
            chown(
                &secrets_file,
                Some(user.uid.as_raw()),
                Some(user.gid.as_raw()),
            )
            .map_err(|source| Error::Chown {
                path: secrets_file.clone(),
                user: system_user.to_string(),
                source,
            })?;
            set_permissions(
                secrets_file.as_path(),
                Permissions::from_mode(SECRET_FILE_MODE),
            )
            .map_err(|source| Error::ApplyPermissions {
                path: secrets_file.clone(),
                mode: SECRET_FILE_MODE,
                source,
            })?;
        }

        Ok(credentials)
    }
}

impl From<SignstarConfig> for Vec<ExtendedUserMapping> {
    /// Creates a `Vec` of [`ExtendedUserMapping`] from a [`SignstarConfig`].
    ///
    /// A [`UserMapping`] can not be aware of credentials if it does not track at least one
    /// [`SystemUserId`] and one [`UserId`]. Therefore only those [`UserMapping`]s for which
    /// [`UserMapping::has_system_and_backend_user`] returns `true` are
    /// returned.
    fn from(value: SignstarConfig) -> Self {
        value
            .iter_user_mappings()
            .filter_map(|mapping| {
                if mapping.has_system_and_backend_user() {
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

#[cfg(test)]
mod tests {
    use log::{LevelFilter, debug};
    use rstest::rstest;
    use signstar_common::logging::setup_logging;
    use signstar_crypto::{key::CryptographicKeyContext, openpgp::OpenPgpUserIdList};
    use tempfile::{NamedTempFile, TempDir};
    use testresult::TestResult;

    use super::*;

    mod nethsm {
        use super::*;

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_system_user`].
        #[rstest]
        #[case::admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), None)]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            Some("system-metrics".parse()?),
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            Some("system-backup".parse()?),
        )]
        #[case::operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("system-operator".parse()?),
        )]
        #[case::hermetic_system_metrics(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            Some("system-metrics".parse()?),
        )]
        fn user_mapping_get_system_user(
            #[case] mapping: UserMapping,
            #[case] result: Option<SystemUserId>,
        ) -> TestResult {
            assert_eq!(mapping.get_system_user(), result.as_ref());
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::backend_users`].
        #[rstest]
        #[case::admin_filter_default(
            UserMapping::NetHsmOnlyAdmin("admin".parse()?),
            UserMappingFilter::default(),
            &[],
        )]
        #[case::admin_filter_admin(
            UserMapping::NetHsmOnlyAdmin("admin".parse()?),
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            &["admin"],
        )]
        #[case::metrics_filter_default(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter::default(),
            &["metrics", "operator"],
        )]
        #[case::metrics_filter_admin(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            &[],
        )]
        #[case::backup_filter_default(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            UserMappingFilter::default(),
            &["backup"],
        )]
        #[case::backup_filter_admin(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            &[],
        )]
        #[case::operator_filter_default(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            UserMappingFilter::default(),
            &["operator"],
        )]
        #[case::operator_filter_admin(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            &[],
        )]
        #[case::hermetic_system_metrics_filter_default(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter::default(),
            &["metrics", "operator"],
        )]
        #[case::hermetic_system_metrics_filter_admin(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            &[],
        )]
        fn user_mapping_backend_users(
            #[case] mapping: UserMapping,
            #[case] filter: UserMappingFilter,
            #[case] expected_names: &[&str],
        ) -> TestResult {
            assert_eq!(mapping.backend_users(filter), expected_names);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::backend_users_with_new_passphrase`].
        #[rstest]
        #[case::admin_filter_default(
            UserMapping::NetHsmOnlyAdmin("admin".parse()?),
            UserMappingFilter::default(),
            0
        )]
        #[case::admin_filter_admin(
            UserMapping::NetHsmOnlyAdmin("admin".parse()?),
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            1
        )]
        #[case::metrics_filter_default(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter::default(),
            2
        )]
        #[case::metrics_filter_admin(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            0
        )]
        #[case::backup_filter_default(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            UserMappingFilter::default(),
            1
        )]
        #[case::backup_filter_admin(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            0
        )]
        #[case::operator_filter_default(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            UserMappingFilter::default(),
            1
        )]
        #[case::operator_filter_admin(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            0
        )]
        #[case::hermetic_system_metrics_filter_default(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter::default(),
            2
        )]
        #[case::hermetic_system_metrics_filter_admin(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            0
        )]
        fn user_mapping_backend_users_with_new_passphrase(
            #[case] mapping: UserMapping,
            #[case] filter: UserMappingFilter,
            #[case] expected_length: usize,
        ) -> TestResult {
            assert_eq!(
                mapping.backend_users_with_new_passphrase(filter).len(),
                expected_length
            );
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_users`].
        #[rstest]
        #[case::admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), vec!["test".parse()?])]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            vec!["metrics".parse()?, "operator".parse()?],
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            vec!["backup".parse()?],
        )]
        #[case::operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            vec!["operator".parse()?],
        )]
        #[case::hermetic_system_metrics(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            vec!["metrics".parse()?, "operator".parse()?],
        )]
        fn user_mapping_get_nethsm_users(
            #[case] mapping: UserMapping,
            #[case] expected: Vec<UserId>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_users(), expected);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_users_and_roles`].
        #[rstest]
        #[case::systemwide_admin(
            UserMapping::NetHsmOnlyAdmin("admin".parse()?),
            vec![("admin".parse()?, UserRole::Administrator)],
        )]
        #[case::namespace_admin(
            UserMapping::NetHsmOnlyAdmin("ns1~admin".parse()?),
            vec![("ns1~admin".parse()?, UserRole::Administrator)],
        )]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            vec![("metrics".parse()?, UserRole::Metrics), ("operator".parse()?, UserRole::Operator)],
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            vec![("backup".parse()?, UserRole::Backup)],
        )]
        #[case::systemwide_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            vec![(
                "operator".parse()?,
                UserRole::Operator,
            )],
        )]
        #[case::namespace_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            vec![(
                "ns1~operator".parse()?,
                UserRole::Operator,
            )],
        )]
        #[case::hermetic_system_metrics(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            vec![
                ("metrics".parse()?, UserRole::Metrics),
                ("operator".parse()?, UserRole::Operator),
            ],
        )]
        fn usermapping_get_nethsm_users_and_roles(
            #[case] mapping: UserMapping,
            #[case] output: Vec<(UserId, UserRole)>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_users_and_roles(), output);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_user_key_and_tag`].
        #[rstest]
        #[case::admin_filter_all(UserMapping::NetHsmOnlyAdmin("test".parse()?), FilterUserKeys::All, Vec::new())]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            FilterUserKeys::All,
            Vec::new(),
        )]
        #[case::backup_filter_all(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            FilterUserKeys::All,
            Vec::new(),
        )]
        #[case::operator_signing_filter_all(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            FilterUserKeys::All,
            vec![(
                "operator".parse()?,
                "key1".parse()?,
                SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                "tag1".to_string(),
            )],
        )]
        #[case::systemwide_operator_filter_namespaced(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            FilterUserKeys::Namespaced,
            Vec::new(),
        )]
        #[case::systemwide_operator_filter_namespace(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            FilterUserKeys::Namespace("ns1".parse()?),
            Vec::new(),
        )]
        #[case::namespace_operator_filter_namespaced(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            FilterUserKeys::Namespaced,
            vec![(
                "ns1~operator".parse()?,
                "key1".parse()?,
                SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                "tag1".to_string(),
            )],
        )]
        #[case::namespace_operator_filter_matching_namespace(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            FilterUserKeys::Namespace("ns1".parse()?),
            vec![(
                "ns1~operator".parse()?,
                "key1".parse()?,
                SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                "tag1".to_string(),
            )],
        )]
        #[case::namespace_operator_filter_matching_tag(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            FilterUserKeys::Tag("tag1".parse()?),
            vec![(
                "ns1~operator".parse()?,
                "key1".parse()?,
                SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                "tag1".to_string(),
            )],
        )]
        #[case::namespace_operator_filter_mismatching_tag(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag2".to_string(),
            },
            FilterUserKeys::Tag("tag1".parse()?),
            Vec::new(),
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            FilterUserKeys::All,
            Vec::new(),
        )]
        fn user_mapping_get_nethsm_user_key_and_tag(
            #[case] mapping: UserMapping,
            #[case] filter: FilterUserKeys,
            #[case] output: Vec<(UserId, KeyId, SigningKeySetup, String)>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_user_key_and_tag(filter), output);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_user_role_and_tags`].
        #[rstest]
        #[case::system_wide_admin(
            UserMapping::NetHsmOnlyAdmin("test".parse()?),
            vec![("test".parse()?, UserRole::Administrator, Vec::new())],
        )]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            vec![("metrics".parse()?, UserRole::Metrics, Vec::new()), ("operator".parse()?, UserRole::Operator, Vec::new())],
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            vec![("backup".parse()?, UserRole::Backup, Vec::new())],
        )]
        #[case::system_wide_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            vec![("operator".parse()?, UserRole::Operator, vec!["tag1".to_string()])],
        )]
        #[case::namespace_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            vec![("ns1~operator".parse()?, UserRole::Operator, vec!["tag1".to_string()])],
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            vec![("metrics".parse()?, UserRole::Metrics, Vec::new()), ("operator".parse()?, UserRole::Operator, Vec::new())],
        )]
        fn user_mapping_get_nethsm_user_role_and_tags(
            #[case] mapping: UserMapping,
            #[case] expected: Vec<(UserId, UserRole, Vec<String>)>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_user_role_and_tags(), expected);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_ssh_authorized_key`].
        #[rstest]
        #[case::system_wide_admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), None)]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?),
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?),
        )]
        #[case::system_wide_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?),
        )]
        #[case::namespace_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?),
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            None,
        )]
        fn user_mapping_get_ssh_authorized_key(
            #[case] mapping: UserMapping,
            #[case] output: Option<AuthorizedKeyEntry>,
        ) -> TestResult {
            assert_eq!(mapping.get_ssh_authorized_key(), output.as_ref());
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_key_ids`].
        #[rstest]
        #[case::system_wide_admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), None, Vec::new())]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            None,
            Vec::new()
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            None,
            Vec::new()
        )]
        #[case::system_wide_operator_target_system_wide(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            None,
            vec!["key1".parse()?],
        )]
        #[case::system_wide_operator_target_namespace(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("ns1".parse()?),
            Vec::new(),
        )]
        #[case::namespace_operator_target_system_wide(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            None,
            Vec::new(),
        )]
        #[case::namespace_operator_target_namespace(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("ns1".parse()?),
            vec!["key1".parse()?],
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            None,
            Vec::new()
        )]
        fn user_mapping_get_nethsm_key_ids(
            #[case] mapping: UserMapping,
            #[case] namespace: Option<NamespaceId>,
            #[case] output: Vec<KeyId>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_key_ids(namespace.as_ref()), output);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_key_ids`].
        #[rstest]
        #[case::system_wide_admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), None, Vec::new())]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            None,
            Vec::new()
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            None,
            Vec::new()
        )]
        #[case::system_wide_operator_target_system_wide(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            None,
            vec!["tag1"],
        )]
        #[case::system_wide_operator_target_namespace(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("ns1".parse()?),
            Vec::new(),
        )]
        #[case::namespace_operator_target_system_wide(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            None,
            Vec::new(),
        )]
        #[case::namespace_operator_target_namespace(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Some("ns1".parse()?),
            vec!["tag1"],
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            None,
            Vec::new()
        )]
        fn user_mapping_get_nethsm_tags(
            #[case] mapping: UserMapping,
            #[case] namespace: Option<NamespaceId>,
            #[case] output: Vec<&str>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_tags(namespace.as_ref()), output);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_namespaces`].
        #[rstest]
        #[case::system_wide_admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), Vec::new())]
        #[case::namespace_admin(UserMapping::NetHsmOnlyAdmin("ns1~test".parse()?), vec!["ns1".parse()?])]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            Vec::new(),
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            Vec::new(),
        )]
        #[case::system_wide_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            Vec::new(),
        )]
        #[case::namespace_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            vec!["ns1".parse()?],
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            Vec::new(),
        )]
        fn user_mapping_get_nethsm_namespaces(
            #[case] mapping: UserMapping,
            #[case] output: Vec<NamespaceId>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_namespaces(), output);
            Ok(())
        }

        /// Ensures that NetHSM specific [`UserMapping`] variants work with
        /// [`UserMapping::has_system_and_backend_user`].
        #[rstest]
        #[case::system_wide_admin(UserMapping::NetHsmOnlyAdmin("test".parse()?), false)]
        #[case::namespace_admin(UserMapping::NetHsmOnlyAdmin("ns1~test".parse()?), false)]
        #[case::metrics(
            UserMapping::SystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    SystemWideUserId::new("metrics".to_string())?,
                    vec![
                        UserId::new("operator".to_string())?,
                    ],
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-metrics".parse()?,
            },
            true,
        )]
        #[case::backup(
            UserMapping::SystemNetHsmBackup {
                nethsm_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-backup".parse()?,
            },
            true,
        )]
        #[case::system_wide_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            true,
        )]
        #[case::namespace_operator(
            UserMapping::SystemNetHsmOperatorSigning {
                nethsm_user: "ns1~operator".parse()?,
                key_id: "key1".parse()?,
                nethsm_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
                tag: "tag1".to_string(),
            },
            true,
        )]
        #[case::hermetic_system_metrics_filter_all(
            UserMapping::HermeticSystemNetHsmMetrics {
                nethsm_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["operator".parse()?],
                )?,
                system_user: "system-metrics".parse()?,
            },
            true,
        )]
        fn user_mapping_has_system_and_backend_user(
            #[case] mapping: UserMapping,
            #[case] output: bool,
        ) -> TestResult {
            assert_eq!(mapping.has_system_and_backend_user(), output);
            Ok(())
        }
    }

    mod system {
        use super::*;

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_system_user`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("system-share".parse()?),
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("system-share".parse()?),
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("system-wireguard".parse()?),
        )]
        fn user_mapping_get_system_user(
            #[case] mapping: UserMapping,
            #[case] result: Option<SystemUserId>,
        ) -> TestResult {
            assert_eq!(mapping.get_system_user(), result.as_ref());
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::backend_users`].
        #[rstest]
        #[case::share_download_filter_default(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter::default(),
        )]
        #[case::share_download_filter_admin(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
        )]
        #[case::share_upload_filter_default(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter::default(),
        )]
        #[case::share_upload_filter_admin(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
        )]
        #[case::wireguard_download_filter_default(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter::default(),
        )]
        #[case::wireguard_download_filter_admin(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
        )]
        fn user_mapping_backend_users(
            #[case] mapping: UserMapping,
            #[case] filter: UserMappingFilter,
        ) -> TestResult {
            assert_eq!(mapping.backend_users(filter).len(), 0);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::backend_users_with_new_passphrase`].
        #[rstest]
        #[case::share_download_filter_default(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter::default(),
        )]
        #[case::share_download_filter_admin(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
        )]
        #[case::share_upload_filter_default(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter::default(),
        )]
        #[case::share_upload_filter_admin(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
        )]
        #[case::wireguard_download_filter_default(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter::default(),
        )]
        #[case::wireguard_download_filter_admin(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
        )]
        fn user_mapping_backend_users_with_new_passphrase(
            #[case] mapping: UserMapping,
            #[case] filter: UserMappingFilter,
        ) -> TestResult {
            assert!(mapping.backend_users_with_new_passphrase(filter).is_empty());
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_users`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Vec::new(),
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Vec::new(),
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Vec::new(),
        )]
        fn user_mapping_get_nethsm_users(
            #[case] mapping: UserMapping,
            #[case] expected: Vec<UserId>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_users(), expected);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_users_and_roles`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        fn usermapping_get_nethsm_users_and_roles(#[case] mapping: UserMapping) -> TestResult {
            let expected: Vec<(UserId, UserRole)> = Vec::new();
            assert_eq!(mapping.get_nethsm_users_and_roles(), expected);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_user_key_and_tag`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            FilterUserKeys::All,
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            FilterUserKeys::All,
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            FilterUserKeys::All,
        )]
        fn user_mapping_get_nethsm_user_key_and_tag(
            #[case] mapping: UserMapping,
            #[case] filter: FilterUserKeys,
        ) -> TestResult {
            let expected: Vec<(UserId, KeyId, SigningKeySetup, String)> = Vec::new();
            assert_eq!(mapping.get_nethsm_user_key_and_tag(filter), expected);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_user_role_and_tags`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        fn user_mapping_get_nethsm_user_role_and_tags(#[case] mapping: UserMapping) -> TestResult {
            let expected: Vec<(UserId, UserRole, Vec<String>)> = Vec::new();
            assert_eq!(mapping.get_nethsm_user_role_and_tags(), expected);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_ssh_authorized_key`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
        )]
        fn user_mapping_get_ssh_authorized_key(#[case] mapping: UserMapping) -> TestResult {
            let expected: Option<AuthorizedKeyEntry> = Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?);
            assert_eq!(mapping.get_ssh_authorized_key(), expected.as_ref());
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_key_ids`].
        #[rstest]
        #[case::share_download_target_system_wide(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            None,
        )]
        #[case::share_download_target_namespace(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("ns1".parse()?),
        )]
        #[case::share_upload_target_system_wide(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            None,
        )]
        #[case::share_upload_target_namespace(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("ns1".parse()?),
        )]
        #[case::wireguard_download_target_system_wide(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            None,
        )]
        #[case::wireguard_download_target_namespace(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("ns1".parse()?),
        )]
        fn user_mapping_get_nethsm_key_ids(
            #[case] mapping: UserMapping,
            #[case] namespace: Option<NamespaceId>,
        ) -> TestResult {
            let expected: Vec<KeyId> = Vec::new();
            assert_eq!(mapping.get_nethsm_key_ids(namespace.as_ref()), expected);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_key_ids`].
        #[rstest]
        #[case::share_download_target_system_wide(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            None,
        )]
        #[case::share_download_target_namespace(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("ns1".parse()?),
        )]
        #[case::share_upload_target_system_wide(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            None,
        )]
        #[case::share_upload_target_namespace(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("ns1".parse()?),
        )]
        #[case::wireguard_download_target_system_wide(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            None,
        )]
        #[case::wireguard_download_target_namespace(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Some("ns1".parse()?),
        )]
        fn user_mapping_get_nethsm_tags(
            #[case] mapping: UserMapping,
            #[case] namespace: Option<NamespaceId>,
        ) -> TestResult {
            let expected: Vec<&str> = Vec::new();
            assert_eq!(mapping.get_nethsm_tags(namespace.as_ref()), expected);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_namespaces`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Vec::new(),
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Vec::new(),
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            Vec::new(),
        )]
        fn user_mapping_get_nethsm_namespaces(
            #[case] mapping: UserMapping,
            #[case] output: Vec<NamespaceId>,
        ) -> TestResult {
            assert_eq!(mapping.get_nethsm_namespaces(), output);
            Ok(())
        }

        /// Ensures that backend agnostic [`UserMapping`] variants work with
        /// [`UserMapping::has_system_and_backend_user`].
        #[rstest]
        #[case::share_download(
            UserMapping::SystemOnlyShareDownload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            false,
        )]
        #[case::share_upload(
            UserMapping::SystemOnlyShareUpload {
                system_user: "system-share".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            false,
        )]
        #[case::wireguard_download(
            UserMapping::SystemOnlyWireGuardDownload {
                system_user: "system-wireguard".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
            },
            false,
        )]
        fn user_mapping_has_system_and_backend_user(
            #[case] mapping: UserMapping,
            #[case] output: bool,
        ) -> TestResult {
            assert_eq!(mapping.has_system_and_backend_user(), output);
            Ok(())
        }
    }

    #[cfg(feature = "yubihsm2")]
    mod yubihsm {
        use super::*;

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_system_user`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1), None)]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
            },
            Some("backup".parse()?),
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            Some("system-operator".parse()?),
        )]
        fn user_mapping_get_system_user(
            #[case] mapping: UserMapping,
            #[case] result: Option<SystemUserId>,
        ) -> TestResult {
            assert_eq!(mapping.get_system_user(), result.as_ref());
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::backend_users`].
        #[rstest]
        #[case::admin_filter_default(UserMapping::YubiHsmOnlyAdmin(1), UserMappingFilter::default(), &[])]
        #[case::admin_filter_admin(UserMapping::YubiHsmOnlyAdmin(1), UserMappingFilter{backend_user_kind: BackendUserKind::Admin}, &["1"])]
        #[case::backup_filter_default(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
            },
            UserMappingFilter::default(),
            &["1"]
        )]
        #[case::backup_filter_admin(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
            },
            UserMappingFilter{ backend_user_kind: BackendUserKind::Admin },
            &[]
        )]
        #[case::operator_filter_default(
            UserMapping::SystemYubiHsmOperatorSigning {
                backend_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                authentication_key_id: 1,
                backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            UserMappingFilter::default(),
            &["1"]
        )]
        #[case::operator_filter_admin(
            UserMapping::SystemYubiHsmOperatorSigning {
                backend_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                authentication_key_id: 1,
                backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            &[]
        )]
        fn user_mapping_backend_users(
            #[case] mapping: UserMapping,
            #[case] filter: UserMappingFilter,
            #[case] expected_names: &[&str],
        ) -> TestResult {
            assert_eq!(mapping.backend_users(filter), expected_names);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::backend_users_with_new_passphrase`].
        #[rstest]
        #[case::admin_filter_default(
            UserMapping::YubiHsmOnlyAdmin(1),
            UserMappingFilter::default(),
            0
        )]
        #[case::admin_filter_admin(
            UserMapping::YubiHsmOnlyAdmin(1),
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            1
        )]
        #[case::backup_filter_default(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
            },
            UserMappingFilter::default(),
            1
        )]
        #[case::backup_filter_admin(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
            },
            UserMappingFilter{ backend_user_kind: BackendUserKind::Admin },
            0
        )]
        #[case::operator_filter_default(
            UserMapping::SystemYubiHsmOperatorSigning {
                backend_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                authentication_key_id: 1,
                backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            UserMappingFilter::default(),
            1
        )]
        #[case::operator_filter_admin(
            UserMapping::SystemYubiHsmOperatorSigning {
                backend_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                authentication_key_id: 1,
                backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            UserMappingFilter{backend_user_kind: BackendUserKind::Admin},
            0
        )]
        fn usermapping_yubihsm_backend_users_with_new_passphrase(
            #[case] mapping: UserMapping,
            #[case] filter: UserMappingFilter,
            #[case] expected_length: usize,
        ) -> TestResult {
            assert_eq!(
                mapping.backend_users_with_new_passphrase(filter).len(),
                expected_length
            );
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_users`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1))]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             }
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
        )]
        fn user_mapping_get_nethsm_users(#[case] mapping: UserMapping) -> TestResult {
            let expected: Vec<UserId> = Vec::new();
            assert_eq!(mapping.get_nethsm_users(), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_users_and_roles`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1))]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             }
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
        )]
        fn usermapping_get_nethsm_users_and_roles(#[case] mapping: UserMapping) -> TestResult {
            let expected: Vec<(UserId, UserRole)> = Vec::new();
            assert_eq!(mapping.get_nethsm_users_and_roles(), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_user_key_and_tag`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1), FilterUserKeys::All)]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
            FilterUserKeys::All,
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            FilterUserKeys::All,
        )]
        fn user_mapping_get_nethsm_user_key_and_tag(
            #[case] mapping: UserMapping,
            #[case] filter: FilterUserKeys,
        ) -> TestResult {
            let expected: Vec<(UserId, KeyId, SigningKeySetup, String)> = Vec::new();
            assert_eq!(mapping.get_nethsm_user_key_and_tag(filter), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_user_role_and_tags`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1))]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             }
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
        )]
        fn user_mapping_get_nethsm_user_role_and_tags(#[case] mapping: UserMapping) -> TestResult {
            let expected: Vec<(UserId, UserRole, Vec<String>)> = Vec::new();
            assert_eq!(mapping.get_nethsm_user_role_and_tags(), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_ssh_authorized_key`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1), None)]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?),
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            Some("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?),
        )]
        fn user_mapping_get_ssh_authorized_key(
            #[case] mapping: UserMapping,
            #[case] output: Option<AuthorizedKeyEntry>,
        ) -> TestResult {
            assert_eq!(mapping.get_ssh_authorized_key(), output.as_ref());
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_key_ids`].
        #[rstest]
        #[case::admin_target_system_wide(UserMapping::YubiHsmOnlyAdmin(1), None)]
        #[case::admin_target_namespace(UserMapping::YubiHsmOnlyAdmin(1), Some("ns1".parse()?))]
        #[case::backup_target_system_wide(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
            None,
        )]
        #[case::backup_target_namespace(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
            Some("ns1".parse()?),
        )]
        #[case::operator_signing_target_system_wide(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            None,
        )]
        #[case::operator_signing_target_namespace(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            Some("ns1".parse()?),
        )]
        fn user_mapping_get_nethsm_key_ids(
            #[case] mapping: UserMapping,
            #[case] namespace: Option<NamespaceId>,
        ) -> TestResult {
            let expected: Vec<KeyId> = Vec::new();
            assert_eq!(mapping.get_nethsm_key_ids(namespace.as_ref()), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_tags`].
        #[rstest]
        #[case::admin_target_system_wide(UserMapping::YubiHsmOnlyAdmin(1), None)]
        #[case::admin_target_namespace(UserMapping::YubiHsmOnlyAdmin(1), Some("ns1".parse()?))]
        #[case::backup_target_system_wide(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
            None,
        )]
        #[case::backup_target_namespace(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
            Some("ns1".parse()?),
        )]
        #[case::operator_signing_target_system_wide(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            None,
        )]
        #[case::operator_signing_target_namespace(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            Some("ns1".parse()?),
        )]
        fn user_mapping_get_nethsm_tags(
            #[case] mapping: UserMapping,
            #[case] namespace: Option<NamespaceId>,
        ) -> TestResult {
            let expected: Vec<&str> = Vec::new();
            assert_eq!(mapping.get_nethsm_tags(namespace.as_ref()), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::get_nethsm_namespaces`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1))]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
        )]
        fn user_mapping_get_nethsm_namespaces(#[case] mapping: UserMapping) -> TestResult {
            let expected: Vec<NamespaceId> = Vec::new();
            assert_eq!(mapping.get_nethsm_namespaces(), expected);
            Ok(())
        }

        /// Ensures that YubiHSM2 specific [`UserMapping`] variants work with
        /// [`UserMapping::has_system_and_backend_user`].
        #[rstest]
        #[case::admin(UserMapping::YubiHsmOnlyAdmin(1), false)]
        #[case::backup(
            UserMapping::SystemYubiHsm2Backup{
                authentication_key_id: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "backup".parse()?,
             },
             true
        )]
        #[case::operator_signing(
            UserMapping::SystemYubiHsmOperatorSigning {
                authentication_key_id: 1,
                backend_key_setup: SigningKeySetup::new(
                    "Curve25519".parse()?,
                    vec!["EdDsaSignature".parse()?],
                    None,
                    "EdDsa".parse()?,
                    CryptographicKeyContext::OpenPgp{
                        user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                        version: "v4".parse()?,
                    },
                )?,
                backend_key_id: 1, backend_key_domain: 1,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH3NyNfSqtDxdnWwSVzulZi0k7Lyjw3vBEG+U8y6KsuW user@host".parse()?,
                system_user: "system-operator".parse()?,
            },
            true,
        )]
        fn user_mapping_has_system_and_backend_user(
            #[case] mapping: UserMapping,
            #[case] output: bool,
        ) -> TestResult {
            assert_eq!(mapping.has_system_and_backend_user(), output);
            Ok(())
        }
    }

    /// Ensures that a file with the correct permissions is successfully checked using
    /// [`check_secrets_file`].
    #[test]
    fn check_secrets_file_succeeds() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();
        set_permissions(path, Permissions::from_mode(SECRET_FILE_MODE))?;
        debug!(
            "Created {path:?} with mode {:o}",
            path.metadata()?.permissions().mode()
        );

        check_secrets_file(path)?;

        Ok(())
    }

    /// Ensures that passing a non-existent file to [`check_secrets_file`] fails.
    #[test]
    fn check_secrets_file_fails_on_missing_file() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path().to_path_buf();
        temp_file.close()?;

        if check_secrets_file(&path).is_ok() {
            panic!("The path {path:?} is missing and should not have passed as a secrets file.");
        }

        Ok(())
    }

    /// Ensures that passing a directory to [`check_secrets_file`] fails.
    #[test]
    fn check_secrets_file_fails_on_dir() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = TempDir::new()?;
        let path = temp_file.path();
        debug!(
            "Created {path:?} with mode {:o}",
            path.metadata()?.permissions().mode()
        );

        if check_secrets_file(path).is_ok() {
            panic!("The dir {path:?} should not have passed as a secrets file.");
        }

        Ok(())
    }

    /// Ensures that a file without the correct permissions fails [`check_secrets_file`].
    #[test]
    fn check_secrets_file_fails_on_invalid_permissions() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let temp_file = NamedTempFile::new()?;
        let path = temp_file.path();
        set_permissions(path, Permissions::from_mode(0o100644))?;
        debug!(
            "Created {path:?} with mode {:o}",
            path.metadata()?.permissions().mode()
        );

        if check_secrets_file(path).is_ok() {
            panic!("The file at {path:?} should not have passed as a secrets file.");
        }

        Ok(())
    }
}
