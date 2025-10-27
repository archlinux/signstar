//! Error handling for [`SignstarConfig`] and related components.

use nethsm::{KeyId, NamespaceId, SystemWideUserId, UserId};
use signstar_common::config::get_config_file_paths;

#[cfg(doc)]
use crate::SignstarConfig;
use crate::SystemUserId;

/// An error that may occur when handling a [`SignstarConfig`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The Signstar configuration is missing.
    #[error("No configuration file found in {}.",
        get_config_file_paths().iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    ConfigIsMissing,

    /// Duplicate NetHSM user names
    #[error("The NetHSM user ID {nethsm_user_id} is used more than once!")]
    DuplicateNetHsmUserId {
        /// The name of a NetHSM user that is used more than once.
        nethsm_user_id: UserId,
    },

    /// An SSH public key is used more than once.
    #[error("The SSH public key \"{ssh_public_key}\" is used more than once!")]
    DuplicateSshPublicKey {
        /// The SSH public key that is used more than once.
        ssh_public_key: String,
    },

    /// Duplicate key ID
    #[error(
        "The key ID \"{key_id}\" ({}) is used more than once",
        if let Some(namespace) = namespace {
            format!("namespace: \"{namespace}\"")
        } else {
            "system-wide".to_string()
        },
    )]
    DuplicateKeyId {
        /// The name of a key that is used more than once.
        key_id: KeyId,
        /// The optional `namespace` in which more than one `key_id` exists.
        namespace: Option<NamespaceId>,
    },

    /// Duplicate system user names
    #[error("The system user ID {system_user_id} is used more than once!")]
    DuplicateSystemUserId {
        /// The name of a system user that is usd more than once.
        system_user_id: SystemUserId,
    },

    /// A tag for a user/key is used more than once.
    #[error(
        "The tag {tag} ({}) is used more than once",
        if let Some(namespace) = namespace {
            format!("namespace: \"{namespace}\"")
        } else {
            "system-wide".to_string()
        },
    )]
    DuplicateTag {
        /// The tag of a key/user that is used more than once.
        tag: String,
        /// The optional name of a namespace in which `tag` is used more than once.
        namespace: Option<NamespaceId>,
    },

    /// A system username is invalid
    #[error("The system user name {name} is invalid")]
    InvalidSystemUserName {
        /// The invalid system user name.
        name: String,
    },

    /// An entry in authorized_keys is invalid.
    #[error("The SSH authorized key \"{entry}\" is invalid")]
    InvalidAuthorizedKeyEntry {
        /// A string that represents an invalid SSH public key.
        entry: String,
    },

    /// A [`UserId`] is used both for a user in the [`Metrics`][`nethsm::UserRole::Metrics`] and
    /// [`Operator`][`nethsm::UserRole::Operator`] role.
    #[error("The NetHsm user {metrics_user} is both in the Metrics and Operator role!")]
    MetricsAlsoOperator {
        /// The system-wide User ID of a NetHSM user that is both in the
        /// [`Metrics`][`nethsm::UserRole::Metrics`] and
        /// [`Operator`][`nethsm::UserRole::Operator`] role.
        metrics_user: SystemWideUserId,
    },

    /// A user in the Administrator role is missing system-wide (_R-Administrator_) or in one or
    /// more namespaces (_N-Administrator_).
    #[error(
        "No user in the Administrator role exists ({})",
        if let Some(namespaces) = namespaces {
            namespaces.iter().map(|id| id.to_string()).collect::<Vec<_>>().join(", ")
        } else {
            "system-wide".to_string()
        }
    )]
    MissingAdministrator {
        /// The list of namespaces in which administrators are missing.
        namespaces: Option<Vec<NamespaceId>>,
    },

    /// Missing system user for downloading shares of a shared secret
    #[error("No system user for downloading shares of a shared secret exists.")]
    MissingShareDownloadSystemUser,

    /// Missing system user for uploading shares of a shared secret
    #[error("No system user for uploading shares of a shared secret exists.")]
    MissingShareUploadSystemUser,

    /// There are no SSH authorized keys
    #[error("No SSH authorized key provided!")]
    NoAuthorizedKeys,

    /// There is no mapping for a provided system user name.
    #[error("No mapping found where a system user matches the name {name}")]
    NoMatchingMappingForSystemUser {
        /// The name of a system user for which no mapping exists.
        name: String,
    },

    /// Shamir's Secret Sharing (SSS) is not used for administrative secret handling, but users for
    /// handling of secret shares are defined
    #[error(
        "Shamir's Secret Sharing not used for administrative secret handling, but the following users are setup to handle shares: {share_users:?}"
    )]
    NoSssButShareUsers {
        /// A list of system user names that are setup for Shamir's Secret Sharing.
        share_users: Vec<SystemUserId>,
    },

    /// User data is invalid
    #[error("User data invalid: {0}")]
    User(#[from] nethsm::UserError),

    /// An SSH key error
    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),
}
