//! Error handling for Signstar configuration and related components.

use std::path::PathBuf;

#[cfg(feature = "nethsm")]
use nethsm::{KeyId, NamespaceId, SystemWideUserId, UserId};

use crate::config::{Config, SystemUserId};

/// An error that may occur when using a Signstar configuration.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The Signstar configuration is missing.
    #[error("No configuration file found in {}.",
        Config::list_config_dirs().iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")
    )]
    ConfigIsMissing,

    /// A Signstar configuration file has no file extension.
    #[error("The Signstar configuration file {path} has no file extension.")]
    MissingFileExtension {
        /// The path of the file.
        path: PathBuf,
    },

    /// A Signstar configuration file has an unsupported file extension.
    #[error(
        "The Signstar configuration file {path} uses the unsupported file extension {extension}."
    )]
    UnsupportedFileExtension {
        /// The path of the file.
        path: PathBuf,
        /// The file extension.
        extension: String,
    },

    /// Duplicate NetHSM user names
    #[cfg(feature = "nethsm")]
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
    #[cfg(feature = "nethsm")]
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
    #[cfg(feature = "nethsm")]
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
    #[cfg(feature = "nethsm")]
    #[error("The NetHsm user {metrics_user} is both in the Metrics and Operator role!")]
    MetricsAlsoOperator {
        /// The system-wide User ID of a NetHSM user that is both in the
        /// [`Metrics`][`nethsm::UserRole::Metrics`] and
        /// [`Operator`][`nethsm::UserRole::Operator`] role.
        metrics_user: SystemWideUserId,
    },

    /// A user in the Administrator role is missing system-wide (_R-Administrator_) or in one or
    /// more namespaces (_N-Administrator_).
    #[cfg(feature = "nethsm")]
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
    #[cfg(feature = "nethsm")]
    #[error("User data invalid: {0}")]
    User(#[from] nethsm::UserError),

    /// An SSH key error
    #[error("SSH key error: {0}")]
    SshKey(#[from] ssh_key::Error),

    /// An error occurred while deserializing an object as a YAML string.
    #[error("YAML deserialization error while {context}:\n{source}")]
    YamlDeserialize {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "YAML deserialization error while ".
        context: String,
        /// The error source.
        source: serde_saphyr::Error,
    },

    /// An error occurred while serializing an object as a YAML string.
    #[error("YAML serialization error while {context}:\n{source}")]
    YamlSerialize {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "YAML serialization error while ".
        context: &'static str,
        /// The error source.
        source: serde_saphyr::ser_error::Error,
    },
}
