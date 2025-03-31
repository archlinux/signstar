//! Error handling specific to interacting with NetHSM backends.

use nethsm::{KeyId, NamespaceId, UserId};
#[cfg(doc)]
use nethsm_config::HermeticParallelConfig;

use super::state::DiffErrors;
#[cfg(doc)]
use crate::AdminCredentials;

/// An error that may occur when handling a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The iteration of the [`AdminCredentials`] and [`HermeticParallelConfig`] are not matching.
    #[error(
        "Iteration mismatch: Administrative credentials ({admin_creds}) vs. Signstar config ({signstar_config})"
    )]
    IterationMismatch {
        /// The iteration of the [`AdminCredentials`].
        admin_creds: u32,
        /// The iteration of the [`HermeticParallelConfig`].
        signstar_config: u32,
    },

    /// A system-wide key is missing.
    #[error("The system-wide key {key_id} is missing")]
    KeyMissing {
        /// The [`KeyId`] of the missing key.
        key_id: KeyId,
    },

    /// A system-wide key misses a tag.
    #[error("The system-wide key {key_id} misses the tag {tag}")]
    KeyMissingTag {
        /// The [`KeyId`] of the missing key.
        key_id: KeyId,

        /// The missing tag.
        tag: String,
    },

    /// A [`nethsm::UserError`] occurred.
    #[error(transparent)]
    NetHsmUser(#[from] nethsm::UserError),

    /// A namespace admin is not in a Namespace.
    #[error("The NetHSM namespace administrator is not in a namespace: {user}")]
    NamespaceAdminNoNamespace {
        /// The [`UserId`] of the namespace administrator without a namespace.
        user: UserId,
    },

    /// A namespace exists and a namespace should be created, but no namespace admin exists.
    #[error(
        "There is no namespace admin available in the existing NetHSM namespace {namespace} to create the admin {user}"
    )]
    NamespaceAdminCreateNoNamespaceAdmin {
        /// The [`UserId`] of the namespace administrator that should be created in a namespace.
        user: UserId,

        /// The namespace for which no other namespace Administrator is available.
        namespace: NamespaceId,
    },

    /// A namespace exists and a namespace should be created, but no namespace admin exists.
    #[error("There is no namespace admin for the existing NetHSM namespace {namespace}")]
    NamespaceAdminMissing {
        /// The namespace for which no other namespace Administrator is available.
        namespace: NamespaceId,
    },

    /// A namespaced key is missing.
    #[error("The key {key_id} in namespace {namespace} is missing")]
    NamespaceKeyMissing {
        /// The [`KeyId`] of the missing key.
        key_id: KeyId,

        /// The namespace of the key that is missing.
        namespace: NamespaceId,
    },

    /// A namespaced key misses a tag.
    #[error("The key {key_id} in namespace {namespace} misses the tag {tag}")]
    NamespaceKeyMissingTag {
        /// The [`KeyId`] of the missing key.
        key_id: KeyId,

        /// The namespace of the key that is missing a tag.
        namespace: NamespaceId,

        /// The missing tag.
        tag: String,
    },

    /// A namespace does not (yet) exist.
    #[error("The is namespace {namespace} does not exist (yet)")]
    NamespaceMissing {
        /// The namespace that does not (yet) exist.
        namespace: NamespaceId,
    },

    /// There is no User ID for an OpenPGP certificate that is supposed to be created.
    #[error(
        "The options for the OpenPGP certificate for key {key_id} in namespace {namespace} do not provide a User ID"
    )]
    NamespaceOpenPgpUserIdMissing {
        /// The [`KeyId`] of the key for which the OpenPGP certificate should be created.
        key_id: KeyId,

        /// The namespace of the key for which the OpenPGP certificate should be created.
        namespace: NamespaceId,
    },

    /// A user is not in a namespace.
    #[error("The user {user} is not in a namespace")]
    NamespaceUserNoNamespace {
        /// The [`UserId`] of the user without a namespace.
        user: UserId,
    },

    /// A user is not in a specific namespace.
    #[error("The user {user} is not the namespace {namespace}")]
    NamespaceUserMissing {
        /// The [`UserId`] of the user not in `namespace`.
        user: UserId,

        /// The [`NamespaceId`] of the namespace that `user` is not in.
        namespace: NamespaceId,
    },

    /// A namespaced non-administrative user misses a tag.
    #[error("The non-administrative user {user} in namespace {namespace} misses the tag {tag}")]
    NamespaceUserMissingTag {
        /// The [`UserId`] of the user that misses `tag`.
        user: UserId,

        /// The namespace that user is in.
        namespace: NamespaceId,

        /// The missing tag.
        tag: String,
    },

    /// There is no User ID for an OpenPGP certificate.
    #[error("The OpenPGP certificate does not have a User ID associated with it")]
    OpenPgpUserIdMissing {
        /// The [`KeyId`] of the key for which the OpenPGP certificate should be created.
        key_id: KeyId,
    },

    /// The passphrase for a system-wide non-administrative user is missing.
    #[error("The passphrase for system-wide user {user} is missing")]
    UserMissingPassphrase {
        /// The [`UserId`] for which the passphrase is missing.
        user: UserId,
    },

    /// A system-wide non-administrative user is missing.
    #[error("The system-wide non-administrative user {user_id} is missing")]
    UserMissing {
        /// The [`UserId`] of the missing user.
        user_id: UserId,
    },

    /// A system-wide non-administrative user misses a tag.
    #[error("The system-wide non-administrative user {user_id} misses the tag {tag}")]
    UserMissingTag {
        /// The [`UserId`] of the user that misses `tag`.
        user_id: UserId,

        /// The  missing tag.
        tag: String,
    },

    /// A system-wide non-administrative user misses a tag.
    #[error("One or more errors occurred when diffing states:\n{0}")]
    DiffErrors(DiffErrors),
}
