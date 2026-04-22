//! Backend handling for [`NetHsm`].
//!
//! Based on a [`NetHsm`], [`NetHsmAdminCredentials`] and a [`Config`] this module offers
//! the ability to populate a [`NetHsm`] backend with the help of the [`NetHsmBackend`] struct.
//!
//! Using [`NetHsmBackend::sync`] all users and keys configured in a [`Config`]
//! are created and adapted to changes upon re-run.
//! The state representation can be found in the [`nethsm::state`][`crate::nethsm::state`] module.
//!
//! # Note
//!
//! This module only works with data for the same iteration (i.e. the iteration of the
//! [`NetHsmAdminCredentials`] and those of the [`NetHsm`] backend must match).

use std::{collections::HashSet, fmt::Display, str::FromStr};

use log::{debug, trace, warn};
use nethsm::{
    CryptographicKeyContext,
    FullCredentials,
    KeyId,
    KeyMechanism,
    KeyType,
    NamespaceId,
    NetHsm,
    OpenPgpKeyUsageFlags,
    Passphrase,
    SystemState,
    Timestamp,
    UserId,
    UserRole,
};
use pgp::composed::{Deserializable, SignedPublicKey};

use crate::{
    config::{Config, KeyCertificateState},
    nethsm::{
        NetHsmAdminCredentials,
        NetHsmConfig,
        NetHsmStateType,
        NetHsmUserKeysFilter,
        NetHsmUserMapping,
        error::Error,
    },
};

/// The state of a user on a [`NetHsm`] backend.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct UserState {
    /// The name of the user.
    pub(crate) name: UserId,
    /// The role of the user.
    pub(crate) role: UserRole,
    /// The zero or more tags assigned to the user.
    pub(crate) tags: Vec<String>,
}

impl Display for UserState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (role: {}", self.name, self.role)?;
        if !self.tags.is_empty() {
            write!(f, "; tags: {}", self.tags.join(", "))?;
        }
        write!(f, ")")?;

        Ok(())
    }
}

/// The state of a key on a [`NetHsm`] backend.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct KeyState {
    /// The name of the key.
    pub(crate) name: KeyId,
    /// The optional namespace the key is used in.
    pub(crate) namespace: Option<NamespaceId>,
    /// The zero or more tags assigned to the key.
    pub(crate) tags: Vec<String>,
    /// The key type of the key.
    pub(crate) key_type: KeyType,
    /// The mechanisms supported by the key.
    pub(crate) mechanisms: Vec<KeyMechanism>,
    /// The context in which the key is used.
    pub(crate) key_cert_state: KeyCertificateState,
}

impl Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (", self.name)?;
        if let Some(namespace) = self.namespace.as_ref() {
            write!(f, "namespace: {namespace}; ")?;
        }
        if !self.tags.is_empty() {
            write!(f, "tags: {}; ", self.tags.join(", "))?;
        }
        write!(f, "type: {}; ", self.key_type)?;
        write!(
            f,
            "mechanisms: {}; ",
            self.mechanisms
                .iter()
                .map(|mechanism| mechanism.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )?;
        write!(f, "context: {}", self.key_cert_state)?;
        write!(f, ")")?;

        Ok(())
    }
}

/// Creates all _R-Administrators_ on a [`NetHsm`].
///
/// If users exist already, only their passphrase is set.
///
/// # Note
///
/// Uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`].
///
/// # Errors
///
/// Returns an error if
///
/// - the default [`Administrator`][`UserRole::Administrator`] can not be retrieved from
///   `admin_credentials`,
/// - the default [`Administrator`][`UserRole::Administrator`] credentials cannot be used with the
///   `nethsm`,
/// - available users of the `nethsm` cannot be retrieved,
/// - or one of the admin credentials cannot be added, or updated.
fn add_system_wide_admins(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup system-wide administrators (R-Administrators) on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Only use administrative credentials that are also available in the NetHSM config.
    let user_list = {
        let mut user_list = Vec::new();

        for creds in admin_credentials.get_administrators() {
            if !user_mappings
                .iter()
                .any(|user_mapping| user_mapping.nethsm_user_ids().contains(&creds.name))
            {
                warn!(
                    "The administrative credentials for system-wide administrator {} are skipped because the user is not found in the Signstar configuration.",
                    creds.name
                );
                continue;
            }
            user_list.push(creds);
        }
        // The available user IDs.
        let available_users = user_list
            .iter()
            .map(|creds| &creds.name)
            .collect::<Vec<_>>();

        let unmatched_config_users = user_mappings
            .iter()
            .flat_map(|user_mapping| {
                user_mapping
                    .nethsm_user_ids()
                    .iter()
                    .filter(|user_id| !available_users.contains(user_id))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if !unmatched_config_users.is_empty() {
            warn!(
                "The following system-wide administrators (R-Administrators) in the Signstar configuration are skipped, because they cannot be found in the provided administrative credentials: {}",
                unmatched_config_users
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if user_list.is_empty() {
            debug!(
                "No system-wide administrators (R-Administrators) to add on NetHSM backend at {}",
                nethsm.get_url()
            );
            return Ok(());
        }

        user_list
    };

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    trace!(
        "Available users on NetHSM: {}",
        available_users
            .iter()
            .map(|user| user.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    for user in user_list {
        // Only add if user doesn't exist yet, else set passphrase
        if !available_users.contains(&user.name) {
            nethsm.add_user(
                format!("System-wide Admin {}", user.name),
                UserRole::Administrator,
                user.passphrase.clone(),
                Some(user.name.clone()),
            )?;
        } else {
            nethsm.set_user_passphrase(user.name.clone(), user.passphrase.clone())?;
        }
    }
    Ok(())
}

/// Retrieves the first available user in the [`Administrator`][`UserRole::Administrator`]
/// (*N-Administrator*) role in a namespace.
///
/// Derives a list of users in the [`Administrator`][`UserRole::Administrator`] role in `namespace`
/// from `available_users`.
/// Ensures that at least one of the users is available on the `nethsm`.
///
/// # Errors
///
/// Returns an error if
/// - user information of an *N-Administrator* cannot be retrieved,
/// - or no *N-Administrator* is available in the `namespace`.
fn get_first_available_namespace_admin(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    available_users: &[UserId],
    namespace: &NamespaceId,
) -> Result<UserId, crate::Error> {
    debug!("Get the first available N-Administrator in namespace \"{namespace}\"");

    // Retrieve the list of users that are both in the namespace and match an entry in the list of
    // N-Administrators in the administrative credentials.
    let namespace_admins = available_users
        .iter()
        .filter(|user| {
            user.namespace() == Some(namespace)
                && admin_credentials
                    .get_namespace_administrators()
                    .iter()
                    .any(|creds| &creds.name == *user)
        })
        .cloned()
        .collect::<Vec<UserId>>();

    let mut checked_namespace_admins = Vec::new();
    for namespace_admin in namespace_admins {
        if Into::<UserRole>::into(nethsm.get_user(&namespace_admin)?.role)
            == UserRole::Administrator
        {
            checked_namespace_admins.push(namespace_admin);
        }
    }

    debug!(
        "All N-Administrators in namespace \"{namespace}\": {}",
        checked_namespace_admins
            .iter()
            .map(|user| user.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );

    if checked_namespace_admins.is_empty() {
        return Err(Error::NamespaceHasNoAdmin {
            namespace: namespace.clone(),
            url: nethsm.get_url(),
        }
        .into());
    }

    // Select the first N-Administrator in the namespace.
    let Some(admin) = checked_namespace_admins.first() else {
        return Err(Error::NamespaceHasNoAdmin {
            namespace: namespace.clone(),
            url: nethsm.get_url(),
        }
        .into());
    };

    Ok(admin.clone())
}

/// Sets up all _N-Administrators_ and their respective namespaces.
///
/// # Note
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
/// namespace-specific _N-Administrator_ for individual operations.
/// If this function succeeds, the `nethsm` is guaranteed to use the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
/// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_.
///
/// # Errors
///
/// Returns an error if
///
/// - user information cannot be retrieved from the `nethsm`,
/// - the available namespaces cannot be retrieved from the `nethsm`,
/// - one of the N-Administrators in the `admin_credentials` is not in a namespace,
/// - a namespace exists already, but no known N-Administrator is available for it,
/// - an N-Administrator and its namespace exist already, but that user's passphrase cannot be set,
/// - an N-Administrator does not yet exist and cannot be added,
/// - a namespace does not yet exist and cannot be added,
/// - or switching back to the default R-Administrator credentials fails.
fn add_namespace_admins(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup namespace administrators (N-Administrators) on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Only use administrative credentials that are also available in the NetHSM config.
    let user_list = {
        let mut user_list = Vec::new();

        for creds in admin_credentials.get_namespace_administrators() {
            if !user_mappings
                .iter()
                .any(|user_mapping| user_mapping.nethsm_user_ids().contains(&creds.name))
            {
                warn!(
                    "The administrative credentials for namespace administrator (N-Administrator) {} are skipped because the user is not found in the Signstar configuration.",
                    creds.name
                );
                continue;
            }
            user_list.push(creds);
        }
        // The available user IDs.
        let available_users = user_list
            .iter()
            .map(|creds| &creds.name)
            .collect::<Vec<_>>();

        let unmatched_config_users = user_mappings
            .iter()
            .flat_map(|user_mapping| {
                user_mapping
                    .nethsm_user_ids()
                    .iter()
                    .filter(|user_id| !available_users.contains(user_id))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        if !unmatched_config_users.is_empty() {
            warn!(
                "The following namespace administrators (N-Administrators) in the Signstar configuration are skipped, because they cannot be found in the provided administrative credentials: {}",
                unmatched_config_users
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        if user_list.is_empty() {
            debug!(
                "No namespace administrators (N-Administrators) to add on NetHSM backend at {}",
                nethsm.get_url()
            );
            return Ok(());
        }

        user_list
    };

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;
    trace!(
        "The available users on the NetHSM backend at {} are: {}",
        nethsm.get_url(),
        available_users
            .iter()
            .map(|user| user.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );
    let available_namespaces = nethsm.get_namespaces()?;
    trace!(
        "The available namespaces on the NetHSM backend at {} are: {}",
        nethsm.get_url(),
        available_namespaces
            .iter()
            .map(|namespace| namespace.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );

    // Extract the namespace from each namespace administrator found in the administrative
    // credentials.
    for user in user_list {
        let Some(namespace) = user.name.namespace() else {
            return Err(Error::NamespaceAdminHasNoNamespace {
                user: user.name.clone(),
            }
            .into());
        };

        let namespace_exists = available_namespaces.contains(namespace);
        if namespace_exists {
            // Select the first available N-Administrator credentials for interacting with the
            // NetHSM backend.
            // This might be the targeted user itself!
            nethsm.use_credentials(&get_first_available_namespace_admin(
                nethsm,
                admin_credentials,
                &available_users,
                namespace,
            )?)?;
        }

        // If the list of available users on the NetHSM does not include the given N-Administrator,
        // we create the user.
        if available_users.contains(&user.name) {
            // Set the passphrase of the user.
            nethsm.set_user_passphrase(user.name.clone(), user.passphrase.clone())?;
        } else {
            nethsm.add_user(
                format!("Namespace Admin {}", user.name),
                UserRole::Administrator,
                user.passphrase.clone(),
                Some(user.name.clone()),
            )?;

            // If the namespace does not yet exist add the namespace (authenticated as the default
            // R-Administrator).
            if !namespace_exists {
                nethsm.add_namespace(namespace)?;
            }
        }
        // Always use the default R-Administrator again.
        nethsm.use_credentials(default_admin)?;
    }

    Ok(())
}

/// Sets up all system-wide, non-administrative users based on provided credentials.
///
/// # Note
///
/// It is assumed that the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] and system-wide keys are
/// already set up, before calling this function (see `add_system_wide_admins` and
/// `add_system_wide_keys`, respectively).
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] and is guaranteed to do
/// so when it finishes.
///
/// # Errors
///
/// Returns an error if
///
/// - there are no matching credentials in `user_credentials` for a user in the list of all
///   available system-wide, non-administrative users,
/// - a user exists already, but its passphrase cannot be set,
/// - a user does not yet exist and it cannot be added,
/// - a user has a tag and deleting it fails,
/// - or adding a tag to a user fails.
fn add_non_administrative_users(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    debug!(
        "Setup non-administrative, system-wide users on NetHSM backend at {}",
        nethsm.get_url()
    );

    let user_data_list = user_mappings
        .iter()
        .filter_map(|user_mapping| {
            let mut user_data_set = user_mapping.nethsm_config_user_data();
            // We are only interested in mappings that define at least one system-wide,
            // non-administrative NetHSM backend user.
            user_data_set
                .retain(|data| !data.user.is_namespaced() && data.role != UserRole::Administrator);
            if user_data_set.is_empty() {
                return None;
            }

            Some(user_data_set)
        })
        .flatten()
        .collect::<Vec<_>>();

    if user_data_list.is_empty() {
        debug!(
            "No non-administrative, system-wide users to setup on NetHSM backend at {}",
            nethsm.get_url()
        );
        return Ok(());
    }

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    debug!("Available users: {available_users:?}");

    for user_data in user_data_list {
        let Some(creds) = user_credentials
            .iter()
            .find(|creds| &creds.name == user_data.user)
        else {
            return Err(Error::UserMissingPassphrase {
                user: user_data.user.clone(),
            }
            .into());
        };

        if available_users.contains(user_data.user) {
            nethsm.set_user_passphrase(user_data.user.clone(), creds.passphrase.clone())?;
        } else {
            nethsm.add_user(
                format!("{} user {}", user_data.role, user_data.user),
                user_data.role,
                creds.passphrase.clone(),
                Some(user_data.user.clone()),
            )?;
        }

        if user_data.role == UserRole::Operator {
            // First, delete all existing tags from user.
            for available_tag in nethsm.get_user_tags(user_data.user)? {
                nethsm.delete_user_tag(user_data.user, available_tag.as_str())?;
            }
            // Then, add optional tag to user.
            if let Some(tag) = user_data.tag {
                nethsm.add_user_tag(user_data.user, tag)?;
            }
        }
    }

    Ok(())
}

/// Sets up all namespaced non-administrative users.
///
/// # Note
///
/// It is assumed that _N-Administrators_ and namespaced keys are already set up, before calling
/// this function (see `add_namespace_admins` and `add_namespaced_keys`, respectively).
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
/// namespace-specific _N-Administrator_ for individual operations.
/// If this function succeeds, the `nethsm` is guaranteed to use the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
/// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_.
///
/// # Errors
///
/// Returns an error if
///
/// - a namespaced user is not in a namespace,
/// - the namespace of a user does not exist,
/// - the namespace of a user exists, but no usable *N-Administrator* for it is known,
/// - there are no matching credentials in `user_credentials` for a user in the list of all,
/// - a user exists already, but its passphrase cannot be set,
/// - a user does not yet exist and cannot be created,
/// - a tag cannot be removed from a user,
/// - or a tag cannot be added to a user.
fn add_namespaced_non_administrative_users(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    debug!(
        "Setup non-administrative, namespaced users on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;
    let available_namespaces = nethsm.get_namespaces()?;
    let user_data_list = user_mappings
        .iter()
        .filter_map(|user_mapping| {
            let mut user_data_set = user_mapping.nethsm_config_user_data();
            // We are only interested in mappings that define at least one namespaced,
            // non-administrative NetHSM backend user.
            user_data_set
                .retain(|data| data.user.is_namespaced() && data.role != UserRole::Administrator);
            if user_data_set.is_empty() {
                return None;
            }

            Some(user_data_set)
        })
        .flatten()
        .collect::<Vec<_>>();

    for user_data in user_data_list {
        // Extract the namespace of the user and ensure that the namespace exists already.
        let Some(namespace) = user_data.user.namespace() else {
            return Err(Error::NamespaceUserNoNamespace {
                user: user_data.user.clone(),
            }
            .into());
        };
        if !available_namespaces.contains(namespace) {
            return Err(Error::NamespaceMissing {
                namespace: namespace.clone(),
            }
            .into());
        }

        // Select the first available N-Administrator credentials for interacting with the
        // NetHSM backend.
        nethsm.use_credentials(&get_first_available_namespace_admin(
            nethsm,
            admin_credentials,
            &available_users,
            namespace,
        )?)?;

        // Retrieve credentials for the specific user.
        let Some(creds) = user_credentials
            .iter()
            .find(|creds| &creds.name == user_data.user)
        else {
            return Err(Error::UserMissingPassphrase {
                user: user_data.user.clone(),
            }
            .into());
        };

        // If the user exists already, only set its passphrase, otherwise create it.
        if available_users.contains(user_data.user) {
            nethsm.set_user_passphrase(user_data.user.clone(), creds.passphrase.clone())?;
        } else {
            nethsm.add_user(
                format!("{} user {}", user_data.role, user_data.user),
                user_data.role,
                creds.passphrase.clone(),
                Some(user_data.user.clone()),
            )?;
        }

        if user_data.role == UserRole::Operator {
            // First, delete all existing tags from user.
            for available_tag in nethsm.get_user_tags(user_data.user)? {
                nethsm.delete_user_tag(user_data.user, available_tag.as_str())?;
            }
            // Then, add optional tag to user.
            if let Some(tag) = user_data.tag {
                nethsm.add_user_tag(user_data.user, tag)?;
            }
        }
    }

    // Always use the default R-Administrator again.
    nethsm.use_credentials(default_admin)?;

    Ok(())
}

/// Comparable components of a key setup between a [`NetHsm`] backend and a Signstar config.
struct KeySetupComparison {
    /// The type of state, that the data originates from.
    pub(crate) state_type: NetHsmStateType,
    /// The key type of the setup.
    pub(crate) key_type: KeyType,
    /// The key mechanisms of the setup.
    pub(crate) key_mechanisms: HashSet<KeyMechanism>,
}

/// Compares the key setups of a key from a Signstar config and that of a NetHSM backend.
///
/// Compares the [`KeyType`] and [`KeyMechanism`]s of `key_setup_a` and `key_setup_b`, which both
/// have to be identical.
///
/// Emits a warning if the [`KeyType`] or list of [`KeyMechanism`]s of `key_setup_a` and
/// `key_setup_b` do not match.
fn compare_key_setups(
    key_id: &KeyId,
    namespace: Option<&NamespaceId>,
    key_setup_a: KeySetupComparison,
    key_setup_b: KeySetupComparison,
) {
    let namespace = if let Some(namespace) = namespace {
        format!(" in namespace \"{namespace}\"")
    } else {
        "".to_string()
    };
    debug!(
        "Compare key setup of key \"{key_id}\"{namespace} in {} (A) and {} (B)",
        key_setup_a.state_type, key_setup_b.state_type
    );

    // Compare key type and warn about mismatches.
    if key_setup_b.key_type != key_setup_a.key_type {
        warn!(
            "Key type mismatch of key \"{key_id}\"{namespace}:\n{} (A): {}\n{} (B) backend: {}!",
            key_setup_a.state_type,
            key_setup_a.key_type,
            key_setup_b.state_type,
            key_setup_b.key_type
        );
    }

    // Compare key mechanisms and warn about mismatches.
    if key_setup_b.key_mechanisms != key_setup_a.key_mechanisms {
        warn!(
            "Key mechanisms mismatch for key \"{key_id}\"{namespace}:\n{} (A): {}\n{} (B): {}!",
            key_setup_a.state_type,
            key_setup_a
                .key_mechanisms
                .iter()
                .map(|mechanism| mechanism.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            key_setup_b.state_type,
            key_setup_b
                .key_mechanisms
                .iter()
                .map(|mechanism| mechanism.to_string())
                .collect::<Vec<String>>()
                .join(", "),
        );
    }
}

/// Sets up all system-wide keys.
///
/// Creates any missing keys and adds the configured tags for all of them.
/// If keys exist already, deletes all tags and adds the configured ones for them.
///
/// # Note
///
/// It is assumed that all required _R-Administrators_ have already been set up (see
/// `add_system_wide_admins`) before calling this function.
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`].
///
/// This function does not fail on mismatching keys, as it is assumed that keys are added
/// intentionally and should not be deleted or altered.
/// However, warnings are emitted if an existing key has a mismatching [`KeyType`] or
/// [`KeyMechanisms`][`KeyMechanism`] from what is configured in the Signstar configuration file.
///
/// # Errors
///
/// Returns an error if
///
/// - the default system-wide *R-Administrator* cannot be retrieved or used for authentication,
/// - the list of available keys on the NetHSM backend cannot be retrieved,
/// - information about a single key cannot be retrieved from the NetHSM backend,
/// - if a tag cannot be removed from an existing key,
/// - if a tag cannot be added to an existing key,
/// - or if a missing key cannot be created.
fn add_system_wide_keys(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup system-wide cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_keys = nethsm.get_keys(None)?;

    for user_mapping in user_mappings {
        let Some(user_key_data) =
            user_mapping.nethsm_config_user_key_data(NetHsmUserKeysFilter::SystemWide)
        else {
            // We are only interested in mappings that define key data.
            continue;
        };

        if available_keys.contains(user_key_data.key_id) {
            // Retrieve information about the key.
            let info = nethsm.get_key(user_key_data.key_id)?;

            // Compare the key setups.
            compare_key_setups(
                user_key_data.key_id,
                None,
                KeySetupComparison {
                    state_type: NetHsmStateType::Config,
                    key_type: user_key_data.key_setup.key_type(),
                    key_mechanisms: HashSet::from_iter(
                        user_key_data.key_setup.key_mechanisms().to_vec(),
                    ),
                },
                KeySetupComparison {
                    state_type: NetHsmStateType::Backend,
                    key_type: info
                        .r#type
                        .try_into()
                        .map_err(nethsm::Error::SignstarCryptoKey)?,
                    key_mechanisms: info
                        .mechanisms
                        .iter()
                        .filter_map(|mechanism| mechanism.try_into().ok())
                        .collect(),
                },
            );

            // Remove all existing tags.
            if let Some(available_tags) = info.restrictions.tags {
                for available_tag in available_tags {
                    nethsm.delete_key_tag(user_key_data.key_id, available_tag.as_str())?;
                }
            }
            // Add the required tag to the key.
            nethsm.add_key_tag(user_key_data.key_id, user_key_data.tag)?;
        } else {
            // Add the key, including the required tag.
            nethsm.generate_key(
                user_key_data.key_setup.key_type(),
                user_key_data.key_setup.key_mechanisms().to_vec(),
                user_key_data.key_setup.key_length(),
                Some(user_key_data.key_id.clone()),
                Some(vec![user_key_data.tag.to_string()]),
            )?;
        }
    }

    Ok(())
}

/// Sets up all namespaced keys and tags them.
///
/// Creates any missing keys and adds the configured tags for all of them.
/// If keys exist already, deletes all tags and adds the configured ones for them.
///
/// # Note
///
/// It is assumed that _N-Administrators_ have already been set up, before calling
/// this function (see `add_namespace_admins`).
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
/// namespace-specific _N-Administrator_ for individual operations.
/// If this function succeeds, the `nethsm` is guaranteed to use the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
/// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_.
///
/// This function does not fail on mismatching keys, as it is assumed that keys are added
/// intentionally and should not be deleted/altered.
/// However, warnings are emitted if an existing key has a mismatching key type or key mechanisms
/// from what is configured in the Signstar configuration file.
///
/// Opposite to the behavior of `add_system_wide_keys`, this function does not delete any tags from
/// keys.
/// This is due to [a bug in the NetHSM firmware], which leads to a crash when adding a tag to a
/// key, trying to remove and then re-adding it again.
///
/// # Errors
///
/// Returns an error if
///
/// - the default system-wide *R-Administrator* cannot be retrieved or used for authentication,
/// - retrieving the list of available users from the NetHSM backend fails,
/// - a namespaced user mapped to a key is not in a namespace,
/// - no usable *N-Administrator* for a namespace is known,
/// - the available keys in the namespace cannot be retrieved,
/// - information about a specific key in the namespace cannot be retrieved,
/// - a tag cannot be added to an already existing key,
/// - a new key cannot be generated,
/// - or using the default system-wide administrator again fails.
///
/// [a bug in the NetHSM firmware]: https://github.com/Nitrokey/nethsm/issues/13
fn add_namespaced_keys(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup namespaced cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    let all_user_key_data = user_mappings
        .iter()
        .filter_map(|user_mapping| {
            user_mapping.nethsm_config_user_key_data(NetHsmUserKeysFilter::Namespaced)
        })
        .collect::<Vec<_>>();

    for user_key_data in all_user_key_data {
        debug!(
            "Set up key \"{}\" with tag {} for user {}",
            user_key_data.key_id, user_key_data.tag, user_key_data.user
        );

        // Extract the namespace from the user or return an error.
        let Some(namespace) = user_key_data.user.namespace() else {
            // Note: Returning this error is not really possible, as we are explicitly
            // requesting tuples of namespaced user, key setup and tag.
            return Err(Error::NamespaceUserNoNamespace {
                user: user_key_data.user.clone(),
            }
            .into());
        };

        // Select the first available N-Administrator credentials for interacting with the
        // NetHSM backend.
        nethsm.use_credentials(&get_first_available_namespace_admin(
            nethsm,
            admin_credentials,
            &available_users,
            namespace,
        )?)?;

        let available_keys = nethsm.get_keys(None)?;

        if available_keys.contains(user_key_data.key_id) {
            let key_info = nethsm.get_key(user_key_data.key_id)?;

            // Compare the key setups.
            compare_key_setups(
                user_key_data.key_id,
                Some(namespace),
                KeySetupComparison {
                    state_type: NetHsmStateType::Config,
                    key_type: user_key_data.key_setup.key_type(),
                    key_mechanisms: HashSet::from_iter(
                        user_key_data.key_setup.key_mechanisms().to_vec(),
                    ),
                },
                KeySetupComparison {
                    state_type: NetHsmStateType::Backend,
                    key_type: key_info
                        .r#type
                        .try_into()
                        .map_err(nethsm::Error::SignstarCryptoKey)?,
                    key_mechanisms: key_info
                        .mechanisms
                        .iter()
                        .filter_map(|mechanism| mechanism.try_into().ok())
                        .collect(),
                },
            );

            // If there are tags already, check if the tag we are looking for is already set and
            // if so, skip to the next key.
            if let Some(available_tags) = key_info.restrictions.tags {
                debug!(
                    "Available tags for key \"{}\" in namespace {namespace}: {}",
                    user_key_data.key_id,
                    available_tags.join(", ")
                );
                // NOTE: If the required tag is already set, continue to the next key.
                //       Without this we otherwise trigger a bug in the NetHSM firmware which
                //       breaks the connection after re-adding the tag for the key further down.
                //       (i.e. "Bad Status: HTTP version did not start with HTTP/")
                //       See https://github.com/Nitrokey/nethsm/issues/13 for details.
                if available_tags.len() == 1
                    && available_tags
                        .iter()
                        .find(|tag| tag.as_str() == user_key_data.tag)
                        .is_some()
                {
                    continue;
                }
            }

            // Add the tag to the key.
            nethsm.add_key_tag(user_key_data.key_id, user_key_data.tag)?;
        } else {
            // Add the key, including the required tag.
            nethsm.generate_key(
                user_key_data.key_setup.key_type(),
                user_key_data.key_setup.key_mechanisms().to_vec(),
                user_key_data.key_setup.key_length(),
                Some(user_key_data.key_id.clone()),
                Some(vec![user_key_data.tag.to_string()]),
            )?;
        }
    }

    // Always use the default R-Administrator again.
    nethsm.use_credentials(default_admin)?;

    Ok(())
}

/// Adds OpenPGP certificates for system-wide keys that are used for OpenPGP signing.
///
/// # Note
///
/// It is assumed that the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], all system-wide keys
/// and all system-wide non-administrative users are already set up, before calling this function
/// (see `add_system_wide_admins`, `add_system_wide_keys` and `add_non_administrative_users`,
/// respectively).
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
/// system-wide, non-administrative user for individual operations.
/// If this function succeeds, the `nethsm` is guaranteed to use the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
/// If this function fails, the `nethsm` may still use a system-wide, non-administrative user.
///
/// This function does not overwrite or alter existing OpenPGP certificates, as this would introduce
/// inconsistencies between signatures created with a previous version of a certificate and those
/// created with a new version of the certificate, which is hard to debug.
///
/// # Errors
///
/// Returns an error if
///
/// - using the default *R-Administrator* fails,
/// - retrieving the names of all system-wide users fails,
/// - retrieving the names of all system-wide keys fails,
/// - a user used for OpenPGP signing does not exist,
/// - the tags assigned to a user cannot be retrieved from the `nethsm`,
/// - a user used for OpenPGP signing does not have a required tag,
/// - a key used for OpenPGP signing does not exist,
/// - the tags assigned to a key cannot be retrieved from the `nethsm`,
/// - a key used for OpenPGP signing does not have a required tag,
/// - the key setup for a key used for OpenPGP signing does not have at least one User ID,
/// - the user assigned the same tag as the key that is used for OpenPGP signing cannot be used to
///   create an OpenPGP certificate for the key,
/// - or the default *R-Administrator* cannot be used to import the generated OpenPGP certificate
///   for the key.
fn add_system_wide_openpgp_certificates(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup OpenPGP certificates for system-wide cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    let all_user_key_data = user_mappings
        .iter()
        .filter_map(|user_mapping| {
            user_mapping.nethsm_config_user_key_data(NetHsmUserKeysFilter::SystemWide)
        })
        .collect::<Vec<_>>();

    for user_key_data in all_user_key_data {
        // Get OpenPGP User IDs and version or continue to the next user/key setup if the
        // mapping is not used for OpenPGP signing.
        let CryptographicKeyContext::OpenPgp { user_ids, version } =
            user_key_data.key_setup.key_context()
        else {
            debug!(
                "Skip creating an OpenPGP certificate for the key \"{}\" used by user \"{}\" as it is not used in an OpenPGP context.",
                user_key_data.key_id, user_key_data.user,
            );
            continue;
        };

        // Ensure the targeted user exists.
        if !available_users.contains(user_key_data.user) {
            return Err(Error::UserMissing {
                user_id: user_key_data.user.clone(),
            }
            .into());
        }
        // Ensure the required tag is assigned to the targeted user.
        if nethsm
            .get_user_tags(user_key_data.user)?
            .iter()
            .find(|tag| tag.as_str() == user_key_data.tag)
            .is_none()
        {
            return Err(Error::UserMissingTag {
                user_id: user_key_data.user.clone(),
                tag: user_key_data.tag.to_string(),
            }
            .into());
        }

        let available_keys = nethsm.get_keys(None)?;

        // Ensure the targeted key exists.
        if !available_keys.contains(user_key_data.key_id) {
            return Err(Error::KeyMissing {
                key_id: user_key_data.key_id.clone(),
            }
            .into());
        }
        // Ensure the required tag is assigned to the targeted key.
        if !nethsm
            .get_key(user_key_data.key_id)?
            .restrictions
            .tags
            .is_some_and(|tags| {
                tags.iter()
                    .find(|tag| tag.as_str() == user_key_data.tag)
                    .is_some()
            })
        {
            return Err(Error::KeyIsMissingTag {
                key_id: user_key_data.key_id.clone(),
                tag: user_key_data.tag.to_string(),
            }
            .into());
        }

        // Create the OpenPGP certificate if it does not exist yet.
        if nethsm.get_key_certificate(user_key_data.key_id)?.is_none() {
            // Ensure the first OpenPGP User ID exists.
            let Some(user_id) = user_ids.first() else {
                return Err(Error::OpenPgpUserIdMissing {
                    key_id: user_key_data.key_id.clone(),
                }
                .into());
            };

            // Switch to the dedicated user with access to the key to create an OpenPGP
            // certificate for the key.
            nethsm.use_credentials(user_key_data.user)?;
            let data = nethsm.create_openpgp_cert(
                user_key_data.key_id,
                OpenPgpKeyUsageFlags::default(),
                user_id.clone(),
                Timestamp::now(),
                *version,
            )?;

            // Switch back to the default R-Administrator for the import of the OpenPGP
            // certificate.
            nethsm.use_credentials(default_admin)?;
            nethsm.import_key_certificate(user_key_data.key_id, data)?;
        }
    }

    // Always use the default R-Administrator again.
    nethsm.use_credentials(default_admin)?;

    Ok(())
}

/// Adds OpenPGP certificates for namespaced keys that are used for OpenPGP signing.
///
/// # Note
///
/// It is assumed that the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], all namespaced keys,
/// all _N-Administrators_ and all namespaced non-administrative users are already set up, before
/// calling this function (see `add_system_wide_admins`, `add_namespaced_keys`,
/// `add_namespace_admins` and `add_namespaced_non_administrative_users`, respectively).
///
/// This function uses the `nethsm` with the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
/// namespace-specific _N-Administrator_ or non-administrative user for individual operations.
/// If this function succeeds, the `nethsm` is guaranteed to use the [default
/// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
/// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_ or
/// non-administrative user.
///
/// This function does not overwrite or alter existing OpenPGP certificates, as this would introduce
/// inconsistencies between signatures created with a previous version of a certificate and those
/// created with a new version of the certificate, which is hard to debug.
///
/// # Errors
///
/// Returns an error if
///
/// - using the default *R-Administrator* fails,
/// - retrieving the names of all users fails,
/// - a namespaced user is not in a namespace,
/// - no usable *N-Administrator* for a namespace is known,
/// - a user used for OpenPGP signing does not exist,
/// - the tags assigned to a user cannot be retrieved from the `nethsm`,
/// - a user used for OpenPGP signing does not have a required tag,
/// - retrieving the names of all keys in a namespace fails,
/// - a key used for OpenPGP signing does not exist,
/// - the tags assigned to a key cannot be retrieved from the `nethsm`,
/// - a key used for OpenPGP signing does not have a required tag,
/// - the key setup for a key used for OpenPGP signing does not have at least one User ID,
/// - the user assigned the same tag as the key that is used for OpenPGP signing cannot be used to
///   create an OpenPGP certificate for the key,
/// - or the *N-Administrator* cannot be used to import the generated OpenPGP certificate for the
///   key.
fn add_namespaced_openpgp_certificates(
    nethsm: &NetHsm,
    admin_credentials: &NetHsmAdminCredentials,
    user_mappings: &[&NetHsmUserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup OpenPGP certificates for namespaced cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    let nethsm_user_key_data_list = user_mappings
        .iter()
        .filter_map(|user_mapping| {
            let Some(user_key_data) =
                user_mapping.nethsm_config_user_key_data(NetHsmUserKeysFilter::Namespaced)
            else {
                // We are only interested in mappings that define key data.
                return None;
            };
            // We are only interested in mappings that define OpenPGP key data.
            if !matches!(
                user_key_data.key_setup.key_context(),
                CryptographicKeyContext::OpenPgp { .. }
            ) {
                return None;
            }

            Some(user_key_data)
        })
        .collect::<Vec<_>>();

    for user_key_data in nethsm_user_key_data_list {
        // Get OpenPGP User IDs and version or continue to the next user/key setup if the
        // mapping is not used for OpenPGP signing.
        let CryptographicKeyContext::OpenPgp { user_ids, version } =
            user_key_data.key_setup.key_context()
        else {
            continue;
        };

        // Extract the namespace from the user.
        let Some(namespace) = user_key_data.user.namespace() else {
            // Note: Returning this error is not really possible, as we are explicitly
            // requesting tuples of namespaced user, key setup and tag.
            return Err(Error::NamespaceUserNoNamespace {
                user: user_key_data.user.clone(),
            }
            .into());
        };

        // Select the first available N-Administrator credentials for interacting with the
        // NetHSM backend.
        let admin = get_first_available_namespace_admin(
            nethsm,
            admin_credentials,
            &available_users,
            namespace,
        )?;
        nethsm.use_credentials(&admin)?;

        // Ensure the targeted user exists.
        if !available_users.contains(user_key_data.user) {
            return Err(Error::NamespaceUserMissing {
                user: user_key_data.user.clone(),
                namespace: namespace.clone(),
            }
            .into());
        }
        // Ensure the required tag is assigned to the targeted user.
        let user_tags = nethsm.get_user_tags(user_key_data.user)?;
        if user_tags
            .iter()
            .find(|tag| tag.as_str() == user_key_data.tag)
            .is_none()
        {
            return Err(Error::NamespaceUserMissingTag {
                user: user_key_data.user.clone(),
                namespace: namespace.clone(),
                tag: user_key_data.tag.to_string(),
            }
            .into());
        }

        let available_keys = nethsm.get_keys(None)?;

        // Ensure the targeted key exists.
        if !available_keys.contains(user_key_data.key_id) {
            return Err(Error::NamespaceKeyMissing {
                key_id: user_key_data.key_id.clone(),
                namespace: namespace.clone(),
            }
            .into());
        }
        // Ensure the required tag is assigned to the targeted key.
        let pubkey = nethsm.get_key(user_key_data.key_id)?;
        if !pubkey.restrictions.tags.is_some_and(|tags| {
            tags.iter()
                .find(|tag| tag.as_str() == user_key_data.tag)
                .is_some()
        }) {
            return Err(Error::NamespaceKeyMissesTag {
                key_id: user_key_data.key_id.clone(),
                namespace: namespace.clone(),
                tag: user_key_data.tag.to_string(),
            }
            .into());
        }

        // Create the OpenPGP certificate if it does not exist yet.
        if nethsm.get_key_certificate(user_key_data.key_id)?.is_none() {
            // Ensure the first OpenPGP User ID exists.
            let Some(user_id) = user_ids.first() else {
                return Err(Error::NamespaceOpenPgpUserIdMissing {
                    key_id: user_key_data.key_id.clone(),
                    namespace: namespace.clone(),
                }
                .into());
            };

            // Switch to the dedicated user with access to the key to create an OpenPGP
            // certificate for the key.
            nethsm.use_credentials(user_key_data.user)?;
            let data = nethsm.create_openpgp_cert(
                user_key_data.key_id,
                OpenPgpKeyUsageFlags::default(),
                user_id.clone(),
                Timestamp::now(),
                *version,
            )?;

            // Switch back to the N-Administrator for the import of the OpenPGP certificate.
            nethsm.use_credentials(&admin)?;
            nethsm.import_key_certificate(user_key_data.key_id, data)?;
        }
    }

    // Always use the default R-Administrator again.
    nethsm.use_credentials(default_admin)?;

    Ok(())
}

/// A NetHSM backend that provides full control over its data.
///
/// This backend allows full control over the data in a [`NetHsm`], to the extend that is configured
/// by the tracked [`NetHsmAdminCredentials`] and [`Config`].
#[derive(Debug)]
pub struct NetHsmBackend<'a, 'b> {
    nethsm: NetHsm,
    admin_credentials: &'a NetHsmAdminCredentials,
    nethsm_config: &'b NetHsmConfig,
}

impl<'a, 'b> NetHsmBackend<'a, 'b> {
    /// Creates a new [`NetHsmBackend`].
    ///
    /// Returns `Some(None)` if `signstar_config` contains no [`NetHsmConfig`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the iteration of the `admin_credentials` does not match that of the `signstar_config`,
    /// - or retrieving the default administrator from the `admin_credentials` fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::{collections::BTreeSet, num::NonZeroUsize};
    ///
    /// use nethsm::{Connection, ConnectionSecurity, FullCredentials, NetHsm};
    /// use signstar_config::{
    ///     config::{ConfigBuilder, SystemConfig, SystemUserMapping},
    ///     nethsm::{NetHsmAdminCredentials, NetHsmBackend, NetHsmConfig, NetHsmMetricsUsers, NetHsmUserMapping},
    /// };
    /// use signstar_crypto::{
    ///     AdministrativeSecretHandling,
    ///     NonAdministrativeSecretHandling,
    ///     key::{CryptographicKeyContext, KeyMechanism, KeyType, SigningKeySetup, SignatureType},
    ///     openpgp::OpenPgpUserIdList,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // The NetHSM connection.
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    /// // The administrative credentials.
    /// let admin_credentials = NetHsmAdminCredentials::new(
    ///     1,
    ///     "backup-passphrase".parse()?,
    ///     "unlock-passphrase".parse()?,
    ///     vec![FullCredentials::new(
    ///         "admin".parse()?,
    ///         "admin-passphrase".parse()?,
    ///     )],
    ///     vec![FullCredentials::new(
    ///         "ns1~admin".parse()?,
    ///         "ns1-admin-passphrase".parse()?,
    ///     )],
    /// )?;
    /// // The Signstar config.
    /// let signstar_config = ConfigBuilder::new(SystemConfig::new(
    ///         1,
    ///         AdministrativeSecretHandling::ShamirsSecretSharing {
    ///             number_of_shares: NonZeroUsize::new(3).expect("3 is larger than 0"),
    ///             threshold: NonZeroUsize::new(2).expect("2 is larger than 0"),
    ///         },
    ///         NonAdministrativeSecretHandling::SystemdCreds,
    ///         BTreeSet::from_iter([
    ///             SystemUserMapping::ShareHolder {
    ///                 system_user: "share-holder1".parse()?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAN54Gd1jMz+yNDjBRwX1SnOtWuUsVF64RJIeYJ8DI7b user@host".parse()?,
    ///             },
    ///             SystemUserMapping::ShareHolder {
    ///                 system_user: "share-holder2".parse()?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?,
    ///             },
    ///             SystemUserMapping::ShareHolder {
    ///                 system_user: "share-holder3".parse()?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILWqWyMCk5BdSl1c3KYoLEokKr7qNVPbI1IbBhgEBQj5 user@host".parse()?
    ///             },
    ///             SystemUserMapping::WireGuardDownload {
    ///                 system_user: "wireguard-downloader".parse()?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
    ///             },
    ///         ]),
    ///     )?)
    ///     .set_nethsm_config(NetHsmConfig::new(
    ///         BTreeSet::from_iter([
    ///             Connection::new("https:///nethsm1.example.org/".parse()?, ConnectionSecurity::Unsafe),
    ///             Connection::new("https:///nethsm2.example.org/".parse()?, ConnectionSecurity::Unsafe),
    ///         ]),
    ///         BTreeSet::from_iter([
    ///             NetHsmUserMapping::Admin("admin".parse()?),
    ///             NetHsmUserMapping::Backup{
    ///                 backend_user: "backup".parse()?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxR0Oc+SWXkEvvZPitc6NvjvykgiKc9iauRI7tLYvcp user@host".parse()?,
    ///                 system_user: "nethsm-backup-user".parse()?,
    ///             },
    ///             NetHsmUserMapping::HermeticMetrics {
    ///                 backend_users: NetHsmMetricsUsers::new("hermeticmetrics".parse()?, vec!["hermetickeymetrics".parse()?])?,
    ///                 system_user: "nethsm-hermetic-metrics-user".parse()?,
    ///             },
    ///             NetHsmUserMapping::Metrics {
    ///                 backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETxhCqeZhfzFLfH0KFyw3u/w/dkRBUrft8tQm7DEVzY user@host".parse()?,
    ///                 system_user: "nethsm-metrics-user".parse()?,
    ///             },
    ///             NetHsmUserMapping::Signing {
    ///                 backend_user: "signing".parse()?,
    ///                 signing_key_id: "signing1".parse()?,
    ///                 key_setup: SigningKeySetup::new(
    ///                     KeyType::Curve25519,
    ///                     vec![KeyMechanism::EdDsaSignature],
    ///                     None,
    ///                     SignatureType::EdDsa,
    ///                     CryptographicKeyContext::OpenPgp {
    ///                         user_ids: OpenPgpUserIdList::new(vec![
    ///                             "Foobar McFooface <foobar@mcfooface.org>".parse()?,
    ///                         ])?,
    ///                         version: "v4".parse()?,
    ///                     },
    ///                 )?,
    ///                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIClIXZdx0aDOPcIQA+6Qx68cwSUgGTL3TWzDSX3qUEOQ user@host".parse()?,
    ///                 system_user: "nethsm-signing-user".parse()?,
    ///                 tag: "signing1".to_string(),
    ///             }
    ///         ]),
    ///     )?)
    ///     .finish()?;
    ///
    /// let nethsm_backend = NetHsmBackend::new(nethsm, &admin_credentials, &signstar_config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        nethsm: NetHsm,
        admin_credentials: &'a NetHsmAdminCredentials,
        signstar_config: &'b Config,
    ) -> Result<Option<Self>, crate::Error> {
        debug!(
            "Create a new NetHSM backend for Signstar config at {}",
            nethsm.get_url()
        );

        let Some(nethsm_config) = signstar_config.nethsm() else {
            return Ok(None);
        };

        // Ensure that the iterations of administrative credentials and signstar config match.
        if admin_credentials.get_iteration() != signstar_config.system().iteration() {
            return Err(Error::IterationMismatch {
                admin_creds: admin_credentials.get_iteration(),
                signstar_config: signstar_config.system().iteration(),
            }
            .into());
        }

        // Add all available system-wide Administrators for the connection
        for user in admin_credentials.get_administrators() {
            nethsm.add_credentials(user.into());
        }
        // Add all available namespace Administrators for the connection
        for user in admin_credentials.get_namespace_administrators() {
            nethsm.add_credentials(user.into());
        }
        // Use the default administrator
        nethsm.use_credentials(&admin_credentials.get_default_administrator()?.name)?;

        Ok(Some(Self {
            nethsm,
            admin_credentials,
            nethsm_config,
        }))
    }

    /// Returns a reference to the tracked [`NetHsm`].
    pub fn nethsm(&self) -> &NetHsm {
        &self.nethsm
    }

    /// Unlocks a locked [`NetHsm`] backend.
    pub(crate) fn unlock_nethsm(&self) -> Result<(), crate::Error> {
        Ok(self.nethsm.unlock(Passphrase::new(
            self.admin_credentials.get_unlock_passphrase().into(),
        ))?)
    }

    /// Retrieves the state for all users on the [`NetHsm`] backend.
    ///
    /// # Note
    ///
    /// Uses the `nethsm` with the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - using the credentials of the default *R-Administrator* fails,
    /// - retrieving all user names of the NetHSM backend fails,
    /// - retrieving information about a specific NetHSM user fails,
    /// - or retrieving the tags of an *Operator* user fails.
    pub(crate) fn user_states(&self) -> Result<Vec<UserState>, crate::Error> {
        // Use the default R-Administrator.
        self.nethsm
            .use_credentials(&self.admin_credentials.get_default_administrator()?.name)?;

        let users = {
            let mut users: Vec<UserState> = Vec::new();

            for user_id in self.nethsm.get_users()? {
                let user_data = self.nethsm.get_user(&user_id)?;
                let tags = if user_data.role == UserRole::Operator.into() {
                    self.nethsm.get_user_tags(&user_id)?
                } else {
                    Vec::new()
                };

                users.push(UserState {
                    name: user_id,
                    role: user_data.role.into(),
                    tags,
                });
            }

            users
        };

        Ok(users)
    }

    /// Retrieves the state of a key certificate on the [`NetHsm`] backend.
    ///
    /// Key certificates may be retrieved for system-wide keys or namespaced keys.
    /// Returns a [`KeyCertificateState`], which may also encode reasons for why state cannot be
    /// retrieved.
    ///
    /// # Note
    ///
    /// It is assumed that the current credentials for the `nethsm` provide access to the key
    /// certificate of key `key_id`.
    fn key_certificate_state(
        &self,
        key_id: &KeyId,
        namespace: Option<&NamespaceId>,
    ) -> KeyCertificateState {
        // Provide a dedicated string for log messages in case a namespace is used.
        let namespace = if let Some(namespace) = namespace {
            format!(" in namespace \"{namespace}\"")
        } else {
            "".to_string()
        };

        match self.nethsm.get_key_certificate(key_id) {
            Ok(Some(key_cert)) => {
                let public_key = match SignedPublicKey::from_reader_single(key_cert.as_slice()) {
                    Ok((public_key, _armor_header)) => public_key,
                    Err(error) => {
                        let message = format!(
                            "Unable to create OpenPGP certificate from key certificate of key \"{key_id}\"{namespace}:\n{error}"
                        );
                        debug!("{message}");
                        return KeyCertificateState::NotAnOpenPgpCertificate { message };
                    }
                };

                match TryInto::<CryptographicKeyContext>::try_into(public_key) {
                    Ok(key_context) => KeyCertificateState::KeyContext(key_context),
                    Err(error) => {
                        let message = format!(
                            "Unable to convert OpenPGP certificate of key \"{key_id}\"{namespace} to key context:\n{error}"
                        );
                        debug!("{message}");
                        KeyCertificateState::NotACryptographicKeyContext { message }
                    }
                }
            }
            Ok(None) => KeyCertificateState::Empty,
            Err(error) => {
                let message = error.to_string();
                debug!("{message}");
                KeyCertificateState::Error { message }
            }
        }
    }

    /// Retrieves the state for all keys on the [`NetHsm`] backend.
    ///
    /// Collects each key, their [`KeyType`] and list of [`KeyMechanisms`][`KeyMechanism`].
    /// Also attempts to derive a [`CryptographicKeyContext`] from the key certificate.
    ///
    /// # Note
    ///
    /// This function uses the `nethsm` with the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
    /// namespace-specific _N-Administrator_ for individual operations.
    /// If this function succeeds, the `nethsm` is guaranteed to use the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
    /// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_.
    ///
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - using the default *R-Administrator* for authentication against the backend fails,
    /// - retrieving the names of all system-wide keys on the backend fails,
    /// - retrieving information on a specific system-wide key on the backend fails,
    /// - an *N-Administrator* in `admin_credentials` is not actually in a namespace,
    /// - using the credentials of an *N-Administrator* fails,
    /// - retrieving the names of all namespaced keys on the backend fails,
    /// - or retrieving information on a specific namespaced key on the backend fails.
    pub(crate) fn key_states(&self) -> Result<Vec<KeyState>, crate::Error> {
        // Use the default administrator
        let default_admin = &self.admin_credentials.get_default_administrator()?.name;
        self.nethsm.use_credentials(default_admin)?;

        let mut keys = Vec::new();
        // Get the state of system-wide keys.
        for key_id in self.nethsm.get_keys(None)? {
            let key = self.nethsm.get_key(&key_id)?;
            let key_context = self.key_certificate_state(&key_id, None);

            keys.push(KeyState {
                name: key_id,
                namespace: None,
                tags: key.restrictions.tags.unwrap_or_default(),
                key_type: key
                    .r#type
                    .try_into()
                    .map_err(nethsm::Error::SignstarCryptoKey)?,
                mechanisms: key
                    .mechanisms
                    .iter()
                    .filter_map(|mechanism| KeyMechanism::try_from(mechanism).ok())
                    .collect(),
                key_cert_state: key_context,
            });
        }

        let mut seen_namespaces = HashSet::new();
        // Get the state of namespaced keys.
        for user_id in self
            .admin_credentials
            .get_namespace_administrators()
            .iter()
            .map(|creds| creds.name.clone())
        {
            // Extract the namespace of the user and ensure that the namespace exists already.
            let Some(namespace) = user_id.namespace() else {
                return Err(Error::NamespaceUserNoNamespace {
                    user: user_id.clone(),
                }
                .into());
            };

            // Only extract key information for the namespace if we have not already looked at it.
            if seen_namespaces.contains(namespace) {
                continue;
            }
            seen_namespaces.insert(namespace.clone());

            self.nethsm.use_credentials(&user_id)?;
            for key_id in self.nethsm.get_keys(None)? {
                let key = self.nethsm.get_key(&key_id)?;
                let key_context = self.key_certificate_state(&key_id, Some(namespace));

                keys.push(KeyState {
                    name: key_id,
                    namespace: Some(namespace.clone()),
                    tags: key.restrictions.tags.unwrap_or_default(),
                    key_type: key
                        .r#type
                        .try_into()
                        .map_err(nethsm::Error::SignstarCryptoKey)?,
                    mechanisms: key
                        .mechanisms
                        .iter()
                        .filter_map(|mechanism| KeyMechanism::try_from(mechanism).ok())
                        .collect(),
                    key_cert_state: key_context,
                });
            }
        }

        // Always use the default *R-Administrator* again.
        self.nethsm.use_credentials(default_admin)?;

        Ok(keys)
    }

    /// Syncs the state of a Signstar configuration with the backend using credentials for users in
    /// non-administrative roles.
    ///
    /// Provisions unprovisioned NetHSM backends and unlocks locked ones.
    /// Then works down the following list to
    ///
    /// - create _R-Administrators_,
    ///     - or set their passphrase if they exist already,
    /// - create system-wide keys and add tags to them,
    ///     - or remove all tags from existing keys and only add the configured tags,
    /// - create users in the system-wide, non-administrative roles (i.e.
    ///   [`Backup`][`UserRole::Backup`], [`Metrics`][`UserRole::Metrics`] and
    ///   [`Operator`][`UserRole::Operator`]),
    ///     - or set their passphrase if they exist already,
    /// - create OpenPGP certificates for system-wide keys,
    ///     - or do nothing if they exist already,
    /// - create _N-Administrators_ and their respective namespaces,
    ///     - or set their passphrase if they exist already,
    /// - create namespaced keys and add tags to them,
    ///     - or remove all tags from existing keys and only add the configured tags,
    /// - create users in the namespaced, non-administrative roles (i.e.
    ///   [`Operator`][`UserRole::Operator`]),
    ///     - or set their passphrase if they exist already,
    /// - and create OpenPGP certificates for namespaced keys,
    ///     - or do nothing if they exist already.
    ///
    /// # Note
    ///
    /// This function uses the `nethsm` with the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
    /// namespace-specific _N-Administrator_ or non-administrative user for individual operations.
    /// If this function succeeds, the `nethsm` is guaranteed to use the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
    /// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_ or
    /// non-administrative user.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - retrieving the state of the [`NetHsm`] backend fails,
    /// - provisioning an unprovisioned [`NetHsm`] fails,
    /// - unlocking a locked [`NetHsm`] backend fails,
    /// - adding users in the system-wide [`Administrator`][`UserRole::Administrator`] role fails,
    /// - adding system-wide keys fails,
    /// - adding system-wide users in the [`Backup`][`UserRole::Backup`],
    ///   [`Metrics`][`UserRole::Metrics`] or [`Operator`][`UserRole::Operator`] role fails,
    /// - adding OpenPGP certificates for system-wide keys fails,
    /// - adding namespaced users in the [`Administrator`][`UserRole::Administrator`] role or adding
    ///   their respective namespace fails,
    /// - adding namespaced keys fails,
    /// - adding namespaced users in the [`Operator`][`UserRole::Operator`] role fails,
    /// - or adding OpenPGP certificates for namespaced keys fails.
    pub fn sync(&self, user_credentials: &[FullCredentials]) -> Result<(), crate::Error> {
        debug!(
            "Synchronize state of users and keys for the NetHSM backend at {} with the Signstar config.",
            self.nethsm.get_url()
        );

        // Extract the non-admin user backend connections.
        let non_admin_users = self
            .nethsm_config
            .mappings()
            .iter()
            .filter(|mapping| !matches!(mapping, NetHsmUserMapping::Admin(..)))
            .collect::<Vec<_>>();

        // Extract the admin user backend connections.
        let admin_users = self
            .nethsm_config
            .mappings()
            .iter()
            .filter(|mapping| matches!(mapping, NetHsmUserMapping::Admin(..)))
            .collect::<Vec<_>>();

        match self.nethsm.state()? {
            SystemState::Unprovisioned => {
                debug!(
                    "Unprovisioned NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );

                self.nethsm.provision(
                    Passphrase::from_str(self.admin_credentials.get_unlock_passphrase()).map_err(
                        |source| {
                            crate::Error::NetHsm(nethsm::Error::SignstarCryptoPassphrase(source))
                        },
                    )?,
                    self.admin_credentials
                        .get_default_administrator()?
                        .passphrase
                        .clone(),
                    nethsm::Utc::now(),
                )?;
            }
            SystemState::Locked => {
                debug!(
                    "Locked NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );

                self.nethsm.unlock(Passphrase::new(
                    self.admin_credentials.get_unlock_passphrase().into(),
                ))?;
            }
            SystemState::Operational => {
                debug!(
                    "Operational NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );
            }
        }

        // Add any missing users and keys.
        add_system_wide_admins(&self.nethsm, self.admin_credentials, &admin_users)?;
        add_system_wide_keys(&self.nethsm, self.admin_credentials, &non_admin_users)?;
        add_non_administrative_users(
            &self.nethsm,
            self.admin_credentials,
            &non_admin_users,
            user_credentials,
        )?;
        add_system_wide_openpgp_certificates(
            &self.nethsm,
            self.admin_credentials,
            &non_admin_users,
        )?;
        add_namespace_admins(&self.nethsm, self.admin_credentials, &admin_users)?;
        add_namespaced_keys(&self.nethsm, self.admin_credentials, &non_admin_users)?;
        add_namespaced_non_administrative_users(
            &self.nethsm,
            self.admin_credentials,
            &non_admin_users,
            user_credentials,
        )?;
        add_namespaced_openpgp_certificates(
            &self.nethsm,
            self.admin_credentials,
            &non_admin_users,
        )?;

        Ok(())
    }
}

/// The state of a [`NetHsmBackend`].
///
/// This tracks the available backend users, their roles and assigned tags, and the key setups
/// associated with users.
#[derive(Debug, Eq, PartialEq)]
pub struct NetHsmBackendState {
    /// The user states.
    pub(crate) user_states: Vec<UserState>,
    /// The key states.
    pub(crate) key_states: Vec<KeyState>,
}

impl<'a, 'b> TryFrom<&NetHsmBackend<'a, 'b>> for NetHsmBackendState {
    type Error = crate::Error;

    /// Creates a new [`NetHsmBackendState`] from a [`NetHsmBackend`].
    ///
    /// # Note
    ///
    /// Uses the [`NetHsm`] backend with the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`], but may switch to a
    /// namespace-specific _N-Administrator_ for individual operations.
    /// If this function succeeds, the `nethsm` is guaranteed to use the [default
    /// _R-Administrator_][`NetHsmAdminCredentials::get_default_administrator`] again.
    /// If this function fails, the `nethsm` may still use a namespace-specific _N-Administrator_.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - retrieving the system state of the [`NetHsm`] backend fails,
    /// - unlocking a locked [`NetHsm`] backend fails,
    /// - or retrieving the state of users or keys on the tracked [`NetHsm`] backend fails.
    fn try_from(value: &NetHsmBackend<'a, 'b>) -> Result<Self, Self::Error> {
        debug!(
            "Retrieve state of the NetHSM backend at {}",
            value.nethsm().get_url()
        );

        let (user_states, key_states) = match value.nethsm().state()? {
            SystemState::Unprovisioned => {
                debug!(
                    "Unprovisioned NetHSM backend detected at {}.\nSync should be run!",
                    value.nethsm().get_url()
                );

                (Vec::new(), Vec::new())
            }
            SystemState::Locked => {
                debug!(
                    "Locked NetHSM backend detected at {}",
                    value.nethsm().get_url()
                );

                value.unlock_nethsm()?;

                let user_states = value.user_states()?;
                let key_states = value.key_states()?;

                (user_states, key_states)
            }
            SystemState::Operational => {
                debug!(
                    "Operational NetHSM backend detected at {}",
                    value.nethsm().get_url()
                );

                let user_states = value.user_states()?;
                let key_states = value.key_states()?;

                (user_states, key_states)
            }
        };

        Ok(Self {
            user_states,
            key_states,
        })
    }
}

#[cfg(test)]
#[cfg(feature = "_test-helpers")]
mod tests {
    use log::LevelFilter;
    use nethsm::{Connection, ConnectionSecurity, FullCredentials, NetHsm};
    use nethsm::{CryptographicKeyContext, OpenPgpUserIdList, OpenPgpVersion, UserRole};
    use rstest::rstest;
    use signstar_common::logging::setup_logging;
    use testresult::TestResult;

    use super::*;
    use crate::test::{ConfigFileConfig, ConfigFileVariant, SystemPrepareConfig};

    /// Ensures that [`UserState::to_string`] shows correctly.
    #[rstest]
    #[case(
        UserState{
            name: "testuser".parse()?,
            role: UserRole::Operator,
            tags: vec!["tag1".to_string(), "tag2".to_string()]
        },
        "testuser (role: Operator; tags: tag1, tag2)",
    )]
    #[case(
        UserState{
            name: "testuser".parse()?,
            role: UserRole::Operator,
            tags: Vec::new(),
        },
        "testuser (role: Operator)",
    )]
    #[case(
        UserState{
            name: "testuser".parse()?,
            role: UserRole::Metrics,
            tags: Vec::new(),
        },
        "testuser (role: Metrics)",
    )]
    #[case(
        UserState{
            name: "testuser".parse()?,
            role: UserRole::Backup,
            tags: Vec::new(),
        },
        "testuser (role: Backup)",
    )]
    #[case(
        UserState{name:
            "testuser".parse()?,
            role: UserRole::Administrator,
            tags: Vec::new(),
        },
        "testuser (role: Administrator)",
    )]
    fn user_state_to_string(#[case] user_state: UserState, #[case] expected: &str) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(user_state.to_string(), expected);
        Ok(())
    }

    /// Ensures that [`KeyState::to_string`] shows correctly.
    #[rstest]
    #[case::namespaced_key_with_openpgp_v4_cert(
        KeyState{
            name: "key1".parse()?,
            namespace: Some("ns1".parse()?),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::KeyContext(
                CryptographicKeyContext::OpenPgp {
                    user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                    version: OpenPgpVersion::V4,
                })
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: \"John Doe <john@example.org>\"))",
    )]
    #[case::namespaced_key_with_raw_cert(
        KeyState{
            name: "key1".parse()?,
            namespace: Some("ns1".parse()?),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Raw)",
    )]
    #[case::namespaced_key_with_no_cert(
        KeyState{
            name: "key1".parse()?,
            namespace: Some("ns1".parse()?),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::Empty
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Empty)",
    )]
    #[case::namespaced_key_with_cert_error(
        KeyState{
            name: "key1".parse()?,
            namespace: Some("ns1".parse()?),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::Error { message: "the dog ate it".to_string() }
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Error retrieving key certificate - the dog ate it)",
    )]
    #[case::namespaced_key_with_not_a_cert_context(
        KeyState{
            name: "key1".parse()?,
            namespace: Some("ns1".parse()?),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::NotACryptographicKeyContext { message: "failed to convert".to_string() }
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Not a cryptographic key context - \"failed to convert\")",
    )]
    #[case::namespaced_key_with_not_an_openpgp_cert(
        KeyState{
            name: "key1".parse()?,
            namespace: Some("ns1".parse()?),
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::NotAnOpenPgpCertificate { message: "it's a blob".to_string() }
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Not an OpenPGP certificate - \"it's a blob\")",
    )]
    #[case::system_wide_key_with_no_cert_and_no_tags_and_raw_cert(
        KeyState{
            name: "key1".parse()?,
            namespace: None,
            tags: Vec::new(),
            key_type: KeyType::Curve25519,
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
        },
        "key1 (type: Curve25519; mechanisms: EdDsaSignature; context: Raw)",
    )]
    fn key_state_to_string(#[case] key_state: KeyState, #[case] expected: &str) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(key_state.to_string(), expected);
        Ok(())
    }

    /// Ensures that the [`NetHsmBackend::new`] fails on mismatching iterations in
    /// [`NetHsmAdminCredentials`] and [`Config`].
    #[test]
    fn nethsm_backend_new_fails_on_iteration_mismatch() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let prepare_config = SystemPrepareConfig {
            machine_id: false,
            credentials_socket: false,
            signstar_config: ConfigFileConfig {
                location: None,
                variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCreds,
                system_user_config: None,
            },
        };
        let signstar_config = prepare_config.signstar_config.variant.to_config()?;

        let nethsm = NetHsm::new(
            Connection::new(
                "https://example.org/api/v1".try_into()?,
                ConnectionSecurity::Unsafe,
            ),
            None,
            None,
            None,
        )?;
        // The administrative credentials.
        let admin_credentials = NetHsmAdminCredentials::new(
            // this is different from the one in the Signstar config.
            2,
            "backup-passphrase".parse()?,
            "unlock-passphrase".parse()?,
            vec![FullCredentials::new(
                "admin".parse()?,
                "admin-passphrase".parse()?,
            )],
            vec![FullCredentials::new(
                "ns1~admin".parse()?,
                "ns1-admin-passphrase".parse()?,
            )],
        )?;
        let nethsm_backend_result =
            NetHsmBackend::new(nethsm, &admin_credentials, &signstar_config);

        assert!(
            nethsm_backend_result.is_err(),
            "Test should have failed, but succeeded"
        );
        assert!(
            matches!(
                nethsm_backend_result,
                Err(crate::Error::NetHsmBackend(Error::IterationMismatch {
                    admin_creds: _,
                    signstar_config: _
                }))
            ),
            "Expected an `Error::IterationMismatch` but got {nethsm_backend_result:?}"
        );

        Ok(())
    }
}
