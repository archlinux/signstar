//! Backend handling for [`NetHsm`].
//!
//! Based on a [`NetHsm`], [`NetHsmAdminCredentials`] and a [`SignstarConfig`] this module offers
//! the ability to populate a [`NetHsm`] backend with the help of the [`NetHsmBackend`] struct.
//!
//! Using [`NetHsmBackend::sync`] all users and keys configured in a [`SignstarConfig`]
//! are created and adapted to changes upon re-run.
//! The state representation can be found in the [`nethsm::state`][`crate::nethsm::state`] module.
//!
//! # Note
//!
//! This module only works with data for the same iteration (i.e. the iteration of the
//! [`NetHsmAdminCredentials`] and those of the [`NetHsm`] backend must match).

use std::{collections::HashSet, str::FromStr};

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

use super::Error;
use crate::{
    FilterUserKeys,
    NetHsmAdminCredentials,
    SignstarConfig,
    UserMapping,
    config::state::{KeyCertificateState, KeyState, UserState},
    state::StateType,
};

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
) -> Result<(), crate::Error> {
    debug!(
        "Setup system-wide administrators (R-Administrators) on NetHSM backend at {}",
        nethsm.get_url()
    );

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

    for user in admin_credentials.get_administrators().iter() {
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
) -> Result<(), crate::Error> {
    debug!(
        "Setup namespace administrators (N-Administrators) on NetHSM backend at {}",
        nethsm.get_url()
    );

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
    for user in admin_credentials.get_namespace_administrators() {
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
    users: &[UserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    debug!(
        "Setup non-administrative, system-wide users on NetHSM backend at {}",
        nethsm.get_url()
    );

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    debug!("Available users: {available_users:?}");

    for mapping in users.iter() {
        // Add all users of the mapping.
        for (user, role, tags) in mapping
            .get_nethsm_user_role_and_tags()
            .iter()
            // Only use system-wide, non-administrative users.
            .filter(|(user, role, _tags)| !user.is_namespaced() && role != &UserRole::Administrator)
        {
            let Some(creds) = user_credentials.iter().find(|creds| &creds.name == user) else {
                return Err(Error::UserMissingPassphrase { user: user.clone() }.into());
            };

            if available_users.contains(user) {
                nethsm.set_user_passphrase(user.clone(), creds.passphrase.clone())?;
            } else {
                nethsm.add_user(
                    format!("{role} user {user}"),
                    *role,
                    creds.passphrase.clone(),
                    Some(user.clone()),
                )?;
            }

            // Add tags to users.
            for tag in tags {
                for available_tag in nethsm.get_user_tags(user)? {
                    nethsm.delete_user_tag(user, available_tag.as_str())?;
                }
                nethsm.add_user_tag(user, tag.as_str())?;
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
    users: &[UserMapping],
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

    for mapping in users.iter() {
        for (user, role, tags) in mapping
            .get_nethsm_user_role_and_tags()
            .iter()
            // Only use non-administrative, namespaced users on the NetHSM backend.
            .filter(|(user, role, _tags)| user.is_namespaced() && role != &UserRole::Administrator)
        {
            // Extract the namespace of the user and ensure that the namespace exists already.
            let Some(namespace) = user.namespace() else {
                return Err(Error::NamespaceUserNoNamespace { user: user.clone() }.into());
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
            let Some(creds) = user_credentials.iter().find(|creds| &creds.name == user) else {
                return Err(Error::UserMissingPassphrase { user: user.clone() }.into());
            };

            // If the user exists already, only set its passphrase, otherwise create it.
            if available_users.contains(user) {
                nethsm.set_user_passphrase(user.clone(), creds.passphrase.clone())?;
            } else {
                nethsm.add_user(
                    format!("{role} user {user}"),
                    *role,
                    creds.passphrase.clone(),
                    Some(user.clone()),
                )?;
            }

            // Delete all tags of the user.
            let available_tags = nethsm.get_user_tags(user)?;
            for available_tag in available_tags {
                nethsm.delete_user_tag(user, available_tag.as_str())?;
            }
            // Setup tags for the user.
            for tag in tags.iter() {
                nethsm.add_user_tag(user, tag)?;
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
    pub state_type: StateType,
    /// The key type of the setup.
    pub key_type: KeyType,
    /// The key mechanisms of the setup.
    pub key_mechanisms: HashSet<KeyMechanism>,
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
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup system-wide cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_keys = nethsm.get_keys(None)?;

    for mapping in users {
        for (_user, key_id, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            if available_keys.contains(&key_id) {
                // Retrieve information about the key.
                let info = nethsm.get_key(&key_id)?;

                // Compare the key setups.
                compare_key_setups(
                    &key_id,
                    None,
                    KeySetupComparison {
                        state_type: StateType::SignstarConfigNetHsm,
                        key_type: key_setup.key_type(),
                        key_mechanisms: HashSet::from_iter(key_setup.key_mechanisms().to_vec()),
                    },
                    KeySetupComparison {
                        state_type: StateType::NetHsm,
                        key_type: info
                            .r#type
                            .try_into()
                            .map_err(nethsm::Error::SignstarCryptoKey)?,
                        key_mechanisms: info.mechanisms.iter().map(Into::into).collect(),
                    },
                );

                // Remove all existing tags.
                if let Some(available_tags) = info.restrictions.tags {
                    for available_tag in available_tags {
                        nethsm.delete_key_tag(&key_id, available_tag.as_str())?;
                    }
                }
                // Add the required tag to the key.
                nethsm.add_key_tag(&key_id, tag.as_str())?;
            } else {
                // Add the key, including the required tag.
                nethsm.generate_key(
                    key_setup.key_type(),
                    key_setup.key_mechanisms().to_vec(),
                    key_setup.key_length(),
                    Some(key_id.clone()),
                    Some(vec![tag]),
                )?;
            }
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
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup namespaced cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    for mapping in users {
        for (user, key_id, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespaced)
        {
            debug!("Set up key \"{key_id}\" with tag {tag} for user {user}");

            // Extract the namespace from the user or return an error.
            let Some(namespace) = user.namespace() else {
                // Note: Returning this error is not really possible, as we are explicitly
                // requesting tuples of namespaced user, key setup and tag.
                return Err(Error::NamespaceUserNoNamespace { user }.into());
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

            if available_keys.contains(&key_id) {
                let key_info = nethsm.get_key(&key_id)?;

                // Compare the key setups.
                compare_key_setups(
                    &key_id,
                    Some(namespace),
                    KeySetupComparison {
                        state_type: StateType::SignstarConfigNetHsm,
                        key_type: key_setup.key_type(),
                        key_mechanisms: HashSet::from_iter(key_setup.key_mechanisms().to_vec()),
                    },
                    KeySetupComparison {
                        state_type: StateType::NetHsm,
                        key_type: key_info
                            .r#type
                            .try_into()
                            .map_err(nethsm::Error::SignstarCryptoKey)?,
                        key_mechanisms: key_info.mechanisms.iter().map(Into::into).collect(),
                    },
                );

                // If there are tags already, check if the tag we are looking for is already set and
                // if so, skip to the next key.
                if let Some(available_tags) = key_info.restrictions.tags {
                    debug!(
                        "Available tags for key \"{key_id}\" in namespace {namespace}: {}",
                        available_tags.join(", ")
                    );
                    // NOTE: If the required tag is already set, continue to the next key.
                    //       Without this we otherwise trigger a bug in the NetHSM firmware which
                    //       breaks the connection after re-adding the tag for the key further down.
                    //       (i.e. "Bad Status: HTTP version did not start with HTTP/")
                    //       See https://github.com/Nitrokey/nethsm/issues/13 for details.
                    if available_tags.len() == 1 && available_tags.contains(&tag) {
                        continue;
                    }
                }

                // Add the tag to the key.
                nethsm.add_key_tag(&key_id, tag.as_str())?;
            } else {
                // Add the key, including the required tag.
                nethsm.generate_key(
                    key_setup.key_type(),
                    key_setup.key_mechanisms().to_vec(),
                    key_setup.key_length(),
                    Some(key_id.clone()),
                    Some(vec![tag]),
                )?;
            }
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
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup OpenPGP certificates for system-wide cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    for mapping in users {
        // Continue to the next mapping if it is not used for signing.
        if !matches!(mapping, UserMapping::SystemNetHsmOperatorSigning { .. }) {
            continue;
        }

        for (user, key_id, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            // Get OpenPGP User IDs and version or continue to the next user/key setup if the
            // mapping is not used for OpenPGP signing.
            let CryptographicKeyContext::OpenPgp { user_ids, version } = key_setup.key_context()
            else {
                debug!(
                    "Skip creating an OpenPGP certificate for the key \"{key_id}\" used by user \"{user}\" as it is not used in an OpenPGP context."
                );
                continue;
            };

            // Ensure the targeted user exists.
            if !available_users.contains(&user) {
                return Err(Error::UserMissing { user_id: user }.into());
            }
            // Ensure the required tag is assigned to the targeted user.
            if !nethsm.get_user_tags(&user)?.contains(&tag) {
                return Err(Error::UserMissingTag { user_id: user, tag }.into());
            }

            let available_keys = nethsm.get_keys(None)?;

            // Ensure the targeted key exists.
            if !available_keys.contains(&key_id) {
                return Err(Error::KeyMissing { key_id }.into());
            }
            // Ensure the required tag is assigned to the targeted key.
            if !nethsm
                .get_key(&key_id)?
                .restrictions
                .tags
                .is_some_and(|tags| tags.contains(&tag))
            {
                return Err(Error::KeyIsMissingTag { key_id, tag }.into());
            }

            // Create the OpenPGP certificate if it does not exist yet.
            if nethsm.get_key_certificate(&key_id)?.is_none() {
                // Ensure the first OpenPGP User ID exists.
                let Some(user_id) = user_ids.first() else {
                    return Err(Error::OpenPgpUserIdMissing { key_id }.into());
                };

                // Switch to the dedicated user with access to the key to create an OpenPGP
                // certificate for the key.
                nethsm.use_credentials(&user)?;
                let data = nethsm.create_openpgp_cert(
                    &key_id,
                    OpenPgpKeyUsageFlags::default(),
                    user_id.clone(),
                    Timestamp::now(),
                    *version,
                )?;

                // Switch back to the default R-Administrator for the import of the OpenPGP
                // certificate.
                nethsm.use_credentials(default_admin)?;
                nethsm.import_key_certificate(&key_id, data)?;
            }
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
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!(
        "Setup OpenPGP certificates for namespaced cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    for mapping in users {
        // Continue to the next mapping if it is not used for signing.
        if !matches!(mapping, UserMapping::SystemNetHsmOperatorSigning { .. }) {
            continue;
        }

        for (user, key_id, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespaced)
        {
            // Get OpenPGP User IDs and version or continue to the next user/key setup if the
            // mapping is not used for OpenPGP signing.
            let CryptographicKeyContext::OpenPgp { user_ids, version } = key_setup.key_context()
            else {
                continue;
            };

            // Extract the namespace from the user.
            let Some(namespace) = user.namespace() else {
                // Note: Returning this error is not really possible, as we are explicitly
                // requesting tuples of namespaced user, key setup and tag.
                return Err(Error::NamespaceUserNoNamespace { user }.into());
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
            if !available_users.contains(&user) {
                return Err(Error::NamespaceUserMissing {
                    user: user.clone(),
                    namespace: namespace.clone(),
                }
                .into());
            }
            // Ensure the required tag is assigned to the targeted user.
            let user_tags = nethsm.get_user_tags(&user)?;
            if !user_tags.contains(&tag) {
                return Err(Error::NamespaceUserMissingTag {
                    user: user.clone(),
                    namespace: namespace.clone(),
                    tag,
                }
                .into());
            }

            let available_keys = nethsm.get_keys(None)?;

            // Ensure the targeted key exists.
            if !available_keys.contains(&key_id) {
                return Err(Error::NamespaceKeyMissing {
                    key_id,
                    namespace: namespace.clone(),
                }
                .into());
            }
            // Ensure the required tag is assigned to the targeted key.
            let pubkey = nethsm.get_key(&key_id)?;
            if !pubkey
                .restrictions
                .tags
                .is_some_and(|tags| tags.contains(&tag))
            {
                return Err(Error::NamespaceKeyMissesTag {
                    key_id,
                    namespace: namespace.clone(),
                    tag,
                }
                .into());
            }

            // Create the OpenPGP certificate if it does not exist yet.
            if nethsm.get_key_certificate(&key_id)?.is_none() {
                // Ensure the first OpenPGP User ID exists.
                let Some(user_id) = user_ids.first() else {
                    return Err(Error::NamespaceOpenPgpUserIdMissing {
                        key_id,
                        namespace: namespace.clone(),
                    }
                    .into());
                };

                // Switch to the dedicated user with access to the key to create an OpenPGP
                // certificate for the key.
                nethsm.use_credentials(&user)?;
                let data = nethsm.create_openpgp_cert(
                    &key_id,
                    OpenPgpKeyUsageFlags::default(),
                    user_id.clone(),
                    Timestamp::now(),
                    *version,
                )?;

                // Switch back to the N-Administrator for the import of the OpenPGP certificate.
                nethsm.use_credentials(&admin)?;
                nethsm.import_key_certificate(&key_id, data)?;
            }
        }
    }
    // Always use the default R-Administrator again.
    nethsm.use_credentials(default_admin)?;

    Ok(())
}

/// A NetHSM backend that provides full control over its data.
///
/// This backend allows full control over the data in a [`NetHsm`], to the extend that is configured
/// by the tracked [`NetHsmAdminCredentials`] and [`SignstarConfig`].
#[derive(Debug)]
pub struct NetHsmBackend<'a, 'b> {
    nethsm: NetHsm,
    admin_credentials: &'a NetHsmAdminCredentials,
    signstar_config: &'b SignstarConfig,
}

impl<'a, 'b> NetHsmBackend<'a, 'b> {
    /// Creates a new [`NetHsmBackend`].
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
    /// use std::collections::HashSet;
    ///
    /// use nethsm::{Connection, ConnectionSecurity, FullCredentials, NetHsm};
    /// use signstar_config::{
    ///     NetHsmAdminCredentials,
    ///     AdministrativeSecretHandling,
    ///     BackendConnection,
    ///     NetHsmBackend,
    ///     NonAdministrativeSecretHandling,
    ///     SignstarConfig,
    ///     UserMapping,
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
    /// let signstar_config = SignstarConfig::new(
    ///     1,
    ///     AdministrativeSecretHandling::ShamirsSecretSharing,
    ///     NonAdministrativeSecretHandling::SystemdCreds,
    ///     HashSet::from([BackendConnection::NetHsm(Connection::new(
    ///         "https://localhost:8443/api/v1/".parse()?,
    ///         "Unsafe".parse()?,
    ///     ))]),
    ///     HashSet::from([
    ///         UserMapping::NetHsmOnlyAdmin("admin".parse()?),
    ///         UserMapping::SystemOnlyShareDownload {
    ///             system_user: "ssh-share-down".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
    ///         },
    ///         UserMapping::SystemOnlyShareUpload {
    ///             system_user: "ssh-share-up".parse()?,
    ///             ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
    ///         }]),
    /// )?;
    ///
    /// let nethsm_backend = NetHsmBackend::new(nethsm, &admin_credentials, &signstar_config)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        nethsm: NetHsm,
        admin_credentials: &'a NetHsmAdminCredentials,
        signstar_config: &'b SignstarConfig,
    ) -> Result<Self, crate::Error> {
        debug!(
            "Create a new NetHSM backend for Signstar config at {}",
            nethsm.get_url()
        );

        // Ensure that the iterations of administrative credentials and signstar config match.
        if admin_credentials.get_iteration() != signstar_config.get_iteration() {
            return Err(Error::IterationMismatch {
                admin_creds: admin_credentials.get_iteration(),
                signstar_config: signstar_config.get_iteration(),
            }
            .into());
        }

        // Add all system-wide Administrators for the connection
        for user in admin_credentials.get_administrators() {
            nethsm.add_credentials(user.into());
        }
        // Add all namespace Administrators for the connection
        for user in admin_credentials.get_namespace_administrators() {
            nethsm.add_credentials(user.into());
        }
        // Use the default administrator
        nethsm.use_credentials(&admin_credentials.get_default_administrator()?.name)?;

        Ok(Self {
            nethsm,
            admin_credentials,
            signstar_config,
        })
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
                mechanisms: key.mechanisms.iter().map(KeyMechanism::from).collect(),
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
                    mechanisms: key.mechanisms.iter().map(KeyMechanism::from).collect(),
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

        // Extract the user mappings.
        let users = self
            .signstar_config
            .iter_user_mappings()
            .cloned()
            .collect::<Vec<UserMapping>>();

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
        add_system_wide_admins(&self.nethsm, self.admin_credentials)?;
        add_system_wide_keys(&self.nethsm, self.admin_credentials, &users)?;
        add_non_administrative_users(
            &self.nethsm,
            self.admin_credentials,
            &users,
            user_credentials,
        )?;
        add_system_wide_openpgp_certificates(&self.nethsm, self.admin_credentials, &users)?;
        add_namespace_admins(&self.nethsm, self.admin_credentials)?;
        add_namespaced_keys(&self.nethsm, self.admin_credentials, &users)?;
        add_namespaced_non_administrative_users(
            &self.nethsm,
            self.admin_credentials,
            &users,
            user_credentials,
        )?;
        add_namespaced_openpgp_certificates(&self.nethsm, self.admin_credentials, &users)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use log::LevelFilter;
    use nethsm::{Connection, ConnectionSecurity, FullCredentials, NetHsm};
    use signstar_common::logging::setup_logging;
    use testresult::TestResult;

    use super::*;
    use crate::{
        AdministrativeSecretHandling,
        NonAdministrativeSecretHandling,
        config::base::BackendConnection,
    };

    /// Ensures that the [`NetHsmBackend::new`] fails on mismatching iterations in
    /// [`NetHsmAdminCredentials`] and [`SignstarConfig`].
    #[test]
    fn nethsm_backend_new_fails_on_iteration_mismatch() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

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
        // The Signstar config.
        let signstar_config = SignstarConfig::new(
         1,
         AdministrativeSecretHandling::ShamirsSecretSharing,
         NonAdministrativeSecretHandling::SystemdCreds,
         HashSet::from([BackendConnection::NetHsm(Connection::new(
             "https://localhost:8443/api/v1/".parse()?,
             "Unsafe".parse()?,
         ))]),
         HashSet::from([
             UserMapping::NetHsmOnlyAdmin("admin".parse()?),
             UserMapping::SystemOnlyShareDownload {
                 system_user: "ssh-share-down".parse()?,
                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
             },
             UserMapping::SystemOnlyShareUpload {
                 system_user: "ssh-share-up".parse()?,
                 ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
             }]),
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
