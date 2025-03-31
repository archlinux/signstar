//! Backend handling for [`NetHsm`].
//!
//! Based on a [`NetHsm`], [`AdminCredentials`] and a [`HermeticParallelConfig`] this module offers
//! the ability to populate a [`NetHsm`] backend with the help of the [`FullNetHsmBackend`] struct.
//!
//! Using [`FullNetHsmBackend::sync`] all users and keys configured in [`HermeticParallelConfig`]
//! are created and adapted to changes upon re-run.
//! With the help of [`FullNetHsmBackend::state`] the current [`State`] of a [`NetHsm`] backend can
//! be created and compared with e.g. the [`State`] representation of a [`HermeticParallelConfig`].
//!
//! # Note
//!
//! This module only works with data for the same iteration (i.e. the iteration of the
//! [`AdminCredentials`] and those of the [`NetHsm`] backend must match).

use std::str::FromStr;

use log::{debug, info, warn};
use nethsm::{
    Connection,
    CryptographicKeyContext,
    FullCredentials,
    InfoData,
    KeyId,
    KeyMechanism,
    KeyType,
    NamespaceId,
    NetHsm,
    OpenPgpKeyUsageFlags,
    Passphrase,
    SystemState,
    UserId,
    UserRole,
    Utc,
};
use nethsm_config::{FilterUserKeys, HermeticParallelConfig, UserMapping};

use super::{Error, get_key_states, get_user_states, state::StateType};
use crate::{AdminCredentials, State};

/// Sets up all users in the system-wide [`Administrator`][`UserRole::Administrator`]
/// (*R-Administrator*) role to a [`NetHsm`].
///
/// Uses the user "admin" which is the default user in the system-wide
/// [`Administrator`][`UserRole::Administrator`] role.
///
/// # Note
///
/// This function skips the "admin" user, as it exists after provisioning and is the one in use to
/// create the other users in the [`Administrator`][`UserRole::Administrator`] role.
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
/// - or one of the admin credentials cannot be added.
fn add_system_wide_admins(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<(), crate::Error> {
    info!(
        "Setup system-wide administrators (R-Administrators) on NetHSM backend at {}",
        nethsm.get_url()
    );

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    for user in admin_credentials
        .get_administrators()
        .iter()
        // Skip the default "admin" as it exists after provisioning
        .filter(|user| user.name != *default_admin)
    {
        // only add if user doesn't exist yet, else set passphrase
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
    admin_credentials: &AdminCredentials,
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

/// Sets up all users in the role of a namespace [`Administrator`][`UserRole::Administrator`]
/// (*N-Administrator*) and their respective namespace.
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
    admin_credentials: &AdminCredentials,
) -> Result<(), crate::Error> {
    info!(
        "Setup namespace administrators (N-Administrators) on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;
    debug!(
        "The available users on the NetHSM backend at {} are: {}",
        nethsm.get_url(),
        available_users
            .iter()
            .map(|user| user.to_string())
            .collect::<Vec<String>>()
            .join(", ")
    );
    let available_namespaces = nethsm.get_namespaces()?;
    debug!(
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
/// It is assumed that system-wide users in the [`Administrator`][`UserRole::Administrator`]
/// (*R-Administrator*) and cryptographic keys are already setup, before calling this function (see
/// `add_system_wide_admins` and `add_system_wide_keys`, respectively).
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
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    info!(
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
/// It is assumed that namespaced users in the [`Administrator`][`UserRole::Administrator`]
/// (*N-Administrator*) and cryptographic keys are already setup, before calling this function (see
/// `add_namespace_admins` and `add_namespaced_keys`, respectively).
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
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    info!(
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

/// The components of a key setup that can be compared between NetHSM backend and Signstar config.
struct KeySetupComparison {
    /// The key type of the setup.
    pub key_type: KeyType,
    /// The key mechanisms of the setup.
    pub key_mechanisms: Vec<KeyMechanism>,
}

/// Compares the key setups of a key from a Signstar config and that of a NetHSM backend.
///
/// Emits a warning if the [`KeyType`] or list of [`KeyMechanism`]s of `signstar_config` and
/// `nethsm_backend` do not match.
fn compare_key_setups(
    key_id: &KeyId,
    signstar_config: KeySetupComparison,
    nethsm_backend: KeySetupComparison,
) {
    debug!("Compare key setups of Signstar config and NetHSM backend for key \"{key_id}\"");

    // Compare key type and warn about mismatches.
    if nethsm_backend.key_type != signstar_config.key_type {
        warn!(
            "The system-wide key \"{key_id}\" has a mismatch in key type:\nSignstar config: {}\nNetHSM backend: {}!",
            signstar_config.key_type, nethsm_backend.key_type
        );
    }

    // Compare key mechanisms and warn about mismatches.
    if !(nethsm_backend
        .key_mechanisms
        .iter()
        .all(|mechanism| signstar_config.key_mechanisms.contains(mechanism))
        && signstar_config
            .key_mechanisms
            .iter()
            .all(|mechanism| nethsm_backend.key_mechanisms.contains(mechanism)))
    {
        warn!(
            "The system-wide key \"{key_id}\" has a mismatch in key mechanisms:\nSignstar config: {}\nNetHSM: {}!",
            signstar_config
                .key_mechanisms
                .iter()
                .map(|mechanism| mechanism.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            nethsm_backend
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
///
/// # Note
///
/// It is assumed that the system-wide users in the [`Administrator`][`UserRole::Administrator`]
/// (*R-Administrator*) role have already been setup (see `add_system_wide_admins`).
///
/// This function does not fail on mismatching keys, as it is assumed that keys are added
/// intentionally and should not be deleted/altered.
/// However, warnings are emitted if an existing key has a mismatching key type or key mechanisms
/// from what is configured in the Signstar configuration file.
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
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    info!(
        "Setup system-wide cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_keys = nethsm.get_keys(None)?;

    for mapping in users {
        for (_user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            let key_id = key_setup.get_key_id();
            if available_keys.contains(&key_setup.get_key_id()) {
                // Retrieve information about the key.
                let info = nethsm.get_key(&key_id)?;

                // Compare the key setups.
                compare_key_setups(
                    &key_id,
                    KeySetupComparison {
                        key_type: key_setup.get_key_type(),
                        key_mechanisms: key_setup.get_key_mechanisms(),
                    },
                    KeySetupComparison {
                        key_type: info.r#type.into(),
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
                    key_setup.get_key_type(),
                    key_setup.get_key_mechanisms(),
                    key_setup.get_key_length(),
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

/// Sets up all namespaced keys and tags them.
///
/// Creates any missing keys and adds the configured tags for all of them.
///
/// # Note
///
/// It is assumed that the namespaced users in the [`Administrator`][`UserRole::Administrator`]
/// role (*N-Administrator*) have already been setup (see `add_namespace_admins`).
///
/// This function does not fail on mismatching keys, as it is assumed that keys are added
/// intentionally and should not be deleted/altered.
/// However, warnings are emitted if an existing key has a mismatching key type or key mechanisms
/// from what is configured in the Signstar configuration file.
///
/// Opposite to the behavior of `add_system_wide_keys`, this function does not delete any tags from
/// keys.
/// This is due to a bug in the NetHSM firmware, which leads to a crash when adding a tag to a key,
/// trying to remove and then re-adding it again.
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
fn add_namespaced_keys(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    info!(
        "Setup namespaced cryptographic keys on NetHSM backend at {}",
        nethsm.get_url()
    );

    // Use the default R-Administrator for authentication to the backend by default.
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let available_users = nethsm.get_users()?;

    for mapping in users {
        for (user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespaced)
        {
            let key_id = key_setup.get_key_id();
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
                    KeySetupComparison {
                        key_type: key_setup.get_key_type(),
                        key_mechanisms: key_setup.get_key_mechanisms(),
                    },
                    KeySetupComparison {
                        key_type: key_info.r#type.into(),
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
                    if available_tags.len() == 1 && available_tags.contains(&tag) {
                        continue;
                    }
                }

                // Add the tag to the key.
                nethsm.add_key_tag(&key_id, tag.as_str())?;
            } else {
                // Add the key, including the required tag.
                nethsm.generate_key(
                    key_setup.get_key_type(),
                    key_setup.get_key_mechanisms(),
                    key_setup.get_key_length(),
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
/// This function does not overwrite or alter existing OpenPGP certificates.
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
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    info!(
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

        for (user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            // Get OpenPGP User IDs and version or continue to the next user/key setup if the
            // mapping is not used for OpenPGP signing.
            let CryptographicKeyContext::OpenPgp { user_ids, version } =
                key_setup.get_key_context()
            else {
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
            let key_id = key_setup.get_key_id();

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
            if nethsm.get_key_certificate(&key_id).is_err() {
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
                    Utc::now(),
                    version,
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
/// This function does not overwrite or alter existing OpenPGP certificates, as this would break any
/// signatures created with the keys associated with them.
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
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    info!(
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

        for (user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespaced)
        {
            // Get OpenPGP User IDs and version or continue to the next user/key setup if the
            // mapping is not used for OpenPGP signing.
            let CryptographicKeyContext::OpenPgp { user_ids, version } =
                key_setup.get_key_context()
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
            let key_id = key_setup.get_key_id();

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
            if nethsm.get_key_certificate(&key_id).is_err() {
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
                    Utc::now(),
                    version,
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

/// A NetHSM backend that provides basic access to its data.
///
/// This backend only allows access to unauthenticated resources, or the specific resources that are
/// available to the currently selected user.
#[derive(Debug)]
pub struct NetHsmBackend {
    nethsm: NetHsm,
}

impl NetHsmBackend {
    /// Creates a new [`NetHsmBackend`].
    pub fn new(connection: Connection) -> Result<Self, crate::Error> {
        Ok(Self {
            nethsm: NetHsm::new(connection, None, None, None)?,
        })
    }

    /// Returns the system state for the [`NetHsmBackend`].
    pub fn state(&self) -> Result<SystemState, crate::Error> {
        self.nethsm.state().map_err(crate::Error::NetHsm)
    }

    /// Returns the system info for the [`NetHsmBackend`].
    pub fn info(&self) -> Result<InfoData, crate::Error> {
        self.nethsm.info().map_err(crate::Error::NetHsm)
    }
}

/// A NetHSM backend that provides full control over its data.
///
/// This backend allows full control over its data, to the extend that is configured by the tracked
/// [`AdminCredentials`] and [`HermeticParallelConfig`].
#[derive(Debug)]
pub struct FullNetHsmBackend<'a, 'b> {
    nethsm: NetHsm,
    admin_credentials: &'a AdminCredentials,
    signstar_config: &'b HermeticParallelConfig,
}

impl<'a, 'b> FullNetHsmBackend<'a, 'b> {
    /// Creates a new [`NetHsmBackend`].
    pub fn new(
        nethsm: NetHsm,
        admin_credentials: &'a AdminCredentials,
        signstar_config: &'b HermeticParallelConfig,
    ) -> Result<Self, crate::Error> {
        info!("Create a new full NetHSM backend at {}", nethsm.get_url());

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

    /// Creates a new [`State`] for the [`NetHsm`] backend.
    pub fn state(&self) -> Result<State, crate::Error> {
        info!(
            "Retrieve state of the NetHSM backend at {}",
            self.nethsm.get_url()
        );

        // Ensure that the iterations match.
        if self.admin_credentials.get_iteration() != self.signstar_config.get_iteration() {
            return Err(Error::IterationMismatch {
                admin_creds: self.admin_credentials.get_iteration(),
                signstar_config: self.signstar_config.get_iteration(),
            }
            .into());
        }

        let (users, keys) = match self.nethsm.state()? {
            SystemState::Unprovisioned => {
                info!(
                    "Unprovisioned NetHSM backend detected at {}.\nSync should be run!",
                    self.nethsm.get_url()
                );

                (Vec::new(), Vec::new())
            }
            SystemState::Locked => {
                info!(
                    "Locked NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );

                self.nethsm.unlock(Passphrase::new(
                    self.admin_credentials.get_unlock_passphrase().into(),
                ))?;

                let users = get_user_states(&self.nethsm, self.admin_credentials)?;
                let keys = get_key_states(&self.nethsm, self.admin_credentials)?;
                (users, keys)
            }
            SystemState::Operational => {
                info!(
                    "Operational NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );

                let users = get_user_states(&self.nethsm, self.admin_credentials)?;
                let keys = get_key_states(&self.nethsm, self.admin_credentials)?;
                (users, keys)
            }
        };

        Ok(State {
            state_type: StateType::NetHsm,
            users,
            keys,
        })
    }

    /// Syncs the state of NetHSM backend using credentials for users in non-administrative roles.
    ///
    /// Checks whether the iteration of the administrative credentials matches that of the Signstar
    /// configuration.
    /// Provisions unprovisioned NetHSM backends and unlocks locked ones.
    /// Then works down the following list to create
    ///
    /// - users in the system-wide [`Administrator`][`UserRole::Administrator`] role,
    /// - system-wide keys,
    /// - users in the system-wide, non-administrative roles,
    /// - OpenPGP certificates for system-wide keys,
    /// - users in the namespaced [`Administrator`][`UserRole::Administrator`] role and respective
    ///   namespaces,
    /// - namespaced keys,
    /// - users in the namespaced, non-administrative roles,
    /// - and OpenPGP certificates for namespaced keys.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the iteration of the administrative credentials and that of the Signstar configuration
    ///   don't match,
    /// - retrieving the state of a NetHSM backend fails,
    /// - provisioning an unprovisioned NetHSM fails,
    /// - unlocking a locked NetHSM backend fails,
    /// - adding users in the system-wide [`Administrator`][`UserRole::Administrator`] role fails,
    /// - adding system-wide keys fails,
    /// - adding users in the system-wide, non-administrative roles fails,
    /// - adding OpenPGP certificates for system-wide keys fails,
    /// - adding users in the namespaced [`Administrator`][`UserRole::Administrator`] role or
    ///   respective namespaces fails,
    /// - adding namespaced keys fails,
    /// - adding users in the namespaced, non-administrative roles fails,
    /// - or adding OpenPGP certificates for namespaced keys fails.
    pub fn sync(&self, user_credentials: &[FullCredentials]) -> Result<(), crate::Error> {
        info!(
            "Synchronize state of users and keys for the NetHSM backend at {} with the Signstar config.",
            self.nethsm.get_url()
        );

        // Ensure that the iterations match.
        if self.admin_credentials.get_iteration() != self.signstar_config.get_iteration() {
            return Err(Error::IterationMismatch {
                admin_creds: self.admin_credentials.get_iteration(),
                signstar_config: self.signstar_config.get_iteration(),
            }
            .into());
        }

        // Extract the user mappings.
        let users = self
            .signstar_config
            .iter_user_mappings()
            .cloned()
            .collect::<Vec<UserMapping>>();

        match self.nethsm.state()? {
            SystemState::Unprovisioned => {
                info!(
                    "Unprovisioned NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );

                self.nethsm.provision(
                    Passphrase::from_str(self.admin_credentials.get_unlock_passphrase())
                        .map_err(Error::NetHsmUser)?,
                    self.admin_credentials
                        .get_default_administrator()?
                        .passphrase
                        .clone(),
                    nethsm::Utc::now(),
                )?;
            }
            SystemState::Locked => {
                info!(
                    "Locked NetHSM backend detected at {}",
                    self.nethsm.get_url()
                );

                self.nethsm.unlock(Passphrase::new(
                    self.admin_credentials.get_unlock_passphrase().into(),
                ))?;
            }
            SystemState::Operational => {
                info!(
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
