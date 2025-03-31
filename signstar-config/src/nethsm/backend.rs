//! Backend handling.

use std::{collections::HashMap, str::FromStr};

use log::{debug, info};
use nethsm::{
    Connection,
    CryptographicKeyContext,
    FullCredentials,
    InfoData,
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
use crate::{AdminCredentials, NetHsmState};

/// Adds all users in the role of a system-wide [`UserRole::Administrator`] to a [`NetHsm`].
fn add_system_wide_admins(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<(), crate::Error> {
    debug!("Setting up system-wide administrators.");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    for user in admin_credentials.get_administrators() {
        // skip the default "admin" as it exists after provisioning
        if user.name.to_string() == *"admin" {
            continue;
        }

        // only add if user doesn't exist yet, else set passphrase
        if !available_users.contains(&user.name) {
            info!(
                "Adding system-wide user {} in role {} as user {default_admin}",
                user.name,
                UserRole::Administrator
            );
            nethsm.add_user(
                format!("System-wide Admin {}", user.name),
                UserRole::Administrator,
                user.passphrase.clone(),
                Some(user.name.clone()),
            )?;
        } else {
            info!(
                "Setting passphrase for system-wide user {} as user {default_admin}",
                user.name
            );
            nethsm.set_user_passphrase(user.name.clone(), user.passphrase.clone())?;
        }
    }
    Ok(())
}

/// Retrieves a list of all available administrators in a namespace.
fn get_available_namespace_admins(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    available_users: &[UserId],
    namespace: &NamespaceId,
) -> Result<Vec<UserId>, crate::Error> {
    let namespace_users = available_users
        .iter()
        .filter(|user| user.namespace() == Some(namespace))
        .cloned()
        .collect::<Vec<UserId>>();

    debug!("All namespace users: {namespace_users:?}");

    let mut namespace_admins = Vec::new();
    for namespace_user in namespace_users {
        let user_data = nethsm.get_user(&namespace_user)?;
        if (UserRole::from(user_data.role) == UserRole::Administrator)
            && admin_credentials
                .get_namespace_administrators()
                .iter()
                .any(|name| name.name == namespace_user)
        {
            namespace_admins.push(namespace_user);
        }
    }
    debug!("All namespace admins: {namespace_admins:?}");
    if namespace_admins.is_empty() {
        return Err(Error::NamespaceAdminMissing {
            namespace: namespace.clone(),
        }
        .into());
    }

    Ok(namespace_admins)
}

/// Adds all users in the role of a namespace [`UserRole::Administrator`] and their namespaces.
fn add_namespace_admins(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<(), crate::Error> {
    debug!("Setting up namespace administrators");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    let available_namespaces = nethsm.get_namespaces()?;

    for user in admin_credentials.get_namespace_administrators() {
        let Some(namespace) = user.name.namespace() else {
            return Err(Error::NamespaceAdminNoNamespace {
                user: user.name.clone(),
            }
            .into());
        };

        // only create if it doesn't exist yet
        if !available_users.contains(&user.name) {
            // if the namespace exists already we have to rely on another, existing namespace
            // administrator
            if available_namespaces.contains(namespace) {
                // get all available namespace admins
                let namespace_admins = get_available_namespace_admins(
                    nethsm,
                    admin_credentials,
                    &available_users,
                    namespace,
                )?;
                // select the first namespace admin
                let Some(admin) = namespace_admins.first() else {
                    return Err(Error::NamespaceAdminCreateNoNamespaceAdmin {
                        user: user.name.clone(),
                        namespace: namespace.clone(),
                    }
                    .into());
                };

                debug!("Using user {admin} for connection");
                nethsm.use_credentials(admin)?;
                info!(
                    "Adding user {} in role {} for namespace {namespace} as user {default_admin}",
                    user.name,
                    UserRole::Administrator
                );
                nethsm.add_user(
                    format!("Namespace Admin {}", user.name),
                    UserRole::Administrator,
                    user.passphrase.clone(),
                    Some(user.name.clone()),
                )?;
                // Use the system-wide administrator again
                debug!("Using user {default_admin} for connection");
                nethsm.use_credentials(default_admin)?;
            } else {
                info!(
                    "Adding user {} in role {} for namespace {namespace} as user {default_admin}",
                    user.name,
                    UserRole::Administrator
                );
                nethsm.add_user(
                    format!("Namespace Admin {}", user.name),
                    UserRole::Administrator,
                    user.passphrase.clone(),
                    Some(user.name.clone()),
                )?;
                info!("Adding namespace {namespace} as user {default_admin}");
                nethsm.add_namespace(namespace)?;
            }
        } else {
            // get all available namespace admins
            let namespace_admins = get_available_namespace_admins(
                nethsm,
                admin_credentials,
                &available_users,
                namespace,
            )?;
            // select the first namespace admin
            let Some(admin) = namespace_admins.first() else {
                return Err(Error::NamespaceAdminCreateNoNamespaceAdmin {
                    user: user.name.clone(),
                    namespace: namespace.clone(),
                }
                .into());
            };
            debug!("Using user {admin} for connection");
            nethsm.use_credentials(admin)?;

            // only set passphrase
            info!(
                "Setting passphrase for user {} in namespace {namespace} as user {admin}",
                user.name
            );
            nethsm.set_user_passphrase(user.name.clone(), user.passphrase.clone())?;
            // Use the system-wide administrator again
            debug!("Using user {default_admin} for connection");
            nethsm.use_credentials(default_admin)?;
        }
    }

    Ok(())
}

/// Adds all system-wide non-administrative users.
fn add_non_administrative_users(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    debug!("Setting up system-wide non-administrative users");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    debug!("Available users: {available_users:?}");

    for mapping in users.iter() {
        // add all users of the mapping
        for (user, role) in mapping.get_nethsm_users_and_roles() {
            // continue to next user if it is not a non-administrative, system-wide user
            if user.is_namespaced() || role == UserRole::Administrator {
                continue;
            }

            let Some(creds) = user_credentials.iter().find(|creds| creds.name == user) else {
                return Err(Error::UserMissingPassphrase { user }.into());
            };

            if available_users.contains(&user) {
                info!("Setting passphrase for system-wide user {user} as user {default_admin}");
                nethsm.set_user_passphrase(user, creds.passphrase.clone())?;
            } else {
                info!("Adding system-wide user {user} in role {role} as user {default_admin}");
                nethsm.add_user(
                    format!("{role} user {user}"),
                    role,
                    creds.passphrase.clone(),
                    Some(user),
                )?;
            }
        }

        // add tags to users after adding them
        for (user, _key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            let available_tags = nethsm.get_user_tags(&user)?;
            if available_tags.len() == 1 && available_tags.contains(&tag) {
                continue;
            }

            for available_tag in available_tags {
                info!("Removing tag {tag} from system-wide user {user} as user {default_admin}");
                nethsm.delete_user_tag(&user, available_tag.as_str())?;
            }
            info!("Adding tag {tag} for system-wide user {user} as user {default_admin}");
            nethsm.add_user_tag(&user, tag.as_str())?;
        }
    }

    Ok(())
}

/// Adds all namespaced non-administrative users.
fn add_namespaced_non_administrative_users(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
    user_credentials: &[FullCredentials],
) -> Result<(), crate::Error> {
    debug!("Setting up namespaced non-administrative users");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    let available_namespaces = nethsm.get_namespaces()?;
    let available_namespace_admins = {
        let mut admins: HashMap<NamespaceId, Vec<UserId>> = HashMap::new();
        for namespace in available_namespaces.iter() {
            admins.insert(
                namespace.clone(),
                get_available_namespace_admins(
                    nethsm,
                    admin_credentials,
                    &available_users,
                    namespace,
                )?,
            );
        }

        admins
    };

    for mapping in users.iter() {
        for (user, role, tags) in mapping.get_nethsm_user_role_and_tags() {
            // we are only interested in non-administrative, namespaced users on the backend
            if !user.is_namespaced() || role == UserRole::Administrator {
                continue;
            }

            // extract the namespace of the user and ensure that the namespace exists already
            let Some(namespace) = user.namespace() else {
                return Err(Error::NamespaceUserNoNamespace { user: user.clone() }.into());
            };
            if !available_namespaces.contains(namespace) {
                return Err(Error::NamespaceMissing {
                    namespace: namespace.clone(),
                }
                .into());
            }

            // get a valid namespace admin
            let Some(admin) = available_namespace_admins
                .get(namespace)
                .ok_or(Error::NamespaceMissing {
                    namespace: namespace.clone(),
                })?
                .first()
            else {
                return Err(Error::NamespaceAdminCreateNoNamespaceAdmin {
                    user: user.clone(),
                    namespace: namespace.clone(),
                }
                .into());
            };
            debug!("Using user {admin} for connection");
            nethsm.use_credentials(admin)?;

            // get credentials for the specific user
            let Some(creds) = user_credentials.iter().find(|creds| creds.name == user) else {
                return Err(Error::UserMissingPassphrase { user }.into());
            };

            if available_users.contains(&user) {
                info!(
                    "Setting passphrase for user {user} in namespace {namespace} as user {admin}"
                );
                nethsm.set_user_passphrase(user.clone(), creds.passphrase.clone())?;
            } else {
                info!("Adding user {user} in role {role} to namespace {namespace} as user {admin}");
                nethsm.add_user(
                    format!("{role} user {user}"),
                    role,
                    creds.passphrase.clone(),
                    Some(user.clone()),
                )?;
            }

            let available_tags = nethsm.get_user_tags(&user)?;
            for available_tag in available_tags {
                info!(
                    "Removing tag {available_tag} from user {user} in namespace {namespace} as user {admin}"
                );
                nethsm.delete_user_tag(&user, available_tag.as_str())?;
            }
            for tag in tags.iter() {
                info!("Adding tag {tag} for user {user} in namespace {namespace} as user {admin}");
                nethsm.add_user_tag(&user, tag)?;
            }
        }
    }

    // switch back to the default system-wide admin user
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;

    Ok(())
}

/// Creates all system-wide keys and tags them.
fn add_system_wide_keys(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!("Setting up system-wide keys");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_keys = nethsm.get_keys(None)?;

    for mapping in users {
        for (_user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            let key_id = key_setup.get_key_id();
            if available_keys.contains(&key_setup.get_key_id()) {
                // adjust tag if needed
                let info = nethsm.get_key(&key_id)?;
                // if there are tags already, remove them
                if let Some(available_tags) = info.restrictions.tags {
                    // if the required tag is already set, continue to the next key/tag
                    if available_tags.len() == 1 && available_tags.contains(&tag) {
                        continue;
                    }
                    // remove any tag that the key has
                    for available_tag in available_tags {
                        nethsm.delete_key_tag(&key_id, available_tag.as_str())?;
                    }
                }
                // add the tag to the key
                info!("Adding tag {tag} for system-wide key {key_id} as user {default_admin}");
                nethsm.add_key_tag(&key_id, tag.as_str())?;
            } else {
                // add the key, including the required tag
                info!("Adding system-wide key {key_id} with tag {tag} as user {default_admin}");
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

    Ok(())
}

/// Creates all namespaced keys and tags them.
fn add_namespaced_keys(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!("Setting up namespaced keys");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;

    for mapping in users {
        for (user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespaced)
        {
            let key_id = key_setup.get_key_id();

            // extract the namespace from the user
            let Some(namespace) = user.namespace() else {
                return Err(Error::NamespaceUserNoNamespace { user }.into());
            };

            // select the first of all available namespace admins
            let available_admins = get_available_namespace_admins(
                nethsm,
                admin_credentials,
                &available_users,
                namespace,
            )?;
            let Some(admin) = available_admins.first() else {
                return Err(Error::NamespaceAdminMissing {
                    namespace: namespace.clone(),
                }
                .into());
            };
            debug!("Using user {admin} for connection");
            nethsm.use_credentials(admin)?;

            let available_keys = nethsm.get_keys(None)?;

            if available_keys.contains(&key_id) {
                // adjust tag if needed
                let info = nethsm.get_key(&key_id)?;
                // if there are tags already, remove them
                if let Some(available_tags) = info.restrictions.tags {
                    // if the required tag is already set, continue to the next key/tag
                    if available_tags.len() == 1 && available_tags.contains(&tag) {
                        continue;
                    }
                    // remove any tag that the key has
                    for available_tag in available_tags {
                        nethsm.delete_key_tag(&key_id, available_tag.as_str())?;
                    }
                }

                // add the tag to the key
                info!("Adding tag {tag} for key {key_id} in namespace {namespace} as user {admin}");
                nethsm.add_key_tag(&key_id, tag.as_str())?;
            } else {
                // add the key, including the required tag
                info!(
                    "Adding key {key_id} with tag {tag} in namespace {namespace} as user {admin}"
                );
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

    Ok(())
}

/// Adds OpenPGP certificates for system-wide keys that require it.
fn add_system_wide_openpgp_certificates(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!("Setting up system-wide OpenPGP certificates");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;
    let available_keys = nethsm.get_keys(None)?;

    for mapping in users {
        for (user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::SystemWide)
        {
            // continue to the next user/setup if the mapping is not used for signing
            if !matches!(mapping, UserMapping::SystemNetHsmOperatorSigning { .. }) {
                continue;
            }
            // continue to the next user/setup if the mapping is not used for OpenPGP signing
            if !matches!(
                key_setup.get_key_context(),
                CryptographicKeyContext::OpenPgp { .. }
            ) {
                continue;
            }

            // ensure the targeted user exists
            if !available_users.contains(&user) {
                return Err(Error::UserMissing { user_id: user }.into());
            }
            // ensure the required tag is assigned to the targeted user
            let user_tags = nethsm.get_user_tags(&user)?;
            if !user_tags.contains(&tag) {
                return Err(Error::UserMissingTag { user_id: user, tag }.into());
            }

            let key_id = key_setup.get_key_id();
            // ensure the targeted key exists
            if !available_keys.contains(&key_id) {
                return Err(Error::KeyMissing { key_id }.into());
            }
            // ensure the required tag is assigned to the targeted key
            let pubkey = nethsm.get_key(&key_id)?;
            if !pubkey
                .restrictions
                .tags
                .is_some_and(|tags| tags.contains(&tag))
            {
                return Err(Error::KeyMissingTag { key_id, tag }.into());
            }

            // if there is no certificate yet, create it
            if nethsm.get_key_certificate(&key_id).is_err() {
                // setup OpenPGP certificate
                if let CryptographicKeyContext::OpenPgp { user_ids, version } =
                    key_setup.get_key_context()
                {
                    let Some(user_id) = user_ids.first() else {
                        return Err(Error::OpenPgpUserIdMissing { key_id }.into());
                    };

                    // switch to the dedicated user with access to the key
                    info!(
                        "Creating OpenPGP certificate for system-wide key {key_id} as user {user}"
                    );
                    debug!("Using user {user} for connection");
                    nethsm.use_credentials(&user)?;
                    let data = nethsm.create_openpgp_cert(
                        &key_id,
                        OpenPgpKeyUsageFlags::default(),
                        user_id.clone(),
                        Utc::now(),
                        version,
                    )?;

                    // switch back to the default admin for the import
                    info!(
                        "Importing OpenPGP certificate for system-wide key {key_id} as user {default_admin}"
                    );
                    debug!("Using user {default_admin} for connection");
                    nethsm.use_credentials(default_admin)?;
                    nethsm.import_key_certificate(&key_id, data)?;
                }
            }
        }
    }

    Ok(())
}

/// Adds OpenPGP certificates for namespaced keys that require it.
fn add_namespaced_openpgp_certificates(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
    users: &[UserMapping],
) -> Result<(), crate::Error> {
    debug!("Setting up namespaced OpenPGP certificates");

    let default_admin = &admin_credentials.get_default_administrator()?.name;
    debug!("Using user {default_admin} for connection");
    nethsm.use_credentials(default_admin)?;
    let available_users = nethsm.get_users()?;

    for mapping in users {
        for (user, key_setup, tag) in
            mapping.get_nethsm_user_key_and_tag(FilterUserKeys::Namespaced)
        {
            // continue to the next user/setup if the mapping is not used for signing
            if !matches!(mapping, UserMapping::SystemNetHsmOperatorSigning { .. }) {
                continue;
            }
            // continue to the next user/setup if the mapping is not used for OpenPGP signing
            if !matches!(
                key_setup.get_key_context(),
                CryptographicKeyContext::OpenPgp { .. }
            ) {
                continue;
            }

            // extract the namespace from the user
            let Some(namespace) = user.namespace() else {
                return Err(Error::NamespaceUserNoNamespace { user }.into());
            };

            // select the first of all available namespace admins
            let available_admins = get_available_namespace_admins(
                nethsm,
                admin_credentials,
                &available_users,
                namespace,
            )?;
            let Some(admin) = available_admins.first() else {
                return Err(Error::NamespaceAdminMissing {
                    namespace: namespace.clone(),
                }
                .into());
            };
            debug!("Using user {admin} for connection");
            nethsm.use_credentials(admin)?;

            let available_keys = nethsm.get_keys(None)?;

            // ensure the targeted user exists
            if !available_users.contains(&user) {
                return Err(Error::NamespaceUserMissing {
                    user: user.clone(),
                    namespace: namespace.clone(),
                }
                .into());
            }
            // ensure the required tag is assigned to the targeted user
            let user_tags = nethsm.get_user_tags(&user)?;
            if !user_tags.contains(&tag) {
                return Err(Error::NamespaceUserMissingTag {
                    user: user.clone(),
                    namespace: namespace.clone(),
                    tag,
                }
                .into());
            }

            let key_id = key_setup.get_key_id();

            // ensure the targeted key exists
            if !available_keys.contains(&key_id) {
                return Err(Error::NamespaceKeyMissing {
                    key_id,
                    namespace: namespace.clone(),
                }
                .into());
            }
            // ensure the required tag is assigned to the targeted key
            let pubkey = nethsm.get_key(&key_id)?;
            if !pubkey
                .restrictions
                .tags
                .is_some_and(|tags| tags.contains(&tag))
            {
                return Err(Error::NamespaceKeyMissingTag {
                    key_id,
                    namespace: namespace.clone(),
                    tag,
                }
                .into());
            }

            // if there is no certificate yet, create it
            if nethsm.get_key_certificate(&key_id).is_err() {
                // setup OpenPGP certificate
                if let CryptographicKeyContext::OpenPgp { user_ids, version } =
                    key_setup.get_key_context()
                {
                    let Some(user_id) = user_ids.first() else {
                        return Err(Error::NamespaceOpenPgpUserIdMissing {
                            key_id,
                            namespace: namespace.clone(),
                        }
                        .into());
                    };

                    // switch to the dedicated user with access to the key
                    info!(
                        "Creating OpenPGP certificate for system-wide key {key_id} as user {user}"
                    );
                    debug!("Using user {user} for connection");
                    nethsm.use_credentials(&user)?;
                    let data = nethsm.create_openpgp_cert(
                        &key_id,
                        OpenPgpKeyUsageFlags::default(),
                        user_id.clone(),
                        Utc::now(),
                        version,
                    )?;

                    // switch back to the namespace admin for the import
                    info!(
                        "Importing OpenPGP certificate for key {key_id} in namespace {namespace} as user {admin}"
                    );
                    debug!("Using user {admin} for connection");
                    nethsm.use_credentials(admin)?;
                    nethsm.import_key_certificate(&key_id, data)?;
                }
            }
        }
    }

    Ok(())
}

/// Provisions the backend.
fn provision(nethsm: &NetHsm, admin_credentials: &AdminCredentials) -> Result<(), crate::Error> {
    debug!("Provisioning NetHSM: {nethsm:?}");
    nethsm.provision(
        Passphrase::from_str(admin_credentials.get_unlock_passphrase())
            .map_err(Error::NetHsmUser)?,
        admin_credentials
            .get_default_administrator()?
            .passphrase
            .clone(),
        nethsm::Utc::now(),
    )?;

    Ok(())
}

/// Creates a new [`NetHsm`].
fn nethsm_with_admin_users(
    connection: Connection,
    admin_credentials: &AdminCredentials,
) -> Result<NetHsm, crate::Error> {
    // Create a NetHSM connection.
    let nethsm = NetHsm::new(connection, None, None, None).map_err(crate::Error::NetHsm)?;
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

    Ok(nethsm)
}

/// A NetHSM backend that provides basic access to its data.
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
#[derive(Debug)]
pub struct FullNetHsmBackend<'a, 'b> {
    nethsm: NetHsm,
    admin_credentials: &'a AdminCredentials,
    signstar_config: &'b HermeticParallelConfig,
}

impl<'a, 'b> FullNetHsmBackend<'a, 'b> {
    /// Creates a new [`NetHsmBackend`].
    pub fn new(
        connection: Connection,
        admin_credentials: &'a AdminCredentials,
        signstar_config: &'b HermeticParallelConfig,
    ) -> Result<Self, crate::Error> {
        Ok(Self {
            nethsm: nethsm_with_admin_users(connection, admin_credentials)?,
            admin_credentials,
            signstar_config,
        })
    }

    /// Creates a new [`NetHsmState`] for the backend.
    pub fn state(&self) -> Result<NetHsmState, crate::Error> {
        debug!("Create state for NetHSM connection {:?}", self.nethsm);
        // Ensure that the iterations match.
        if self.admin_credentials.get_iteration() != self.signstar_config.get_iteration() {
            return Err(Error::IterationMismatch {
                admin_creds: self.admin_credentials.get_iteration(),
                signstar_config: self.signstar_config.get_iteration(),
            }
            .into());
        }

        match self.nethsm.state()? {
            SystemState::Unprovisioned => {
                debug!("Unprovisioned backend detected");
            }
            // If the backend is locked, unlock it.
            SystemState::Locked => {
                debug!("Locked backend detected");
                self.nethsm.unlock(Passphrase::new(
                    self.admin_credentials.get_unlock_passphrase().into(),
                ))?;
            }
            SystemState::Operational => {
                debug!("Operational backend detected");
            }
        }

        let users = get_user_states(&self.nethsm, self.admin_credentials)?;
        let keys = get_key_states(&self.nethsm, self.admin_credentials)?;

        Ok(NetHsmState {
            state_type: StateType::NetHsm,
            users,
            keys,
        })
    }

    /// Syncs the state of NetHSM backend and returns it.
    ///
    /// TODO: deal with previous vs. new state based on iteration information
    pub fn sync(&self, user_credentials: &[FullCredentials]) -> Result<(), crate::Error> {
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
                debug!("Unprovisioned backend detected");
                provision(&self.nethsm, self.admin_credentials)?;
            }
            // If the backend is locked, unlock it and sync
            SystemState::Locked => {
                debug!("Locked backend detected");
                self.nethsm.unlock(Passphrase::new(
                    self.admin_credentials.get_unlock_passphrase().into(),
                ))?;
            }
            SystemState::Operational => {
                debug!("Operational backend detected");
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
