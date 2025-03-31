//! State handling for

use log::debug;
use nethsm::{
    CryptographicKeyContext,
    KeyId,
    KeyMechanism,
    KeyType,
    NamespaceId,
    NetHsm,
    UserId,
    UserRole,
};
use nethsm_config::{FilterUserKeys, HermeticParallelConfig};
use pgp::{Deserializable, SignedPublicKey};

use crate::{AdminCredentials, NetHsmBackendError};

/// Retrieves the state for all users.
pub fn get_user_states(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<Vec<UserState>, crate::Error> {
    // Use the default administrator
    nethsm.use_credentials(&admin_credentials.get_default_administrator()?.name)?;

    let mut users = Vec::new();
    for user_id in nethsm.get_users()? {
        let user_data = nethsm.get_user(&user_id)?;
        let tags = nethsm.get_user_tags(&user_id)?;
        users.push(UserState {
            name: user_id,
            role: user_data.role.into(),
            tags,
        });
    }

    Ok(users)
}

fn get_key_state_from_certificate(
    nethsm: &NetHsm,
    key_id: &KeyId,
) -> Option<CryptographicKeyContext> {
    match nethsm.get_key_certificate(key_id) {
        Ok(key_cert) => {
            let public_key = match SignedPublicKey::from_reader_single(key_cert.as_slice()) {
                Ok((public_key, _armor_header)) => public_key,
                Err(error) => {
                    debug!(
                        "Unable to create public key from certificate of key {key_id}:\n{error}"
                    );
                    return None;
                }
            };

            match TryInto::<CryptographicKeyContext>::try_into(public_key) {
                Ok(key_context) => Some(key_context),
                Err(error) => {
                    debug!("Unable to convert certificate of {key_id} to key context:\n{error}");
                    None
                }
            }
        }
        Err(error) => {
            debug!("Unable to retrieve certificate for key {key_id}:\n{error}");
            None
        }
    }
}

/// Retrieves the state for all keys.
pub fn get_key_states(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<Vec<KeyState>, crate::Error> {
    // Use the default administrator
    nethsm.use_credentials(&admin_credentials.get_default_administrator()?.name)?;

    let mut keys = Vec::new();
    // Get the state of system-wide keys.
    for key_id in nethsm.get_keys(None)? {
        let key = nethsm.get_key(&key_id)?;
        let key_context = get_key_state_from_certificate(nethsm, &key_id);

        keys.push(KeyState {
            name: key_id,
            namespace: None,
            tags: key.restrictions.tags.unwrap_or_default(),
            key_type: key.r#type.into(),
            mechanisms: key.mechanisms.iter().map(KeyMechanism::from).collect(),
            key_context,
        });
    }
    // Get the state of namespaced keys.
    for full_credentials in admin_credentials.get_namespace_administrators() {
        nethsm.use_credentials(&full_credentials.name)?;
        for key_id in nethsm.get_keys(None)? {
            let key = nethsm.get_key(&key_id)?;
            let key_context = get_key_state_from_certificate(nethsm, &key_id);

            keys.push(KeyState {
                name: key_id,
                namespace: None,
                tags: key.restrictions.tags.unwrap_or_default(),
                key_type: key.r#type.into(),
                mechanisms: key.mechanisms.iter().map(KeyMechanism::from).collect(),
                key_context,
            });
        }
    }

    // Use the default administrator
    nethsm.use_credentials(&admin_credentials.get_default_administrator()?.name)?;

    Ok(keys)
}

/// The state of a user in the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserState {
    /// The name of the user in the backend.
    pub name: UserId,
    /// The role of the user in the backend.
    pub role: UserRole,
    /// The tags assigned to the user in the backend.
    pub tags: Vec<String>,
}

/// The state of a key in the backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyState {
    /// The name of the key in the backend.
    pub name: KeyId,
    /// The optional namespace the key is used in.
    pub namespace: Option<NamespaceId>,
    /// The tags assigned to the key in the backend.
    pub tags: Vec<String>,
    /// The key type of the key.
    pub key_type: KeyType,
    /// The mechanisms supported by the key.
    pub mechanisms: Vec<KeyMechanism>,
    /// The context in which the key is used.
    pub key_context: Option<CryptographicKeyContext>,
}

/// The state of a [`NetHsm`] backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetHsmState {
    /// The state of all users on the backend.
    pub users: Vec<UserState>,
    /// The state of all keys on the backend.
    pub keys: Vec<KeyState>,
}

impl NetHsmState {
    /// Creates a diff between this and another [`NetHsmState`].
    ///
    /// Compares all components of each [`NetHsmState`].
    ///
    /// # Errors
    ///
    /// Returns an error with one or more messages, that provide information on the discrepancy
    /// between `self` and `other`.
    pub fn diff(&self, other: &NetHsmState) -> Result<(), Vec<crate::Error>> {
        let mut errors = Vec::new();
        // Compare users.
        for (self_user, other_user) in self.users.iter().zip(other.users.iter()) {
            if self_user != other_user {
                errors.push(
                    NetHsmBackendError::UserStateMismatch {
                        self_user: format!("{self_user:?}"),
                        other_user: format!("{other_user:?}"),
                    }
                    .into(),
                )
            }
        }
        // Compare keys.
        for (self_key, other_key) in self.keys.iter().zip(other.keys.iter()) {
            if self_key != other_key {
                errors.push(
                    NetHsmBackendError::KeyStateMismatch {
                        self_key: format!("{self_key:?}"),
                        other_key: format!("{other_key:?}"),
                    }
                    .into(),
                )
            }
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(())
    }
}

impl From<&HermeticParallelConfig> for NetHsmState {
    /// Creates a [`NetHsmState`] from [`HermeticParallelConfig`] reference.
    fn from(value: &HermeticParallelConfig) -> Self {
        let users: Vec<UserState> = value
            .iter_user_mappings()
            .filter_map(|mapping| {
                mapping
                    .get_nethsm_user_role_and_tag()
                    .map(|(name, role, tag)| UserState {
                        name,
                        role,
                        tags: vec![tag.to_string()],
                    })
            })
            .collect();
        let keys: Vec<KeyState> = value
            .iter_user_mappings()
            .flat_map(|mapping| {
                mapping
                    .get_nethsm_user_key_and_tag(FilterUserKeys::All)
                    .iter()
                    .map(|(user_id, key_setup, tag)| KeyState {
                        name: key_setup.get_key_id(),
                        namespace: user_id.namespace().cloned(),
                        tags: vec![tag.to_string()],
                        key_type: key_setup.get_key_type(),
                        mechanisms: key_setup.get_key_mechanisms(),
                        key_context: Some(key_setup.get_key_context()),
                    })
                    .collect::<Vec<KeyState>>()
            })
            .collect();

        Self { users, keys }
    }
}
