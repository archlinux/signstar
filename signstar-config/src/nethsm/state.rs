//! State handling for NetHSM backends.

use std::fmt::Display;

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
use strum::IntoStaticStr;

use crate::{AdminCredentials, NetHsmBackendError};

/// A wrapper around a [`StateType`] and a [`UserState`].
#[derive(Clone, Debug)]
pub struct UserStateType {
    /// The type of state the user state belongs to.
    pub state_type: StateType,
    /// The state of the user.
    pub user_state: UserState,
}

impl Display for UserStateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.state_type, self.user_state)
    }
}

/// A wrapper around a [`StateType`] and a [`KeyState`].
#[derive(Clone, Debug)]
pub struct KeyStateType {
    /// The type of state the user state belongs to.
    pub state_type: StateType,
    /// The state of the user.
    pub key_state: KeyState,
}

impl Display for KeyStateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.state_type, self.key_state)
    }
}

/// An error that may occur when diffing two [`NetHsmState`]s.
#[derive(Debug, thiserror::Error)]
pub enum DiffError {
    /// Two key states mismatch.
    #[error(
        "Key state mismatch detected between {} and {}:\n{}\n{}",
        self_key.state_type, other_key.state_type, self_key.key_state, other_key.key_state
    )]
    KeyStateMismatch {
        /// The state of the left hand side key.
        self_key: KeyStateType,

        /// The state of the right hand side key.
        other_key: KeyStateType,
    },

    /// Two user states mismatch.
    #[error(
        "User state mismatch detected between {} and {}:\n{}\n{}",
        self_user.state_type, other_user.state_type, self_user.user_state, other_user.user_state
    )]
    UserStateMismatch {
        /// The state of the left hand side user.
        self_user: UserStateType,

        /// The state of the right hand side user.
        other_user: UserStateType,
    },

    /// The user states in one state type can not be matched by those in another.
    #[error(
        "The following {state_type} user states are not present in {other_state_type}:\n{}",
        user_states.iter().fold(
            String::new(),
            |mut output, user| {
                output.push_str(&format!("{user}\n"));
                output
            }
        ))]
    UnmatchedUserStates {
        /// The type of state the unmatched user states belong to.
        state_type: StateType,

        /// The type of state in which the user states are not present.
        other_state_type: StateType,

        /// The user states that are present in `state_type` but not in `other_state_type`.
        user_states: Vec<UserState>,
    },

    /// The key states in one state type can not be matched by those in another.
    #[error(
        "The following {state_type} key states are not present in {other_state_type}:\n{}",
        key_states.iter().fold(
            String::new(),
            |mut output, user| {
                output.push_str(&format!("{user}\n"));
                output
            }
        ))]
    UnmatchedKeyStates {
        /// The type of state the unmatched key states belong to.
        state_type: StateType,

        /// The type of state in which the key states are not present.
        other_state_type: StateType,

        /// The key states that are present in `state_type` but not in `other_state_type`.
        key_states: Vec<KeyState>,
    },
}

/// One or more errors that occur when diffing two [`NetHsmState`]s.
#[derive(Debug, Default)]
pub struct DiffErrors {
    errors: Vec<DiffError>,
}

impl DiffErrors {
    /// Creates a new [`DiffErrors`].
    pub fn new() -> Self {
        Self { errors: Vec::new() }
    }

    /// Appends a list of [`DiffError`]s to `self.errors`.
    pub fn append(&mut self, other: &mut Vec<DiffError>) {
        self.errors.append(other)
    }

    /// Checks if errors have been appended and consumes `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if one or more errors have been appended.
    pub fn check(self) -> Result<(), crate::Error> {
        if !self.errors.is_empty() {
            return Err(NetHsmBackendError::DiffErrors(self).into());
        }

        Ok(())
    }
}

impl Display for DiffErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.errors.iter().fold(String::new(), |mut output, error| {
                output.push_str(&format!("{error}\n"));
                output
            })
        )
    }
}

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
        let tags = if user_data.role == UserRole::Operator.into() {
            nethsm.get_user_tags(&user_id)?
        } else {
            Vec::new()
        };
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
    /// The optional tags assigned to the user in the backend.
    pub tags: Vec<String>,
}

impl Display for UserState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}) {:?}", self.name, self.role, self.tags)
    }
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

impl Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{} with tags {:?} {}, mechanisms {:?}, {}",
            self.name,
            if let Some(namespace) = self.namespace.as_ref() {
                format!(" in namespace {namespace}")
            } else {
                "".to_string()
            },
            self.tags,
            self.key_type,
            self.mechanisms,
            if let Some(key_context) = self.key_context.as_ref() {
                format!("{key_context:?}")
            } else {
                "".to_string()
            }
        )
    }
}

/// Indicator for [`NetHsmState`] to differentiate what the data belongs to.
#[derive(Clone, Copy, Debug, strum::Display, PartialEq, Eq, IntoStaticStr)]
pub enum StateType {
    /// A [`NetHsm`] backend.
    NetHsm,
    /// A Signstar configuration file.
    SignstarConfig,
}

/// The state of a [`NetHsm`] backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetHsmState {
    /// The indicator for what the data belongs to.
    pub state_type: StateType,
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
    pub fn diff(&self, other: &NetHsmState) -> Result<(), crate::Error> {
        debug!(
            "Diffing state of {} ({} users, {} keys) and {} ({} users, {} keys)",
            self.state_type,
            self.users.len(),
            self.keys.len(),
            other.state_type,
            other.users.len(),
            other.keys.len()
        );
        let mut errors = DiffErrors::new();

        // Create a list of all unmatched user states in `self.users` and the matched ones in
        // `other.users`.
        let (unmatched_self_users, matched_other_users) = {
            let mut unmatched_self_users = Vec::new();
            let mut matched_other_users = Vec::new();

            // Get all user states in `self.users` that are also in `other.users` and compare them.
            // Create a `DiffError::UserStateMismatch` for all mismatching user states.
            for self_user in self.users.iter() {
                let Some(other_user) = other.users.iter().find(|user| user.name == self_user.name)
                else {
                    unmatched_self_users.push(self_user);
                    continue;
                };

                matched_other_users.push(other_user);
                if self_user != other_user {
                    errors.append(&mut vec![DiffError::UserStateMismatch {
                        self_user: UserStateType {
                            state_type: self.state_type,
                            user_state: self_user.clone(),
                        },
                        other_user: UserStateType {
                            state_type: other.state_type,
                            user_state: other_user.clone(),
                        },
                    }]);
                    continue;
                }
            }

            (unmatched_self_users, matched_other_users)
        };

        // If there are unmatched user states `self.users`, add a dedicated error for them.
        if !unmatched_self_users.is_empty() {
            errors.append(&mut vec![DiffError::UnmatchedUserStates {
                state_type: self.state_type,
                other_state_type: other.state_type,
                user_states: unmatched_self_users.into_iter().cloned().collect(),
            }]);
        }

        {
            // If there are unmatched user states for `other.users`, add a dedicated error for them.
            let mut unmatched_other_users = Vec::new();
            if matched_other_users.len() != other.users.len() {
                for other_user in other.users.iter() {
                    if !matched_other_users.contains(&other_user) {
                        unmatched_other_users.push(other_user);
                        continue;
                    };
                }
            }
            if !unmatched_other_users.is_empty() {
                errors.append(&mut vec![DiffError::UnmatchedUserStates {
                    state_type: other.state_type,
                    other_state_type: self.state_type,
                    user_states: unmatched_other_users.into_iter().cloned().collect(),
                }]);
            }
        }

        // Create a list of all unmatched key states in `self.keys` and the matched ones in
        // `other.keys`.
        let (unmatched_self_keys, matched_other_keys) =
            {
                let mut unmatched_self_keys = Vec::new();
                let mut matched_other_keys = Vec::new();

                // Get all key states in `self.keys` that are also in `other.keys` and compare them.
                // Create a `DiffError::KeyStateMismatch` for all mismatching key states.
                for self_key in self.keys.iter() {
                    let Some(other_key) = other.keys.iter().find(|key| {
                        key.name == self_key.name && key.namespace == self_key.namespace
                    }) else {
                        unmatched_self_keys.push(self_key);
                        continue;
                    };

                    matched_other_keys.push(other_key);
                    if self_key != other_key {
                        errors.append(&mut vec![DiffError::KeyStateMismatch {
                            self_key: KeyStateType {
                                state_type: self.state_type,
                                key_state: self_key.clone(),
                            },
                            other_key: KeyStateType {
                                state_type: other.state_type,
                                key_state: other_key.clone(),
                            },
                        }])
                    }
                }

                (unmatched_self_keys, matched_other_keys)
            };

        // If there are unmatched key states `self.keys`, add a dedicated error for them.
        if !unmatched_self_keys.is_empty() {
            errors.append(&mut vec![DiffError::UnmatchedKeyStates {
                state_type: self.state_type,
                other_state_type: other.state_type,
                key_states: unmatched_self_keys.into_iter().cloned().collect(),
            }]);
        }

        {
            // If there are unmatched key states in `other.keys`, add a dedicated error for them.
            let mut unmatched_other_keys = Vec::new();
            if matched_other_keys.len() != other.keys.len() {
                for other_key in other.keys.iter() {
                    if !matched_other_keys.contains(&other_key) {
                        unmatched_other_keys.push(other_key);
                        continue;
                    };
                }
            }
            if !unmatched_other_keys.is_empty() {
                errors.append(&mut vec![DiffError::UnmatchedKeyStates {
                    state_type: other.state_type,
                    other_state_type: self.state_type,
                    key_states: unmatched_other_keys.into_iter().cloned().collect(),
                }]);
            }
        }

        errors.check()?;

        Ok(())
    }
}

impl From<&HermeticParallelConfig> for NetHsmState {
    /// Creates a [`NetHsmState`] from [`HermeticParallelConfig`] reference.
    fn from(value: &HermeticParallelConfig) -> Self {
        let users: Vec<UserState> = value
            .iter_user_mappings()
            .flat_map(|mapping| {
                mapping
                    .get_nethsm_user_role_and_tags()
                    .iter()
                    .map(|(name, role, tags)| UserState {
                        name: name.clone(),
                        role: *role,
                        tags: tags.clone(),
                    })
                    .collect::<Vec<UserState>>()
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

        Self {
            state_type: StateType::SignstarConfig,
            users,
            keys,
        }
    }
}
