//! State representation for [`NetHsm`] backends and Signstar configurations.
//!
//! Allows to create state representations of users ([`UserState`]) and keys ([`KeyState`] and
//! [`KeyCertificateState`]) for [`NetHsm`] backends and Signstar configurations ([`State`]).
//!
//! Each [`State`] may be compared against another which may lead to [`StateComparisonErrors`]
//! returning an error, that describes the discrepancies between the two.
//!
//! With the help of [`get_user_states`] and [`get_key_states`] the state of users and keys
//! (respectively) can be retrieved from a [`NetHsm`] and a set of [`AdminCredentials`].

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
use pgp::composed::{Deserializable, SignedPublicKey};
use strum::IntoStaticStr;

use super::Error;
use crate::{AdminCredentials, NetHsmBackendError};

/// An error that may occur when comparing two [`State`] structs.
#[derive(Debug, thiserror::Error)]
pub enum StateComparisonError {
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

    /// The key states in one state type can not be matched by those in another.
    #[error(
        "The following {state_type} key states are not present in {other_state_type}:\n{}",
        key_states.iter().map(|state| state.to_string()).collect::<Vec<String>>().join("\n"))]
    UnmatchedKeyStates {
        /// The type of state the unmatched key states belong to.
        state_type: StateType,

        /// The type of state in which the key states are not present.
        other_state_type: StateType,

        /// The key states that are present in `state_type` but not in `other_state_type`.
        key_states: Vec<KeyState>,
    },

    /// The user states in one state type can not be matched by those in another.
    #[error(
        "The following {state_type} user states are not present in {other_state_type}:\n{}",
        user_states.iter().map(|state| state.to_string()).collect::<Vec<String>>().join("\n"))]
    UnmatchedUserStates {
        /// The type of state the unmatched user states belong to.
        state_type: StateType,

        /// The type of state in which the user states are not present.
        other_state_type: StateType,

        /// The user states that are present in `state_type` but not in `other_state_type`.
        user_states: Vec<UserState>,
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
}

/// Zero or more errors that may occur when comparing two [`State`] structs.
#[derive(Debug, Default)]
pub struct StateComparisonErrors {
    errors: Vec<StateComparisonError>,
}

impl StateComparisonErrors {
    /// Creates a new [`StateComparisonErrors`].
    pub fn new() -> Self {
        Default::default()
    }

    /// Adds a [`StateComparisonError`] to `self`.
    pub fn add(&mut self, elem: StateComparisonError) {
        self.errors.push(elem)
    }

    /// Checks if errors have been appended and consumes `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if one or more errors have been appended.
    pub fn check(self) -> Result<(), crate::Error> {
        if !self.errors.is_empty() {
            return Err(NetHsmBackendError::CompareStates(self).into());
        }

        Ok(())
    }
}

impl Display for StateComparisonErrors {
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

/// Retrieves the state for all users on a [`NetHsm`] backend.
///
/// # Note
///
/// Assumes that the `admin_credentials` have already been added for the `nethsm`.
///
/// # Errors
///
/// Returns an error if
///
/// - using the credentials of the default *R-Administrator* fails,
/// - retrieving all user names of the NetHSM backend fails,
/// - retrieving information about a specific NetHSM user fails,
/// - or retrieving the tags of an *Operator* user fails.
pub fn get_user_states(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<Vec<UserState>, crate::Error> {
    // Use the default R-Administrator.
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

/// The state of a key certificate.
///
/// Key certificates carry information on the context in which a key is used.
/// They can be derived e.g. from NetHSM backends or Signstar configuration files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyCertificateState {
    /// A [`CryptographicKeyContext`] describing the context in which a certificate is used.
    KeyContext(CryptographicKeyContext),
    /// There is no key certificate.
    None {
        /// A message explaining why there is no key certificate.
        message: String,
    },
    /// The key certificate cannot be turned into a [`CryptographicKeyContext`].
    NotACryptographicKeyContext {
        /// A message explaining that and why the [`CryptographicKeyContext`] cannot be created.
        message: String,
    },
    /// The key certificate cannot be turned into a [`SignedPublicKey`] (an OpenPGP certificate).
    NotAnOpenPgpCertificate {
        /// A message explaining why the key certificate cannot be converted to a
        /// [`SignedPublicKey`].
        message: String,
    },
}

impl Display for KeyCertificateState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::KeyContext(context) => format!("{context:?}"),
                Self::None { message }
                | Self::NotACryptographicKeyContext { message }
                | Self::NotAnOpenPgpCertificate { message } => message.clone(),
            }
        )
    }
}

/// Retrieve the state of a key certificate.
///
/// Key certificates may be retrieved for system-wide keys or namespaced keys.
/// Returns a [`KeyCertificateState`], which may also encode reasons for why state cannot be
/// retrieved.
///
/// # Note
///
/// It is assumed that the current credentials for the `nethsm` provide access to the key
/// certificate of key `key_id`.
fn get_key_certificate_state(
    nethsm: &NetHsm,
    key_id: &KeyId,
    namespace: Option<&NamespaceId>,
) -> KeyCertificateState {
    // Provide a dedicated string for log messages in case a namespace is used.
    let namespace = if let Some(namespace) = namespace {
        format!(" in namespace \"{namespace}\"")
    } else {
        "".to_string()
    };

    match nethsm.get_key_certificate(key_id) {
        Ok(key_cert) => {
            let public_key = match SignedPublicKey::from_reader_single(key_cert.as_slice()) {
                Ok((public_key, _armor_header)) => public_key,
                Err(error) => {
                    let message = format!(
                        "Unable to create public key from certificate of key {key_id}{namespace}:\n{error}"
                    );
                    debug!("{message}");
                    return KeyCertificateState::NotAnOpenPgpCertificate { message };
                }
            };

            match TryInto::<CryptographicKeyContext>::try_into(public_key) {
                Ok(key_context) => KeyCertificateState::KeyContext(key_context),
                Err(error) => {
                    let message = format!(
                        "Unable to convert certificate of key \"{key_id}\"{namespace} to key context:\n{error}"
                    );
                    debug!("{message}");
                    // None
                    KeyCertificateState::NotACryptographicKeyContext { message }
                }
            }
        }
        Err(error) => {
            let message =
                format!("Unable to retrieve certificate for key \"{key_id}\"{namespace}:\n{error}");
            debug!("{message}");
            KeyCertificateState::None { message }
        }
    }
}

/// Retrieves the state for all keys on a [`NetHsm`] backend.
///
/// Collects each key, their [`KeyType`] and list of [`KeyMechanisms`][`KeyMechanism`].
/// Also attempts to derive a [`CryptographicKeyContext`] from the public key
///
/// # Note
///
/// Assumes that the `admin_credentials` have already been added for the `nethsm`.
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
pub fn get_key_states(
    nethsm: &NetHsm,
    admin_credentials: &AdminCredentials,
) -> Result<Vec<KeyState>, crate::Error> {
    // Use the default administrator
    let default_admin = &admin_credentials.get_default_administrator()?.name;
    nethsm.use_credentials(default_admin)?;

    let mut keys = Vec::new();
    // Get the state of system-wide keys.
    for key_id in nethsm.get_keys(None)? {
        let key = nethsm.get_key(&key_id)?;
        let key_context = get_key_certificate_state(nethsm, &key_id, None);

        keys.push(KeyState {
            name: key_id,
            namespace: None,
            tags: key.restrictions.tags.unwrap_or_default(),
            key_type: key.r#type.into(),
            mechanisms: key.mechanisms.iter().map(KeyMechanism::from).collect(),
            key_context,
        });
    }

    let mut seen_namespace = Vec::new();
    // Get the state of namespaced keys.
    for user_id in admin_credentials
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
        if seen_namespace.contains(namespace) {
            continue;
        }
        seen_namespace.push(namespace.clone());

        nethsm.use_credentials(&user_id)?;
        for key_id in nethsm.get_keys(None)? {
            let key = nethsm.get_key(&key_id)?;
            let key_context = get_key_certificate_state(nethsm, &key_id, Some(namespace));

            keys.push(KeyState {
                name: key_id,
                namespace: Some(namespace.clone()),
                tags: key.restrictions.tags.unwrap_or_default(),
                key_type: key.r#type.into(),
                mechanisms: key.mechanisms.iter().map(KeyMechanism::from).collect(),
                key_context,
            });
        }
    }

    // Always use the default *R-Administrator* again.
    nethsm.use_credentials(default_admin)?;

    Ok(keys)
}

/// The state of a user.
///
/// State may be derived e.g. from a [`NetHsm`] backend or a Signstar configuration file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserState {
    /// The name of the user.
    pub name: UserId,
    /// The role of the user.
    pub role: UserRole,
    /// The zero or more tags assigned to the user.
    pub tags: Vec<String>,
}

impl Display for UserState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}) {:?}", self.name, self.role, self.tags)
    }
}

/// The state of a key.
///
/// State may be derived e.g. from a [`NetHsm`] backend or a Signstar configuration file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyState {
    /// The name of the key.
    pub name: KeyId,
    /// The optional namespace the key is used in.
    pub namespace: Option<NamespaceId>,
    /// The zero or more tags assigned to the key.
    pub tags: Vec<String>,
    /// The key type of the key.
    pub key_type: KeyType,
    /// The mechanisms supported by the key.
    pub mechanisms: Vec<KeyMechanism>,
    /// The context in which the key is used.
    pub key_context: KeyCertificateState,
}

impl Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(namespace) = self.namespace.as_ref() {
            write!(f, " in namespace {namespace}")?;
        }
        write!(f, " with tags {:?}", self.tags)?;
        write!(f, " {},", self.key_type)?;
        write!(f, " mechanisms {:?},", self.mechanisms)?;
        write!(f, " {}", self.key_context)?;

        Ok(())
    }
}

/// Indicator for [`State`] to distinguish what its data belongs to.
#[derive(Clone, Copy, Debug, strum::Display, Eq, IntoStaticStr, PartialEq)]
pub enum StateType {
    /// A [`NetHsm`] backend.
    NetHsm,
    /// A Signstar configuration file.
    SignstarConfig,
}

/// A wrapper around a [`StateType`] and a [`UserState`].
///
/// Describes the state of a user for a given type of state (e.g. on a NetHSM backend or in a
/// Signstar configuration file).
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
///
/// Describes the state of a key for a given type of state (e.g. on a NetHSM backend or in a
/// Signstar configuration file).
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

/// The state of a users and keys for a given type of state.
///
/// Tracks a list of [`UserState`]s and a list of [`KeyState`]s for a type of state ([`StateType`]).
#[derive(Clone, Debug)]
pub struct State {
    /// The indicator for what the data belongs to.
    pub state_type: StateType,
    /// The state of all users on the backend.
    pub users: Vec<UserState>,
    /// The state of all keys on the backend.
    pub keys: Vec<KeyState>,
}

impl State {
    /// Compares `self` with another [`State`].
    ///
    /// Compares all components of each [`State`] and returns without error if all components
    /// match.
    ///
    /// # Errors
    ///
    /// Returns an error if one or more components of `self` and `other` do not match.
    pub fn compare(&self, other: &State) -> Result<(), crate::Error> {
        debug!(
            "Create state diff of {} ({} users, {} keys) and {} ({} users, {} keys)",
            self.state_type,
            self.users.len(),
            self.keys.len(),
            other.state_type,
            other.users.len(),
            other.keys.len()
        );
        let mut errors = StateComparisonErrors::new();

        // Create a list of all unmatched user states in `self.users` and the matched ones in
        // `other.users`.
        let (unmatched_self_users, matched_other_users) = {
            let mut unmatched_self_users = Vec::new();
            let mut matched_other_users = Vec::new();

            // Get all user states in `self.users` that are also in `other.users` and compare them.
            // Create a `StateComparisonError::UserStateMismatch` for all mismatching user states.
            for self_user in self.users.iter() {
                let Some(other_user) = other.users.iter().find(|user| user.name == self_user.name)
                else {
                    unmatched_self_users.push(self_user);
                    continue;
                };

                matched_other_users.push(other_user);
                if self_user != other_user {
                    errors.add(StateComparisonError::UserStateMismatch {
                        self_user: UserStateType {
                            state_type: self.state_type,
                            user_state: self_user.clone(),
                        },
                        other_user: UserStateType {
                            state_type: other.state_type,
                            user_state: other_user.clone(),
                        },
                    });
                    continue;
                }
            }

            (unmatched_self_users, matched_other_users)
        };

        // If there are unmatched user states `self.users`, add a dedicated error for them.
        if !unmatched_self_users.is_empty() {
            errors.add(StateComparisonError::UnmatchedUserStates {
                state_type: self.state_type,
                other_state_type: other.state_type,
                user_states: unmatched_self_users.into_iter().cloned().collect(),
            });
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
                errors.add(StateComparisonError::UnmatchedUserStates {
                    state_type: other.state_type,
                    other_state_type: self.state_type,
                    user_states: unmatched_other_users.into_iter().cloned().collect(),
                });
            }
        }

        // Create a list of all unmatched key states in `self.keys` and the matched ones in
        // `other.keys`.
        let (unmatched_self_keys, matched_other_keys) =
            {
                let mut unmatched_self_keys = Vec::new();
                let mut matched_other_keys = Vec::new();

                // Get all key states in `self.keys` that are also in `other.keys` and compare them.
                // Create a `StateComparisonError::KeyStateMismatch` for all mismatching key states.
                for self_key in self.keys.iter() {
                    let Some(other_key) = other.keys.iter().find(|key| {
                        key.name == self_key.name && key.namespace == self_key.namespace
                    }) else {
                        unmatched_self_keys.push(self_key);
                        continue;
                    };

                    matched_other_keys.push(other_key);
                    if self_key != other_key {
                        errors.add(StateComparisonError::KeyStateMismatch {
                            self_key: KeyStateType {
                                state_type: self.state_type,
                                key_state: self_key.clone(),
                            },
                            other_key: KeyStateType {
                                state_type: other.state_type,
                                key_state: other_key.clone(),
                            },
                        })
                    }
                }

                (unmatched_self_keys, matched_other_keys)
            };

        // If there are unmatched key states in `self.keys`, add a dedicated error for them.
        if !unmatched_self_keys.is_empty() {
            errors.add(StateComparisonError::UnmatchedKeyStates {
                state_type: self.state_type,
                other_state_type: other.state_type,
                key_states: unmatched_self_keys.into_iter().cloned().collect(),
            });
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
                errors.add(StateComparisonError::UnmatchedKeyStates {
                    state_type: other.state_type,
                    other_state_type: self.state_type,
                    key_states: unmatched_other_keys.into_iter().cloned().collect(),
                });
            }
        }

        errors.check()?;

        Ok(())
    }
}

impl From<&HermeticParallelConfig> for State {
    /// Creates a [`State`] from [`HermeticParallelConfig`] reference.
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
                        key_context: KeyCertificateState::KeyContext(key_setup.get_key_context()),
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
