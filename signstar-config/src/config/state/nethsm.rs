//! State representation of Signstar configuration items for a NetHSM backend.

use std::any::Any;
use std::fmt::Display;

use nethsm::{KeyId, NamespaceId, UserId, UserRole};
use signstar_crypto::key::{CryptographicKeyContext, KeyMechanism, KeyType};

use crate::{
    config::state::KeyCertificateState,
    state::{StateComparisonReport, StateHandling, StateType},
};

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
        write!(f, "{} (role: {}", self.name, self.role)?;
        if !self.tags.is_empty() {
            write!(f, "; tags: {}", self.tags.join(", "))?;
        }
        write!(f, ")")?;

        Ok(())
    }
}

/// A failure that can occur when comparing two sets of [`UserState`].
#[derive(Debug)]
pub enum UserStateComparisonFailure {
    /// A [`UserState`] is present in the left hand side but not in the right hand side.
    Unmatched {
        /// The type of state of the left hand side of the comparison.
        state_type: StateType,

        /// The type of state of the right hand side of the comparison.
        other_state_type: StateType,

        /// The user state is present in `state_type`, but not in `other_state_type`.
        user_state: UserState,
    },

    /// One [`UserState`] does not match another.
    Mismatch {
        /// The user state of the left hand side of the comparison.
        user: UserState,

        /// The type of state of the left hand side of the comparison.
        state_type: StateType,

        /// The user state of the right hand side of the comparison.
        other_user: UserState,

        /// The type of state of the right hand side of the comparison.
        other_state_type: StateType,
    },
}

impl Display for UserStateComparisonFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmatched {
                user_state,
                state_type,
                other_state_type,
            } => {
                writeln!(
                    f,
                    "User state present in {state_type}, but not in {other_state_type}: {user_state}"
                )?;
            }
            Self::Mismatch {
                user,
                state_type,
                other_user,
                other_state_type,
            } => {
                writeln!(
                    f,
                    "Differing user state between {state_type} (A) and {other_state_type} (B):"
                )?;
                writeln!(f, "A: {user}")?;
                writeln!(f, "B: {other_user}")?;
            }
        }
        Ok(())
    }
}

/// A set of [`UserState`].
#[derive(Debug)]
pub struct UserStates<'a> {
    /// The type of state the users are used in.
    pub state_type: StateType,
    /// The user states.
    pub users: &'a [UserState],
}

impl<'a> UserStates<'a> {
    /// Compares this [`UserStates`] with another.
    pub fn compare(&self, other: &UserStates) -> Vec<UserStateComparisonFailure> {
        let mut failures = Vec::new();

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
                    failures.push(UserStateComparisonFailure::Mismatch {
                        user: self_user.clone(),
                        state_type: self.state_type,
                        other_user: other_user.clone(),
                        other_state_type: other.state_type,
                    });
                    continue;
                }
            }

            (unmatched_self_users, matched_other_users)
        };

        // If there are unmatched user states `self.users`, add a dedicated error for them.
        if !unmatched_self_users.is_empty() {
            for user_state in unmatched_self_users {
                failures.push(UserStateComparisonFailure::Unmatched {
                    state_type: self.state_type,
                    other_state_type: other.state_type,
                    user_state: user_state.clone(),
                });
            }
        }

        {
            // If there are unmatched user states for `other.users`, add a dedicated error for them.
            let mut unmatched_other_users = Vec::new();
            if matched_other_users.len() != other.users.len() {
                for other_user in other.users.iter() {
                    if !matched_other_users.contains(&other_user) {
                        unmatched_other_users.push(other_user);
                    };
                }
            }
            if !unmatched_other_users.is_empty() {
                for user_state in unmatched_other_users {
                    failures.push(UserStateComparisonFailure::Unmatched {
                        state_type: other.state_type,
                        other_state_type: self.state_type,
                        user_state: user_state.clone(),
                    });
                }
            }
        }

        failures
    }
}

/// A failure that can occur when comparing two sets of [`UserState`].
#[derive(Debug)]
pub enum KeyStateComparisonFailure {
    /// A [`KeyState`] is present in the left hand side but not in the right hand side.
    Unmatched {
        /// The type of state of the left hand side of the comparison.
        state_type: StateType,

        /// The type of state of the right hand side of the comparison.
        other_state_type: StateType,

        /// The key states that are present in `state_type`, but not in `other_state_type`.
        key_state: KeyState,
    },

    /// One [`KeyState`] does not match another.
    Mismatch {
        /// The key state of the left hand side of the comparison.
        key: KeyState,

        /// The type of state of the left hand side of the comparison.
        state_type: StateType,

        /// The key state of the right hand side of the comparison.
        other_key: KeyState,

        /// The type of state of the right hand side of the comparison.
        other_state_type: StateType,
    },
}

impl Display for KeyStateComparisonFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmatched {
                key_state,
                state_type,
                other_state_type,
            } => {
                writeln!(
                    f,
                    "Key state present in {state_type}, but not in {other_state_type}:\n{key_state}"
                )?;
            }
            Self::Mismatch {
                key,
                state_type,
                other_key,
                other_state_type,
            } => {
                writeln!(
                    f,
                    "Differing key state between {state_type} (A) and {other_state_type} (B):"
                )?;
                writeln!(f, "A: {key}")?;
                writeln!(f, "B: {other_key}")?;
            }
        }
        Ok(())
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
    pub key_cert_state: KeyCertificateState,
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

/// A set of [`KeyState`]s used in the same [`StateType`].
#[derive(Debug)]
pub struct KeyStates<'a> {
    /// The type of state the keys are used in.
    pub state_type: StateType,
    /// The key states.
    pub keys: &'a [KeyState],
}

impl<'a> KeyStates<'a> {
    /// Compares this [`UserStates`] with another.
    pub fn compare(&self, other: &KeyStates) -> Vec<KeyStateComparisonFailure> {
        let mut failures = Vec::new();

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

                    // Note: If `self_key.key_cert_state` or `other_key.key_cert_state` has a
                    // `CryptographicKeyContext::Raw`, it cannot have a `KeyCertificateState` other
                    // than `KeyCertificateState::Empty`, as "raw" keys do not have a certificate.
                    if (matches!(self_key.key_cert_state, KeyCertificateState::Empty)
                        && matches!(
                            other_key.key_cert_state,
                            KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
                        ))
                        || (matches!(
                            self_key.key_cert_state,
                            KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
                        ) && matches!(other_key.key_cert_state, KeyCertificateState::Empty))
                    {
                        continue;
                    }

                    if self_key != other_key {
                        failures.push(KeyStateComparisonFailure::Mismatch {
                            state_type: self.state_type,
                            key: self_key.clone(),
                            other_state_type: other.state_type,
                            other_key: other_key.clone(),
                        })
                    }
                }

                (unmatched_self_keys, matched_other_keys)
            };

        // If there are unmatched key states in `self.keys`, add a dedicated error for them.
        if !unmatched_self_keys.is_empty() {
            for key_state in unmatched_self_keys {
                failures.push(KeyStateComparisonFailure::Unmatched {
                    state_type: self.state_type,
                    other_state_type: other.state_type,
                    key_state: key_state.clone(),
                });
            }
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
                for key_state in unmatched_other_keys {
                    failures.push(KeyStateComparisonFailure::Unmatched {
                        state_type: other.state_type,
                        other_state_type: self.state_type,
                        key_state: key_state.clone(),
                    });
                }
            }
        }

        failures
    }
}

/// The state of configuration items for a NetHSM backend.
#[derive(Debug)]
pub struct SignstarConfigStateNetHsm {
    /// The user states.
    pub user_states: Vec<UserState>,
    /// The key states.
    pub key_states: Vec<KeyState>,
}

impl SignstarConfigStateNetHsm {
    /// The specific [`StateType`] of this state.
    const STATE_TYPE: StateType = StateType::SignstarConfigNetHsm;
}

impl StateHandling for SignstarConfigStateNetHsm {
    fn state_type(&self) -> StateType {
        Self::STATE_TYPE
    }

    fn compare(&self, other: &'static impl StateHandling) -> StateComparisonReport {
        if !self.is_comparable(other) {
            return StateComparisonReport::Incompatible;
        }

        match other.state_type() {
            StateType::SignstarConfigNetHsm => {
                let Some(other) = (&other as &dyn Any).downcast_ref::<SignstarConfigStateNetHsm>()
                else {
                    return StateComparisonReport::Incompatible;
                };
                let user_failures = UserStates {
                    state_type: self.state_type(),
                    users: &self.user_states,
                }
                .compare(&UserStates {
                    state_type: other.state_type(),
                    users: &other.user_states,
                });
                let key_failures = KeyStates {
                    state_type: self.state_type(),
                    keys: &self.key_states,
                }
                .compare(&KeyStates {
                    state_type: other.state_type(),
                    keys: &other.key_states,
                });

                let mut failures: Vec<String> = Vec::new();
                for user_failure in user_failures.iter() {
                    failures.push(user_failure.to_string());
                }
                for key_failure in key_failures.iter() {
                    failures.push(key_failure.to_string());
                }

                if !failures.is_empty() {
                    return StateComparisonReport::Failure(failures);
                }
            }
            _ => return StateComparisonReport::Incompatible,
        }

        StateComparisonReport::Success
    }
}
