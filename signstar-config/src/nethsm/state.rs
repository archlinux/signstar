//! State representation for a [`NetHsmBackend`].
//!
//! Allows to create state representations of users ([`UserState`]) and keys ([`KeyState`] and
//! [`KeyCertificateState`]) for [`NetHsm`] backends using the [`NetHsmState`] struct.
//! It implements the [`StateHandling`] trait which allows comparison with
//! other implementations.

use std::{any::Any, fmt::Display};

use log::{debug, trace, warn};
#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{KeyId, NamespaceId, SystemState, UserId, UserRole};
use signstar_crypto::key::{CryptographicKeyContext, KeyMechanism, KeyType};

#[cfg(doc)]
use crate::{config::Config, nethsm::NetHsmAdminCredentials};
use crate::{
    config::KeyCertificateState,
    nethsm::{NetHsmConfig, NetHsmUserKeysFilter, backend::NetHsmBackend},
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
                    "User state present in {state_type}, but not in {other_state_type}:\n{user_state}"
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
struct UserStates<'a> {
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

impl<'a> Display for UserStates<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} users:", self.state_type)?;
        for key in self.users.iter() {
            writeln!(f, "{key}")?;
        }

        Ok(())
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
struct KeyStates<'a> {
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

impl<'a> Display for KeyStates<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} keys:", self.state_type)?;
        for key in self.keys.iter() {
            writeln!(f, "{key}")?;
        }

        Ok(())
    }
}

/// The state of configuration items in a [`NetHsmConfig`].
///
/// [`NetHsmConfig`] objects are used in [`Config`] objects.
#[derive(Debug, Eq, PartialEq)]
pub struct NetHsmConfigState {
    /// The user states.
    pub(crate) user_states: Vec<UserState>,
    /// The key states.
    pub(crate) key_states: Vec<KeyState>,
}

impl NetHsmConfigState {
    /// The specific [`StateType`] of this state.
    const STATE_TYPE: StateType = StateType::SignstarConfigNetHsm;
}

impl StateHandling for NetHsmConfigState {
    fn state_type(&self) -> StateType {
        Self::STATE_TYPE
    }

    fn compare(&self, other: &dyn StateHandling) -> StateComparisonReport {
        if !self.is_comparable(other) {
            trace!(
                "{} is not compatible with {}",
                self.state_type(),
                other.state_type()
            );
            return StateComparisonReport::Incompatible {
                self_state: self.state_type(),
                other_state: other.state_type(),
            };
        }

        let (user_failures, key_failures) = {
            let (self_user_states, other_user_states, self_key_states, other_key_states) =
                match other.state_type() {
                    StateType::SignstarConfigNetHsm => {
                        let Some(other) = (other as &dyn Any).downcast_ref::<NetHsmConfigState>()
                        else {
                            warn!("Unexpectedly unable to find a {}", other.state_type());
                            return StateComparisonReport::Incompatible {
                                self_state: self.state_type(),
                                other_state: other.state_type(),
                            };
                        };
                        (
                            UserStates {
                                state_type: self.state_type(),
                                users: &self.user_states,
                            },
                            UserStates {
                                state_type: other.state_type(),
                                users: &other.user_states,
                            },
                            KeyStates {
                                state_type: self.state_type(),
                                keys: &self.key_states,
                            },
                            KeyStates {
                                state_type: other.state_type(),
                                keys: &other.key_states,
                            },
                        )
                    }
                    StateType::NetHsm => {
                        let Some(other) = (other as &dyn Any).downcast_ref::<NetHsmState>() else {
                            warn!("Unexpectedly unable to find a {}", other.state_type());
                            return StateComparisonReport::Incompatible {
                                self_state: self.state_type(),
                                other_state: other.state_type(),
                            };
                        };
                        (
                            UserStates {
                                state_type: self.state_type(),
                                users: &self.user_states,
                            },
                            UserStates {
                                state_type: other.state_type(),
                                users: &other.user_states,
                            },
                            KeyStates {
                                state_type: self.state_type(),
                                keys: &self.key_states,
                            },
                            KeyStates {
                                state_type: other.state_type(),
                                keys: &other.key_states,
                            },
                        )
                    }
                    StateType::SignstarConfigYubiHsm2 | StateType::YubiHsm2 => {
                        return StateComparisonReport::Incompatible {
                            self_state: self.state_type(),
                            other_state: other.state_type(),
                        };
                    }
                };

            let user_failures = self_user_states.compare(&other_user_states);
            let key_failures = self_key_states.compare(&other_key_states);

            (user_failures, key_failures)
        };

        let failures = {
            let mut failures: Vec<String> = Vec::new();

            for user_failure in user_failures.iter() {
                failures.push(user_failure.to_string());
            }
            for key_failure in key_failures.iter() {
                failures.push(key_failure.to_string());
            }

            failures
        };

        if !failures.is_empty() {
            return StateComparisonReport::Failure(failures);
        }

        StateComparisonReport::Success
    }
}

impl From<&NetHsmConfig> for NetHsmConfigState {
    fn from(value: &NetHsmConfig) -> Self {
        let mut key_states: Vec<KeyState> = Vec::new();
        let mut user_states: Vec<UserState> = Vec::new();

        for mapping in value.mappings() {
            if let Some(user_key_data) =
                mapping.nethsm_config_user_key_data(NetHsmUserKeysFilter::All)
            {
                key_states.push(KeyState {
                    name: user_key_data.key_id.clone(),
                    namespace: user_key_data.user.namespace().cloned(),
                    tags: vec![user_key_data.tag.to_string()],
                    key_type: user_key_data.key_setup.key_type(),
                    mechanisms: user_key_data.key_setup.key_mechanisms().to_vec(),
                    key_cert_state: KeyCertificateState::KeyContext(
                        user_key_data.key_setup.key_context().clone(),
                    ),
                })
            }
            for user_data in mapping.nethsm_config_user_data() {
                user_states.push(UserState {
                    name: user_data.user.clone(),
                    role: user_data.role,
                    tags: user_data
                        .tag
                        .map(|tag| vec![tag.to_string()])
                        .unwrap_or_else(Vec::new),
                })
            }
        }

        NetHsmConfigState {
            user_states,
            key_states,
        }
    }
}

/// The state of a NetHSM backend.
///
/// Tracks a list of [`UserState`] and a list of [`KeyState`] data, which describes the overall
/// state of the backend.
#[derive(Debug)]
pub struct NetHsmState {
    /// The user states.
    pub(crate) user_states: Vec<UserState>,
    /// The key states.
    pub(crate) key_states: Vec<KeyState>,
}

impl NetHsmState {
    /// The specific [`StateType`] of this state.
    const STATE_TYPE: StateType = StateType::NetHsm;
}

impl StateHandling for NetHsmState {
    fn state_type(&self) -> StateType {
        Self::STATE_TYPE
    }

    fn compare(&self, other: &dyn StateHandling) -> StateComparisonReport {
        if !self.is_comparable(other) {
            trace!(
                "{} is not compatible with {}",
                self.state_type(),
                other.state_type()
            );
            return StateComparisonReport::Incompatible {
                self_state: self.state_type(),
                other_state: other.state_type(),
            };
        }

        let (user_failures, key_failures) = {
            let (self_user_states, other_user_states, self_key_states, other_key_states) =
                match other.state_type() {
                    StateType::SignstarConfigNetHsm => {
                        let Some(other) = (other as &dyn Any).downcast_ref::<NetHsmConfigState>()
                        else {
                            return StateComparisonReport::Incompatible {
                                self_state: self.state_type(),
                                other_state: other.state_type(),
                            };
                        };
                        (
                            UserStates {
                                state_type: self.state_type(),
                                users: &self.user_states,
                            },
                            UserStates {
                                state_type: other.state_type(),
                                users: &other.user_states,
                            },
                            KeyStates {
                                state_type: self.state_type(),
                                keys: &self.key_states,
                            },
                            KeyStates {
                                state_type: other.state_type(),
                                keys: &other.key_states,
                            },
                        )
                    }
                    StateType::NetHsm => {
                        let Some(other) = (other as &dyn Any).downcast_ref::<NetHsmState>() else {
                            return StateComparisonReport::Incompatible {
                                self_state: self.state_type(),
                                other_state: other.state_type(),
                            };
                        };
                        (
                            UserStates {
                                state_type: self.state_type(),
                                users: &self.user_states,
                            },
                            UserStates {
                                state_type: other.state_type(),
                                users: &other.user_states,
                            },
                            KeyStates {
                                state_type: self.state_type(),
                                keys: &self.key_states,
                            },
                            KeyStates {
                                state_type: other.state_type(),
                                keys: &other.key_states,
                            },
                        )
                    }
                    StateType::SignstarConfigYubiHsm2 | StateType::YubiHsm2 => {
                        return StateComparisonReport::Incompatible {
                            self_state: self.state_type(),
                            other_state: other.state_type(),
                        };
                    }
                };

            let user_failures = self_user_states.compare(&other_user_states);
            let key_failures = self_key_states.compare(&other_key_states);

            (user_failures, key_failures)
        };

        let failures = {
            let mut failures: Vec<String> = Vec::new();

            for user_failure in user_failures.iter() {
                failures.push(user_failure.to_string());
            }
            for key_failure in key_failures.iter() {
                failures.push(key_failure.to_string());
            }

            failures
        };

        if !failures.is_empty() {
            return StateComparisonReport::Failure(failures);
        }

        StateComparisonReport::Success
    }
}

impl<'a, 'b> TryFrom<&NetHsmBackend<'a, 'b>> for NetHsmState {
    type Error = crate::Error;

    /// Creates a new [`NetHsmState`] from a [`NetHsmBackend`].
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
    fn try_from(value: &NetHsmBackend) -> Result<Self, Self::Error> {
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
mod tests {
    use std::collections::BTreeSet;

    use log::LevelFilter;
    use nethsm::{
        Connection,
        ConnectionSecurity,
        OpenPgpUserIdList,
        OpenPgpVersion,
        SignatureType,
    };
    use rstest::rstest;
    use signstar_common::logging::setup_logging;
    use signstar_crypto::key::SigningKeySetup;
    use testresult::TestResult;

    use super::*;
    use crate::nethsm::NetHsmUserMapping;

    /// Ensures, that a [`SignstarConfigNetHsmState`] can be reliable created from a
    /// [`NetHsmConfig`].
    #[rstest]
    #[case::with_signing_user(
        NetHsmConfig::new(
            BTreeSet::from_iter([Connection::new(
                "https://nethsm.example.org".parse()?,
                ConnectionSecurity::Unsafe,
            )]),
            BTreeSet::from_iter([
                NetHsmUserMapping::Admin("admin".parse()?),
                NetHsmUserMapping::Signing {
                    backend_user: "signing1".parse()?,
                    signing_key_id: "signing1".parse()?,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec![
                                "John Doe <john@example.org>".parse()?,
                            ])?,
                            version: OpenPgpVersion::V4,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "nethsm-signing1".parse()?,
                    tag: "tag1".to_string(),
                },
            ]),
        )?,
        NetHsmConfigState {
            user_states: vec![
                UserState {
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
                UserState {
                    name: "signing1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()],
                },
            ],
            key_states: vec![KeyState {
                name: "signing1".parse()?,
                namespace: None,
                key_type: KeyType::Curve25519,
                tags: vec!["tag1".to_string()],
                mechanisms: vec![KeyMechanism::EdDsaSignature],
                key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::OpenPgp {
                    user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                    version: OpenPgpVersion::V4,
                }),
            }],
        }
    )]
    #[case::without_signing_user(
        NetHsmConfig::new(
            BTreeSet::from_iter([Connection::new(
                "https://nethsm.example.org".parse()?,
                ConnectionSecurity::Unsafe,
            )]),
            BTreeSet::from_iter([
                NetHsmUserMapping::Admin("admin".parse()?),
            ]),
        )?,
        NetHsmConfigState {
            user_states: vec![
                UserState {
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: Vec::new(),
        }
    )]
    fn signstar_state_nethsm_from_nethsm_config(
        #[case] input: NetHsmConfig,
        #[case] expected: NetHsmConfigState,
    ) -> TestResult {
        assert_eq!(expected, NetHsmConfigState::from(&input));

        Ok(())
    }

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

    /// Ensures that [`KeyStates::to_string`] shows correctly.
    #[rstest]
    #[case(
        KeyStates{
            state_type: StateType::NetHsm,
            keys: &[KeyState{
                name: "key1".parse()?,
                namespace: None,
                tags: Vec::new(),
                key_type: KeyType::Curve25519,
                mechanisms: vec![KeyMechanism::EdDsaSignature],
                key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
            }],
        },
        "NetHSM keys:\nkey1 (type: Curve25519; mechanisms: EdDsaSignature; context: Raw)\n",
    )]
    #[case(
        KeyStates{
            state_type: StateType::SignstarConfigNetHsm,
            keys: &[KeyState{
                name: "key1".parse()?,
                namespace: None,
                tags: Vec::new(),
                key_type: KeyType::Curve25519,
                mechanisms: vec![KeyMechanism::EdDsaSignature],
                key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
            }],
        },
        "Signstar configuration (NetHSM) keys:\nkey1 (type: Curve25519; mechanisms: EdDsaSignature; context: Raw)\n",
    )]
    fn key_state_type_display(#[case] key_states: KeyStates, #[case] expected: &str) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(key_states.to_string(), expected);
        Ok(())
    }

    /// Ensures that [`UserStates::to_string`] shows correctly.
    #[rstest]
    #[case(
        UserStates{
            state_type: StateType::NetHsm,
            users: &[UserState{
                name: "testuser".parse()?,
                role: UserRole::Administrator,
                tags: Vec::new(),
            }]
        },
        "NetHSM users:\ntestuser (role: Administrator)\n",
    )]
    #[case(
        UserStates{
            state_type: StateType::SignstarConfigNetHsm,
            users: &[UserState{
                name: "testuser".parse()?,
                role: UserRole::Administrator,
                tags: Vec::new(),
            }],
        },
        "Signstar configuration (NetHSM) users:\ntestuser (role: Administrator)\n",
    )]
    fn user_state_type_display(
        #[case] user_states: UserStates,
        #[case] expected: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(user_states.to_string(), expected);
        Ok(())
    }

    /// Ensures that [`StateHandling::compare`] successfully compares [`NetHsmState`] and
    /// [`SignstarConfigNetHsmState`] containing the same data.
    #[rstest]
    #[case::nethsm_vs_config_empty(
        NetHsmState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
        NetHsmConfigState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
    )]
    #[case::config_vs_config_empty(
        NetHsmConfigState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
        NetHsmConfigState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
    )]
    #[case::nethsm_vs_nethsm_empty(
        NetHsmState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
        NetHsmState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
    )]
    #[case::nethsm_vs_config_with_users_and_keys(
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
    )]
    #[case::config_vs_config_with_users_and_keys(
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
    )]
    #[case::nethsm_vs_nethsm_with_users_and_keys(
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
    )]
    fn state_compare_succeeds(
        #[case] state_a: impl StateHandling,
        #[case] state_b: impl StateHandling,
    ) -> TestResult {
        setup_logging(LevelFilter::Trace)?;

        let comparison_report = state_a.compare(&state_b);

        if !matches!(comparison_report, StateComparisonReport::Success) {
            panic!("Comparison should have succeeded but failed:\n{comparison_report:?}")
        }

        Ok(())
    }

    /// Ensures that [`StateHandling::compare`] fails on [`NetHsmState`] and
    /// [`SignstarConfigNetHsmState`] containing differing data.
    #[rstest]
    #[case::one_empty(
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        NetHsmState {
            user_states: Vec::new(),
            key_states: Vec::new(),
        },
        r#"User state present in Signstar configuration (NetHSM), but not in NetHSM:
operator1 (role: Operator; tags: tag1)

User state present in Signstar configuration (NetHSM), but not in NetHSM:
admin (role: Administrator)

Key state present in Signstar configuration (NetHSM), but not in NetHSM:
key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "John Doe <john@example.org>"))
"#,
    )]
    #[case::differing_users_and_keys(
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator2".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag2".to_string(), "tag3".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key2".parse()?,
                    namespace: None,
                    tags: vec!["tag2".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
                },
                KeyState{
                    name: "key3".parse()?,
                    namespace: None,
                    tags: vec!["tag3".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        r#"User state present in Signstar configuration (NetHSM), but not in NetHSM:
operator1 (role: Operator; tags: tag1)

User state present in NetHSM, but not in Signstar configuration (NetHSM):
operator2 (role: Operator; tags: tag2, tag3)

Key state present in Signstar configuration (NetHSM), but not in NetHSM:
key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "John Doe <john@example.org>"))

Key state present in NetHSM, but not in Signstar configuration (NetHSM):
key2 (tags: tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Raw)

Key state present in NetHSM, but not in Signstar configuration (NetHSM):
key3 (tags: tag3; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "John Doe <john@example.org>"))
"#,
    )]
    #[case::user_and_key_mismatch(
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Metrics,
                    tags: Vec::new(),
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
                },
            ],
        },
        r#"Differing user state between Signstar configuration (NetHSM) (A) and NetHSM (B):
A: operator1 (role: Operator; tags: tag1)
B: operator1 (role: Metrics)

Differing key state between Signstar configuration (NetHSM) (A) and NetHSM (B):
A: key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "John Doe <john@example.org>"))
B: key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: Raw)
"#,
    )]
    fn state_compare_fails(
        #[case] state_a: impl StateHandling,
        #[case] state_b: impl StateHandling,
        #[case] expected: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let comparison_report = state_a.compare(&state_b);

        match comparison_report {
            StateComparisonReport::Success => panic!("Comparison should have failed but succeeded"),
            StateComparisonReport::Incompatible { .. } => {
                panic!("Comparison should have failed but was incompatible")
            }
            StateComparisonReport::Failure(failures) => assert_eq!(failures.join("\n"), expected),
        }

        Ok(())
    }

    /// A dummy YubiHSM2 backend.
    ///
    /// This backend is only used in tests as a [`StateHandling`] implementation.
    struct DummyYubiHsm2ConfigBackend;

    impl DummyYubiHsm2ConfigBackend {
        pub fn new() -> Self {
            DummyYubiHsm2ConfigBackend
        }
    }

    impl StateHandling for DummyYubiHsm2ConfigBackend {
        fn state_type(&self) -> StateType {
            StateType::SignstarConfigYubiHsm2
        }

        fn compare(&self, other: &dyn StateHandling) -> StateComparisonReport {
            StateComparisonReport::Incompatible {
                self_state: self.state_type(),
                other_state: other.state_type(),
            }
        }
    }

    #[rstest]
    #[case::dummy_and_signstar_config_nethsm_state(
        DummyYubiHsm2ConfigBackend::new(),
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
    )]
    #[case::dummy_and_nethsm_state(
        DummyYubiHsm2ConfigBackend::new(),
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Metrics,
                    tags: Vec::new(),
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
                },
            ],
        },
    )]
    #[case::signstar_config_nethsm_state_and_dummy(
        NetHsmConfigState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Operator,
                    tags: vec!["tag1".to_string()]
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["John Doe <john@example.org>".parse()?])?,
                            version: OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        DummyYubiHsm2ConfigBackend::new(),
    )]
    #[case::nethsm_state_and_dummy(
        NetHsmState {
            user_states: vec![
                UserState{
                    name: "operator1".parse()?,
                    role: UserRole::Metrics,
                    tags: Vec::new(),
                },
                UserState{
                    name: "admin".parse()?,
                    role: UserRole::Administrator,
                    tags: Vec::new(),
                },
            ],
            key_states: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
                },
            ],
        },
        DummyYubiHsm2ConfigBackend::new(),
    )]
    fn state_compare_incompatible(
        #[case] state_a: impl StateHandling,
        #[case] state_b: impl StateHandling,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let comparison_report = state_a.compare(&state_b);

        match comparison_report {
            StateComparisonReport::Incompatible { .. } => {}
            StateComparisonReport::Success => panic!("Comparison should have failed but succeeded"),
            StateComparisonReport::Failure(failures) => panic!(
                "Comparison should have been incompatible but failed instead: {}",
                failures.join("\n")
            ),
        }

        Ok(())
    }
}
