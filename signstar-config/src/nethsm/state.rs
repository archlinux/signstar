//! State representation for [`NetHsm`] backends and Signstar configurations.
//!
//! Allows to create state representations of users ([`UserState`]) and keys ([`KeyState`] and
//! [`KeyCertificateState`]) for [`NetHsm`] backends and Signstar configurations ([`State`]).
//!
//! Each [`State`] may be compared against another which may lead to [`StateComparisonErrors`]
//! returning an error, that describes the discrepancies between the two.

use std::fmt::Display;

use log::debug;
#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::{
    CryptographicKeyContext,
    KeyId,
    KeyMechanism,
    KeyType,
    NamespaceId,
    UserId,
    UserRole,
};
#[cfg(doc)]
use pgp::composed::SignedPublicKey;
use strum::IntoStaticStr;

use crate::NetHsmBackendError;
use crate::{FilterUserKeys, SignstarConfig};

/// An error that may occur when comparing two [`State`] structs.
#[derive(Debug, thiserror::Error)]
pub enum StateComparisonError {
    /// Two key states mismatch.
    #[error(
        "Key mismatch:\n{} (A) => {}\n{} (B) => {}",
        self_key.state_type, self_key.key_state, other_key.state_type, other_key.key_state
    )]
    KeyStateMismatch {
        /// The state of the left hand side key.
        self_key: KeyStateType,

        /// The state of the right hand side key.
        other_key: KeyStateType,
    },

    /// The key states in one state type can not be matched by those in another.
    #[error(
        "Keys missing in {other_state_type} (B), but present in {state_type} (A):\n{}",
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
        "Users missing in {other_state_type} (B), but present in {state_type} (A):\n{}",
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
        "User mismatch:\n{} (A) => {}\n{} (B) => {}",
        self_user.state_type, self_user.user_state, other_user.state_type, other_user.user_state
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
        for error in self.errors.iter() {
            writeln!(f, "{error}")?;
        }
        Ok(())
    }
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
        write!(f, "{} (role: {}", self.name, self.role)?;
        if !self.tags.is_empty() {
            write!(f, "; tags: {}", self.tags.join(", "))?;
        }
        write!(f, ")")?;

        Ok(())
    }
}

/// The state of a key certificate.
///
/// Key certificates carry information on the context in which a key is used.
/// They can be derived e.g. from NetHSM backends or Signstar configuration files.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyCertificateState {
    /// A [`CryptographicKeyContext`] describing the context in which a certificate is used.
    KeyContext(CryptographicKeyContext),

    /// There is no key certificate for the key.
    Empty,

    /// A key certificate could not be retrieved due to an error.
    Error {
        /// A string containing the error message.
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
        match self {
            Self::KeyContext(context) => write!(f, "{context}"),
            Self::Empty => write!(f, "Empty"),
            Self::Error { message } => {
                write!(f, "Error retrieving key certificate - {message}")
            }
            Self::NotACryptographicKeyContext { message } => {
                write!(f, "Not a cryptographic key context - \"{message}\"")
            }
            Self::NotAnOpenPgpCertificate { message } => {
                write!(f, "Not an OpenPGP certificate - \"{message}\"")
            }
        }
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

/// Indicator for [`State`] to distinguish what its data belongs to.
#[derive(Clone, Copy, Debug, strum::Display, Eq, IntoStaticStr, PartialEq)]
pub enum StateType {
    /// A [`NetHsm`] backend.
    #[strum(to_string = "NetHSM")]
    NetHsm,

    /// A Signstar configuration file.
    #[strum(to_string = "Signstar configuration")]
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
        write!(f, "{} (user): {}", self.state_type, self.user_state)
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
        write!(f, "{} (key): {}", self.state_type, self.key_state)
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
                        // continue;
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

impl From<&SignstarConfig> for State {
    /// Creates a [`State`] from [`SignstarConfig`] reference.
    fn from(value: &SignstarConfig) -> Self {
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
                        key_cert_state: KeyCertificateState::KeyContext(
                            key_setup.get_key_context(),
                        ),
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

#[cfg(test)]
mod tests {
    use log::LevelFilter;
    use nethsm::OpenPgpUserIdList;
    use rstest::rstest;
    use signstar_common::logging::setup_logging;
    use testresult::TestResult;

    use super::*;

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
                    user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                    version: nethsm::OpenPgpVersion::V4,
                })
        },
        "key1 (namespace: ns1; tags: tag1, tag2; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: \"Foobar McFooface <foobar@mcfooface.org>\"))",
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

    /// Ensures that [`StateType::to_string`] shows correctly.
    #[rstest]
    #[case(StateType::NetHsm, "NetHSM")]
    #[case(StateType::SignstarConfig, "Signstar configuration")]
    fn state_type_display(#[case] state_type: StateType, #[case] expected: &str) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(state_type.to_string(), expected);
        Ok(())
    }

    /// Ensures that [`KeyStateType::to_string`] shows correctly.
    #[rstest]
    #[case(
        KeyStateType{
            state_type: StateType::NetHsm,
            key_state: KeyState{
                name: "key1".parse()?,
                namespace: None,
                tags: Vec::new(),
                key_type: KeyType::Curve25519,
                mechanisms: vec![KeyMechanism::EdDsaSignature],
                key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
            },
        },
        "NetHSM (key): key1 (type: Curve25519; mechanisms: EdDsaSignature; context: Raw)",
    )]
    #[case(
        KeyStateType{
            state_type: StateType::SignstarConfig,
            key_state: KeyState{
                name: "key1".parse()?,
                namespace: None,
                tags: Vec::new(),
                key_type: KeyType::Curve25519,
                mechanisms: vec![KeyMechanism::EdDsaSignature],
                key_cert_state: KeyCertificateState::KeyContext(CryptographicKeyContext::Raw)
            },
        },
        "Signstar configuration (key): key1 (type: Curve25519; mechanisms: EdDsaSignature; context: Raw)",
    )]
    fn key_state_type_display(
        #[case] state_type: KeyStateType,
        #[case] expected: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(state_type.to_string(), expected);
        Ok(())
    }

    /// Ensures that [`UserStateType::to_string`] shows correctly.
    #[rstest]
    #[case(
        UserStateType{
            state_type: StateType::NetHsm,
            user_state: UserState{
                name: "testuser".parse()?,
                role: UserRole::Administrator,
                tags: Vec::new(),
            }
        },
        "NetHSM (user): testuser (role: Administrator)",
    )]
    #[case(
        UserStateType{
            state_type: StateType::SignstarConfig,
            user_state: UserState{
                name: "testuser".parse()?,
                role: UserRole::Administrator,
                tags: Vec::new(),
            },
        },
        "Signstar configuration (user): testuser (role: Administrator)",
    )]
    fn user_state_type_display(
        #[case] state_type: UserStateType,
        #[case] expected: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(state_type.to_string(), expected);
        Ok(())
    }

    /// Ensures that [`State::compare`] successfully compares [`State`] containing the same data.
    #[rstest]
    #[case::empty(
        State {
            state_type: StateType::SignstarConfig,
            users: Vec::new(),
            keys: Vec::new(),
        },
        State {
            state_type: StateType::NetHsm,
            users: Vec::new(),
            keys: Vec::new(),
        },
    )]
    #[case::with_users_and_keys(
        State {
            state_type: StateType::SignstarConfig,
            users: vec![
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
            keys: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                            version: nethsm::OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        State {
            state_type: StateType::NetHsm,
            users: vec![
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
            keys: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                            version: nethsm::OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
    )]
    fn state_compare_succeeds(#[case] state_a: State, #[case] state_b: State) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let compare_result = state_a.compare(&state_b);

        if let Err(error) = compare_result {
            panic!("Comparison should have succeeded but failed:\n{error}")
        }

        Ok(())
    }

    /// Ensures that [`State::compare`] fails on [`State`] containing differing data.
    #[rstest]
    #[case::one_empty(
        State {
            state_type: StateType::SignstarConfig,
            users: vec![
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
            keys: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                            version: nethsm::OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        State {
            state_type: StateType::NetHsm,
            users: Vec::new(),
            keys: Vec::new(),
        },
        r#"NetHSM backend error:
Errors occurred when comparing states:
Users missing in NetHSM (B), but present in Signstar configuration (A):
operator1 (role: Operator; tags: tag1)
admin (role: Administrator)
Keys missing in NetHSM (B), but present in Signstar configuration (A):
key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "Foobar McFooface <foobar@mcfooface.org>"))
"#,
    )]
    #[case::differing_users_and_keys(
        State {
            state_type: StateType::SignstarConfig,
            users: vec![
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
            keys: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                            version: nethsm::OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        State {
            state_type: StateType::NetHsm,
            users: vec![
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
            keys: vec![
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
                            user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                            version: nethsm::OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        r#"NetHSM backend error:
Errors occurred when comparing states:
Users missing in NetHSM (B), but present in Signstar configuration (A):
operator1 (role: Operator; tags: tag1)
Users missing in Signstar configuration (B), but present in NetHSM (A):
operator2 (role: Operator; tags: tag2, tag3)
Keys missing in NetHSM (B), but present in Signstar configuration (A):
key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "Foobar McFooface <foobar@mcfooface.org>"))
Keys missing in Signstar configuration (B), but present in NetHSM (A):
key2 (tags: tag2; type: Curve25519; mechanisms: EdDsaSignature; context: Raw)
key3 (tags: tag3; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "Foobar McFooface <foobar@mcfooface.org>"))
"#,
    )]
    #[case::user_and_key_mismatch(
        State {
            state_type: StateType::SignstarConfig,
            users: vec![
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
            keys: vec![
                KeyState{
                    name: "key1".parse()?,
                    namespace: None,
                    tags: vec!["tag1".to_string()],
                    key_type: KeyType::Curve25519,
                    mechanisms: vec![KeyMechanism::EdDsaSignature],
                    key_cert_state: KeyCertificateState::KeyContext(
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec!["Foobar McFooface <foobar@mcfooface.org>".parse()?])?,
                            version: nethsm::OpenPgpVersion::V4,
                        }
                    )
                },
            ],
        },
        State {
            state_type: StateType::NetHsm,
            users: vec![
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
            keys: vec![
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
        r#"NetHSM backend error:
Errors occurred when comparing states:
User mismatch:
Signstar configuration (A) => operator1 (role: Operator; tags: tag1)
NetHSM (B) => operator1 (role: Metrics)
Key mismatch:
Signstar configuration (A) => key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: "Foobar McFooface <foobar@mcfooface.org>"))
NetHSM (B) => key1 (tags: tag1; type: Curve25519; mechanisms: EdDsaSignature; context: Raw)
"#,
    )]
    fn state_compare_fails(
        #[case] state_a: State,
        #[case] state_b: State,
        #[case] expected: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let compare_result = state_a.compare(&state_b);

        match compare_result {
            Ok(_) => panic!("Comparison should have failed but succeeded"),
            Err(error) => assert_eq!(error.to_string(), expected),
        }

        Ok(())
    }
}
