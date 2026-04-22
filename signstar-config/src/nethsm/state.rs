//! Common types for state representation of a NetHSM.

use std::fmt::Display;

use strum::AsRefStr;

use crate::nethsm::{KeyState, UserState};

/// The type of state used for NetHSM backends and related configuration.
#[derive(AsRefStr, Clone, Copy, Debug, strum::Display)]
pub enum NetHsmStateType {
    /// State of a NetHSM backend.
    #[strum(to_string = "NetHSM backend")]
    Backend,

    /// State of a NetHSM configuration.
    #[strum(to_string = "NetHSM configuration")]
    Config,
}

/// A discrepancy occurred between two [`UserState`] instances.
#[derive(Debug)]
pub(crate) enum NetHsmUserStateDiscrepancy {
    /// A [`UserState`] is present in the left hand side but not in the right hand side.
    Unmatched {
        /// The type of state of the left hand side of the comparison.
        state_type: NetHsmStateType,

        /// The type of state of the right hand side of the comparison.
        other_state_type: NetHsmStateType,

        /// The user state that is present in `state_type`, but not in `other_state_type`.
        user_state: UserState,
    },

    /// One [`UserState`] does not match another.
    Mismatch {
        /// The user state of the left hand side of the comparison.
        user: UserState,

        /// The type of state of the left hand side of the comparison.
        state_type: NetHsmStateType,

        /// The user state of the right hand side of the comparison.
        other_user: UserState,

        /// The type of state of the right hand side of the comparison.
        other_state_type: NetHsmStateType,
    },
}

impl Display for NetHsmUserStateDiscrepancy {
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

/// The discrepancy occurred between two [`KeyState`] instances.
#[derive(Debug)]
pub(crate) enum NetHsmKeyStateDiscrepancy {
    /// A [`KeyState`] is present in the left hand side but not in the right hand side.
    Unmatched {
        /// The type of state of the left hand side of the comparison.
        state_type: NetHsmStateType,

        /// The type of state of the right hand side of the comparison.
        other_state_type: NetHsmStateType,

        /// A key state that is present in `state_type`, but not in `other_state_type`.
        key_state: KeyState,
    },

    /// One [`KeyState`] does not match another.
    Mismatch {
        /// The key state of the left hand side of the comparison.
        key: KeyState,

        /// The type of state of the left hand side of the comparison.
        state_type: NetHsmStateType,

        /// The key state of the right hand side of the comparison.
        other_key: KeyState,

        /// The type of state of the right hand side of the comparison.
        other_state_type: NetHsmStateType,
    },
}

impl Display for NetHsmKeyStateDiscrepancy {
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
