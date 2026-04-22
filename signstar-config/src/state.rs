//! State handling and comparison.

use std::fmt::Display;

/// The indicator for where state originates from.
#[derive(Clone, Copy, Debug, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum StateOrigin {
    /// A backend.
    Backend,

    /// A configuration file.
    Config,

    /// The operating system.
    System,
}

/// An interface for returning the name of an object providing state.
pub trait StateOriginInfo: std::fmt::Debug {
    /// The name of the state implementation.
    fn state_name(&self) -> &str;

    /// The origin of the state.
    fn state_origin(&self) -> StateOrigin;
}

/// The target of an asymmetric [`StateDiffFailure`].
///
/// Asymmetric failure types are those, where a state is present in one, but not another state
/// origin (i.e. [`StateDiffFailure::DoesNotExist`]).
///
/// Here, the target allows to mark the state origin that introduces the asymmetry (e.g. by not
/// providing state that another state origin offers).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateDiffFailureTarget {
    /// The target is the `one`.
    One,

    /// The target is the `other`.
    Other,
}

/// A report on the state diff of two objects.
#[derive(Debug)]
pub enum StateDiffFailure<'a, 'b> {
    /// An item exists only in the state of a single object.
    DoesNotExist {
        /// The name of the one object.
        one: Box<&'a dyn StateOriginInfo>,

        /// The name of the other object.
        other: Box<&'b dyn StateOriginInfo>,

        /// The indicator for where the item is missing.
        ///
        /// # Note
        ///
        /// If `target` is set to [`StateDiffFailureTarget::One`], the item is missing in `one`, if
        /// `target` is set to [`StateDiffFailureTarget::Other`], the item is missing in `other`.
        target: StateDiffFailureTarget,

        /// The representation of a state item, present in `one` but not `other`
        state: String,
    },

    /// Mismatching items exists in the state of the one object and in that of the other.
    Mismatch {
        /// The name of the one object.
        one: Box<&'a dyn StateOriginInfo>,

        /// The name of the other object.
        other: Box<&'b dyn StateOriginInfo>,

        /// The representation of a state item, present in `one`, different from the state
        /// item present in `other` (`other_state`).
        one_state: String,

        /// The representation of a state item, present in `other`, different from the state
        /// item present in `one` (`one_state`).
        other_state: String,
    },
}

impl<'a, 'b> Display for StateDiffFailure<'a, 'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DoesNotExist {
                one,
                other,
                target,
                state,
            } => {
                write!(
                    f,
                    "Present in A ({}) but not in B ({}): {state}",
                    match target {
                        StateDiffFailureTarget::One => other.state_name(),
                        StateDiffFailureTarget::Other => one.state_name(),
                    },
                    match target {
                        StateDiffFailureTarget::One => one.state_name(),
                        StateDiffFailureTarget::Other => other.state_name(),
                    },
                )
            }
            Self::Mismatch {
                one,
                other,
                one_state,
                other_state,
            } => write!(
                f,
                "Different in A ({}) and B ({}):\nA: {one_state}\nB: {other_state}",
                one.state_name(),
                other.state_name(),
            ),
        }
    }
}

/// A report on the state diff of two objects.
#[derive(Debug)]
pub enum StateDiffReport<'a, 'b> {
    /// The diff of two object states is not successful.
    ///
    /// This means that a discrepancy between the one and the other object exists.
    Failure {
        /// A list of messages, that each describe a specific state discrepancy.
        messages: Vec<StateDiffFailure<'a, 'b>>,
    },

    /// The diff of two object states is successful.
    Success,
}

/// An interface to compare the state of two objects.
pub trait StateDiff<'a, 'b> {
    /// Returns a [`StateDiffReport`] for two objects.
    fn diff(&self) -> StateDiffReport<'a, 'b>;
}
