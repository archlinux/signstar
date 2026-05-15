//! State handling and comparison.

use std::{any::Any, fmt::Display};

use strum::IntoStaticStr;

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

/// The type of a state.
#[derive(Clone, Copy, Debug, strum::Display, Eq, IntoStaticStr, PartialEq)]
pub enum StateType {
    /// A NetHSM backend.
    #[strum(to_string = "NetHSM")]
    NetHsm,

    /// Configuration items relevant for a NetHSM backend in a Signstar configuration file.
    #[strum(to_string = "Signstar configuration (NetHSM)")]
    SignstarConfigNetHsm,

    /// Configuration items relevant for a YubiHSM2 backend in a Signstar configuration file.
    #[strum(to_string = "Signstar configuration (YubiHSM2)")]
    SignstarConfigYubiHsm2,

    /// A YubiHSM2 backend.
    #[strum(to_string = "YubiHSM2")]
    YubiHsm2,
}

impl StateType {
    /// Checks whether this and another [`StateType`] are comparable.
    ///
    /// Returns `true`, if `self` and `other` can be compared, `false` otherwise.
    fn is_compatible(&self, other: StateType) -> bool {
        matches!(
            (self, other),
            (StateType::NetHsm, StateType::SignstarConfigNetHsm)
                | (StateType::NetHsm, StateType::NetHsm)
                | (StateType::SignstarConfigNetHsm, StateType::NetHsm)
                | (
                    StateType::SignstarConfigNetHsm,
                    StateType::SignstarConfigNetHsm
                )
                | (StateType::YubiHsm2, StateType::SignstarConfigYubiHsm2)
                | (StateType::YubiHsm2, StateType::YubiHsm2)
                | (StateType::SignstarConfigYubiHsm2, StateType::YubiHsm2)
                | (
                    StateType::SignstarConfigYubiHsm2,
                    StateType::SignstarConfigYubiHsm2
                )
        )
    }
}

/// A report on the comparison between two compatible [`StateHandling`] implementations.
#[derive(Debug)]
pub enum StateComparisonReport {
    /// The two [`StateHandling`] implementations are not compatible.
    Incompatible {
        /// The type of state of the caller.
        self_state: StateType,

        /// The type of state of the called.
        other_state: StateType,
    },

    /// The comparison of two [`StateHandling`] implementations failed.
    ///
    /// Tracks a list of strings that explain a failure each.
    Failure(Vec<String>),

    /// The state of the two [`StateHandling`] implementations is equal.
    Success,
}

/// An interface to handle and compare the state of various types.
pub trait StateHandling: Any {
    /// Returns the [`StateType`] of the implementation.
    fn state_type(&self) -> StateType;

    /// Checks whether this [`StateHandling`] implementation is comparable to another.
    ///
    /// Returns `true`, if the [`StateType`] of `self` and that of `other` can be compared, `false`
    /// otherwise.
    ///
    /// # Note
    ///
    /// It should not be necessary to specifically implement this method.
    fn is_comparable(&self, other: &dyn StateHandling) -> bool {
        self.state_type().is_compatible(other.state_type())
    }

    /// Compares this and another [`StateHandling`] implementation.
    ///
    /// # Notes
    ///
    /// An implementation is expected to return
    ///
    /// - an [`Error`][`crate::Error`] if the facilities of a backend cannot be used
    /// - a [`StateComparisonReport::Incompatible`] if `self` and `other` are not compatible (see
    ///   [`StateHandling::is_comparable`])
    fn compare(&self, other: &dyn StateHandling) -> StateComparisonReport;
}

#[cfg(test)]
mod tests {
    use log::LevelFilter;
    use rstest::rstest;
    use signstar_common::logging::setup_logging;
    use testresult::TestResult;

    use super::*;

    /// Ensures that [`StateType::to_string`] shows correctly.
    #[rstest]
    #[case(StateType::NetHsm, "NetHSM")]
    #[case(StateType::SignstarConfigNetHsm, "Signstar configuration (NetHSM)")]
    #[case(StateType::SignstarConfigYubiHsm2, "Signstar configuration (YubiHSM2)")]
    #[case(StateType::YubiHsm2, "YubiHSM2")]
    fn state_type_display(#[case] state_type: StateType, #[case] expected: &str) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        assert_eq!(state_type.to_string(), expected);
        Ok(())
    }
}
