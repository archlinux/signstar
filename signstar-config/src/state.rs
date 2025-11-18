//! State handling and comparison.

use std::any::Any;

use strum::IntoStaticStr;

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

/// The description of a failure in comparing an item between two [`StateHandling`] implementations.
#[derive(Debug)]
pub struct StateComparisonFailure {
    /// A message describing the discrepancy.
    pub message: String,

    /// The [`StateType`] of the calling [`StateHandling`] implementation.
    pub self_state_type: StateType,

    /// The [`StateType`] of the [`StateHandling`] implementation that is compared against.
    pub other_state_type: StateType,
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
pub trait StateHandling {
    /// Returns the [`StateType`] of the implementation.
    fn state_type(&self) -> StateType;

    /// Returns `self` as an [`Any`].
    fn as_any(&self) -> &dyn Any;

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
