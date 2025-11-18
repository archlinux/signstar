//! State handling and comparison.

use strum::IntoStaticStr;

/// The type of a state.
#[derive(Clone, Copy, Debug, strum::Display, Eq, IntoStaticStr, PartialEq)]
pub enum StateType {
    /// A NetHSM backend.
    #[strum(to_string = "NetHSM")]
    NetHsm,

    /// Configuration items relevant for a NetHSM backend in a Signstar configuration file.
    #[strum(to_string = "Signstar configuration items for NetHSM")]
    SignstarConfigNetHsm,

    /// Configuration items relevant for a YubiHSM2 backend in a Signstar configuration file.
    #[strum(to_string = "Signstar configuration items for YubiHSM2")]
    SignstarConfigYubiHsm2,

    /// A YubiHSM2 backend.
    #[strum(to_string = "YubiHSM2")]
    YubiHsm2,
}

impl StateType {
    /// Checks whether this and another [`StateType`] are comparable.
    ///
    /// Returns `true`, if `self` and `other` can be compared, `false` otherwise.
    fn is_comparable(&self, other: StateType) -> bool {
        matches!(
            (self, other),
            (StateType::NetHsm, StateType::SignstarConfigNetHsm)
                | (StateType::NetHsm, StateType::NetHsm)
                | (
                    StateType::SignstarConfigNetHsm,
                    StateType::SignstarConfigNetHsm
                )
                | (StateType::YubiHsm2, StateType::SignstarConfigYubiHsm2)
                | (StateType::YubiHsm2, StateType::YubiHsm2)
                | (
                    StateType::SignstarConfigYubiHsm2,
                    StateType::SignstarConfigYubiHsm2
                )
        )
    }
}

/// A report on the comparison between two compatible [`StateHandling`] implementations.
#[derive(Debug)]
pub struct StateComparisonReport {}

/// An interface to handle and compare the state of various types.
pub trait StateHandling {
    /// Returns the [`StateType`] of the implementation.
    fn state_type(&self) -> StateType;

    /// Compares this and another, compatible [`StateHandling`].
    ///
    /// Returns [`Some`] [`StateComparison`], if `self` and `other` are comparable, [`None`]
    /// otherwise.
    fn compare_compatible(&self, other: impl StateHandling) -> Option<StateComparisonReport> {
        if !self.state_type().is_comparable(other.state_type()) {
            return None;
        }

        Some(self.compare(other))
    }

    /// Compares this and another [`StateHandling`] implementation.
    fn compare(&self, other: impl StateHandling) -> StateComparisonReport;
}
