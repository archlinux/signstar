//! State representation for a [`NetHsmBackend`].
//!
//! Allows to create state representations of users ([`UserState`]) and keys ([`KeyState`] and
//! [`KeyCertificateState`]) for [`NetHsm`] backends using the [`NetHsmState`] struct.
//! It implements the [`StateHandling`] trait which allows comparison with
//! other implementations.

use std::any::Any;

use log::{debug, trace};
#[cfg(doc)]
use nethsm::NetHsm;
use nethsm::SystemState;

use crate::{
    NetHsmBackend,
    config::state::{KeyState, KeyStates, UserState, UserStates},
    state::StateType,
};
#[cfg(doc)]
use crate::{
    config::state::KeyCertificateState,
    nethsm::admin_credentials::NetHsmAdminCredentials,
};
use crate::{
    config::state::SignstarConfigNetHsmState,
    state::{StateComparisonReport, StateHandling},
};

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

    fn as_any(&self) -> &dyn Any {
        self
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
                        let Some(other) =
                            other.as_any().downcast_ref::<SignstarConfigNetHsmState>()
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
                        let Some(other) = other.as_any().downcast_ref::<NetHsmState>() else {
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
