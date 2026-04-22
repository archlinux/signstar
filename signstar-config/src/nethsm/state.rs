//! Common types for state representation of a NetHSM.

use crate::{
    nethsm::{NetHsmConfigState, backend::NetHsmBackendState},
    state::{StateDiff, StateDiffFailure, StateDiffFailureTarget, StateDiffReport},
};

/// The diff between [`NetHsmConfigState`] and [`NetHsmBackendState`].
#[derive(Debug)]
pub struct NetHsmDiff<'config_state, 'backend_state, 'config_items> {
    /// The reference to the state of a NetHSM config.
    pub config: &'config_state NetHsmConfigState<'config_items>,

    /// The reference to the state of a NetHSM backend.
    pub backend: &'backend_state NetHsmBackendState,
}

impl<'config_state, 'backend_state, 'config_items> StateDiff<'config_state, 'backend_state>
    for NetHsmDiff<'config_state, 'backend_state, 'config_items>
{
    fn diff(&self) -> StateDiffReport<'config_state, 'backend_state> {
        if self.config == self.backend {
            return StateDiffReport::Success;
        }

        let user_state_discrepancies = {
            let mut matched_config_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for backend_user_state in self.backend.user_states.iter() {
                for config_user_state in self.config.user_data.iter() {
                    // The states match.
                    if config_user_state == backend_user_state {
                        matched_config_states.push(config_user_state);
                        continue 'outer;
                    }

                    // The unique backend user name matches, but not the remaining data.
                    if &backend_user_state.name == config_user_state.user {
                        matched_config_states.push(config_user_state);
                        state_discrepancies.push(StateDiffFailure::Mismatch {
                            one: Box::new(self.config),
                            other: Box::new(self.backend),
                            one_state: config_user_state.to_string(),
                            other_state: backend_user_state.to_string(),
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(StateDiffFailure::DoesNotExist {
                    one: Box::new(self.config),
                    other: Box::new(self.backend),
                    target: StateDiffFailureTarget::One,
                    state: backend_user_state.to_string(),
                });
            }

            // Unmatched config states.
            self.config
                .user_data
                .iter()
                .filter(|state| !matched_config_states.contains(state))
                .for_each(|config_user_state| {
                    state_discrepancies.push(StateDiffFailure::DoesNotExist {
                        one: Box::new(self.config),
                        other: Box::new(self.backend),
                        target: StateDiffFailureTarget::Other,
                        state: config_user_state.to_string(),
                    })
                });

            state_discrepancies
        };

        let key_state_discrepancies = {
            let mut matched_config_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for backend_key_state in self.backend.key_states.iter() {
                for config_key_state in self.config.key_data.iter() {
                    // The states match.
                    if config_key_state == backend_key_state {
                        matched_config_states.push(config_key_state);
                        continue 'outer;
                    }

                    // The unique backend name and namespace matches, but not the remaining data.
                    if &backend_key_state.name == config_key_state.key_id
                        && backend_key_state.namespace.as_ref() == config_key_state.user.namespace()
                    {
                        matched_config_states.push(config_key_state);
                        state_discrepancies.push(StateDiffFailure::Mismatch {
                            one: Box::new(self.config),
                            other: Box::new(self.backend),
                            one_state: config_key_state.to_string(),
                            other_state: backend_key_state.to_string(),
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(StateDiffFailure::DoesNotExist {
                    one: Box::new(self.config),
                    other: Box::new(self.backend),
                    target: StateDiffFailureTarget::One,
                    state: backend_key_state.to_string(),
                });
            }

            // Unmatched other states.
            self.config
                .key_data
                .iter()
                .filter(|state| !matched_config_states.contains(state))
                .for_each(|key_state| {
                    state_discrepancies.push(StateDiffFailure::DoesNotExist {
                        one: Box::new(self.config),
                        other: Box::new(self.backend),
                        target: StateDiffFailureTarget::Other,
                        state: key_state.to_string(),
                    })
                });

            state_discrepancies
        };

        let messages = {
            let mut output = Vec::new();
            output.extend(user_state_discrepancies);
            output.extend(key_state_discrepancies);
            output
        };

        if messages.is_empty() {
            return StateDiffReport::Success;
        }

        StateDiffReport::Failure { messages }
    }
}
