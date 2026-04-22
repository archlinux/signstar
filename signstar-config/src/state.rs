//! State handling and comparison.

use std::fmt::Display;

use signstar_common::system_user::get_home_base_dir_path;
use strum::AsRefStr;

use crate::config::{SystemUserConfigState, SystemUserData, SystemUserHostState};
#[cfg(feature = "nethsm")]
use crate::nethsm::{
    NetHsmBackendState,
    NetHsmConfigState,
    NetHsmKeyStateDiscrepancy,
    NetHsmStateType,
    NetHsmUserStateDiscrepancy,
};

/// The type of state used for system users.
#[derive(AsRefStr, Clone, Copy, Debug, strum::Display)]
pub(crate) enum SystemUserStateType {
    /// State of system users on a host.
    #[strum(to_string = "system users on the host")]
    Host,

    /// State of system users in a Signstar configuration.
    #[strum(to_string = "system users in the configuration")]
    Config,
}

/// A discrepancy occurred between two system user state instances.
#[derive(Debug)]
enum SystemUserDataDiscrepancy<'a, 'b> {
    /// A [`SystemUserData`] is present in the left hand side but not in the right hand side.
    Unmatched {
        /// The type of state of the left hand side of the comparison.
        state_type: SystemUserStateType,

        /// The type of state of the right hand side of the comparison.
        other_state_type: SystemUserStateType,

        /// The system user state that is present in `state_type`, but not in `other_state_type`.
        user_state: SystemUserData<'a>,
    },

    /// One [`SystemUserData`] does not match another.
    Mismatch {
        /// The user state of the left hand side of the comparison.
        user: SystemUserData<'a>,

        /// The type of state of the left hand side of the comparison.
        state_type: SystemUserStateType,

        /// The user state of the right hand side of the comparison.
        other_user: SystemUserData<'b>,

        /// The type of state of the right hand side of the comparison.
        other_state_type: SystemUserStateType,
    },
}

impl<'a, 'b> Display for SystemUserDataDiscrepancy<'a, 'b> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmatched {
                user_state,
                state_type,
                other_state_type,
            } => {
                writeln!(
                    f,
                    "System user state present in {state_type}, but not in {other_state_type}:\n{user_state}"
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
                    "Differing system user state between {state_type} (A) and {other_state_type} (B):"
                )?;
                writeln!(f, "A: {user}")?;
                writeln!(f, "B: {other_user}")?;
            }
        }
        Ok(())
    }
}

/// The state of a YubiHSM2 backend.
#[derive(Debug)]
pub struct YubiHsm2BackendState {}

/// The state of a YubiHSM2 configuration.
#[derive(Debug)]
pub struct YubiHsm2ConfigState {}

/// The type of [`SignstarState`].
#[derive(AsRefStr, Clone, Copy, Debug, strum::Display, Eq, PartialEq)]
pub enum SignstarStateType {
    /// State of a NetHSM backend.
    #[cfg(feature = "nethsm")]
    #[strum(serialize = "NetHSM backend")]
    NetHsmBackend,

    /// State of a NetHSM configuration.
    #[cfg(feature = "nethsm")]
    #[strum(serialize = "NetHSM config")]
    NetHsmConfig,

    /// State of a YubiHSM2 backend.
    #[cfg(feature = "yubihsm2")]
    #[strum(serialize = "YubiHSM2 backend")]
    YubiHsm2Backend,

    /// State of a YubiHSM2 configuration.
    #[cfg(feature = "yubihsm2")]
    #[strum(serialize = "YubiHSM2 config")]
    YubiHsm2Config,

    /// State of system users on a host.
    #[strum(serialize = "system users on host")]
    SystemUserHost,

    /// State of a system users in a Signstar configuration.
    #[strum(serialize = "system users in config")]
    SystemUserConfig,
}

impl<'a, 'b> From<&SignstarState<'a, 'b>> for SignstarStateType {
    fn from(value: &SignstarState<'a, 'b>) -> Self {
        match value {
            #[cfg(feature = "nethsm")]
            SignstarState::NetHsmBackend(..) => Self::NetHsmBackend,
            #[cfg(feature = "nethsm")]
            SignstarState::NetHsmConfig(..) => Self::NetHsmConfig,
            #[cfg(feature = "yubihsm2")]
            SignstarState::YubiHsm2Backend(..) => Self::YubiHsm2Backend,
            #[cfg(feature = "yubihsm2")]
            SignstarState::YubiHsm2Config(..) => Self::YubiHsm2Config,
            SignstarState::SystemUserHost(..) => Self::SystemUserHost,
            SignstarState::SystemUserConfig(..) => Self::SystemUserConfig,
        }
    }
}

/// A report on the comparison between two [`SignstarState`] variants.
#[derive(Debug, Eq, PartialEq)]
pub enum StateComparisonReport {
    /// The two [`SignstarState`] variants are not compatible.
    Incompatible {
        /// The type of state of the caller.
        self_state: SignstarStateType,

        /// The type of state of the called.
        other_state: SignstarStateType,
    },

    /// The comparison of two compatible [`SignstarState`] variants failed.
    ///
    /// Tracks a list of strings that explain a failure each.
    Failure(Vec<String>),

    /// The state of two compatible [`SignstarState`] variants is equal.
    Success,
}

#[cfg(feature = "nethsm")]
impl From<(&NetHsmBackendState, &NetHsmBackendState)> for StateComparisonReport {
    fn from(value: (&NetHsmBackendState, &NetHsmBackendState)) -> Self {
        let (one, other) = value;
        if one == other {
            return Self::Success;
        }

        let user_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_user_state in one.user_states.iter() {
                for other_user_state in other.user_states.iter() {
                    // The states match.
                    if self_user_state == other_user_state {
                        matched_other_states.push(other_user_state);
                        continue 'outer;
                    }

                    // The unique backend user name matches, but not the remaining data.
                    if self_user_state.name == other_user_state.name {
                        matched_other_states.push(other_user_state);
                        state_discrepancies.push(NetHsmUserStateDiscrepancy::Mismatch {
                            user: self_user_state.clone(),
                            state_type: NetHsmStateType::Backend,
                            other_user: other_user_state.clone(),
                            other_state_type: NetHsmStateType::Backend,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(NetHsmUserStateDiscrepancy::Unmatched {
                    state_type: NetHsmStateType::Backend,
                    other_state_type: NetHsmStateType::Backend,
                    user_state: self_user_state.clone(),
                });
            }

            // Unmatched other states.
            other
                .user_states
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|user_state| {
                    state_discrepancies.push(NetHsmUserStateDiscrepancy::Unmatched {
                        state_type: NetHsmStateType::Backend,
                        other_state_type: NetHsmStateType::Backend,
                        user_state: user_state.clone(),
                    })
                });

            state_discrepancies
        };

        let key_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_state in one.key_states.iter() {
                for other_state in other.key_states.iter() {
                    // The states match.
                    if self_state == other_state {
                        matched_other_states.push(other_state);
                        continue 'outer;
                    }

                    // The unique backend name and namespace matches, but not the remaining data.
                    if self_state.name == other_state.name
                        && self_state.namespace.as_ref() == other_state.namespace.as_ref()
                    {
                        matched_other_states.push(other_state);
                        state_discrepancies.push(NetHsmKeyStateDiscrepancy::Mismatch {
                            key: self_state.clone(),
                            state_type: NetHsmStateType::Backend,
                            other_key: other_state.clone(),
                            other_state_type: NetHsmStateType::Backend,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(NetHsmKeyStateDiscrepancy::Unmatched {
                    state_type: NetHsmStateType::Backend,
                    other_state_type: NetHsmStateType::Backend,
                    key_state: self_state.clone(),
                });
            }

            // Unmatched other states.
            other
                .key_states
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|key_state| {
                    state_discrepancies.push(NetHsmKeyStateDiscrepancy::Unmatched {
                        state_type: NetHsmStateType::Backend,
                        other_state_type: NetHsmStateType::Backend,
                        key_state: key_state.clone(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() && key_state_discrepancies.is_empty() {
            return Self::Success;
        }

        Self::Failure(
            user_state_discrepancies
                .iter()
                .map(ToString::to_string)
                .chain(key_state_discrepancies.iter().map(ToString::to_string))
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(feature = "nethsm")]
impl<'a> From<(&NetHsmBackendState, &NetHsmConfigState<'a>)> for StateComparisonReport {
    fn from(value: (&NetHsmBackendState, &NetHsmConfigState<'a>)) -> Self {
        let (backend, config) = value;
        if config == backend {
            return Self::Success;
        }

        let user_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_user_state in backend.user_states.iter() {
                for other_user_state in config.user_data.iter() {
                    // The states match.
                    if other_user_state == self_user_state {
                        matched_other_states.push(other_user_state);
                        continue 'outer;
                    }

                    // The unique backend user name matches, but not the remaining data.
                    if &self_user_state.name == other_user_state.user {
                        matched_other_states.push(other_user_state);
                        state_discrepancies.push(NetHsmUserStateDiscrepancy::Mismatch {
                            user: self_user_state.clone(),
                            state_type: NetHsmStateType::Backend,
                            other_user: other_user_state.into(),
                            other_state_type: NetHsmStateType::Config,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(NetHsmUserStateDiscrepancy::Unmatched {
                    state_type: NetHsmStateType::Backend,
                    other_state_type: NetHsmStateType::Backend,
                    user_state: self_user_state.clone(),
                });
            }

            // Unmatched other states.
            config
                .user_data
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|user_state| {
                    state_discrepancies.push(NetHsmUserStateDiscrepancy::Unmatched {
                        state_type: NetHsmStateType::Backend,
                        other_state_type: NetHsmStateType::Config,
                        user_state: user_state.into(),
                    })
                });

            state_discrepancies
        };

        let key_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_state in backend.key_states.iter() {
                for other_state in config.key_data.iter() {
                    // The states match.
                    if other_state == self_state {
                        matched_other_states.push(other_state);
                        continue 'outer;
                    }

                    // The unique backend name and namespace matches, but not the remaining data.
                    if &self_state.name == other_state.key_id
                        && self_state.namespace.as_ref() == other_state.user.namespace()
                    {
                        matched_other_states.push(other_state);
                        state_discrepancies.push(NetHsmKeyStateDiscrepancy::Mismatch {
                            key: self_state.clone(),
                            state_type: NetHsmStateType::Backend,
                            other_key: other_state.into(),
                            other_state_type: NetHsmStateType::Config,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(NetHsmKeyStateDiscrepancy::Unmatched {
                    state_type: NetHsmStateType::Backend,
                    other_state_type: NetHsmStateType::Backend,
                    key_state: self_state.clone(),
                });
            }

            // Unmatched other states.
            config
                .key_data
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|key_state| {
                    state_discrepancies.push(NetHsmKeyStateDiscrepancy::Unmatched {
                        state_type: NetHsmStateType::Backend,
                        other_state_type: NetHsmStateType::Config,
                        key_state: key_state.into(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() && key_state_discrepancies.is_empty() {
            return Self::Success;
        }

        Self::Failure(
            user_state_discrepancies
                .iter()
                .map(ToString::to_string)
                .chain(key_state_discrepancies.iter().map(ToString::to_string))
                .collect::<Vec<_>>(),
        )
    }
}

#[cfg(feature = "nethsm")]
impl<'a, 'b> From<(&NetHsmConfigState<'a>, &NetHsmConfigState<'b>)> for StateComparisonReport {
    fn from(value: (&NetHsmConfigState<'a>, &NetHsmConfigState<'b>)) -> Self {
        let (config_a, config_b) = value;
        if config_a == config_b {
            return Self::Success;
        }

        let user_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_user_state in config_a.user_data.iter() {
                for other_user_state in config_b.user_data.iter() {
                    // The states match.
                    if other_user_state == self_user_state {
                        matched_other_states.push(other_user_state);
                        continue 'outer;
                    }

                    // The unique backend user name matches, but not the remaining data.
                    if self_user_state.user == other_user_state.user {
                        matched_other_states.push(other_user_state);
                        state_discrepancies.push(NetHsmUserStateDiscrepancy::Mismatch {
                            user: self_user_state.into(),
                            state_type: NetHsmStateType::Config,
                            other_user: other_user_state.into(),
                            other_state_type: NetHsmStateType::Config,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(NetHsmUserStateDiscrepancy::Unmatched {
                    state_type: NetHsmStateType::Config,
                    other_state_type: NetHsmStateType::Config,
                    user_state: self_user_state.into(),
                });
            }

            // Unmatched other states.
            config_b
                .user_data
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|user_state| {
                    state_discrepancies.push(NetHsmUserStateDiscrepancy::Unmatched {
                        state_type: NetHsmStateType::Config,
                        other_state_type: NetHsmStateType::Config,
                        user_state: user_state.into(),
                    })
                });

            state_discrepancies
        };

        let key_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_state in config_a.key_data.iter() {
                for other_state in config_b.key_data.iter() {
                    // The states match.
                    if other_state == self_state {
                        matched_other_states.push(other_state);
                        continue 'outer;
                    }

                    // The unique backend name and namespace matches, but not the remaining data.
                    if self_state.key_id == other_state.key_id
                        && self_state.user.namespace() == other_state.user.namespace()
                    {
                        matched_other_states.push(other_state);
                        state_discrepancies.push(NetHsmKeyStateDiscrepancy::Mismatch {
                            key: self_state.into(),
                            state_type: NetHsmStateType::Config,
                            other_key: other_state.into(),
                            other_state_type: NetHsmStateType::Config,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(NetHsmKeyStateDiscrepancy::Unmatched {
                    state_type: NetHsmStateType::Config,
                    other_state_type: NetHsmStateType::Config,
                    key_state: self_state.into(),
                });
            }

            // Unmatched other states.
            config_b
                .key_data
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|key_state| {
                    state_discrepancies.push(NetHsmKeyStateDiscrepancy::Unmatched {
                        state_type: NetHsmStateType::Config,
                        other_state_type: NetHsmStateType::Config,
                        key_state: key_state.into(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() && key_state_discrepancies.is_empty() {
            return Self::Success;
        }

        Self::Failure(
            user_state_discrepancies
                .iter()
                .map(ToString::to_string)
                .chain(key_state_discrepancies.iter().map(ToString::to_string))
                .collect::<Vec<_>>(),
        )
    }
}

impl<'a, 'b> From<(&SystemUserConfigState<'a>, &SystemUserConfigState<'b>)>
    for StateComparisonReport
{
    fn from(value: (&SystemUserConfigState<'a>, &SystemUserConfigState<'b>)) -> Self {
        let (one, other) = value;
        if one == other {
            return Self::Success;
        }

        let user_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for self_user_state in one.system_user_data.iter() {
                for other_user_state in other.system_user_data.iter() {
                    // The states match.
                    if self_user_state == other_user_state {
                        matched_other_states.push(other_user_state);
                        continue 'outer;
                    }

                    // The unique system user name matches, but not the remaining data.
                    if self_user_state.system_user() == other_user_state.system_user() {
                        matched_other_states.push(other_user_state);
                        state_discrepancies.push(SystemUserDataDiscrepancy::Mismatch {
                            user: self_user_state.clone(),
                            state_type: SystemUserStateType::Config,
                            other_user: other_user_state.clone(),
                            other_state_type: SystemUserStateType::Config,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(SystemUserDataDiscrepancy::Unmatched {
                    state_type: SystemUserStateType::Config,
                    other_state_type: SystemUserStateType::Config,
                    user_state: self_user_state.clone(),
                });
            }

            // Unmatched other states.
            other
                .system_user_data
                .iter()
                .filter(|state| !matched_other_states.contains(state))
                .for_each(|user_state| {
                    state_discrepancies.push(SystemUserDataDiscrepancy::Unmatched {
                        state_type: SystemUserStateType::Config,
                        other_state_type: SystemUserStateType::Config,
                        user_state: user_state.clone(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() {
            return Self::Success;
        }

        Self::Failure(
            user_state_discrepancies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
    }
}

impl<'a, 'b> From<(&SystemUserHostState<'a>, &SystemUserConfigState<'b>)>
    for StateComparisonReport
{
    fn from(value: (&SystemUserHostState<'a>, &SystemUserConfigState<'b>)) -> Self {
        let (host, config) = value;

        let user_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for host_user_state in host.system_user_data.iter() {
                for config_user_state in config.system_user_data.iter() {
                    // The states match.
                    if host_user_state == config_user_state {
                        matched_other_states.push(config_user_state);
                        continue 'outer;
                    }

                    // The `SystemUserData` on the host side are unknown but fully map to an
                    // existing system user in the configuration.
                    if let &SystemUserData::Unknown {
                        system_user,
                        ssh_authorized_keys,
                        home_dir,
                    } = &host_user_state
                        && config_user_state.system_user() == system_user
                        && config_user_state.ssh_authorized_keys()
                            == ssh_authorized_keys.iter().collect::<Vec<_>>()
                        && *home_dir
                            == get_home_base_dir_path()
                                .join(config_user_state.system_user().as_ref())
                    {
                        matched_other_states.push(config_user_state);
                        continue 'outer;
                    }

                    // The unique system user name matches, but not the remaining data.
                    if host_user_state.system_user() == config_user_state.system_user() {
                        matched_other_states.push(config_user_state);
                        state_discrepancies.push(SystemUserDataDiscrepancy::Mismatch {
                            user: host_user_state.clone(),
                            state_type: SystemUserStateType::Config,
                            other_user: config_user_state.clone(),
                            other_state_type: SystemUserStateType::Config,
                        });
                        continue 'outer;
                    }
                }
                // NOTE: We ignore unmatched users on the host, as they are not relevant to the
                // Signstar system.
            }

            // Unmatched other states.
            config
                .system_user_data
                .iter()
                .filter(|data| !matched_other_states.contains(data))
                .for_each(|data| {
                    state_discrepancies.push(SystemUserDataDiscrepancy::Unmatched {
                        state_type: SystemUserStateType::Config,
                        other_state_type: SystemUserStateType::Config,
                        user_state: data.clone(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() {
            return Self::Success;
        }

        Self::Failure(
            user_state_discrepancies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
    }
}

impl<'a, 'b> From<(&SystemUserHostState<'a>, &SystemUserHostState<'b>)> for StateComparisonReport {
    fn from(value: (&SystemUserHostState<'a>, &SystemUserHostState<'b>)) -> Self {
        let (host_a, host_b) = value;

        let user_state_discrepancies = {
            let mut matched_other_states = Vec::new();
            let mut state_discrepancies = Vec::new();

            'outer: for host_a_data in host_a.system_user_data.iter() {
                for host_b_data in host_b.system_user_data.iter() {
                    // The states match.
                    if host_a_data == host_b_data {
                        matched_other_states.push(host_b_data);
                        continue 'outer;
                    }

                    // The data in host_a is for unknown use but fully maps to an existing system
                    // user in host_b.
                    if let &SystemUserData::Unknown {
                        system_user,
                        ssh_authorized_keys,
                        home_dir,
                    } = &host_a_data
                        && !matches!(host_b_data, SystemUserData::Unknown { .. })
                        && host_b_data.system_user() == system_user
                        && host_b_data.ssh_authorized_keys()
                            == ssh_authorized_keys.iter().collect::<Vec<_>>()
                        && *home_dir
                            == get_home_base_dir_path().join(host_b_data.system_user().as_ref())
                    {
                        matched_other_states.push(host_b_data);
                        continue 'outer;
                    }

                    // The data in host_b is for unknown use but fully maps to an existing system
                    // user in host_a.
                    if let &SystemUserData::Unknown {
                        system_user,
                        ssh_authorized_keys,
                        home_dir,
                    } = &host_b_data
                        && !matches!(host_a_data, SystemUserData::Unknown { .. })
                        && host_a_data.system_user() == system_user
                        && host_a_data.ssh_authorized_keys()
                            == ssh_authorized_keys.iter().collect::<Vec<_>>()
                        && *home_dir
                            == get_home_base_dir_path().join(host_a_data.system_user().as_ref())
                    {
                        matched_other_states.push(host_b_data);
                        continue 'outer;
                    }

                    // The unique system user name matches, but not the remaining data.
                    if host_a_data.system_user() == host_b_data.system_user() {
                        matched_other_states.push(host_b_data);
                        state_discrepancies.push(SystemUserDataDiscrepancy::Mismatch {
                            user: host_a_data.clone(),
                            state_type: SystemUserStateType::Host,
                            other_user: host_b_data.clone(),
                            other_state_type: SystemUserStateType::Host,
                        });
                        continue 'outer;
                    }
                }

                // No match has been found.
                state_discrepancies.push(SystemUserDataDiscrepancy::Unmatched {
                    state_type: SystemUserStateType::Host,
                    other_state_type: SystemUserStateType::Host,
                    user_state: host_a_data.clone(),
                });
            }

            // Unmatched other states.
            host_b
                .system_user_data
                .iter()
                .filter(|data| !matched_other_states.contains(data))
                .for_each(|data| {
                    state_discrepancies.push(SystemUserDataDiscrepancy::Unmatched {
                        state_type: SystemUserStateType::Host,
                        other_state_type: SystemUserStateType::Host,
                        user_state: data.clone(),
                    })
                });

            state_discrepancies
        };

        if user_state_discrepancies.is_empty() {
            return Self::Success;
        }

        Self::Failure(
            user_state_discrepancies
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        )
    }
}

/// The state representation of a Signstar component.
#[derive(Debug)]
pub enum SignstarState<'a, 'b> {
    /// State of a NetHSM backend.
    #[cfg(feature = "nethsm")]
    NetHsmBackend(NetHsmBackendState),

    /// State of a NetHSM configuration.
    #[cfg(feature = "nethsm")]
    NetHsmConfig(NetHsmConfigState<'a>),

    /// State of a YubiHSM2 backend.
    #[cfg(feature = "yubihsm2")]
    YubiHsm2Backend(YubiHsm2BackendState),

    /// State of a YubiHSM2 configuration.
    #[cfg(feature = "yubihsm2")]
    YubiHsm2Config(YubiHsm2ConfigState),

    /// State of system users on a host.
    SystemUserHost(SystemUserHostState<'a>),

    /// State of system users according to Signstar configuration.
    SystemUserConfig(SystemUserConfigState<'b>),
}

impl<'a, 'b> SignstarState<'a, 'b> {
    /// Compares two variants of [`SignstarState`] and returns a [`StateComparisonReport`].
    pub fn compare(&self, other: &SignstarState<'a, 'b>) -> StateComparisonReport {
        match (self, other) {
            #[cfg(feature = "nethsm")]
            (Self::NetHsmBackend(..), Self::SystemUserHost(..))
            | (Self::NetHsmBackend(..), Self::SystemUserConfig(..))
            | (Self::NetHsmConfig(..), Self::SystemUserHost(..))
            | (Self::NetHsmConfig(..), Self::SystemUserConfig(..))
            | (Self::SystemUserHost(..), Self::NetHsmBackend(..))
            | (Self::SystemUserHost(..), Self::NetHsmConfig(..))
            | (Self::SystemUserConfig(..), Self::NetHsmBackend(..))
            | (Self::SystemUserConfig(..), Self::NetHsmConfig(..)) => {
                StateComparisonReport::Incompatible {
                    self_state: self.into(),
                    other_state: other.into(),
                }
            }
            #[cfg(feature = "yubihsm2")]
            (Self::YubiHsm2Backend(..), Self::SystemUserHost(..))
            | (Self::YubiHsm2Backend(..), Self::SystemUserConfig(..))
            | (Self::YubiHsm2Config(..), Self::SystemUserHost(..))
            | (Self::YubiHsm2Config(..), Self::SystemUserConfig(..))
            | (Self::SystemUserHost(..), Self::YubiHsm2Backend(..))
            | (Self::SystemUserHost(..), Self::YubiHsm2Config(..))
            | (Self::SystemUserConfig(..), Self::YubiHsm2Backend(..))
            | (Self::SystemUserConfig(..), Self::YubiHsm2Config(..)) => {
                StateComparisonReport::Incompatible {
                    self_state: self.into(),
                    other_state: other.into(),
                }
            }
            #[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
            (Self::NetHsmBackend(..), Self::YubiHsm2Backend(..))
            | (Self::NetHsmBackend(..), Self::YubiHsm2Config(..))
            | (Self::NetHsmConfig(..), Self::YubiHsm2Backend(..))
            | (Self::NetHsmConfig(..), Self::YubiHsm2Config(..))
            | (Self::YubiHsm2Backend(..), Self::NetHsmBackend(..))
            | (Self::YubiHsm2Backend(..), Self::NetHsmConfig(..))
            | (Self::YubiHsm2Config(..), Self::NetHsmBackend(..))
            | (Self::YubiHsm2Config(..), Self::NetHsmConfig(..)) => {
                StateComparisonReport::Incompatible {
                    self_state: self.into(),
                    other_state: other.into(),
                }
            }
            #[cfg(feature = "nethsm")]
            (Self::NetHsmBackend(self_state), Self::NetHsmBackend(other_state)) => {
                StateComparisonReport::from((self_state, other_state))
            }
            #[cfg(feature = "nethsm")]
            (Self::NetHsmBackend(self_state), Self::NetHsmConfig(other_state)) => {
                StateComparisonReport::from((self_state, other_state))
            }
            #[cfg(feature = "nethsm")]
            (Self::NetHsmConfig(self_state), Self::NetHsmBackend(other_state)) => {
                StateComparisonReport::from((other_state, self_state))
            }
            #[cfg(feature = "nethsm")]
            (Self::NetHsmConfig(self_state), Self::NetHsmConfig(other_state)) => {
                StateComparisonReport::from((self_state, other_state))
            }
            #[cfg(feature = "yubihsm2")]
            (Self::YubiHsm2Backend(..), Self::YubiHsm2Backend(..)) => unimplemented!(),
            #[cfg(feature = "yubihsm2")]
            (Self::YubiHsm2Backend(..), Self::YubiHsm2Config(..)) => unimplemented!(),
            #[cfg(feature = "yubihsm2")]
            (Self::YubiHsm2Config(..), Self::YubiHsm2Backend(..)) => unimplemented!(),
            #[cfg(feature = "yubihsm2")]
            (Self::YubiHsm2Config(..), Self::YubiHsm2Config(..)) => unimplemented!(),
            (Self::SystemUserHost(host_a), Self::SystemUserHost(host_b)) => {
                StateComparisonReport::from((host_a, host_b))
            }
            (Self::SystemUserHost(host), Self::SystemUserConfig(config)) => {
                StateComparisonReport::from((host, config))
            }
            (Self::SystemUserConfig(config), Self::SystemUserHost(host)) => {
                StateComparisonReport::from((host, config))
            }
            (Self::SystemUserConfig(config_a), Self::SystemUserConfig(config_b)) => {
                StateComparisonReport::from((config_a, config_b))
            }
        }
    }
}
