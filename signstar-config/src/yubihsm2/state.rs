//! Common types for state representation of a YubiHSM2.

use std::{collections::HashSet, fmt::Display};

use log::{debug, info, warn};
use signstar_crypto::key::{
    SigningKeySetup,
    base::{CryptographicKeyContext, KeyType},
};
use signstar_yubihsm2::{
    automation::ObjectType,
    backup::Label,
    object::{
        AsymmetricAlgorithm,
        Capabilities,
        Capability,
        Domain,
        Domains,
        ObjectAlgorithm,
        WrapKeyKind,
    },
    yubihsm::Id,
};

use crate::{
    state::{
        StateDiff,
        StateDiffFailure,
        StateDiffFailureTarget,
        StateDiffReport,
        StateOrigin,
        StateOriginInfo,
    },
    yubihsm2::{YubiHsm2Backend, YubiHsm2Config, YubiHsm2UserMapping, config::AuthType},
};

/// Returns information on the (implicitly defined) wrapping key used to backup all objects.
fn implicit_wrap_key_state() -> YubiHsm2BackendUserKeyData {
    YubiHsm2BackendUserKeyData {
        id: YubiHsm2Config::WRAP_KEY_ID,
        object_type: ObjectType::WrapKey,
        capabilities: Capabilities::from(YubiHsm2UserMapping::CAP_BACKUP),
        domains: Domains::all(),
        algorithm: ObjectAlgorithm::Wrap(WrapKeyKind::Aes256),
        label: Label::from(&[0; 40]),
        length: 32,
    }
}

/// The state of a user in a [`YubiHsm2Backend`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct YubiHsm2BackendUserData {
    /// The ID of the user.
    pub id: Id,

    /// The capabilities of the user.
    pub capabilities: Capabilities,

    /// The domains of the user.
    pub domains: Domains,
}

impl Display for YubiHsm2BackendUserData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (capabilities: {}; domains: {})",
            self.id, self.capabilities, self.domains
        )
    }
}

impl PartialEq<YubiHsm2ConfigUserData> for YubiHsm2BackendUserData {
    fn eq(&self, other: &YubiHsm2ConfigUserData) -> bool {
        self.id == other.authentication_key_id
            && self.capabilities == other.capabilities
            && self.domains == other.domains
    }
}

/// The state of a key in a [`YubiHsm2Backend`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct YubiHsm2BackendUserKeyData {
    /// The ID of the signing key.
    pub id: Id,

    /// The type of object.
    pub object_type: ObjectType,

    /// The capabilities of the signing key.
    pub capabilities: Capabilities,

    /// The domain of the signing key.
    pub domains: Domains,

    /// The object's algorithm.
    pub algorithm: ObjectAlgorithm,

    /// The object's label.
    pub label: Label,

    /// The object's size in bytes.
    pub length: u16,
}

impl Display for YubiHsm2BackendUserKeyData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (type: {}; algorithm: {}; capabilities: {}; domains: {}; label: {}; length: {})",
            self.id,
            self.object_type,
            self.algorithm,
            self.capabilities,
            self.domains,
            self.label,
            self.length
        )
    }
}

impl<'config> PartialEq<YubiHsm2ConfigUserKeyData<'config>> for YubiHsm2BackendUserKeyData {
    fn eq(&self, other: &YubiHsm2ConfigUserKeyData<'config>) -> bool {
        self.id == *other.signing_key_id
            && self.object_type == ObjectType::AsymmetricKey
            && other.key_setup.key_type() == KeyType::Curve25519
            && self.algorithm == ObjectAlgorithm::Asymmetric(AsymmetricAlgorithm::Ed25519)
            && self.capabilities == other.capabilities
            && self.domains == Domains::from(*other.domain)
    }
}

/// The state of a [`YubiHsm2Backend`].
///
/// This tracks two lists of data in the backend:
///
/// - the authentication keys ("user credentials"), their capabilities and domains
/// - all other key types, their capabilities, domains, algorithms, labels and lengths
#[derive(Debug, Eq, PartialEq)]
pub struct YubiHsm2BackendState {
    /// The user states.
    pub(crate) user_data: Vec<YubiHsm2BackendUserData>,

    /// The key states.
    pub(crate) key_data: Vec<YubiHsm2BackendUserKeyData>,
}

impl YubiHsm2BackendState {
    /// The name of the origin for the state.
    pub const STATE_NAME: &'static str = "YubiHSM2 backend";
}

impl<'admin_creds, 'config> TryFrom<&YubiHsm2Backend<'admin_creds, 'config>>
    for YubiHsm2BackendState
{
    type Error = crate::Error;

    /// Creates a new [`YubiHsm2BackendState`] from a [`YubiHsm2Backend`].
    ///
    /// # Errors
    ///
    /// Returns an error if retrieving the user or key states from the backend fails.
    fn try_from(value: &YubiHsm2Backend<'admin_creds, 'config>) -> Result<Self, Self::Error> {
        debug!(
            "Retrieve state of the YubiHSM2 backend at {}",
            value
                .yubihsm2_config()
                .connections()
                .iter()
                .map(|connection| format!("{connection:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(Self {
            user_data: value.user_states()?,
            key_data: value.key_states()?,
        })
    }
}

impl<'config> PartialEq<YubiHsm2ConfigState<'config>> for YubiHsm2BackendState {
    fn eq(&self, other: &YubiHsm2ConfigState) -> bool {
        debug!(
            "Compare backend state ({} users, {} keys) and config state ({} users, {} keys)",
            self.user_data.len(),
            self.key_data.len(),
            other.user_data.len(),
            other.key_data.len()
        );

        let (found_self_user_data, found_other_user_data) = {
            let mut found_self_user_data: HashSet<&YubiHsm2BackendUserData> = HashSet::new();
            let mut found_other_user_data: HashSet<&YubiHsm2ConfigUserData> = HashSet::new();

            'outer: for other_user_data in other.user_data.iter() {
                for self_user_data in self.user_data.iter() {
                    if self_user_data == other_user_data
                        // NOTE: For administrative credentials we only track a subset of the entirety
                        // of available capabilities in the config (the set of capabilities we require).
                        // We only check if those are available in the set of capabilities (no complete
                        // match).
                        || (other_user_data.auth_type == AuthType::Admin
                            && other_user_data.authentication_key_id == self_user_data.id
                            && other_user_data
                                .capabilities
                                .as_ref()
                                .is_subset(self_user_data.capabilities.as_ref())
                            && other_user_data.domains == self_user_data.domains)
                    {
                        found_self_user_data.insert(self_user_data);
                        found_other_user_data.insert(other_user_data);
                        debug!(
                            "Found matching config item for backend user {}",
                            self_user_data.id
                        );
                        continue 'outer;
                    }
                }

                debug!(
                    "Unable to find a matching backend item for config user {}",
                    other_user_data.authentication_key_id
                );
                return false;
            }

            (found_self_user_data, found_other_user_data)
        };

        // The implicit wrap key must be present.
        if !self.key_data.iter().any(|key_data| {
            key_data.id == YubiHsm2Config::WRAP_KEY_ID
                && key_data.object_type == ObjectType::WrapKey
        }) {
            debug!("The implicitly defined wrap key is not present");
            return false;
        }

        let self_key_data_without_wrap_key = self.key_data.iter().filter(|key_data| {
            !(key_data.id == YubiHsm2Config::WRAP_KEY_ID
                && key_data.object_type == ObjectType::WrapKey)
        });

        let (found_self_user_key_data, found_other_user_key_data) = {
            let mut found_self_user_key_data: HashSet<(Id, ObjectType)> = HashSet::new();
            let mut found_other_user_key_data: HashSet<&YubiHsm2ConfigUserKeyData> = HashSet::new();

            'outer: for other_user_key_data in other.key_data.iter() {
                // For OpenPGP we require the asymmetric key (configured) and the OpenPGP
                // certificate (implicitly defined).
                if matches!(
                    other_user_key_data.key_setup.key_context(),
                    CryptographicKeyContext::OpenPgp { .. }
                ) {
                    let data = self_key_data_without_wrap_key
                        .clone()
                        .filter_map(|key_data| {
                            if key_data.id == *other_user_key_data.signing_key_id
                                && (key_data.object_type == ObjectType::AsymmetricKey
                                    || key_data.object_type == ObjectType::Opaque)
                            {
                                Some((key_data.id, key_data.object_type))
                            } else {
                                None
                            }
                        })
                        .collect::<HashSet<_>>();

                    if !(data.contains(&(*other_user_key_data.signing_key_id, ObjectType::Opaque))
                        && data.contains(&(
                            *other_user_key_data.signing_key_id,
                            ObjectType::AsymmetricKey,
                        )))
                    {
                        debug!(
                            "Unable to find a matching backend asymmetric key and certificate for OpenPGP key in config: {}",
                            other_user_key_data.authentication_key_id
                        );
                        return false;
                    }

                    debug!(
                        "Found matching backend item for OpenPGP key {} in config",
                        other_user_key_data.signing_key_id
                    );
                    found_self_user_key_data.extend(data);
                    found_other_user_key_data.insert(other_user_key_data);
                    continue 'outer;
                }

                // For all other key contexts we assume, that we do a direct comparison and that no
                // implicit objects need to be considered.
                for self_user_key_data in self.key_data.iter().filter(|key_data| {
                    !(key_data.id == YubiHsm2Config::WRAP_KEY_ID
                        && key_data.object_type == ObjectType::WrapKey)
                }) {
                    if self_user_key_data == other_user_key_data {
                        found_self_user_key_data
                            .insert((self_user_key_data.id, self_user_key_data.object_type));
                        found_other_user_key_data.insert(other_user_key_data);
                        debug!(
                            "Found matching config item for backend key {}",
                            other_user_key_data.signing_key_id
                        );
                        continue 'outer;
                    }
                }

                debug!(
                    "Unable to find a matching backend item for key {} in config",
                    other_user_key_data.authentication_key_id
                );
                return false;
            }

            (found_self_user_key_data, found_other_user_key_data)
        };

        let mut return_value = true;
        if found_self_user_data.len() != self.user_data.len() {
            debug!(
                "The following backend users have no matching item in the config: {}",
                HashSet::from_iter(self.user_data.iter())
                    .difference(&found_self_user_data)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return_value = false;
        }
        if found_other_user_data.len() != other.user_data.len() {
            debug!(
                "The following config users have no matching item in the backend: {}",
                HashSet::from_iter(other.user_data.iter())
                    .difference(&found_other_user_data)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return_value = false;
        }

        if found_self_user_key_data.len() != self_key_data_without_wrap_key.clone().count() {
            debug!(
                "The following backend keys have no matching item in the config: {}",
                HashSet::from_iter(
                    self_key_data_without_wrap_key
                        .clone()
                        .map(|key_data| { (key_data.id, key_data.object_type) })
                )
                .difference(&found_self_user_key_data)
                .map(|data| format!("{} ({})", data.0, data.1))
                .collect::<Vec<_>>()
                .join(", ")
            );
            return_value = false;
        }
        if found_other_user_key_data.len() != other.key_data.len() {
            debug!(
                "The following config keys have no matching item in the backend: {}",
                HashSet::from_iter(other.key_data.iter())
                    .difference(&found_other_user_key_data)
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            return_value = false;
        }

        if return_value {
            debug!("The backend state and config state are considered equal.");
        }

        return_value
    }
}

impl StateOriginInfo for YubiHsm2BackendState {
    fn state_name(&self) -> &str {
        Self::STATE_NAME
    }

    fn state_origin(&self) -> StateOrigin {
        StateOrigin::Backend
    }
}

/// Data about a YubiHSM2 user.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct YubiHsm2ConfigUserData {
    /// The ID of the authentication key.
    pub authentication_key_id: Id,

    /// The user type.
    pub auth_type: AuthType,

    /// The capabilities of the authentication key.
    pub capabilities: Capabilities,

    /// The optional domains of the authentication key.
    pub domains: Domains,
}

impl Display for YubiHsm2ConfigUserData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (auth type: {}; capabilities: {}; domains: {})",
            self.authentication_key_id, self.auth_type, self.capabilities, self.domains
        )?;

        Ok(())
    }
}

/// Data about a YubiHSM2 signing user associated with a signing key.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct YubiHsm2ConfigUserKeyData<'config> {
    /// The ID of the signing key.
    pub signing_key_id: &'config Id,

    /// The ID of the authentication key.
    pub authentication_key_id: &'config Id,

    /// The capabilities of the signing key.
    pub capabilities: Capabilities,

    /// The domain of the signing key.
    pub domain: &'config Domain,

    /// The setup of the signing key.
    pub key_setup: &'config SigningKeySetup,
}

impl<'config> Display for YubiHsm2ConfigUserKeyData<'config> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (authentication: {}; capabilities: {}; domain: {}; ",
            self.signing_key_id, self.authentication_key_id, self.capabilities, self.domain,
        )?;
        write!(f, "type: {}; ", self.key_setup.key_type())?;
        write!(
            f,
            "mechanisms: {}; ",
            self.key_setup
                .key_mechanisms()
                .iter()
                .map(|mechanism| mechanism.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )?;
        write!(f, "context: {}", self.key_setup.key_context())?;
        write!(f, ")")?;

        Ok(())
    }
}

/// The state of a YubiHSM2 configuration.
///
/// Tracks the available backend authentication keys, their capabilities and domains, as well as the
/// signing key setups associated with those authentication keys.
#[derive(Debug)]
pub struct YubiHsm2ConfigState<'config> {
    /// The user states.
    pub(crate) user_data: Vec<YubiHsm2ConfigUserData>,

    /// The key states.
    pub(crate) key_data: Vec<YubiHsm2ConfigUserKeyData<'config>>,
}

impl<'config> YubiHsm2ConfigState<'config> {
    /// The name of the origin for the state.
    pub const STATE_NAME: &'static str = "YubiHSM2 config";
}

impl<'config> From<&'config YubiHsm2Config> for YubiHsm2ConfigState<'config> {
    /// Creates a new [`YubiHsm2ConfigState`] from a [`YubiHsm2Config`].
    fn from(value: &'config YubiHsm2Config) -> Self {
        let mut user_data = Vec::new();
        let mut key_data = Vec::new();

        for mapping in value.mappings() {
            if let YubiHsm2UserMapping::Signing {
                authentication_key_id,
                key_setup,
                domain,
                signing_key_id,
                ..
            } = mapping
            {
                key_data.push(YubiHsm2ConfigUserKeyData {
                    signing_key_id,
                    authentication_key_id,
                    capabilities: mapping.capabilities(),
                    domain,
                    key_setup,
                })
            }

            user_data.push(YubiHsm2ConfigUserData {
                authentication_key_id: mapping.backend_user_id(),
                auth_type: mapping.into(),
                capabilities: mapping.capabilities(),
                domains: mapping.domains(),
            })
        }

        Self {
            user_data,
            key_data,
        }
    }
}

impl<'config> StateOriginInfo for YubiHsm2ConfigState<'config> {
    fn state_name(&self) -> &str {
        Self::STATE_NAME
    }

    fn state_origin(&self) -> StateOrigin {
        StateOrigin::Config
    }
}

/// The diff between [`YubiHsm2ConfigState`] and [`YubiHsm2BackendState`].
#[derive(Debug)]
pub struct YubiHsm2Diff<'config_state, 'backend_state, 'config_items> {
    /// The reference to the state of a NetHSM config.
    pub(crate) config: &'config_state YubiHsm2ConfigState<'config_items>,

    /// The reference to the state of a NetHSM backend.
    pub(crate) backend: &'backend_state YubiHsm2BackendState,
}

impl<'config_state, 'backend_state, 'config_items> StateDiff<'config_state, 'backend_state>
    for YubiHsm2Diff<'config_state, 'backend_state, 'config_items>
{
    fn diff(&self) -> StateDiffReport<'config_state, 'backend_state> {
        info!(
            "Creating state diff report between {} and {}",
            self.config.state_name(),
            self.backend.state_name()
        );

        if self.backend == self.config {
            debug!(
                "The states of {} and {} are considered equal.",
                self.config.state_name(),
                self.backend.state_name()
            );
            return StateDiffReport::Success;
        }

        warn!(
            "The states of {} and {} are not considered equal. Collecting discrepancies...",
            self.config.state_name(),
            self.backend.state_name()
        );
        let mut messages = Vec::new();

        {
            let mut matched_config_states = Vec::new();

            'outer: for backend_user_data in self.backend.user_data.iter() {
                for config_user_data in self.config.user_data.iter() {
                    // The states match, or these are administrative credentials.
                    //
                    // NOTE: For administrative credentials we only track a subset of the entirety
                    // of available capabilities in the config (the set of capabilities we require).
                    // We only check if those are available in the set of capabilities (no complete
                    // match).
                    if (backend_user_data == config_user_data)
                        || (config_user_data.auth_type == AuthType::Admin
                            && backend_user_data.id == config_user_data.authentication_key_id
                            && config_user_data
                                .capabilities
                                .as_ref()
                                .is_subset(backend_user_data.capabilities.as_ref())
                            && backend_user_data.domains == config_user_data.domains)
                    {
                        matched_config_states.push(config_user_data);
                        debug!(
                            "Found matching config item for backend user {}.",
                            backend_user_data.id
                        );
                        continue 'outer;
                    }

                    // The unique backend authentication key ID matches, but not the remaining data.
                    if backend_user_data.id == config_user_data.authentication_key_id {
                        matched_config_states.push(config_user_data);
                        messages.push(StateDiffFailure::Mismatch {
                            one: Box::new(self.config),
                            other: Box::new(self.backend),
                            one_state: config_user_data.to_string(),
                            other_state: backend_user_data.to_string(),
                        });
                        debug!(
                            "Found mismatching data in config and backend for authentication key {}.",
                            backend_user_data.id
                        );
                        continue 'outer;
                    }
                }

                // No match has been found.
                debug!(
                    "Unable to find a matching config item for backend user {}.",
                    backend_user_data.id
                );
                messages.push(StateDiffFailure::DoesNotExist {
                    one: Box::new(self.config),
                    other: Box::new(self.backend),
                    target: StateDiffFailureTarget::One,
                    state: backend_user_data.to_string(),
                });
            }

            // Unmatched config states.
            self.config
                .user_data
                .iter()
                .filter(|state| !matched_config_states.contains(state))
                .for_each(|config_user_data| {
                    debug!(
                        "Unable to find a matching backend item for config user {}.",
                        config_user_data.authentication_key_id
                    );
                    messages.push(StateDiffFailure::DoesNotExist {
                        one: Box::new(self.config),
                        other: Box::new(self.backend),
                        target: StateDiffFailureTarget::Other,
                        state: config_user_data.to_string(),
                    })
                });
        }

        {
            let implicit_wrap_key_state = implicit_wrap_key_state();
            let mut matched_config_states = Vec::new();

            // Check whether there is at least one wrap key.
            if !self
                .backend
                .key_data
                .iter()
                .any(|key_state| key_state.object_type == ObjectType::WrapKey)
            {
                debug!("Unable to find any wrap key in backend.");
                messages.push(StateDiffFailure::DoesNotExist {
                    one: Box::new(self.config),
                    other: Box::new(self.backend),
                    target: StateDiffFailureTarget::Other,
                    state: implicit_wrap_key_state.to_string(),
                });
            }

            'outer: for backend_user_key_data in self.backend.key_data.iter() {
                match backend_user_key_data.object_type {
                    ObjectType::WrapKey => {
                        // NOTE: The backup key is an implicit object, that is not part of the
                        // specific YubiHSM2 configuration object.
                        // It differs from signing keys, which is why we compare it here explicitly
                        // to ensure, that it matches our implicit
                        // expectations.
                        if backend_user_key_data != &implicit_wrap_key_state {
                            debug!("The implicit wrap key in the backend is not correct.");
                            messages.push(StateDiffFailure::Mismatch {
                                one: Box::new(self.config),
                                other: Box::new(self.backend),
                                one_state: implicit_wrap_key_state.to_string(),
                                other_state: backend_user_key_data.to_string(),
                            });
                        }
                    }
                    ObjectType::AsymmetricKey => {
                        for config_user_key_data in self.config.key_data.iter() {
                            // The states match.
                            if backend_user_key_data == config_user_key_data {
                                matched_config_states.push(config_user_key_data);
                                debug!(
                                    "Found matching config item for asymmetric key {} in backend.",
                                    backend_user_key_data.id
                                );
                                continue 'outer;
                            }

                            // The unique backend ID matches, but not the remaining data.
                            if &backend_user_key_data.id == config_user_key_data.signing_key_id {
                                matched_config_states.push(config_user_key_data);
                                messages.push(StateDiffFailure::Mismatch {
                                    one: Box::new(self.config),
                                    other: Box::new(self.backend),
                                    one_state: config_user_key_data.to_string(),
                                    other_state: backend_user_key_data.to_string(),
                                });
                                debug!(
                                    "Found mismatching data in config and backend for asymmetric key {}.",
                                    backend_user_key_data.id
                                );
                                continue 'outer;
                            }
                        }

                        // No match has been found.
                        debug!(
                            "Unable to find a matching config item for asymmetric key {} in backend.",
                            backend_user_key_data.id
                        );
                        messages.push(StateDiffFailure::DoesNotExist {
                            one: Box::new(self.config),
                            other: Box::new(self.backend),
                            target: StateDiffFailureTarget::One,
                            state: backend_user_key_data.to_string(),
                        });
                    }
                    // NOTE: Certificates (e.g. OpenPGP) are added as opaque data with the same
                    // object ID as the key they are created from.
                    ObjectType::Opaque => {
                        for config_user_key_data in self.config.key_data.iter() {
                            // The states match.
                            if (backend_user_key_data == config_user_key_data)
                                || (backend_user_key_data.id
                                    == *config_user_key_data.signing_key_id
                                    && backend_user_key_data.capabilities
                                        == Capabilities::from(
                                            vec![Capability::ExportableUnderWrap].as_slice(),
                                        )
                                    && backend_user_key_data.domains
                                        == Domains::from(*config_user_key_data.domain)
                                    && backend_user_key_data.label == Label::from(&[0; 40]))
                            {
                                matched_config_states.push(config_user_key_data);
                                debug!(
                                    "Found matching config item for opaque object {} in backend.",
                                    backend_user_key_data.id
                                );
                                continue 'outer;
                            }

                            // The unique backend ID matches, but not the remaining data.
                            if &backend_user_key_data.id == config_user_key_data.signing_key_id {
                                matched_config_states.push(config_user_key_data);
                                messages.push(StateDiffFailure::Mismatch {
                                    one: Box::new(self.config),
                                    other: Box::new(self.backend),
                                    one_state: config_user_key_data.to_string(),
                                    other_state: backend_user_key_data.to_string(),
                                });
                                debug!(
                                    "Found mismatching data in config and backend for opaque object {}.",
                                    backend_user_key_data.id
                                );
                                continue 'outer;
                            }
                        }

                        // No match has been found.
                        debug!(
                            "Unable to find a matching config item for opaque object {} in backend.",
                            backend_user_key_data.id
                        );
                        messages.push(StateDiffFailure::DoesNotExist {
                            one: Box::new(self.config),
                            other: Box::new(self.backend),
                            target: StateDiffFailureTarget::One,
                            state: backend_user_key_data.to_string(),
                        });
                    }
                    ObjectType::AuthenticationKey
                    | ObjectType::HmacKey
                    | ObjectType::SymmetricKey
                    | ObjectType::Template
                    | ObjectType::OtpAeakey => {
                        // NOTE: We do not support these key types.
                        warn!(
                            "Found unsupported key type ({}) for backend key {}",
                            backend_user_key_data.object_type, backend_user_key_data.id
                        );
                        messages.push(StateDiffFailure::DoesNotExist {
                            one: Box::new(self.config),
                            other: Box::new(self.backend),
                            target: StateDiffFailureTarget::One,
                            state: backend_user_key_data.to_string(),
                        });
                    }
                }
            }

            // Unmatched config states.
            self.config
                .key_data
                .iter()
                .filter(|state| !matched_config_states.contains(state))
                .for_each(|key_data| {
                    debug!(
                        "Unable to find a matching backend item for config key {}",
                        key_data.signing_key_id
                    );
                    messages.push(StateDiffFailure::DoesNotExist {
                        one: Box::new(self.config),
                        other: Box::new(self.backend),
                        target: StateDiffFailureTarget::Other,
                        state: key_data.to_string(),
                    })
                });
        }

        StateDiffReport::Failure { messages }
    }
}

#[cfg(all(test, feature = "_yubihsm2-mockhsm"))]
mod tests {
    use std::{collections::BTreeSet, thread::current};

    use insta::{assert_snapshot, with_settings};
    use log::{LevelFilter, info};
    use rstest::{fixture, rstest};
    use signstar_common::logging::setup_logging;
    use signstar_crypto::{
        AdministrativeSecretHandling,
        NonAdministrativeSecretHandling,
        key::{
            CryptographicKeyContext,

            SigningKeySetup,
            base::{KeyMechanism, KeyType, SignatureType},
        },
        openpgp::OpenPgpUserIdList,
        passphrase::Passphrase,
    };
    use signstar_yubihsm2::{
        Connection,
        Credentials,
        object::{Domain, WrapKey, WrapKeyFromPassphrase},
        yubihsm::{Client, Connector},
    };
    use testresult::TestResult;

    use super::*;
    use crate::{
        admin_credentials::AdminCredentials,
        config::{Config, ConfigBuilder, SystemConfig},
        state::{StateDiff, StateDiffReport},
        yubihsm2::{
            YubiHsm2Config,
            YubiHsm2UserMapping,
            admin_credentials::YubiHsm2AdminCredentials,
        },
    };

    const SNAPSHOT_PATH: &str = "fixtures/state/";

    /// Creates a MockHSM [`Connector`].
    #[fixture]
    fn connector() -> Connector {
        Connector::mockhsm()
    }

    /// Creates a default [`YubiHsm2AdminCredentials`].
    #[fixture]
    fn yubihsm2_admin_credentials() -> TestResult<YubiHsm2AdminCredentials> {
        Ok(YubiHsm2AdminCredentials::new(
                1,
                Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
                vec![
                    Credentials::new(1, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
                ]
            )?)
    }

    /// Creates a basic, default [`YubiHsm2Config`].
    #[fixture]
    fn yubihsm2_config() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            ]),
        )?)
    }

    /// Creates a default [`Confi`].
    #[fixture]
    fn config(yubihsm2_config: TestResult<YubiHsm2Config>) -> TestResult<Config> {
        Ok(ConfigBuilder::new(SystemConfig::new(
            1,
            AdministrativeSecretHandling::Plaintext,
            NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::from_iter([]),
        )?)
        .set_yubihsm2_config(yubihsm2_config?)
        .finish()?)
    }

    /// Creates a [`YubiHsm2Config`], without non-admin users.
    #[fixture]
    fn yubihsm2_config_no_non_admin_users() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([Connection::Mock]),
            BTreeSet::from_iter([YubiHsm2UserMapping::Admin {
                authentication_key_id: 1,
            }]),
        )?)
    }

    /// Creates [`YubiHsm2Config`] with fully mismatching user IDs (compared to the default).
    #[fixture]
    fn yubihsm2_config_fully_mismatching_ids() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 7 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 9,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 8,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 10,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 11,
                    signing_key_id: 2,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            ]),
        )?)
    }

    /// Creates [`YubiHsm2Config`] with mismatching roles (compared to the default).
    #[fixture]
    fn yubihsm2_config_mismatching_roles() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 5 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 1,
                    signing_key_id: 1,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            ]),
        )?)
    }

    /// Creates [`YubiHsm2Config`] with mismatching signing key ID (compared to the default).
    #[fixture]
    fn yubihsm2_config_mismatching_signing_key_id() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 2,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            ]),
        )?)
    }

    /// Creates a [`YubiHsm2Config`] with an additional signing key (compared to the default).
    #[fixture]
    fn yubihsm2_config_additional_signing_key() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 6,
                    signing_key_id: 2,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McBehface <foobar@mcbehface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGoUTEsi84KZGtD3jqSDbQxkLQPqSJsdc0mxQjODm/Oy user@host".parse()?,
                    system_user: "yubihsm2-signing-user-2".parse()?,
                    domain: Domain::Two,
                },
            ]),
        )?)
    }

    /// Creates [`YubiHsm2Config`] with a mismatching signing key domain (compared to the default).
    #[fixture]
    fn yubihsm2_config_mismatching_signing_key_domain() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            notations: Default::default(),
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::Two,
                }
            ]),
        )?)
    }

    #[fixture]
    fn yubihsm2_mappings() -> TestResult<[YubiHsm2UserMapping; 5]> {
        Ok([
                    YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                    YubiHsm2UserMapping::Backup{
                        authentication_key_id: "2".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                        system_user: "backup-user".parse()?,
                        wrapping_key_id: "1".parse()?,
                    },
                    YubiHsm2UserMapping::AuditLog {
                        authentication_key_id: "3".parse()?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                        system_user: "metrics-user".parse()?,
                    },
                    YubiHsm2UserMapping::HermeticAuditLog {
                        authentication_key_id: "4".parse()?,
                        system_user: "hermetic-metrics".parse()?,
                    },
                    YubiHsm2UserMapping::Signing {
                        authentication_key_id: "5".parse()?,
                        signing_key_id: "1".parse()?,
                        key_setup: SigningKeySetup::new(
                            KeyType::Curve25519,
                            vec![KeyMechanism::EdDsaSignature],
                            None,
                            SignatureType::EdDsa,
                            CryptographicKeyContext::OpenPgp {
                                notations: Default::default(),
                                user_ids: OpenPgpUserIdList::new(vec![
                                    "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                                ])?,
                                version: "v4".parse()?,
                            },
                        )?,
                        ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                        system_user: "signing-user".parse()?,
                        domain: Domain::One,
                    }
                ])
    }

    /// Returns a set of default non-administrative credentials (used with the default YubiHSM2
    /// config).
    #[fixture]
    fn yubihsm2_non_admin_credentials() -> TestResult<Vec<Credentials>> {
        Ok(vec![
            Credentials::new("2".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("3".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("4".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("5".parse()?, Passphrase::generate(Some(50))),
        ])
    }

    /// A helper struct to expose [`Config`], [`Connector`] and [`YubiHsm2AdminCredentials`].
    struct ConfigConnectorCreds {
        pub config: Config,
        pub connector: Connector,
        pub admin_creds: YubiHsm2AdminCredentials,
    }

    /// Creates a new, pre-populated YubiHSM2 backend and accompanying non-admin creds.
    ///
    /// The data in the backend is based on the default YubiHSM2 config and non-admin credentials
    /// fixtures.
    #[fixture]
    fn config_connector_creds(
        connector: Connector,
        config: TestResult<Config>,
        yubihsm2_admin_credentials: TestResult<YubiHsm2AdminCredentials>,
        yubihsm2_non_admin_credentials: TestResult<Vec<Credentials>>,
    ) -> TestResult<ConfigConnectorCreds> {
        let config = config?;
        let admin_creds = yubihsm2_admin_credentials?;
        let non_admin_creds = yubihsm2_non_admin_credentials?;

        let Some(backend) = YubiHsm2Backend::new(connector.clone(), &admin_creds, &config)? else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };
        backend.sync(&non_admin_creds)?;

        Ok(ConfigConnectorCreds {
            config,
            connector,
            admin_creds,
        })
    }

    /// Ensures that [`YubiHsm2ConfigUserData`] is displayed correctly.
    #[rstest]
    #[case::single_cap_single_domain(
        AuthType::Signing,
        Capabilities::from(vec![Capability::SignEddsa].as_slice()),
        Domains::from(vec![Domain::One].as_slice()),
        "1 (auth type: signing; capabilities: sign-eddsa; domains: 1)"
    )]
    #[case::multi_cap_multi_domain(
        AuthType::Signing,
        Capabilities::from(vec![Capability::SignEddsa, Capability::SignEcdsa].as_slice()),
        Domains::from(vec![Domain::One, Domain::Two].as_slice()),
        "1 (auth type: signing; capabilities: sign-ecdsa, sign-eddsa; domains: 1, 2)"
    )]
    #[case::multi_cap_single_domain(
        AuthType::Signing,
        Capabilities::from(vec![Capability::SignEddsa, Capability::SignEcdsa].as_slice()),
        Domains::from(vec![Domain::One].as_slice()),
        "1 (auth type: signing; capabilities: sign-ecdsa, sign-eddsa; domains: 1)"
    )]
    fn yubihsm2_config_user_data_display(
        #[case] auth_type: AuthType,
        #[case] capabilities: Capabilities,
        #[case] domains: Domains,
        #[case] display: &str,
    ) -> TestResult {
        let data = YubiHsm2ConfigUserData {
            authentication_key_id: "1".parse()?,
            auth_type,
            capabilities,
            domains,
        };

        assert_eq!(format!("{data}"), display);

        Ok(())
    }

    /// Ensures that [`YubiHsm2ConfigUserKeyData`] is displayed correctly.
    #[test]
    fn yubihsm2_config_user_key_data_display() -> TestResult {
        let capabilities = Capabilities::from(vec![Capability::SignEddsa].as_slice());
        let domain = Domain::One;
        let key_setup = SigningKeySetup::new(
            KeyType::Curve25519,
            vec![KeyMechanism::EdDsaSignature],
            None,
            SignatureType::EdDsa,
            CryptographicKeyContext::OpenPgp {
                notations: Default::default(),
                user_ids: vec!["John Doe <john.doe@example.org>".to_string()].try_into()?,
                version: "4".parse()?,
            },
        )?;
        let display = "1 (authentication: 1; capabilities: sign-eddsa; domain: 1; type: Curve25519; mechanisms: EdDsaSignature; context: OpenPGP (Version: 4; User IDs: \"John Doe <john.doe@example.org>\"))";
        let data = YubiHsm2ConfigUserKeyData {
            authentication_key_id: &"1".parse()?,
            signing_key_id: &"1".parse()?,
            capabilities,
            domain: &domain,
            key_setup: &key_setup,
        };

        assert_eq!(data.to_string(), display);

        Ok(())
    }

    /// Ensures that [`YubiHsm2ConfigState`] can be created from [`YubiHsm2Config`].
    #[rstest]
    fn yubihsm2_config_state_from_yubihsm_config(
        yubihsm2_config: TestResult<YubiHsm2Config>,
        yubihsm2_mappings: TestResult<[YubiHsm2UserMapping; 5]>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let yubihsm2_config = yubihsm2_config?;
        let yubihsm2_mappings = yubihsm2_mappings?;
        let state = YubiHsm2ConfigState::from(&yubihsm2_config);

        for authentication_key_id in yubihsm2_mappings
            .iter()
            .map(|mapping| mapping.backend_user_id())
        {
            debug!(
                "Ensuring that the YubiHSM2 authentication key ID {authentication_key_id} can be found in the YubiHSM2 config state."
            );
            assert!(
                state
                    .user_data
                    .iter()
                    .any(|user_data| user_data.authentication_key_id == authentication_key_id)
            );
        }

        for (authentication_key_id, signing_key_id) in
            yubihsm2_mappings.iter().filter_map(|mapping| {
                if let YubiHsm2UserMapping::Signing {
                    authentication_key_id,
                    signing_key_id,
                    ..
                } = mapping
                {
                    Some((authentication_key_id, signing_key_id))
                } else {
                    None
                }
            })
        {
            debug!(
                "Ensuring that the YubiHSM2 authentication key ID {authentication_key_id} and signing key ID {signing_key_id} can be found in the YubiHSM2 config state."
            );
            assert!(
                state
                    .key_data
                    .iter()
                    .any(|data| data.authentication_key_id == authentication_key_id
                        && data.signing_key_id == signing_key_id)
            );
        }

        Ok(())
    }

    /// Ensures, that [`YubiHsm2ConfigState::state_name`] returns the correct data.
    #[rstest]
    fn yubihsm_config_state_state_name(yubihsm2_config: TestResult<YubiHsm2Config>) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let yubihsm2_config = yubihsm2_config?;
        let state = YubiHsm2ConfigState::from(&yubihsm2_config);

        assert_eq!(state.state_name(), YubiHsm2ConfigState::STATE_NAME);

        Ok(())
    }

    /// Ensures, that [`YubiHsm2ConfigState::state_name`] returns the correct data.
    #[rstest]
    fn yubihsm_config_state_state_origin(
        yubihsm2_config: TestResult<YubiHsm2Config>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let yubihsm2_config = yubihsm2_config?;
        let state = YubiHsm2ConfigState::from(&yubihsm2_config);

        assert_eq!(state.state_origin(), StateOrigin::Config);

        Ok(())
    }

    /// Ensures that [`YubiHsm2Diff::diff`] fails on mismatching backend and config.
    #[rstest]
    #[case::no_non_admin_users(
        yubihsm2_config_no_non_admin_users()?,
        "State diff of pre-populated YubiHSM2 backend and mismatching YubiHSM2 config: No non-admin users.",
    )]
    #[case::fully_mismatching_user_ids(
        yubihsm2_config_fully_mismatching_ids()?,
        "State diff of pre-populated YubiHSM2 backend and mismatching YubiHSM2 config: Fully mismatching user IDs.",
    )]
    #[case::fully_mismatching_roles(
        yubihsm2_config_mismatching_roles()?,
        "State diff of pre-populated YubiHSM2 backend and mismatching YubiHSM2 config: Mismatching user roles.",
    )]
    #[case::mismatching_signing_key_id(
        yubihsm2_config_mismatching_signing_key_id()?,
        "State diff of pre-populated YubiHSM2 backend and mismatching YubiHSM2 config: Mismatching signing key ID.",
    )]
    #[case::mismatching_additional_signing_key(
        yubihsm2_config_additional_signing_key()?,
        "State diff of pre-populated YubiHSM2 backend and mismatching YubiHSM2 config: Additional signing key.",
    )]
    #[case::mismatching_mismatching_signing_key_domain(
        yubihsm2_config_mismatching_signing_key_domain()?,
        "State diff of pre-populated YubiHSM2 backend and mismatching YubiHSM2 config: Mismatching signing key domain.",
    )]
    fn yubihsm2_diff_diff_fails_on_mismatching_data(
        config_connector_creds: TestResult<ConfigConnectorCreds>,
        #[case] yubihsm2_config: YubiHsm2Config,
        #[case] description: &str,
    ) -> TestResult {
        let config_connector_creds = config_connector_creds?;

        let Some(backend) = YubiHsm2Backend::new(
            config_connector_creds.connector.clone(),
            &config_connector_creds.admin_creds,
            &config_connector_creds.config,
        )?
        else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };
        let backend_state = YubiHsm2BackendState::try_from(&backend)?;
        let yubihsm2_config_state = YubiHsm2ConfigState::from(&yubihsm2_config);

        let yubihsm2_diff = YubiHsm2Diff {
            config: &yubihsm2_config_state,
            backend: &backend_state,
        };
        let diff = yubihsm2_diff.diff();
        with_settings!({
            description => description,
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), diff);
        });
        info!("StateDiffReport:\n{diff}");
        assert!(matches!(diff, StateDiffReport::Failure { .. }));

        Ok(())
    }

    /// Ensures, that [`YubiHsm2Diff::diff`] fails on an unprovisioned backend.
    #[rstest]
    fn yubihsm2_diff_diff_fails_on_unprovisioned_backend(
        connector: Connector,
        yubihsm2_config: TestResult<YubiHsm2Config>,
        yubihsm2_admin_credentials: TestResult<YubiHsm2AdminCredentials>,
    ) -> TestResult {
        let yubihsm2_admin_credentials = yubihsm2_admin_credentials?;
        let yubihsm2_config = yubihsm2_config?;
        let config = ConfigBuilder::new(SystemConfig::new(
            1,
            AdministrativeSecretHandling::Plaintext,
            NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::from_iter([]),
        )?)
        .set_yubihsm2_config(yubihsm2_config.clone())
        .finish()?;
        let Some(backend) =
            YubiHsm2Backend::new(connector.clone(), &yubihsm2_admin_credentials, &config)?
        else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };
        let backend_state = YubiHsm2BackendState::try_from(&backend)?;
        let yubihsm2_config_state = YubiHsm2ConfigState::from(&yubihsm2_config);

        let yubihsm2_diff = YubiHsm2Diff {
            config: &yubihsm2_config_state,
            backend: &backend_state,
        };
        let diff = yubihsm2_diff.diff();
        info!("StateDiffReport:\n{diff}");
        assert!(matches!(diff, StateDiffReport::Failure { .. }));

        with_settings!({
            description => "State diff of unprovisioned YubiHSM2 backend and YubiHSM2 config.",
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), diff);
        });

        Ok(())
    }

    /// Ensures, that [`YubiHsm2Diff::diff`] fails on a provisioned backend, where the wrap key has
    /// a mismatching key ID.
    #[rstest]
    fn yubihsm2_diff_diff_fails_on_mismatching_wrap_key_id(
        config_connector_creds: TestResult<ConfigConnectorCreds>,
    ) -> TestResult {
        let config_connector_creds = config_connector_creds?;
        let config = config_connector_creds.config;

        // Delete the default wrap key.
        let client = Client::open(
            config_connector_creds.connector.clone(),
            config_connector_creds
                .admin_creds
                .administrators()
                .first()
                .expect("there to be at least one administrator credentials")
                .into(),
            false,
        )?;
        client.delete_object(YubiHsm2Config::WRAP_KEY_ID, (&ObjectType::WrapKey).into())?;

        // Add a new wrap key, with mismatching key ID.
        let passphrase = config_connector_creds.admin_creds.backup_passphrase();
        let wrapping_key: WrapKey =
            WrapKeyFromPassphrase::new(passphrase, WrapKeyKind::Aes256)?.try_into()?;
        client.put_wrap_key(
            2,
            (&Label::from(&[0u8; 40])).into(),
            (&Domains::all()).into(),
            (&Capabilities::from(YubiHsm2UserMapping::CAP_BACKUP)).into(),
            (&Capabilities::from(YubiHsm2UserMapping::CAP_BACKUP)).into(),
            (&WrapKeyKind::default()).into(),
            &wrapping_key,
        )?;

        // Diff config and backend state.
        let Some(backend) = YubiHsm2Backend::new(
            config_connector_creds.connector.clone(),
            &config_connector_creds.admin_creds,
            &config,
        )?
        else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };
        let backend_state = YubiHsm2BackendState::try_from(&backend)?;

        let Some(yubihsm2_config) = config.yubihsm2() else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };
        let yubihsm2_config_state = YubiHsm2ConfigState::from(yubihsm2_config);

        let yubihsm2_diff = YubiHsm2Diff {
            config: &yubihsm2_config_state,
            backend: &backend_state,
        };
        let diff = yubihsm2_diff.diff();
        info!("StateDiffReport:\n{diff}");
        assert!(matches!(diff, StateDiffReport::Failure { .. }));

        with_settings!({
            description => "State diff of provisioned YubiHSM2 backend and YubiHSM2 config: Mismatching wrap key ID.",
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), diff);
        });

        Ok(())
    }

    /// Ensures, that [`YubiHsm2Diff::diff`] succeeds (against a MockHSM backend).
    #[rstest]
    fn yubihsm2_diff_diff_succeeds(
        connector: Connector,
        yubihsm2_admin_credentials: TestResult<YubiHsm2AdminCredentials>,
        yubihsm2_non_admin_credentials: TestResult<Vec<Credentials>>,
        config: TestResult<Config>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let yubihsm2_admin_credentials = yubihsm2_admin_credentials?;
        let yubihsm2_non_admin_credentials = yubihsm2_non_admin_credentials?;
        let config = config?;

        let Some(yubihsm2_config) = config.yubihsm2() else {
            panic!("There should be a YubiHSM2 config");
        };
        let yubihsm2_config_state = YubiHsm2ConfigState::from(yubihsm2_config);
        let Some(backend) = YubiHsm2Backend::new(connector, &yubihsm2_admin_credentials, &config)?
        else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };

        let backend_state = YubiHsm2BackendState::try_from(&backend)?;
        let yubihsm2_diff = YubiHsm2Diff {
            config: &yubihsm2_config_state,
            backend: &backend_state,
        };
        let diff = yubihsm2_diff.diff();
        info!("StateDiffReport:\n{diff}");
        assert!(matches!(diff, StateDiffReport::Failure { .. }));

        backend.sync(&yubihsm2_non_admin_credentials)?;

        let backend_state = YubiHsm2BackendState::try_from(&backend)?;
        let yubihsm2_diff = YubiHsm2Diff {
            config: &yubihsm2_config_state,
            backend: &backend_state,
        };
        let diff = yubihsm2_diff.diff();
        info!("StateDiffReport:\n{diff}");
        assert!(matches!(diff, StateDiffReport::Success));

        // Re-run the sync
        backend.sync(&yubihsm2_non_admin_credentials)?;

        let backend_state = YubiHsm2BackendState::try_from(&backend)?;
        let yubihsm2_diff = YubiHsm2Diff {
            config: &yubihsm2_config_state,
            backend: &backend_state,
        };
        let diff = yubihsm2_diff.diff();
        info!("StateDiffReport:\n{diff}");
        assert!(matches!(diff, StateDiffReport::Success));

        Ok(())
    }
}
