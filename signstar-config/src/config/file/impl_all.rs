//! Impls for [`UserBackendConnection`] and [`Config`] when using all HSM backends.
//!
//! # Note
//!
//! This module with `impl` blocks is only used, if all HSM backend features are used:
//!
//! - `nethsm`: for NetHSM backends
//! - `yubihsm2`: for YubiHSM2 backends

use signstar_crypto::{
    AdministrativeSecretHandling,
    NonAdministrativeSecretHandling,
    traits::UserWithPassphrase,
};

use crate::{
    SystemUserId,
    config::{
        Config,
        ConfigBuilder,
        MappingBackendUserSecrets,
        MappingSystemUserId,
        SystemConfig,
        UserBackendConnection,
        UserBackendConnectionFilter,
        traits::NonAdminBackendUserIdFilter,
    },
    nethsm::NetHsmUserMapping,
    yubihsm2::YubiHsm2UserMapping,
};

impl UserBackendConnection {
    /// Returns the administrative secret handling of this [`UserBackendConnection`].
    pub fn admin_secret_handling(&self) -> AdministrativeSecretHandling {
        match self {
            Self::NetHsm {
                admin_secret_handling,
                ..
            } => *admin_secret_handling,
            Self::YubiHsm2 {
                admin_secret_handling,
                ..
            } => *admin_secret_handling,
        }
    }

    /// Returns the non-administrative secret handling of this [`UserBackendConnection`].
    pub fn non_admin_secret_handling(&self) -> NonAdministrativeSecretHandling {
        match self {
            Self::NetHsm {
                non_admin_secret_handling,
                ..
            } => *non_admin_secret_handling,
            Self::YubiHsm2 {
                non_admin_secret_handling,
                ..
            } => *non_admin_secret_handling,
        }
    }

    /// Creates on-disk secrets for non-administrative backend users of the mapping.
    ///
    /// # Note
    ///
    /// Delegates to [`MappingBackendUserSecrets::create_non_admin_backend_user_secrets`].
    ///
    /// # Errors
    ///
    /// Returns an error if [`MappingBackendUserSecrets::create_non_admin_backend_user_secrets`]
    /// fails.
    pub fn create_non_admin_backend_user_secrets(
        &self,
    ) -> Result<Option<Vec<Box<dyn UserWithPassphrase>>>, crate::Error> {
        match self {
            Self::NetHsm {
                non_admin_secret_handling,
                mapping,
                ..
            } => mapping.create_non_admin_backend_user_secrets(*non_admin_secret_handling),
            Self::YubiHsm2 {
                non_admin_secret_handling,
                mapping,
                ..
            } => mapping.create_non_admin_backend_user_secrets(*non_admin_secret_handling),
        }
    }

    /// Loads secrets for each backend user matching a `filter`.
    ///
    /// # Note
    ///
    /// Delegates to [`MappingBackendUserSecrets::load_non_admin_backend_user_secrets`].
    ///
    /// # Errors
    ///
    /// Returns an error if [`MappingBackendUserSecrets::load_non_admin_backend_user_secrets`]
    /// fails.
    pub fn load_non_admin_backend_user_secrets(
        &self,
        filter: NonAdminBackendUserIdFilter,
    ) -> Result<Option<Vec<Box<dyn UserWithPassphrase>>>, crate::Error> {
        match self {
            Self::NetHsm {
                non_admin_secret_handling,
                mapping,
                ..
            } => mapping.load_non_admin_backend_user_secrets(*non_admin_secret_handling, filter),
            Self::YubiHsm2 {
                non_admin_secret_handling,
                mapping,
                ..
            } => mapping.load_non_admin_backend_user_secrets(*non_admin_secret_handling, filter),
        }
    }
}

impl Config {
    /// Returns the optional [`UserBackendConnection`] matching a [`SystemUserId`].
    pub fn user_backend_connection(&self, user: &SystemUserId) -> Option<UserBackendConnection> {
        if let Some(nethsm_config) = self.nethsm.as_ref()
            && let Some(mapping) = nethsm_config
                .mappings()
                .iter()
                .find(|mapping| mapping.system_user_id().is_some_and(|id| id == user))
        {
            return Some(UserBackendConnection::NetHsm {
                admin_secret_handling: *self.system.admin_secret_handling(),
                non_admin_secret_handling: *self.system.non_admin_secret_handling(),
                connections: nethsm_config.connections().clone(),
                mapping: mapping.clone(),
            });
        }

        if let Some(yubihsm2_config) = self.yubihsm2.as_ref()
            && let Some(mapping) = yubihsm2_config
                .mappings()
                .iter()
                .find(|mapping| mapping.system_user_id().is_some_and(|id| id == user))
        {
            return Some(UserBackendConnection::YubiHsm2 {
                admin_secret_handling: *self.system.admin_secret_handling(),
                non_admin_secret_handling: *self.system.non_admin_secret_handling(),
                connections: yubihsm2_config.connections().clone(),
                mapping: mapping.clone(),
            });
        }

        None
    }

    /// Returns a list of [`UserBackendConnection`] objects matching a `filter`.
    ///
    /// Using the [`UserBackendConnectionFilter`] `filter` it is possible to only return
    /// administrative or non-administrative, or all [`UserBackendConnection`] objects..
    pub fn user_backend_connections(
        &self,
        filter: UserBackendConnectionFilter,
    ) -> Vec<UserBackendConnection> {
        let mut user_backend_connections = Vec::new();

        if let Some(nethsm_config) = &self.nethsm {
            let mappings = match filter {
                UserBackendConnectionFilter::All => {
                    nethsm_config.mappings().iter().collect::<Vec<_>>()
                }
                UserBackendConnectionFilter::Admin => nethsm_config
                    .mappings()
                    .iter()
                    .filter(|mapping| matches!(mapping, NetHsmUserMapping::Admin(_)))
                    .collect::<Vec<_>>(),
                UserBackendConnectionFilter::NonAdmin => nethsm_config
                    .mappings()
                    .iter()
                    .filter(|mapping| !matches!(mapping, NetHsmUserMapping::Admin(_)))
                    .collect::<Vec<_>>(),
            };
            for mapping in mappings {
                user_backend_connections.push(UserBackendConnection::NetHsm {
                    admin_secret_handling: *self.system.admin_secret_handling(),
                    non_admin_secret_handling: *self.system.non_admin_secret_handling(),
                    connections: nethsm_config.connections().clone(),
                    mapping: mapping.clone(),
                });
            }
        }

        if let Some(yubihsm2_config) = &self.yubihsm2 {
            let mappings = match filter {
                UserBackendConnectionFilter::All => {
                    yubihsm2_config.mappings().iter().collect::<Vec<_>>()
                }
                UserBackendConnectionFilter::Admin => yubihsm2_config
                    .mappings()
                    .iter()
                    .filter(|mapping| matches!(mapping, YubiHsm2UserMapping::Admin { .. }))
                    .collect::<Vec<_>>(),
                UserBackendConnectionFilter::NonAdmin => yubihsm2_config
                    .mappings()
                    .iter()
                    .filter(|mapping| !matches!(mapping, YubiHsm2UserMapping::Admin { .. }))
                    .collect::<Vec<_>>(),
            };
            for mapping in mappings {
                user_backend_connections.push(UserBackendConnection::YubiHsm2 {
                    admin_secret_handling: *self.system.admin_secret_handling(),
                    non_admin_secret_handling: *self.system.non_admin_secret_handling(),
                    connections: yubihsm2_config.connections().clone(),
                    mapping: mapping.clone(),
                });
            }
        }

        user_backend_connections
    }
}

impl ConfigBuilder {
    /// Creates a new [`ConfigBuilder`].
    pub fn new(system: SystemConfig) -> Self {
        Self(Config {
            system,
            nethsm: None,
            yubihsm2: None,
        })
    }
}
