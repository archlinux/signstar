//! Functionality when support for NetHSM backends is compiled in.

use log::{error, info, warn};
use signstar_common::traits::BackendCheck;
use signstar_config::{
    admin_credentials::AdminCredentials,
    config::{BackendType, UserBackendConnection, UserBackendConnectionFilter},
    nethsm::{
        NetHsmAdminCredentials,
        NetHsmBackend,
        NetHsmConfig,
        nethsm_export::{FullCredentials, NetHsm, NetHsmError, UserId},
    },
};

use crate::{Error, backend::BackendSync};

/// The available NetHSM connections.
#[derive(Debug)]
pub struct AvailableNetHsmConnections(pub(crate) Vec<NetHsm>);

impl AvailableNetHsmConnections {
    /// Creates a new [`AvailableNetHsmConnections`] from a [`NetHsmConfig`].
    ///
    /// # Note
    ///
    /// Only considers available connections (see [`BackendCheck::is_available`]).
    ///
    /// Opportunistically creates as many [`NetHsm`] connections as possible and does not fail on
    /// errors returned by [`NetHsm::new`] but instead emits them as error messages.
    fn new(config: &NetHsmConfig) -> Self {
        info!("Querying all NetHSM connections for availability...");
        let connections = config
            .connections()
            .iter()
            .filter_map(|connection| {
                if connection.is_available() {
                    // Opportunistically create the network connection, as we want to connect to as
                    // many as possible.
                    match NetHsm::new(connection.clone(), None, None, None) {
                        Err(error) => {
                            error!(
                                "Skipping NetHSM connection {} due to an error: {error}",
                                connection.url()
                            );
                            None
                        }
                        Ok(nethsm) => {
                            info!("Adding available NetHSM connection {}", connection.url());
                            Some(nethsm)
                        }
                    }
                } else {
                    warn!(
                        "Skipping unavailable NetHSM connection {}",
                        connection.url()
                    );
                    None
                }
            })
            .collect();

        Self(connections)
    }
}

impl<'config> BackendSync<'config> {
    /// Loads [`NetHsmAdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if [`NetHsmAdminCredentials::load`] fails.
    fn load_nethsm_admin_credentials(&self) -> Result<NetHsmAdminCredentials, Error> {
        Ok(NetHsmAdminCredentials::load(
            *self.config().system().admin_secret_handling(),
        )?)
    }

    /// Creates new credentials for all non-administrative NetHSM backend users.
    ///
    /// # Errors
    ///
    /// Returns an error, if the non-administrative credentials for a specific user cannot be
    /// created.
    fn create_nethsm_non_admin_credentials(&self) -> Result<Vec<FullCredentials>, Error> {
        let user_backend_connections = self.config().user_backend_connections(&[
            UserBackendConnectionFilter::NonAdmin,
            UserBackendConnectionFilter::Backend(BackendType::NetHsm),
        ]);

        let credentials_list = {
            let mut creds_list = Vec::new();
            for user_backend_connection in user_backend_connections {
                if let UserBackendConnection::NetHsm { .. } = &user_backend_connection
                    && let Some(creds_per_user) =
                        user_backend_connection.create_non_admin_backend_user_secrets()?
                {
                    for credentials in creds_per_user {
                        creds_list.push(FullCredentials::new(
                            // NOTE: Here we cannot fail, because we already know that
                            // the user name is valid.
                            UserId::try_from(credentials.user()).map_err(|source| {
                                signstar_config::Error::NetHsm(NetHsmError::User(source))
                            })?,
                            credentials.passphrase().clone(),
                        ));
                    }
                }
            }

            creds_list
        };

        Ok(credentials_list)
    }

    /// Syncs all available NetHSM backends.
    ///
    /// Returns early success, if there is no NetHSM section in the Signstar config.
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - [`NetHsmAdminCredentials::load`] cannot load administrative credentials
    /// - a [`NetHsmBackend`] cannot be created for a connection
    /// - running [`NetHsmBackend::sync`] for a specific backend fails
    fn sync_nethsm_backends(
        &self,
        available_connections: AvailableNetHsmConnections,
        admin_credentials: &NetHsmAdminCredentials,
        user_credentials: &[FullCredentials],
    ) -> Result<(), Error> {
        let backends = {
            let mut backends = Vec::new();
            for nethsm in available_connections.0.into_iter() {
                if let Some(backend) = NetHsmBackend::new(nethsm, admin_credentials, self.config())?
                {
                    backends.push(backend);
                }
            }
            backends
        };

        for backend in backends {
            backend.sync(user_credentials)?;
        }

        Ok(())
    }

    /// Syncs the states of all available NetHSM backends with that of the Signstar configuration.
    pub fn sync_nethsm(&self) -> Result<(), Error> {
        info!("Sync the state of the Signstar configuration with all available NetHSM backends.");
        let Some(nethsm_config) = self.config().nethsm() else {
            warn!("There is no NetHSM section in the Signstar configuration. Skipping...");
            return Ok(());
        };
        info!("Found NetHSM section in the Signstar configuration.");

        let admin_credentials = match self.load_nethsm_admin_credentials() {
            Ok(admin_credentials) => admin_credentials,
            Err(error) => {
                error!(
                    "An error occurred when trying to load administrative credentials for NetHSM: {error}"
                );
                return Ok(());
            }
        };
        info!("Found administrative credentials for NetHSM.");

        let available_connections = AvailableNetHsmConnections::new(nethsm_config);

        info!("Creating new non-administrative user credentials for NetHSM...");
        let user_credentials = self.create_nethsm_non_admin_credentials()?;

        self.sync_nethsm_backends(
            available_connections,
            &admin_credentials,
            user_credentials.as_slice(),
        )
    }
}
