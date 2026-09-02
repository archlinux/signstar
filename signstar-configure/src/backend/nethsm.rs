//! Functionality when support for NetHSM backends is compiled in.

use log::{debug, error, info, warn};
use signstar_common::{backend::BackendType, traits::BackendCheck};
use signstar_config::{
    admin_credentials::AdminCredentials,
    config::{UserBackendConnection, UserBackendConnectionFilter},
    nethsm::{
        NetHsmAdminCredentials,
        NetHsmBackend,
        NetHsmConfig,
        nethsm_export::{Connection, FullCredentials, NetHsm, NetHsmError, UserId},
    },
};

use crate::{Error, backend::BackendSync};

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

    /// Returns the list of available connections to NetHSM backends.
    fn available_nethsm_connections(config: &NetHsmConfig) -> Vec<NetHsm> {
        info!("Query all NetHSM connections for availability.");
        config
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
                            info!("Detected available NetHSM connection {}", connection.url());
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
            .collect()
    }

    /// Returns the list of provisioned NetHSM backend connections.
    fn provisioned_nethsm_connections(config: &NetHsmConfig) -> Vec<&Connection> {
        info!("Detect all provisioned NetHSM connections.");
        config
            .connections()
            .iter()
            .filter(|connection| {
                if connection.is_provisioned() {
                    debug!("Detected provisioned NetHSM connection {connection:?}");
                    true
                } else {
                    debug!("Skipping unprovisioned NetHSM connection {connection:?}");
                    false
                }
            })
            .collect::<Vec<_>>()
    }

    /// Creates new credentials for all non-administrative NetHSM backend users.
    ///
    /// # Errors
    ///
    /// Returns an error, if the non-administrative credentials for a specific user cannot be
    /// created.
    fn create_nethsm_non_admin_credentials(&self) -> Result<Vec<FullCredentials>, Error> {
        info!("Create new non-administrative user credentials for NetHSM backends.");
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
        available_connections: Vec<NetHsm>,
        admin_credentials: &NetHsmAdminCredentials,
        user_credentials: &[FullCredentials],
    ) -> Result<(), Error> {
        let backends = {
            let mut backends = Vec::new();
            for nethsm in available_connections.into_iter() {
                if let Some(backend) = NetHsmBackend::new(nethsm, admin_credentials, self.config())?
                {
                    backends.push(backend);
                }
            }
            backends
        };

        for backend in backends {
            info!(
                "Sync the state of the Signstar configuration with the NetHSM backend {}",
                backend.nethsm().get_url()
            );
            backend.sync(user_credentials)?;
        }

        Ok(())
    }

    /// Syncs the states of all available NetHSM backends with that of the Signstar configuration.
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - the creation of non-administrative credentials fails
    /// - the syncing of the backend fails
    pub fn sync_nethsm(&self) -> Result<(), Error> {
        info!("Sync the state of the Signstar configuration with all available NetHSM backends.");
        let Some(nethsm_config) = self.config().nethsm() else {
            warn!("There is no NetHSM section in the Signstar configuration. Skipping...");
            return Ok(());
        };
        info!("Found NetHSM section in the Signstar configuration.");

        let available_connections = {
            let available_connections = Self::available_nethsm_connections(nethsm_config);
            if available_connections.is_empty() {
                error!("There are no available NetHSM connections. Aborting...");
                return Ok(());
            }

            available_connections
        };
        let provisioned_backends = Self::provisioned_nethsm_connections(nethsm_config);

        let admin_credentials = match self.load_nethsm_admin_credentials() {
            Ok(admin_credentials) => {
                info!("Found administrative credentials for NetHSM.");
                admin_credentials
            }
            Err(Error::SignstarConfig(signstar_config::Error::AdminSecretHandling(
                signstar_config::admin_credentials::Error::CredsFileMissing { .. },
            ))) => {
                if !provisioned_backends.is_empty() {
                    error!(
                        "There are provisioned backends, but administrative credentials are not present. Aborting..."
                    );
                    return Ok(());
                }
                if available_connections.len() != nethsm_config.connections().len() {
                    error!(
                        "Not all configured connections are (yet) available ({}/{}) and administrative credentials are not present. Aborting...",
                        available_connections.len(),
                        nethsm_config.connections().len()
                    );
                    return Ok(());
                }

                // All backends are available and unprovisioned.
                // There are no administrative credentials (yet), so they are created.
                NetHsmAdminCredentials::try_from(self.config())?
            }
            Err(error) => {
                error!(
                    "An error occurred when trying to load administrative credentials for NetHSM: {error}"
                );
                return Ok(());
            }
        };

        // Non-administrative credentials are always created from scratch, unconditionally.
        let user_credentials = self.create_nethsm_non_admin_credentials()?;

        self.sync_nethsm_backends(
            available_connections,
            &admin_credentials,
            user_credentials.as_slice(),
        )
    }
}
