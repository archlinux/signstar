//! Functionality when support for YubiHSM2 backends is compiled in.

use std::str::FromStr;

use log::{debug, error, info, warn};
use signstar_common::{backend::BackendType, traits::BackendCheck};
use signstar_config::{
    admin_credentials::AdminCredentials,
    config::{UserBackendConnection, UserBackendConnectionFilter},
    yubihsm2::{
        YubiHsm2Backend,
        YubiHsm2Config,
        admin_credentials::YubiHsm2AdminCredentials,
        signstar_yubihsm2_export::{Connection, Credentials},
        yubihsm2_export::{Connector, Id},
    },
};

use crate::{Error, backend::BackendSync};

impl<'config> BackendSync<'config> {
    /// Loads [`YubiHsm2AdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if [`YubiHsm2AdminCredentials::load`] fails.
    fn load_yubihsm2_admin_credentials(&self) -> Result<YubiHsm2AdminCredentials, Error> {
        Ok(YubiHsm2AdminCredentials::load(
            *self.config().system().admin_secret_handling(),
        )?)
    }

    /// Creates new credentials for all non-administrative YubiHSM2 backend users.
    ///
    /// # Errors
    ///
    /// Returns an error, if the non-administrative credentials for a specific user cannot be
    /// created.
    fn create_yubihsm2_non_admin_credentials(&self) -> Result<Vec<Credentials>, Error> {
        info!("Create new non-administrative user credentials for YubiHSM2.");
        let user_backend_connections = self.config().user_backend_connections(&[
            UserBackendConnectionFilter::NonAdmin,
            UserBackendConnectionFilter::Backend(BackendType::YubiHsm2),
        ]);

        let credentials_list = {
            let mut creds_list = Vec::new();
            for user_backend_connection in user_backend_connections {
                if let UserBackendConnection::YubiHsm2 { .. } = &user_backend_connection
                    && let Some(creds_per_user) =
                        user_backend_connection.create_non_admin_backend_user_secrets()?
                {
                    for credentials in creds_per_user {
                        creds_list.push(Credentials::new(
                            // NOTE: Here we cannot fail, because we already know that
                            // the user name is valid.
                            Id::from_str(&credentials.user())?,
                            credentials.passphrase().clone(),
                        ));
                    }
                }
            }

            creds_list
        };
        debug!(
            "Created non-administrative credentials for the following IDs: {}",
            credentials_list
                .iter()
                .map(|creds| creds.id().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(credentials_list)
    }

    /// Returns the list of available connections to YubiHSM2 backends.
    fn available_yubihsm2_connections(config: &YubiHsm2Config) -> Vec<Connector> {
        info!("Query all YubiHSM2 connections for availability.");
        config
            .connections()
            .iter()
            .filter_map(|connection| {
                if connection.is_available() {
                    debug!("Detected available YubiHSM2 connection {connection:?}");
                    Some(Connector::from(connection))
                } else {
                    warn!("Skipping unavailable YubiHSM2 connection {connection:?}");
                    None
                }
            })
            .collect::<Vec<_>>()
    }

    /// Returns the list of provisioned YubiHSM2 backend connections.
    fn provisioned_yubihsm2_connections(config: &YubiHsm2Config) -> Vec<&Connection> {
        info!("Detect all provisioned YubiHSM2 connections.");
        config
            .connections()
            .iter()
            .filter(|connection| {
                if connection.is_provisioned() {
                    debug!("Detected provisioned YubiHSM2 connection {connection:?}");
                    true
                } else {
                    debug!("Skipping unprovisioned YubiHSM2 connection {connection:?}");
                    false
                }
            })
            .collect::<Vec<_>>()
    }

    /// Syncs all available YubiHSM2 backends.
    ///
    /// Returns early success, if there is no YubiHSM2 section in the Signstar config.
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - [`YubiHsm2AdminCredentials::load`] cannot load administrative credentials
    /// - a [`YubiHsm2Backend`] cannot be created for a connection
    /// - running [`YubiHsm2Backend::sync`] for a specific backend fails
    fn sync_yubihsm2_backends(
        &self,
        available_connections: Vec<Connector>,
        admin_credentials: &YubiHsm2AdminCredentials,
        user_credentials: &[Credentials],
    ) -> Result<(), Error> {
        let backends = {
            let mut backends = Vec::new();
            for nethsm in available_connections.into_iter() {
                if let Some(backend) =
                    YubiHsm2Backend::new(nethsm, admin_credentials, self.config())?
                {
                    backends.push(backend);
                }
            }
            backends
        };

        for backend in backends {
            info!(
                "Sync the state of the Signstar configuration with the YubiHSM2 backend {backend:?}",
            );
            backend.sync(user_credentials)?;
        }

        Ok(())
    }

    /// Syncs the states of all available YubiHSM2 backends with that of the Signstar configuration.
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - the creation of non-administrative credentials fails
    /// - the syncing of the backend fails
    pub fn sync_yubihsm2(&self) -> Result<(), Error> {
        info!("Sync the state of the Signstar configuration with all available YubiHSM2 backends.");
        let Some(yubihsm2_config) = self.config().yubihsm2() else {
            warn!("There is no YubiHSM2 section in the Signstar configuration. Skipping...");
            return Ok(());
        };
        info!("Found YubiHSM2 section in the Signstar configuration.");

        let available_connections = {
            let available_connections = Self::available_yubihsm2_connections(yubihsm2_config);
            if available_connections.is_empty() {
                error!("There are no available YubiHSM2 connections. Aborting...");
                return Ok(());
            }

            available_connections
        };
        let provisioned_backends = Self::provisioned_yubihsm2_connections(yubihsm2_config);

        let admin_credentials = match self.load_yubihsm2_admin_credentials() {
            Ok(admin_credentials) => {
                info!("Found administrative credentials for YubiHSM2.");
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
                if available_connections.len() != yubihsm2_config.connections().len() {
                    error!(
                        "Not all configured connections are (yet) available ({}/{}) and administrative credentials are not present. Aborting...",
                        available_connections.len(),
                        yubihsm2_config.connections().len()
                    );
                    return Ok(());
                }

                // All backends are available and unprovisioned.
                // There are no administrative credentials (yet), so they are created.
                YubiHsm2AdminCredentials::try_from(self.config())?
            }
            Err(error) => {
                error!(
                    "An error occurred when trying to load administrative credentials for YubiHSM2: {error}"
                );
                return Ok(());
            }
        };

        // Non-administrative credentials are always created from scratch, unconditionally.
        let user_credentials = self.create_yubihsm2_non_admin_credentials()?;

        self.sync_yubihsm2_backends(
            available_connections,
            &admin_credentials,
            user_credentials.as_slice(),
        )
    }
}
