//! Functionality when support for YubiHSM2 backends is compiled in.

use std::str::FromStr;

use log::{error, info, warn};
use signstar_common::traits::BackendCheck;
use signstar_config::{
    admin_credentials::AdminCredentials,
    config::{BackendType, UserBackendConnection, UserBackendConnectionFilter},
    yubihsm2::{
        YubiHsm2Backend,
        YubiHsm2Config,
        admin_credentials::YubiHsm2AdminCredentials,
        signstar_yubihsm2_export::Credentials,
        yubihsm2_export::{Connector, Id},
    },
};

use crate::{Error, backend::BackendSync};

/// The available YubiHSM2 connections.
#[derive(Debug)]
pub struct AvailableYubiHsm2Connections(pub(crate) Vec<Connector>);

impl AvailableYubiHsm2Connections {
    /// Creates a new [`AvailableYubiHsm2Connections`] from a [`YubiHsm2Config`].
    ///
    /// # Note
    ///
    /// Only considers available connections (see [`BackendCheck::is_available`]).
    fn new(config: &YubiHsm2Config) -> Self {
        info!("Querying all YubiHSM2 connections for availability...");
        let connections = config
            .connections()
            .iter()
            .filter_map(|connection| {
                if connection.is_available() {
                    info!("Adding available YubiHSM2 connection {connection:?}");
                    Some(Connector::from(connection))
                } else {
                    warn!("Skipping unavailable YubiHSM2 connection {connection:?}");
                    None
                }
            })
            .collect();

        Self(connections)
    }
}

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

        Ok(credentials_list)
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
        available_connections: AvailableYubiHsm2Connections,
        admin_credentials: &YubiHsm2AdminCredentials,
        user_credentials: &[Credentials],
    ) -> Result<(), Error> {
        let backends = {
            let mut backends = Vec::new();
            for nethsm in available_connections.0.into_iter() {
                if let Some(backend) =
                    YubiHsm2Backend::new(nethsm, admin_credentials, self.config())?
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

    /// Syncs the states of all available YubiHSM2 backends with that of the Signstar configuration.
    pub fn sync_yubihsm2(&self) -> Result<(), Error> {
        info!("Sync the state of the Signstar configuration with all available YubiHSM2 backends.");
        let Some(yubihsm2_config) = self.config().yubihsm2() else {
            warn!("There is no YubiHSM2 section in the Signstar configuration. Skipping...");
            return Ok(());
        };
        info!("Found YubiHSM2 section in the Signstar configuration.");

        let admin_credentials = match self.load_yubihsm2_admin_credentials() {
            Ok(admin_credentials) => admin_credentials,
            Err(error) => {
                error!(
                    "An error occurred when trying to load administrative credentials for YubiHSM2: {error}"
                );
                return Ok(());
            }
        };
        info!("Found administrative credentials for YubiHSM2.");

        let available_connections = AvailableYubiHsm2Connections::new(yubihsm2_config);

        info!("Creating new non-administrative user credentials for YubiHSM2...");
        let user_credentials = self.create_yubihsm2_non_admin_credentials()?;

        self.sync_yubihsm2_backends(
            available_connections,
            &admin_credentials,
            user_credentials.as_slice(),
        )
    }
}
