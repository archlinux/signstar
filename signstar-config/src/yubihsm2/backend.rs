//! Backend handling for YubiHSM2.
#![cfg(feature = "yubihsm2")]

use std::fmt::Debug;

use log::debug;
use signstar_yubihsm2::yubihsm::Connector;

use crate::{
    Error,
    admin_credentials::AdminCredentials,
    config::Config,
    yubihsm2::{YubiHsm2Config, admin_credentials::YubiHsm2AdminCredentials},
};

/// A YubiHSM2 backend that provides control over a YubiHSM2 and its data.
///
/// Using a specific [`Connector`], it is possible to synchronize a YubiHSM2 with the data provided
/// by a [`YubiHsm2AdminCredentials`] and a [`YubiHsm2Config`].
pub struct YubiHsm2Backend<'admin_creds, 'config> {
    connector: Connector,
    admin_credentials: &'admin_creds YubiHsm2AdminCredentials,
    yubihsm2_config: &'config YubiHsm2Config,
}

impl<'admin_creds, 'config> YubiHsm2Backend<'admin_creds, 'config> {
    /// Creates a new [`YubiHsm2Backend`].
    ///
    /// Returns `Some(None)` if `signstar_config` contains no [`YubiHsm2Config`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the iteration of the `admin_credentials` does not match that of the `signstar_config`,
    pub fn new(
        connector: Connector,
        admin_credentials: &'admin_creds YubiHsm2AdminCredentials,
        signstar_config: &'config Config,
    ) -> Result<Option<Self>, Error> {
        debug!("Create a new YubiHSM2 backend for Signstar config");

        let Some(yubihsm2_config) = signstar_config.yubihsm2() else {
            return Ok(None);
        };

        // Ensure that the iterations of administrative credentials and signstar config match.
        if admin_credentials.iteration() != signstar_config.system().iteration() {
            return Err(Error::IterationMismatch {
                admin_creds: admin_credentials.iteration(),
                signstar_config: signstar_config.system().iteration(),
            });
        }

        Ok(Some(Self {
            connector,
            admin_credentials,
            yubihsm2_config,
        }))
    }

    /// Returns a reference to the [`Connector`].
    pub fn connector(&self) -> &Connector {
        &self.connector
    }
}

impl<'admin_creds, 'config> Debug for YubiHsm2Backend<'admin_creds, 'config> {
    /// Formats the value usinig the given formatter.
    ///
    /// # Note
    ///
    /// This is needed because [`Connector`] doesn't implement [`Debug`].
    /// <https://github.com/iqlusioninc/yubihsm.rs/pull/660>
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YubiHsm2Backend")
            .field("admin_credentials", self.admin_credentials)
            .field("yubihsm2_config", self.yubihsm2_config)
            .finish()
    }
}
