//! [`NetHsm`] functionality that requires no authentication.

use log::debug;
use nethsm_sdk_rs::{
    apis::default_api::{health_alive_get, health_ready_get, health_state_get, info_get},
    models::{InfoData, SystemState},
};

#[cfg(doc)]
use crate::Credentials;
use crate::{Error, NetHsm, nethsm_sdk::NetHsmApiError, user::NamespaceSupport};

impl NetHsm {
    /// Returns whether the NetHSM is in [`Unprovisioned`][`SystemState::Unprovisioned`] or
    /// [`Locked`][`SystemState::Locked`] [state].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the information can not be retrieved or the NetHSM is in
    /// [`Operational`][`SystemState::Operational`] [state].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // check whether the NetHSM is locked or unprovisioned
    /// assert!(nethsm.alive().is_ok());
    /// # Ok(())
    /// # }
    /// ```
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn alive(&self) -> Result<(), Error> {
        debug!("Check whether the NetHSM at {} is alive", self.url.borrow());

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        health_alive_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving alive status failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns whether the NetHSM is in [`Operational`][`SystemState::Operational`] [state].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the information can not be retrieved or the NetHSM is in
    /// [`Unprovisioned`][`SystemState::Unprovisioned`] or [`Locked`][`SystemState::Locked`]
    /// [state].
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // check whether the NetHSM is operational
    /// assert!(nethsm.ready().is_ok());
    /// # Ok(())
    /// # }
    /// ```
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn ready(&self) -> Result<(), Error> {
        debug!("Check whether the NetHSM at {} is ready", self.url.borrow());

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        health_ready_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving ready status failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns the system [state] of the NetHSM.
    ///
    /// Returns a variant of [`SystemState`], which describes the [state] a NetHSM is currently in.
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the [state] information can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the state
    /// println!("{:?}", nethsm.state()?);
    /// # Ok(())
    /// # }
    /// ```
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn state(&self) -> Result<SystemState, Error> {
        debug!("Get the state of the NetHSM at {}", self.url.borrow());

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let health_state = health_state_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving state failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(health_state.entity.state)
    }

    /// Returns [device information] for the NetHSM.
    ///
    /// Returns an [`InfoData`], which provides the [device information].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM [device information] can not be retrieved.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial credentials are required
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     None,
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the NetHSM info
    /// println!("{:?}", nethsm.info()?);
    /// # Ok(())
    /// # }
    /// ```
    /// [device information]: https://docs.nitrokey.com/nethsm/administration#device-information
    pub fn info(&self) -> Result<InfoData, Error> {
        debug!("Get info about the NetHSM at {}", self.url.borrow());

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let info = info_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving device information failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(info.entity)
    }
}
