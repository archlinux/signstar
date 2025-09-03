//! Base implementation for [`NetHsm`]

#[cfg(doc)]
use std::thread::available_parallelism;
use std::{cell::RefCell, collections::HashMap};

use log::{debug, trace};
use nethsm_sdk_rs::apis::configuration::Configuration;
#[cfg(doc)]
use ureq::Agent;

use crate::{
    Connection,
    ConnectionSecurity,
    Credentials,
    DEFAULT_MAX_IDLE_CONNECTIONS,
    DEFAULT_TIMEOUT_SECONDS,
    Error,
    NetHsm,
    Url,
    UserId,
    UserRole,
    tls::create_agent,
    user::NamespaceSupport,
};

impl NetHsm {
    /// Creates a new NetHSM connection.
    ///
    /// Creates a new NetHSM connection based on a [`Connection`].
    ///
    /// Optionally initial `credentials` (used when communicating with the NetHSM),
    /// `max_idle_connections` to set the size of the connection pool (defaults to `100`) and
    /// `timeout_seconds` to set the timeout for a successful socket connection (defaults to `10`)
    /// can be provided.
    ///
    /// # Errors
    ///
    /// - the TLS client configuration can not be created,
    /// - or [`ConnectionSecurity::Native`] is provided as `tls_security`, but no certification
    ///   authority certificates are available on the system.
    pub fn new(
        connection: Connection,
        credentials: Option<Credentials>,
        max_idle_connections: Option<usize>,
        timeout_seconds: Option<u64>,
    ) -> Result<Self, Error> {
        let (current_credentials, credentials) = if let Some(credentials) = credentials {
            debug!(
                "Create new NetHSM connection {connection} with initial credentials {credentials}"
            );
            (
                RefCell::new(Some(credentials.user_id.clone())),
                RefCell::new(HashMap::from([(credentials.user_id.clone(), credentials)])),
            )
        } else {
            debug!("Create new NetHSM connection {connection} with no initial credentials");
            (Default::default(), Default::default())
        };

        let agent = RefCell::new(create_agent(
            connection.tls_security,
            max_idle_connections,
            timeout_seconds,
        )?);

        Ok(Self {
            agent,
            url: RefCell::new(connection.url),
            current_credentials,
            credentials,
        })
    }

    /// Validates the potential [namespace] access of a context.
    ///
    /// Validates, that [`current_credentials`][`NetHsm::current_credentials`] can be used in a
    /// defined context. This function relies on [`UserId::validate_namespace_access`] and should be
    /// used for validating the context of [`NetHsm`] methods.
    ///
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    pub(crate) fn validate_namespace_access(
        &self,
        support: NamespaceSupport,
        target: Option<&UserId>,
        role: Option<&UserRole>,
    ) -> Result<(), Error> {
        debug!(
            "Validate namespace access (target: {}; namespace: {support}; role: {}) for NetHSM at {}",
            if let Some(target) = target {
                target.to_string()
            } else {
                "n/a".to_string()
            },
            if let Some(role) = role {
                role.to_string()
            } else {
                "n/a".to_string()
            },
            self.url.borrow()
        );

        if let Some(current_user_id) = self.current_credentials.borrow().to_owned() {
            current_user_id.validate_namespace_access(support, target, role)?
        }
        Ok(())
    }

    /// Creates a connection configuration.
    ///
    /// Uses the [`Agent`] configured during creation of the [`NetHsm`], the current [`Url`] and
    /// [`Credentials`] to create a [`Configuration`] for a connection to the API of a NetHSM.
    pub(crate) fn create_connection_config(&self) -> Configuration {
        debug!(
            "Create connection config for NetHSM at {}",
            self.url.borrow()
        );

        let current_credentials = self.current_credentials.borrow().to_owned();
        Configuration {
            client: self.agent.borrow().to_owned(),
            base_path: self.url.borrow().to_string(),
            basic_auth: if let Some(current_credentials) = current_credentials {
                self.credentials
                    .borrow()
                    .get(&current_credentials)
                    .map(Into::into)
            } else {
                None
            },
            user_agent: Some(format!(
                "{}/{}",
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION")
            )),
            ..Default::default()
        }
    }

    /// Sets the connection agent for the NetHSM connection.
    ///
    /// Allows setting the
    /// - [`ConnectionSecurity`] which defines the TLS security model for the connection,
    /// - maximum idle connections per host using the optional `max_idle_connections` (defaults to
    ///   [`available_parallelism`] and falls back to `100` if unavailable),
    /// - and timeout in seconds for a successful socket connection using the optional
    ///   `timeout_seconds` (defaults to `10`).
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the TLS client configuration can not be created,
    /// - [`ConnectionSecurity::Native`] is provided as `tls_security`, but no certification
    ///   authority certificates are available on the system.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm, Url};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // Create a new connection for a NetHSM at "https://example.org"
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
    /// // change the connection agent to something else
    /// nethsm.set_agent(ConnectionSecurity::Unsafe, Some(200), Some(30))?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_agent(
        &self,
        tls_security: ConnectionSecurity,
        max_idle_connections: Option<usize>,
        timeout_seconds: Option<u64>,
    ) -> Result<(), Error> {
        debug!(
            "Set TLS agent (TLS security: {tls_security}; max idle: {}, timeout: {}) for NetHSM at {}",
            if let Some(max_idle_connections) = max_idle_connections {
                max_idle_connections.to_string()
            } else {
                DEFAULT_MAX_IDLE_CONNECTIONS.to_string()
            },
            if let Some(timeout_seconds) = timeout_seconds {
                format!("{timeout_seconds}s")
            } else {
                format!("{DEFAULT_TIMEOUT_SECONDS}s")
            },
            self.url.borrow()
        );

        *self.agent.borrow_mut() =
            create_agent(tls_security, max_idle_connections, timeout_seconds)?;
        Ok(())
    }

    /// Sets the URL for the NetHSM connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm, Url};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // Create a new connection for a NetHSM at "https://example.org"
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
    /// // change the url to something else
    /// nethsm.set_url(Url::new("https://other.org/api/v1")?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn set_url(&self, url: Url) {
        debug!(
            "Set the URL to {url} for the NetHSM at {}",
            self.url.borrow()
        );

        *self.url.borrow_mut() = url;
    }

    /// Retrieves the current URL for the NetHSM connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm, Url};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // Create a new connection for a NetHSM at "https://example.org"
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
    /// // retrieve the current URL
    /// assert_eq!(nethsm.get_url(), "https://example.org/api/v1".try_into()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_url(&self) -> Url {
        trace!("Get the URL for the NetHSM at {}", self.url.borrow());

        self.url.borrow().clone()
    }

    /// Adds [`Credentials`] to the list of available ones.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
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
    /// // add credentials
    /// nethsm.add_credentials(Credentials::new(
    ///     "admin".parse()?,
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// ));
    /// nethsm.add_credentials(Credentials::new(
    ///     "user1".parse()?,
    ///     Some(Passphrase::new("other_passphrase".to_string())),
    /// ));
    /// nethsm.add_credentials(Credentials::new("user2".parse()?, None));
    /// # Ok(())
    /// # }
    /// ```
    pub fn add_credentials(&self, credentials: Credentials) {
        debug!("Add NetHSM connection credentials for {credentials}");

        self.credentials
            .borrow_mut()
            .insert(credentials.user_id.clone(), credentials);
    }

    /// Removes [`Credentials`] from the list of available and currently used ones.
    ///
    /// Removes [`Credentials`] from the list of available ones and if identical unsets the
    /// ones used for further authentication as well.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // remove credentials
    /// nethsm.remove_credentials(&"admin".parse()?);
    /// # Ok(())
    /// # }
    /// ```
    pub fn remove_credentials(&self, user_id: &UserId) {
        debug!("Remove NetHSM connection credentials for {user_id}");

        self.credentials.borrow_mut().remove(user_id);
        if self
            .current_credentials
            .borrow()
            .as_ref()
            .is_some_and(|id| id == user_id)
        {
            *self.current_credentials.borrow_mut() = None
        }
    }

    /// Sets [`Credentials`] to use for the next connection.
    ///
    /// # Errors
    ///
    /// An [`Error`] is returned if no [`Credentials`] with the [`UserId`] `user_id` can be found.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
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
    /// // add credentials
    /// nethsm.add_credentials(Credentials::new(
    ///     "admin".parse()?,
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// ));
    /// nethsm.add_credentials(Credentials::new(
    ///     "user1".parse()?,
    ///     Some(Passphrase::new("other_passphrase".to_string())),
    /// ));
    ///
    /// // use admin credentials
    /// nethsm.use_credentials(&"admin".parse()?)?;
    ///
    /// // use operator credentials
    /// nethsm.use_credentials(&"user1".parse()?)?;
    ///
    /// // this fails, because the user has not been added yet
    /// assert!(nethsm.use_credentials(&"user2".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn use_credentials(&self, user_id: &UserId) -> Result<(), Error> {
        debug!("Use NetHSM connection credentials of {user_id}");

        if self.credentials.borrow().contains_key(user_id) {
            if self.current_credentials.borrow().as_ref().is_none()
                || self
                    .current_credentials
                    .borrow()
                    .as_ref()
                    .is_some_and(|id| id != user_id)
            {
                *self.current_credentials.borrow_mut() = Some(user_id.to_owned());
            }
        } else {
            return Err(Error::Default(format!(
                "The credentials for User ID \"{user_id}\" need to be added before they can be used!"
            )));
        }
        Ok(())
    }

    /// Get the [`UserId`] of the currently used [`Credentials`] for the connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "admin".parse()?,
    ///         Some("passphrase".parse()?),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // Get current User ID
    /// assert_eq!(nethsm.get_current_user(), Some("admin".parse()?));
    /// # Ok(())
    /// # }
    /// ```
    pub fn get_current_user(&self) -> Option<UserId> {
        trace!(
            "Get current User ID of NetHSM connection at {}",
            self.url.borrow()
        );

        self.current_credentials.borrow().clone()
    }
}
