//! [`NetHsm`] implementation for system functionality.

use std::net::Ipv4Addr;

use base64ct::{Base64, Encoding};
use chrono::{DateTime, Utc};
use log::debug;
use nethsm_sdk_rs::{
    apis::default_api::{
        config_backup_passphrase_put,
        config_logging_get,
        config_logging_put,
        config_network_get,
        config_network_put,
        config_time_get,
        config_time_put,
        config_tls_cert_pem_get,
        config_tls_cert_pem_put,
        config_tls_csr_pem_post,
        config_tls_generate_post,
        config_tls_public_pem_get,
        config_unattended_boot_get,
        config_unattended_boot_put,
        config_unlock_passphrase_put,
        lock_post,
        metrics_get,
        provision_post,
        random_post,
        system_backup_post,
        system_cancel_update_post,
        system_commit_update_post,
        system_factory_reset_post,
        system_info_get,
        system_reboot_post,
        system_restore_post,
        system_shutdown_post,
        system_update_post,
        unlock_post,
    },
    models::{
        BackupPassphraseConfig,
        DistinguishedName,
        LoggingConfig,
        NetworkConfig,
        ProvisionRequestData,
        RandomRequestData,
        SystemInfo,
        SystemUpdateData,
        TimeConfig,
        TlsKeyGenerateRequestData,
        UnlockPassphraseConfig,
        UnlockRequestData,
    },
};
use serde_json::Value;

use crate::{
    BootMode,
    Error,
    LogLevel,
    NetHsm,
    Passphrase,
    TlsKeyType,
    base::utils::user_or_no_user_string,
    nethsm_sdk::NetHsmApiError,
    tls_key_type_matches_length,
    user::NamespaceSupport,
};
#[cfg(doc)]
use crate::{Credentials, SystemState, UserRole};

impl NetHsm {
    /// Provisions a NetHSM.
    ///
    /// [Provisioning] is the initial setup step for a NetHSM.
    /// It sets the `unlock_passphrase`, which is used to [`unlock`][`NetHsm::unlock`] a device in
    /// [`Locked`][`SystemState::Locked`] [state], the initial `admin_passphrase` for the
    /// default [`Administrator`][`UserRole::Administrator`] account ("admin") and the
    /// `system_time`. The unlock passphrase can later on be changed using
    /// [`set_unlock_passphrase`][`NetHsm::set_unlock_passphrase`] and the admin passphrase using
    /// [`set_user_passphrase`][`NetHsm::set_user_passphrase`].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if provisioning fails:
    /// * the NetHSM is not in [`Unprovisioned`][`SystemState::Unprovisioned`] [state]
    /// * the provided data is malformed
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::Utc;
    /// use nethsm::{Connection, ConnectionSecurity, NetHsm, Passphrase};
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
    /// // provision the NetHSM
    /// nethsm.provision(
    ///     Passphrase::new("unlock-the-device".to_string()),
    ///     Passphrase::new("admin-passphrase".to_string()),
    ///     Utc::now(),
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Provisioning]: https://docs.nitrokey.com/nethsm/getting-started#provisioning
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn provision(
        &self,
        unlock_passphrase: Passphrase,
        admin_passphrase: Passphrase,
        system_time: DateTime<Utc>,
    ) -> Result<(), Error> {
        debug!("Provision the NetHSM at {}", self.url.borrow());

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        provision_post(
            &self.create_connection_config(),
            ProvisionRequestData::new(
                unlock_passphrase.expose_owned(),
                admin_passphrase.expose_owned(),
                system_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            ),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Provisioning failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns metrics for the NetHSM.
    ///
    /// Returns a [`Value`][`serde_json::Value`] which provides [metrics] for the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a user in the [`Metrics`][`UserRole::Metrics`]
    /// [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM [metrics] can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Metrics`][`UserRole::Metrics`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Metrics role
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "metrics".parse()?,
    ///         Some(Passphrase::new("metrics-passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // retrieve the metrics
    /// println!("{:?}", nethsm.metrics()?);
    /// # Ok(())
    /// # }
    /// ```
    /// [metrics]: https://docs.nitrokey.com/nethsm/administration#metrics
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn metrics(&self) -> Result<Value, Error> {
        debug!(
            "Retrieve metrics of the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let metrics = metrics_get(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Retrieving metrics failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(metrics.entity)
    }

    /// Sets the [unlock passphrase].
    ///
    /// Changes the [unlock passphrase] from `current_passphrase` to `new_passphrase`.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the [unlock passphrase] can not be changed:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `current_passphrase` is not correct
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the unlock passphrase
    /// nethsm.set_unlock_passphrase(
    ///     Passphrase::new("current-unlock-passphrase".to_string()),
    ///     Passphrase::new("new-unlock-passphrase".to_string()),
    /// )?;
    ///
    /// // N-Administrators can not set the unlock passphrase
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(
    ///     nethsm
    ///         .set_unlock_passphrase(
    ///             Passphrase::new("current-unlock-passphrase".to_string()),
    ///             Passphrase::new("new-unlock-passphrase".to_string()),
    ///         )
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [unlock passphrase]: https://docs.nitrokey.com/nethsm/administration#unlock-passphrase
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_unlock_passphrase(
        &self,
        current_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> Result<(), Error> {
        debug!(
            "Set unlock passphrase for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_unlock_passphrase_put(
            &self.create_connection_config(),
            UnlockPassphraseConfig::new(
                new_passphrase.expose_owned(),
                current_passphrase.expose_owned(),
            ),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Changing unlock passphrase failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Returns the [boot mode].
    ///
    /// Returns a variant of [`BootMode`] which represents the NetHSM's [boot mode].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the boot mode can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can retrieve the boot mode
    /// println!("{:?}", nethsm.get_boot_mode()?);
    ///
    /// // N-Administrators can not retrieve the boot mode
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_boot_mode().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [boot mode]: https://docs.nitrokey.com/nethsm/administration#boot-mode
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_boot_mode(&self) -> Result<BootMode, Error> {
        debug!(
            "Get the boot mode of the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(BootMode::from(
            config_unattended_boot_get(&self.create_connection_config())
                .map_err(|error| {
                    Error::Api(format!(
                        "Retrieving boot mode failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        ))
    }

    /// Sets the [boot mode].
    ///
    /// Sets the NetHSM's [boot mode] based on a [`BootMode`] variant.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the boot mode can not be set:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     BootMode,
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     NetHsm,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the boot mode
    /// // set the boot mode to unattended
    /// nethsm.set_boot_mode(BootMode::Unattended)?;
    /// // set the boot mode to attended
    /// nethsm.set_boot_mode(BootMode::Attended)?;
    ///
    /// // N-Administrators can not set the boot mode
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_boot_mode(BootMode::Attended).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [boot mode]: https://docs.nitrokey.com/nethsm/administration#boot-mode
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_boot_mode(&self, boot_mode: BootMode) -> Result<(), Error> {
        debug!(
            "Set the boot mode for the NetHSM at {} to {boot_mode} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_unattended_boot_put(&self.create_connection_config(), boot_mode.into()).map_err(
            |error| {
                Error::Api(format!(
                    "Setting boot mode failed: {}",
                    NetHsmApiError::from(error)
                ))
            },
        )?;
        Ok(())
    }

    /// Returns the TLS public key of the API.
    ///
    /// Returns the NetHSM's public key part of its [TLS certificate] which is used for
    /// communication with the API.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM's TLS public key can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the TLS public key
    /// println!("{}", nethsm.get_tls_public_key()?);
    ///
    /// // N-Administrators can not get the TLS public key
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_tls_public_key().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_tls_public_key(&self) -> Result<String, Error> {
        debug!(
            "Retrieve the TLS public key for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_tls_public_pem_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Retrieving API TLS public key failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Returns the TLS certificate of the API.
    ///
    /// Returns the NetHSM's [TLS certificate] which is used for communication with the API.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the NetHSM's TLS certificate can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the TLS certificate
    /// println!("{}", nethsm.get_tls_cert()?);
    ///
    /// // N-Administrators can not get the TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_tls_cert().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_tls_cert(&self) -> Result<String, Error> {
        debug!(
            "Retrieve the TLS certificate for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_tls_cert_pem_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Retrieving API TLS certificate failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Returns a Certificate Signing Request ([CSR]) for the API's [TLS certificate].
    ///
    /// Based on [`DistinguishedName`] data returns a [CSR] in [PKCS#10] format for the NetHSM's
    /// [TLS certificate].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the [CSR] can not be retrieved:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     DistinguishedName,
    ///     NetHsm,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get a CSR for the TLS certificate
    /// println!(
    ///     "{}",
    ///     nethsm.get_tls_csr(DistinguishedName {
    ///         country_name: Some("DE".to_string()),
    ///         state_or_province_name: Some("Berlin".to_string()),
    ///         locality_name: Some("Berlin".to_string()),
    ///         organization_name: Some("Foobar Inc".to_string()),
    ///         organizational_unit_name: Some("Department of Foo".to_string()),
    ///         common_name: "Foobar Inc".to_string(),
    ///         email_address: Some("foobar@mcfooface.com".to_string()),
    ///     })?
    /// );
    ///
    /// // N-Administrators can not get a CSR for the TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(
    ///     nethsm
    ///         .get_tls_csr(DistinguishedName {
    ///             country_name: Some("DE".to_string()),
    ///             state_or_province_name: Some("Berlin".to_string()),
    ///             locality_name: Some("Berlin".to_string()),
    ///             organization_name: Some("Foobar Inc".to_string()),
    ///             organizational_unit_name: Some("Department of Foo".to_string()),
    ///             common_name: "Foobar Inc".to_string(),
    ///             email_address: Some("foobar@mcfooface.com".to_string()),
    ///         })
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [CSR]: https://en.wikipedia.org/wiki/Certificate_signing_request
    /// [PKCS#10]: https://en.wikipedia.org/wiki/Certificate_signing_request#Structure_of_a_PKCS_#10_CSR
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_tls_csr(&self, distinguished_name: DistinguishedName) -> Result<String, Error> {
        debug!(
            "Retrieve a Certificate Signing Request (for {}) for the TLS certificate of the NetHSM at {} using {}",
            distinguished_name.common_name,
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(
            config_tls_csr_pem_post(&self.create_connection_config(), distinguished_name)
                .map_err(|error| {
                    Error::Api(format!(
                        "Retrieving CSR for TLS certificate failed: {}",
                        NetHsmApiError::from(error),
                    ))
                })?
                .entity,
        )
    }

    /// Generates a new [TLS certificate] for the API.
    ///
    /// Generates a new [TLS certificate] (used for communication with the API) based on
    /// `tls_key_type` and `length`.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if the new [TLS certificate] can not be generated:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the `tls_key_type` and `length` combination is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     NetHsm,
    ///     Passphrase,
    ///     TlsKeyType,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can generate a new TLS certificate
    /// nethsm.generate_tls_cert(TlsKeyType::Rsa, Some(4096))?;
    ///
    /// // N-Administrators can not generate a new TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(
    ///     nethsm
    ///         .generate_tls_cert(TlsKeyType::Rsa, Some(4096))
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn generate_tls_cert(
        &self,
        tls_key_type: TlsKeyType,
        length: Option<u32>,
    ) -> Result<(), Error> {
        debug!(
            "Generate a TLS certificate ({tls_key_type}{}) on the NetHSM at {} using {}",
            if let Some(length) = length {
                format!(" {length} bit long")
            } else {
                "{}".to_string()
            },
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        // ensure the tls_key_type - length combination is valid
        tls_key_type_matches_length(tls_key_type, length)?;
        config_tls_generate_post(
            &self.create_connection_config(),
            TlsKeyGenerateRequestData {
                r#type: tls_key_type.into(),
                length: length.map(|length| length as i32),
            },
        )
        .map_err(|error| {
            Error::Api(format!(
                "Generating API TLS certificate failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Sets a new [TLS certificate] for the API.
    ///
    /// Accepts a Base64 encoded [DER] certificate provided using `certificate` which is added as
    /// new [TLS certificate] for communication with the API.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting a new TLS certificate fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `certificate` is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// let cert = r#"-----BEGIN CERTIFICATE-----
    /// MIIBHjCBxKADAgECAghDngCv6xWIXDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlr
    /// ZXlmZW5kZXIwIBcNNzAwMTAxMDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMBQxEjAQ
    /// BgNVBAMMCWtleWZlbmRlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJsHIrsZ
    /// 6fJzrk12GK7nW6bGyTIIZiQUq0uaKbn21dgPiDCO5+iYVXAqnWu4IMVZQnkFJmte
    /// PRUUuM3119f8ffkwCgYIKoZIzj0EAwIDSQAwRgIhALH4fDYJ21tRecXp9IipBlil
    /// p+hJCj77zBvFmGYy/UnPAiEA8csj7U6BfzvK4EiQyUZa7/as+nXwj3XHU/i8LyLm
    /// Chw=
    /// -----END CERTIFICATE-----"#;
    ///
    /// // R-Administrators can set a new TLS certificate
    /// nethsm.set_tls_cert(cert)?;
    ///
    /// // N-Administrators can not set a new TLS certificate
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_tls_cert(cert).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [DER]: https://en.wikipedia.org/wiki/X.690#DER_encoding
    /// [TLS certificate]: https://docs.nitrokey.com/nethsm/administration#tls-certificate
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_tls_cert(&self, certificate: &str) -> Result<(), Error> {
        debug!(
            "Set a new TLS certificate for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_tls_cert_pem_put(&self.create_connection_config(), certificate).map_err(
            |error| {
                Error::Api(format!(
                    "Setting API TLS certificate failed: {}",
                    NetHsmApiError::from(error)
                ))
            },
        )?;
        Ok(())
    }

    /// Gets the [network configuration].
    ///
    /// Retrieves the [network configuration] of the NetHSM as [`NetworkConfig`].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving network configuration fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the network configuration
    /// println!("{:?}", nethsm.get_network()?);
    ///
    /// // N-Administrators can not get the network configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_network().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [network configuration]: https://docs.nitrokey.com/nethsm/administration#network
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_network(&self) -> Result<NetworkConfig, Error> {
        debug!(
            "Get network configuration for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_network_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting network config failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Sets the [network configuration].
    ///
    /// Sets the [network configuration] of the NetHSM on the basis of a [`NetworkConfig`].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the network configuration fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `network_config` is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     NetHsm,
    ///     NetworkConfig,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// let network_config = NetworkConfig::new(
    ///     "192.168.1.1".to_string(),
    ///     "255.255.255.0".to_string(),
    ///     "0.0.0.0".to_string(),
    /// );
    ///
    /// // R-Administrators can set the network configuration
    /// nethsm.set_network(network_config.clone())?;
    ///
    /// // N-Administrators can not set the network configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_network(network_config).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [network configuration]: https://docs.nitrokey.com/nethsm/administration#network
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_network(&self, network_config: NetworkConfig) -> Result<(), Error> {
        debug!(
            "Set a new network configuration (IP: {}, Netmask: {}, Gateway: {}) for the NetHSM at {} using {}",
            network_config.ip_address,
            network_config.netmask,
            network_config.gateway,
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_network_put(&self.create_connection_config(), network_config).map_err(|error| {
            Error::Api(format!(
                "Setting network config failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets the current [time].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving [time] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get the time
    /// println!("{:?}", nethsm.get_time()?);
    ///
    /// // N-Administrators can not get the time
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_time().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [time]: https://docs.nitrokey.com/nethsm/administration#time
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_time(&self) -> Result<String, Error> {
        debug!(
            "Retrieve the system time for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_time_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting NetHSM system time failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity
            .time)
    }

    /// Sets the current [time].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting [time] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `time` is not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::Utc;
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the time
    /// nethsm.set_time(Utc::now())?;
    ///
    /// // N-Administrators can not set the time
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.set_time(Utc::now()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [time]: https://docs.nitrokey.com/nethsm/administration#time
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_time(&self, time: DateTime<Utc>) -> Result<(), Error> {
        debug!(
            "Set the system time to {time} for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_time_put(
            &self.create_connection_config(),
            TimeConfig::new(time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting NetHSM system time failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Gets the [logging configuration].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the [logging configuration] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can get logging configuration
    /// println!("{:?}", nethsm.get_logging()?);
    ///
    /// // N-Administrators can not get logging configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_logging().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [logging configuration]: https://docs.nitrokey.com/nethsm/administration#logging
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_logging(&self) -> Result<LoggingConfig, Error> {
        debug!(
            "Retrieve the logging information of the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(config_logging_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting logging config failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Sets the [logging configuration].
    ///
    /// Sets the NetHSM's [logging configuration] by providing `ip_address` and `port` of a host to
    /// send logs to. The log level is configured using `log_level`.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the logging configuration fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `ip_address`, `port` or `log_level` are not valid
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::net::Ipv4Addr;
    ///
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     LogLevel,
    ///     NetHsm,
    ///     Passphrase,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set logging configuration
    /// nethsm.set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)?;
    ///
    /// // N-Administrators can not set logging configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(
    ///     nethsm
    ///         .set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [logging configuration]: https://docs.nitrokey.com/nethsm/administration#logging
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_logging(
        &self,
        ip_address: Ipv4Addr,
        port: u32,
        log_level: LogLevel,
    ) -> Result<(), Error> {
        debug!(
            "Set the logging configuration to {ip_address}:{port} ({log_level}) for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        let ip_address = ip_address.to_string();
        config_logging_put(
            &self.create_connection_config(),
            LoggingConfig::new(ip_address, port as i32, log_level.into()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting logging config failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Sets the [backup] passphrase.
    ///
    /// Sets `current_passphrase` to `new_passphrase`, which changes the [backup] passphrase for the
    /// NetHSM.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the backup passphrase fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `current_passphrase` is not correct
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can set the backup passphrase
    /// nethsm.set_backup_passphrase(
    ///     Passphrase::new("current-backup-passphrase".to_string()),
    ///     Passphrase::new("new-backup-passphrase".to_string()),
    /// )?;
    ///
    /// // N-Administrators can not set logging configuration
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(
    ///     nethsm
    ///         .set_backup_passphrase(
    ///             Passphrase::new("new-backup-passphrase".to_string()),
    ///             Passphrase::new("current-backup-passphrase".to_string()),
    ///         )
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_backup_passphrase(
        &self,
        current_passphrase: Passphrase,
        new_passphrase: Passphrase,
    ) -> Result<(), Error> {
        debug!(
            "Set the backup passphrase for the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        config_backup_passphrase_put(
            &self.create_connection_config(),
            BackupPassphraseConfig::new(
                new_passphrase.expose_owned(),
                current_passphrase.expose_owned(),
            ),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting backup passphrase failed: {}",
                NetHsmApiError::from(error),
            ))
        })?;
        Ok(())
    }

    /// Creates a [backup].
    ///
    /// Triggers the creation and download of a [backup] of the NetHSM.
    /// **NOTE**: Before creating the first [backup], the [backup] passphrase must be set using
    /// [`set_backup_passphrase`][`NetHsm::set_backup_passphrase`].
    ///
    /// This call requires using [`Credentials`] of a user in the [`Backup`][`UserRole::Backup`]
    /// [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if creating a [backup] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Backup`][`UserRole::Backup`]
    ///   [role]
    /// * the [backup] passphrase has not yet been set
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a user in the Backup role
    /// let nethsm = NetHsm::new(
    ///     Connection::new(
    ///         "https://example.org/api/v1".try_into()?,
    ///         ConnectionSecurity::Unsafe,
    ///     ),
    ///     Some(Credentials::new(
    ///         "backup1".parse()?,
    ///         Some(Passphrase::new("passphrase".to_string())),
    ///     )),
    ///     None,
    ///     None,
    /// )?;
    ///
    /// // create a backup and write it to file
    /// std::fs::write("nethsm.bkp", nethsm.backup()?)?;
    /// # Ok(())
    /// # }
    /// ```
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn backup(&self) -> Result<Vec<u8>, Error> {
        debug!(
            "Retrieve a backup of the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(system_backup_post(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Getting backup failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Triggers a [factory reset].
    ///
    /// Triggers a [factory reset] of the NetHSM.
    /// **WARNING**: This action deletes all user and system data! Make sure to create a [backup]
    /// using [`backup`][`NetHsm::backup`] first!
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if resetting the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     NetHsm,
    ///     Passphrase,
    ///     SystemState,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not trigger factory reset
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.factory_reset().is_err());
    ///
    /// // R-Administrators are able to trigger a factory reset
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.factory_reset()?;
    /// assert_eq!(nethsm.state()?, SystemState::Unprovisioned);
    /// # Ok(())
    /// # }
    /// ```
    /// [factory reset]: https://docs.nitrokey.com/nethsm/administration#reset-to-factory-defaults
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn factory_reset(&self) -> Result<(), Error> {
        debug!(
            "Trigger a factory reset of the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_factory_reset_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Factory reset failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Restores NetHSM from [backup].
    ///
    /// [Restores] a NetHSM from a [backup], by providing a `backup_passphrase` (see
    /// [`set_backup_passphrase`][`NetHsm::set_backup_passphrase`]) a new `system_time` for the
    /// NetHSM and a backup file (created using [`backup`][`NetHsm::backup`]).
    ///
    /// The NetHSM must be in [`Operational`][`SystemState::Operational`] or
    /// [`Unprovisioned`][`SystemState::Unprovisioned`] [state].
    ///
    /// Any existing user data is safely removed and replaced by that of the [backup], after which
    /// the NetHSM ends up in [`Locked`][`SystemState::Locked`] [state].
    /// If the NetHSM is in [`Unprovisioned`][`SystemState::Unprovisioned`] [state], additionally
    /// the system configuration from the backup is applied and leads to a
    /// [`reboot`][`NetHsm::reboot`] of the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if restoring the NetHSM from [backup] fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] or
    ///   [`Unprovisioned`][`SystemState::Unprovisioned`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use chrono::Utc;
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// #
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not restore from backup
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(
    ///     nethsm
    ///         .restore(
    ///             Passphrase::new("backup-passphrase".to_string()),
    ///             Utc::now(),
    ///             std::fs::read("nethsm.bkp")?,
    ///         )
    ///         .is_err()
    /// );
    ///
    /// // R-Administrators can restore from backup
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.restore(
    ///     Passphrase::new("backup-passphrase".to_string()),
    ///     Utc::now(),
    ///     std::fs::read("nethsm.bkp")?,
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Restores]: https://docs.nitrokey.com/nethsm/administration#restore
    /// [backup]: https://docs.nitrokey.com/nethsm/administration#backup
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn restore(
        &self,
        backup_passphrase: Passphrase,
        system_time: DateTime<Utc>,
        backup: Vec<u8>,
    ) -> Result<(), Error> {
        debug!(
            "Restore the NetHSM at {} from backup with the new system time {system_time} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_restore_post(
            &self.create_connection_config(),
            Some(nethsm_sdk_rs::models::RestoreRequestArguments {
                backup_passphrase: Some(backup_passphrase.expose_owned()),
                system_time: Some(system_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            }),
            Some(backup),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Restoring backup failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Locks the NetHSM.
    ///
    /// Locks the NetHSM and sets its [state] to [`Locked`][`SystemState::Locked`].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if locking the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     NetHsm,
    ///     Passphrase,
    ///     SystemState,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    ///
    /// // N-Administrators can not lock the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.lock().is_err());
    ///
    /// // R-Administrators can lock the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.lock()?;
    /// assert_eq!(nethsm.state()?, SystemState::Locked);
    /// # Ok(())
    /// # }
    /// ```
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn lock(&self) -> Result<(), Error> {
        debug!(
            "Lock the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        lock_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Locking NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Unlocks the NetHSM.
    ///
    /// Unlocks the NetHSM if it is in [`Locked`][`SystemState::Locked`] [state] by providing
    /// `unlock_passphrase` and sets its [state] to [`Operational`][`SystemState::Operational`].
    ///
    /// For this call no [`Credentials`] are required and if any are configured, they are ignored.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if unlocking the NetHSM fails:
    /// * the NetHSM is not in [`Locked`][`SystemState::Locked`] [state]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, SystemState};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // no initial [`Credentials`] are required
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
    /// assert_eq!(nethsm.state()?, SystemState::Locked);
    /// // unlock the NetHSM
    /// nethsm.unlock(Passphrase::new("unlock-passphrase".to_string()))?;
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// # Ok(())
    /// # }
    /// ```
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn unlock(&self, unlock_passphrase: Passphrase) -> Result<(), Error> {
        debug!(
            "Unlock the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        unlock_post(
            &self.create_connection_config(),
            UnlockRequestData::new(unlock_passphrase.expose_owned()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Unlocking NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Retrieves [system information].
    ///
    /// Returns [system information] in the form of a [`SystemInfo`], which contains various pieces
    /// of information such as software version, software build, firmware version, hardware
    /// version, device ID and information on TPM related components such as attestation key and
    /// relevant PCR values.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving the system information fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can retrieve system information
    /// println!("{:?}", nethsm.system_info()?);
    ///
    /// // N-Administrators can not retrieve system information
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.system_info().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [system information]: https://docs.nitrokey.com/nethsm/administration#system-information
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn system_info(&self) -> Result<SystemInfo, Error> {
        debug!(
            "Retrieve system information about the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(system_info_get(&self.create_connection_config())
            .map_err(|error| {
                Error::Api(format!(
                    "Retrieving system information failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// [Reboots] the NetHSM.
    ///
    /// [Reboots] the NetHSM, if it is in [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if rebooting the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not reboot the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.reboot().is_err());
    ///
    /// // R-Administrators can reboot the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.reboot()?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Reboots]: https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn reboot(&self) -> Result<(), Error> {
        debug!(
            "Reboot the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_reboot_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Rebooting NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// [Shuts down] the NetHSM.
    ///
    /// [Shuts down] the NetHSM, if it is in [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if shutting down the NetHSM fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not shut down the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.shutdown().is_err());
    ///
    /// // R-Administrators can shut down the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.shutdown()?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Shuts down]: https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn shutdown(&self) -> Result<(), Error> {
        debug!(
            "Shut down the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_shutdown_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Shutting down NetHSM failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Uploads a software update.
    ///
    /// WARNING: This function has shown flaky behavior during tests with the official container!
    /// Upload may have to be repeated!
    ///
    /// Uploads a [software update] to the NetHSM, if it is in
    /// [`Operational`][`SystemState::Operational`] [state] and returns information about the
    /// software update as [`SystemUpdateData`].
    /// Software updates can successively be installed ([`commit_update`][`NetHsm::commit_update`])
    /// or canceled ([`cancel_update`][`NetHsm::cancel_update`]).
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if uploading the software update fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // N-Administrators can not upload software updates to the NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.upload_update(std::fs::read("update.bin")?).is_err());
    ///
    /// // R-Administrators can upload software updates to the NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// println!("{:?}", nethsm.upload_update(std::fs::read("update.bin")?)?);
    /// # Ok(())
    /// # }
    /// ```
    /// [software update]: https://docs.nitrokey.com/nethsm/administration#software-update
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn upload_update(&self, update: Vec<u8>) -> Result<SystemUpdateData, Error> {
        debug!(
            "Upload an update to the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        Ok(system_update_post(&self.create_connection_config(), update)
            .map_err(|error| {
                println!("error during upload");
                Error::Api(format!(
                    "Uploading update failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?
            .entity)
    }

    /// Commits an already uploaded [software update].
    ///
    /// Commits a [software update] previously uploaded to the NetHSM (using
    /// [`upload_update`][`NetHsm::upload_update`]), if the NetHSM is in
    /// [`Operational`][`SystemState::Operational`] [state].
    /// Successfully committing a [software update] leads to the [reboot] of the NetHSM.
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if committing the software update fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * there is no software update to commit
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// println!("{:?}", nethsm.upload_update(std::fs::read("update.bin")?)?);
    ///
    /// // N-Administrators can not commit software updates on a NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.commit_update().is_err());
    ///
    /// // R-Administrators can commit software updates on a NetHSM
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.commit_update()?;
    /// # Ok(())
    /// # }
    /// ```
    /// [software update]: https://docs.nitrokey.com/nethsm/administration#software-update
    /// [reboot]: https://docs.nitrokey.com/nethsm/administration#reboot-and-shutdown
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn commit_update(&self) -> Result<(), Error> {
        debug!(
            "Commit an already uploaded update on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_commit_update_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Committing update failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Cancels an already uploaded [software update].
    ///
    /// Cancels a [software update] previously uploaded to the NetHSM (using
    /// [`upload_update`][`NetHsm::upload_update`]), if the NetHSM is in
    /// [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if canceling the software update fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * there is no software update to cancel
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     NetHsm,
    ///     Passphrase,
    ///     SystemState,
    ///     UserRole,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // create accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// println!("{:?}", nethsm.upload_update(std::fs::read("update.bin")?)?);
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    ///
    /// // N-Administrators can not cancel software updates on a NetHSM
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.cancel_update().is_err());
    ///
    /// // R-Administrators can cancel software updates on a NetHSM
    /// nethsm.cancel_update()?;
    /// assert_eq!(nethsm.state()?, SystemState::Operational);
    /// # Ok(())
    /// # }
    /// ```
    /// [software update]: https://docs.nitrokey.com/nethsm/administration#software-update
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn cancel_update(&self) -> Result<(), Error> {
        debug!(
            "Cancel an already uploaded update on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        system_cancel_update_post(&self.create_connection_config()).map_err(|error| {
            Error::Api(format!(
                "Cancelling update failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;
        Ok(())
    }

    /// Generates [random] bytes.
    ///
    /// Retrieves `length` [random] bytes from the NetHSM, if it is in
    /// [`Operational`][`SystemState::Operational`] [state].
    ///
    /// This call requires using [`Credentials`] of a user in the [`Operator`][`UserRole::Operator`]
    /// [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving random bytes fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the [`Operator`][`UserRole::Operator`]
    ///   [role]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{Connection, ConnectionSecurity, Credentials, NetHsm, Passphrase, UserRole};
    ///
    /// # fn main() -> testresult::TestResult {
    /// // create a connection with a system-wide user in the Administrator role (R-Administrator)
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
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator1".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator-passphrase".to_string()),
    ///     Some("operator1".parse()?),
    /// )?;
    /// nethsm.use_credentials(&"operator1".parse()?)?;
    ///
    /// // get 10 random bytes
    /// println!("{:#?}", nethsm.random(10)?);
    /// # Ok(())
    /// # }
    /// ```
    /// [random]: https://docs.nitrokey.com/nethsm/operation#random
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn random(&self, length: u32) -> Result<Vec<u8>, Error> {
        debug!(
            "Create {length} random bytes on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let base64_bytes = random_post(
            &self.create_connection_config(),
            RandomRequestData::new(length as i32),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Getting random bytes failed: {}",
                NetHsmApiError::from(error)
            ))
        })?
        .entity
        .random;
        Base64::decode_vec(&base64_bytes).map_err(Error::Base64Decode)
    }
}
