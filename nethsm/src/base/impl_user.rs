//! [`NetHsm`] implementation for user and namespace handling.

use log::debug;
use nethsm_sdk_rs::{
    apis::default_api::{
        namespaces_get,
        namespaces_namespace_id_delete,
        namespaces_namespace_id_put,
        users_get,
        users_post,
        users_user_id_delete,
        users_user_id_get,
        users_user_id_passphrase_post,
        users_user_id_put,
        users_user_id_tags_get,
        users_user_id_tags_tag_delete,
        users_user_id_tags_tag_put,
    },
    models::{UserData, UserPassphrasePostData, UserPostData},
};

#[cfg(doc)]
use crate::SystemState;
use crate::{
    Credentials,
    Error,
    NamespaceId,
    NetHsm,
    Passphrase,
    UserError,
    UserId,
    UserRole,
    base::utils::user_or_no_user_string,
    nethsm_sdk::NetHsmApiError,
    user::NamespaceSupport,
};

impl NetHsm {
    /// Adds a new namespace.
    ///
    /// Adds a new [namespace] with the ID `namespace_id`.
    ///
    /// **WARNING**: A user in the [`Administrator`][`UserRole::Administrator`] [role] must be added
    /// for the [namespace] using [`add_user`][`NetHsm::add_user`] **before** creating the
    /// [namespace]! Otherwise there is no user to administrate the new [namespace]!
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the namespace fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the namespace identified by `namespace_id` exists already
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
    ///
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
    /// // N-Administrator can not create namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.add_namespace(&"namespace2".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_namespace(&self, namespace_id: &NamespaceId) -> Result<(), Error> {
        debug!(
            "Add the namespace {namespace_id} on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        namespaces_namespace_id_put(&self.create_connection_config(), namespace_id.as_ref())
            .map_err(|error| {
                Error::Api(format!(
                    "Adding namespace failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// Gets all available [namespaces].
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the namespaces fails:
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
    ///
    /// // print list of all namespaces
    /// println!("{:?}", nethsm.get_namespaces()?);
    ///
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
    /// // N-Administrator can not get namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_namespaces().is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [namespaces]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_namespaces(&self) -> Result<Vec<NamespaceId>, Error> {
        debug!(
            "Retrieve all available namespaces from the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        let valid_namespaces = {
            let mut invalid_namespaces = Vec::new();
            let valid_namespaces = namespaces_get(&self.create_connection_config())
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting namespaces failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity
                .into_iter()
                .filter_map(|x| {
                    if let Ok(namespace) = NamespaceId::new(x.id.clone()) {
                        Some(namespace)
                    } else {
                        invalid_namespaces.push(x.id);
                        None
                    }
                })
                .collect::<Vec<NamespaceId>>();

            if !invalid_namespaces.is_empty() {
                return Err(UserError::InvalidNamespaceIds {
                    namespace_ids: invalid_namespaces,
                }
                .into());
            }
            valid_namespaces
        };

        Ok(valid_namespaces)
    }

    /// Deletes an existing [namespace].
    ///
    /// Deletes the [namespace] identified by `namespace_id`.
    ///
    /// **WARNING**: This call deletes the [namespace] and all keys in it! Make sure to create a
    /// [`backup`][`NetHsm::backup`]!
    ///
    /// This call requires using [`Credentials`] of a system-wide user in the
    /// [`Administrator`][`UserRole::Administrator`] [role] (*R-Administrator*).
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the namespace fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the [namespace] identified by `namespace_id` does not exist
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
    /// // N-Administrators can not delete namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.delete_namespace(&"namespace1".parse()?).is_err());
    ///
    /// // R-Administrators can delete namespaces
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.delete_namespace(&"namespace1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_namespace(&self, namespace_id: &NamespaceId) -> Result<(), Error> {
        debug!(
            "Delete the namespace {namespace_id} from the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Unsupported, None, None)?;
        namespaces_namespace_id_delete(&self.create_connection_config(), namespace_id.as_ref())
            .map_err(|error| {
                Error::Api(format!(
                    "Deleting namespace failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// [Adds a user] and returns its User ID.
    ///
    /// A new user is created by providing a `real_name` from which a User ID is derived (optionally
    /// a User ID can be provided with `user_id`), a `role` which describes the user's access rights
    /// on the NetHSM (see [`UserRole`]) and a `passphrase`.
    ///
    /// Internally, this function also calls [`add_credentials`][`NetHsm::add_credentials`] to
    /// add the new user to the list of available credentials.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    /// When adding a user to a [namespace], that does not yet exist, the caller must
    /// be a system-wide [`Administrator`][`UserRole::Administrator`] (*R-Administrator*).
    /// When adding a user to an already existing [namespace], the caller must be an
    /// [`Administrator`][`UserRole::Administrator`] in that [namespace]
    /// (*N-Administrator*).
    ///
    /// ## Namespaces
    ///
    /// New users *implicitly* inherit the [namespace] of the caller.
    /// A [namespace] can be provided *explicitly* by prefixing the User ID with the ID of a
    /// [namespace] and the `~` character (e.g. `namespace1~user1`).
    /// When specifying a namespace as part of the User ID and the [namespace] exists already, the
    /// caller must be an [`Administrator`][`UserRole::Administrator`] of that [namespace]
    /// (*N-Administrator*).
    /// When specifying a [namespace] as part of the User ID and the [namespace] does not yet exist,
    /// the caller must be a system-wide [`Administrator`][`UserRole::Administrator`]
    /// (*R-Administrator*).
    ///
    /// **NOTE**: Users in the [`Backup`][`UserRole::Backup`] and [`Metrics`][`UserRole::Metrics`]
    /// [role] can not be created for a [namespace], as their underlying functionality can only be
    /// used in a system-wide context!
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the provided `real_name`, `passphrase` or `user_id` are not valid
    /// * the provided `user_id` exists already
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a system-wide
    ///   [`Administrator`][`UserRole::Administrator`], when adding a user to a not yet existing
    ///   [namespace]
    /// * the used [`Credentials`] are not that of an [`Administrator`][`UserRole::Administrator`]
    ///   in the [namespace] the user is about to be added to
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
    ///
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    ///
    /// // this fails because the user exists already
    /// assert!(nethsm
    ///     .add_user(
    ///         "Operator One".to_string(),
    ///         UserRole::Operator,
    ///         Passphrase::new("operator1-passphrase".to_string()),
    ///         Some("user1".parse()?),
    ///     )
    ///     .is_err());
    ///
    /// // add a user in the Administrator role (N-Administrator) for a not yet existing namespace "namespace1"
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespace1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    /// [Adds a user]: https://docs.nitrokey.com/nethsm/administration#add-user
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_user(
        &self,
        real_name: String,
        role: UserRole,
        passphrase: Passphrase,
        user_id: Option<UserId>,
    ) -> Result<UserId, Error> {
        debug!(
            "Add the user \"{real_name}\"{} in the role {role} to the NetHSM at {} using {}",
            if let Some(user_id) = user_id.as_ref() {
                format!(" (\"{user_id}\")")
            } else {
                "".to_string()
            },
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, user_id.as_ref(), Some(&role))?;
        let user_id = if let Some(user_id) = user_id {
            users_user_id_put(
                &self.create_connection_config(),
                &user_id.to_string(),
                UserPostData::new(real_name, role.into(), passphrase.expose_owned()),
            )
            .map_err(|error| {
                Error::Api(format!(
                    "Adding user failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
            user_id
        } else {
            UserId::new(
                users_post(
                    &self.create_connection_config(),
                    UserPostData::new(real_name, role.into(), passphrase.expose_owned()),
                )
                .map_err(|error| {
                    Error::Api(format!(
                        "Adding user failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity
                .id,
            )?
        };

        // add to list of users
        self.add_credentials(Credentials::new(user_id.clone(), Some(passphrase)));

        Ok(user_id)
    }

    /// Deletes an existing user.
    ///
    /// [Deletes a user] identified by `user_id`.
    ///
    /// Internally, this function also calls [`remove_credentials`][`NetHsm::remove_credentials`] to
    /// remove the user from the list of available credentials.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) can only delete users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) can
    ///   only delete system-wide users, but not those in a [namespace]. To allow *R-Administrators*
    ///   to delete users in a [namespace], the given [namespace] has to be deleted first using
    ///   [`delete_namespace`][`NetHsm::delete_namespace`].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting a user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] role
    /// * the targeted user is in an existing [namespace], but the caller is an *R-Administrator* or
    ///   an *N-Administrator* in a different [namespace]
    /// * the targeted user is a system-wide user, but the caller is not an *R-Administrator*
    /// * the user attempts to delete itself
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
    ///
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // R-Administrators can not delete N-Administrators, as long as their namespace exists
    /// assert!(nethsm.delete_user(&"namespace1~admin1".parse()?).is_err());
    /// // however, after deleting the namespace, this becomes possible
    /// nethsm.delete_namespace(&"namespace1".parse()?)?;
    /// nethsm.delete_user(&"namespace1~admin1".parse()?)?;
    ///
    /// // R-Administrators can delete system-wide users
    /// nethsm.delete_user(&"user1".parse()?)?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Deletes a user]: https://docs.nitrokey.com/nethsm/administration#delete-user
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_user(&self, user_id: &UserId) -> Result<(), Error> {
        debug!(
            "Delete the user \"{user_id}\" from the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        users_user_id_delete(&self.create_connection_config(), &user_id.to_string()).map_err(
            |error| {
                Error::Api(format!(
                    "Deleting user failed: {}",
                    NetHsmApiError::from(error)
                ))
            },
        )?;

        // remove from list of credentials
        self.remove_credentials(user_id);

        Ok(())
    }

    /// Gets a [list of all User IDs].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) can only list users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) can
    ///   list all users on the system.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving the list of all User IDs fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] role
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
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// // the N-Administrator only sees itself
    /// assert_eq!(nethsm.get_users()?.len(), 1);
    ///
    /// // use the credentials of the R-Administrator
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// // the R-Administrator sees at least itself and the previously created N-Administrator
    /// assert!(nethsm.get_users()?.len() >= 2);
    /// # Ok(())
    /// # }
    /// ```
    /// [list of all User IDs]: https://docs.nitrokey.com/nethsm/administration#list-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_users(&self) -> Result<Vec<UserId>, Error> {
        debug!(
            "Get the users of the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, None, None)?;
        let valid_users = {
            let mut invalid_users = Vec::new();
            let valid_users = users_get(&self.create_connection_config())
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting users failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity
                .into_iter()
                .filter_map(|x| {
                    if let Ok(user) = UserId::new(x.user.clone()) {
                        Some(user)
                    } else {
                        invalid_users.push(x.user);
                        None
                    }
                })
                .collect::<Vec<UserId>>();

            if !invalid_users.is_empty() {
                return Err(UserError::InvalidUserIds {
                    user_ids: invalid_users,
                }
                .into());
            }

            valid_users
        };

        Ok(valid_users)
    }

    /// Gets [information of a user].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) can only access information about users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) can
    ///   access information about all users on the system.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if retrieving information of the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] role
    /// * the used [`Credentials`] do not provide access to information about a user in the targeted
    ///   [namespace] (*N-Administrator* of a different [namespace])
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
    ///
    /// // add a user in the Administrator role for a namespace (N-Administrator)
    /// nethsm.add_user(
    ///     "Namespace1 Admin".to_string(),
    ///     UserRole::Administrator,
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// // the N-Administrator sees itself
    /// println!("{:?}", nethsm.get_user(&"namespace1~admin1".parse()?)?);
    /// // the N-Administrator can not see the R-Administrator
    /// assert!(nethsm.get_user(&"admin".parse()?).is_err());
    ///
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// // the R-Administrator sees itself
    /// println!("{:?}", nethsm.get_user(&"admin".parse()?)?);
    /// // the R-Administrator sees the N-Administrator
    /// println!("{:?}", nethsm.get_user(&"namespace1~admin1".parse()?)?);
    /// // this fails if the user does not exist
    /// assert!(nethsm.get_user(&"user1".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [information of a user]: https://docs.nitrokey.com/nethsm/administration#list-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_user(&self, user_id: &UserId) -> Result<UserData, Error> {
        debug!(
            "Get the information of the user \"{user_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        Ok(
            users_user_id_get(&self.create_connection_config(), &user_id.to_string())
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting user failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }

    /// Sets the [passphrase for a user] on the NetHSM.
    ///
    /// ## Namespaces
    ///
    /// *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    /// [namespace]) are only able to set the passphrases for users in their own [namespace].
    /// *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are only
    /// able to set the passphrases for system-wide users.
    ///
    /// Internally, this function also calls [`add_credentials`][`NetHsm::add_credentials`] to add
    /// the updated user [`Credentials`] to the list of available ones.
    /// If the calling user is in the [`Administrator`][`UserRole::Administrator`] [role] and
    /// changes their own passphrase, additionally
    /// [`use_credentials`][`NetHsm::use_credentials`] is called to use the updated passphrase
    /// after changing it.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if setting the passphrase for the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the targeted user is in a [namespace], but the caller is not an
    ///   [`Administrator`][`UserRole::Administrator`] of that [namespace] (*N-Administrator*)
    /// * the targeted user is a system-wide user, but the caller is not a system-wide
    ///   [`Administrator`][`UserRole::Administrator`] (*R-Administrator*)
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
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    ///
    /// // the R-Administrator can set its own passphrase
    /// nethsm.set_user_passphrase(
    ///     "admin".parse()?,
    ///     Passphrase::new("new-admin-passphrase".to_string()),
    /// )?;
    /// // the R-Administrator can not set the N-Administrator's passphrase
    /// assert!(
    ///     nethsm
    ///         .set_user_passphrase(
    ///             "namespace1~admin".parse()?,
    ///             Passphrase::new("new-admin-passphrase".to_string()),
    ///         )
    ///         .is_err()
    /// );
    ///
    /// // the N-Administrator can set its own passphrase
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// nethsm.set_user_passphrase(
    ///     "namespace1~admin1".parse()?,
    ///     Passphrase::new("new-admin-passphrase".to_string()),
    /// )?;
    /// // the N-Administrator can not set the R-Administrator's passphrase
    /// assert!(
    ///     nethsm
    ///         .set_user_passphrase(
    ///             "admin".parse()?,
    ///             Passphrase::new("new-admin-passphrase".to_string())
    ///         )
    ///         .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    /// [passphrase for a user]: https://docs.nitrokey.com/nethsm/administration#user-passphrase
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn set_user_passphrase(
        &self,
        user_id: UserId,
        passphrase: Passphrase,
    ) -> Result<(), Error> {
        debug!(
            "Set the passphrase of the user \"{user_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, Some(&user_id), None)?;
        users_user_id_passphrase_post(
            &self.create_connection_config(),
            &user_id.to_string(),
            UserPassphrasePostData::new(passphrase.expose_owned()),
        )
        .map_err(|error| {
            Error::Api(format!(
                "Setting user passphrase failed: {}",
                NetHsmApiError::from(error)
            ))
        })?;

        // add to list of available credentials
        self.add_credentials(Credentials::new(user_id, Some(passphrase)));

        Ok(())
    }

    /// [Adds a tag] to a user in the [`Operator`][`UserRole::Operator`] [role].
    ///
    /// A `tag` provides the user identified by `user_id` with access to keys in their [namespace],
    /// that are tagged with that same `tag`.
    ///
    /// **NOTE**: The tag for the key in the same [namespace] must be added beforehand, by calling
    /// [`add_key_tag`][`NetHsm::add_key_tag`].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to add tags for users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to add tags for system-wide users.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if adding the tag for the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the [`Operator`][`UserRole::Operator`] [role]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the caller does not have access to the target user's [namespace]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
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
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add a user in the Operator role for a namespace
    /// nethsm.add_user(
    ///     "Namespace1 Operator".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("namespce1-operator-passphrase".to_string()),
    ///     Some("namespace1~operator1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".parse()?),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    ///
    /// // R-Administrators can add tags for system-wide users
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    /// // R-Administrators can not add tags for namespace users
    /// assert!(
    ///     nethsm
    ///         .add_user_tag(&"namespace1~user1".parse()?, "tag1")
    ///         .is_err()
    /// );
    ///
    /// // user tags in namespaces
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// // generate key in namespace1 with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing2".parse()?),
    ///     Some(vec!["tag2".to_string()]),
    /// )?;
    /// // N-Administrators can not add tags to system-wide users
    /// assert!(nethsm.add_user_tag(&"user1".parse()?, "tag2").is_err());
    /// // N-Administrators can add tags to users in their own namespace
    /// nethsm.add_user_tag(&"namespace1~user1".parse()?, "tag2")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Adds a tag]: https://docs.nitrokey.com/nethsm/administration#tags-for-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn add_user_tag(&self, user_id: &UserId, tag: &str) -> Result<(), Error> {
        debug!(
            "Add the tag \"{tag}\" for the user \"{user_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        users_user_id_tags_tag_put(&self.create_connection_config(), &user_id.to_string(), tag)
            .map_err(|error| {
                Error::Api(format!(
                    "Adding tag for user failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// [Deletes a tag] from a user in the [`Operator`][`UserRole::Operator`] [role].
    ///
    /// Removes a `tag` from a target user identified by `user_id`, which removes its access to any
    /// key in their [namespace], that carries the same `tag`.
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to delete tags for users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   only able to delete tags for system-wide users.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if deleting the tag from the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the [`Operator`][`UserRole::Operator`] [role]
    /// * the `tag` is not added to user identified by `user_id`
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the caller does not have access to the target user's [namespace]
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use nethsm::{
    ///     Connection,
    ///     ConnectionSecurity,
    ///     Credentials,
    ///     KeyMechanism,
    ///     KeyType,
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
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add a user in the Operator role for a namespace
    /// nethsm.add_user(
    ///     "Namespace1 Operator".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("namespce1-operator-passphrase".to_string()),
    ///     Some("namespace1~operator1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    /// // generate system-wide key with tag
    /// nethsm.generate_key(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     Some("signing1".parse()?),
    ///     Some(vec!["tag1".to_string()]),
    /// )?;
    /// // add tag for system-wide user
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    ///
    /// // N-Administrators can not delete tags from system-wide Operator users
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.delete_user_tag(&"user1".parse()?, "tag2").is_err());
    ///
    /// // R-Administrators can delete tags from system-wide Operator users
    /// nethsm.use_credentials(&"admin".parse()?)?;
    /// nethsm.delete_user_tag(&"user1".parse()?, "tag1")?;
    /// # Ok(())
    /// # }
    /// ```
    /// [Deletes a tag]: https://docs.nitrokey.com/nethsm/administration#tags-for-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn delete_user_tag(&self, user_id: &UserId, tag: &str) -> Result<(), Error> {
        debug!(
            "Delete the tag \"{tag}\" from the user \"{user_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        users_user_id_tags_tag_delete(&self.create_connection_config(), &user_id.to_string(), tag)
            .map_err(|error| {
                Error::Api(format!(
                    "Deleting tag for user failed: {}",
                    NetHsmApiError::from(error)
                ))
            })?;
        Ok(())
    }

    /// [Gets all tags] of a user in the [`Operator`][`UserRole::Operator`] [role].
    ///
    /// This call requires using [`Credentials`] of a user in the
    /// [`Administrator`][`UserRole::Administrator`] [role].
    ///
    /// ## Namespaces
    ///
    /// * *N-Administrators* ([`Administrator`][`UserRole::Administrator`] users in a given
    ///   [namespace]) are only able to get tags of users in their own [namespace].
    /// * *R-Administrators* (system-wide [`Administrator`][`UserRole::Administrator`] users) are
    ///   able to get tags of system-wide and all [namespace] users.
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Api`] if getting the tags for the user fails:
    /// * the NetHSM is not in [`Operational`][`SystemState::Operational`] [state]
    /// * the user identified by `user_id` does not exist
    /// * the user identified by `user_id` is not in the [`Operator`][`UserRole::Operator`] [role]
    /// * the used [`Credentials`] are not correct
    /// * the used [`Credentials`] are not that of a user in the
    ///   [`Administrator`][`UserRole::Administrator`] [role]
    /// * the caller does not have access to the target user's [namespace]
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
    ///     Passphrase::new("namespce1-admin-passphrase".to_string()),
    ///     Some("namespace1~admin1".parse()?),
    /// )?;
    /// // add the accompanying namespace
    /// nethsm.add_namespace(&"namespace1".parse()?)?;
    /// // add a system-wide user in the Operator role
    /// nethsm.add_user(
    ///     "Operator One".to_string(),
    ///     UserRole::Operator,
    ///     Passphrase::new("operator1-passphrase".to_string()),
    ///     Some("user1".parse()?),
    /// )?;
    ///
    /// // R-Administrators can access tags of all users
    /// assert!(nethsm.get_user_tags(&"user1".parse()?)?.is_empty());
    /// // add a tag for the user
    /// nethsm.add_user_tag(&"user1".parse()?, "tag1")?;
    /// assert_eq!(nethsm.get_user_tags(&"user1".parse()?)?.len(), 1);
    ///
    /// // N-Administrators can not access tags of system-wide users
    /// nethsm.use_credentials(&"namespace1~admin1".parse()?)?;
    /// assert!(nethsm.get_user_tags(&"user1".parse()?).is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [Gets all tags]: https://docs.nitrokey.com/nethsm/administration#tags-for-users
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    /// [state]: https://docs.nitrokey.com/nethsm/administration#state
    pub fn get_user_tags(&self, user_id: &UserId) -> Result<Vec<String>, Error> {
        debug!(
            "Get the tags of the user \"{user_id}\" on the NetHSM at {} using {}",
            self.url.borrow(),
            user_or_no_user_string(self.current_credentials.borrow().as_ref()),
        );

        self.validate_namespace_access(NamespaceSupport::Supported, Some(user_id), None)?;
        Ok(
            users_user_id_tags_get(&self.create_connection_config(), &user_id.to_string())
                .map_err(|error| {
                    Error::Api(format!(
                        "Getting tags of user failed: {}",
                        NetHsmApiError::from(error)
                    ))
                })?
                .entity,
        )
    }
}
