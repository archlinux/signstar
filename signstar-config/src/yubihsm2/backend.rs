//! Backend handling for YubiHSM2.
//!
//! Using this module, a YubiHSM2 can be synchronized against a Signstar configuration file,
//! describing its desired state.
//!
//! While the configuration allows for setting up administrative and non-administrative users of the
//! backend in a declarative fashion, there are also certain implicit elements, which this module
//! takes care of.
//! Most notably, the wrap key, used for backups is always stored using the ID `1`.
#![cfg(feature = "yubihsm2")]

use std::{
    cell::RefCell,
    collections::HashSet,
    fmt::{Debug, Display},
};

use log::{debug, error, info};
use signstar_crypto::traits::UserWithPassphrase;
use signstar_yubihsm2::{
    Credentials,
    automation::{
        AuthenticatedCommandChain,
        Command,
        CommandReturnValue,
        ListObjectFilter,
        ObjectType,
        Scenario,
        ScenarioRunner,
    },
    backup::Label,
    object::{AuthenticationKey, Capabilities, Domains, Id, KeyInfo, ObjectAlgorithm, ObjectId},
    yubihsm::{Connector, Info},
};

use crate::{
    admin_credentials::AdminCredentials,
    config::Config,
    state::{StateOrigin, StateOriginInfo},
    yubihsm2::{
        Error,
        YubiHsm2Config,
        YubiHsm2UserMapping,
        admin_credentials::YubiHsm2AdminCredentials,
    },
};

/// Returns a list of [`Id`]s for a specific object type `filter`.
///
/// # Errors
///
/// Returns an error, if
///
/// - running a scenario fails
/// - there is a logic error in the value(s) returned by the backend
fn get_key_ids(
    runner: &ScenarioRunner,
    credentials: &Credentials,
    object_type: ObjectType,
) -> Result<Vec<Id>, crate::Error> {
    debug!(
        "Retrieving list of {object_type} using the credentials {}",
        credentials.id()
    );

    let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(
        credentials.clone(),
        vec![Command::ListObjects(vec![ListObjectFilter::Type(
            object_type,
        )])],
    )]);
    let scenario_result = runner.run(&scenario)?;

    let Some(command_return_values) = scenario_result.chains().first() else {
        return Err(Error::ScenarioLogic {
            context: "there is no list of command return values when retrieving the list of keys for an object type",
        }
        .into());
    };
    let Some(command_return_value) = command_return_values.first() else {
        return Err(Error::ScenarioLogic {
            context: "there is no command return value for retrieving the list of keys for an object type",
        }
        .into());
    };
    let CommandReturnValue::ListObjects(entries) = command_return_value else {
        return Err(Error::ScenarioLogic {
            context: "there are no return values for retrieving the list of keys for an object type",
        }
        .into());
    };

    // Get a validated list of IDs (all must be in the range of 1 - 256).
    let ids = {
        let mut ids = Vec::new();
        for entry in entries {
            debug!("{entry:?}");
            ids.push(Id::try_from(entry.object_id)?);
        }

        ids
    };

    Ok(ids)
}

/// Returns a list of object infos for a list of object IDs.
///
/// # Errors
///
/// Returns an error, if
///
/// - retrieving object information from the backend fails
/// - there is a logic error in the value(s) returned by the backend
fn get_object_infos_for_object_ids(
    runner: &ScenarioRunner,
    credentials: &Credentials,
    object_ids: &[ObjectId],
) -> Result<Vec<Info>, crate::Error> {
    debug!(
        "Retrieving list of object infos for object IDs {} using the credentials {}",
        object_ids
            .iter()
            .map(|id| format!("{id:?}"))
            .collect::<Vec<_>>()
            .join(", "),
        credentials.id()
    );

    if object_ids.is_empty() {
        return Ok(Vec::new());
    }

    let commands = object_ids
        .iter()
        .map(|id| Command::GetObjectInfo(*id))
        .collect::<Vec<Command>>();
    let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(
        credentials.clone(),
        commands,
    )]);
    let scenario_return_value = runner.run(&scenario)?;

    let command_return_values = {
        let return_values: Vec<Vec<CommandReturnValue>> = scenario_return_value.into();
        let mut return_values_iter = return_values.into_iter();

        let Some(command_return_values) = return_values_iter.next() else {
            return Err(Error::ScenarioLogic {
                    context: "there is no list of command return values when retrieving the list of object infos",
                }
                .into());
        };
        if return_values_iter.next().is_some() {
            return Err(Error::ScenarioLogic {
                context: "there are more return values than there were chains of commands for retrieving the list of object infos",
            }
            .into());
        }
        if command_return_values.len() != object_ids.len() {
            return Err(Error::ScenarioLogic {
                    context: "the number of requested object infos does not match the number of retrieved object infos",
                }
                .into());
        }

        command_return_values
    };

    let infos = {
        let mut infos = Vec::new();

        for (command_return_value, id) in command_return_values
            .into_iter()
            .zip(object_ids.iter().map(|object_id| object_id.id()))
        {
            let CommandReturnValue::GetObjectInfo(info) = command_return_value else {
                return Err(Error::ScenarioLogic {
                            context: "something different from object information was returned when requesting object information",
                        }
                        .into());
            };

            if id.get().get() != info.object_id {
                return Err(Error::ScenarioLogic {
                            context: "retrieved object information does not match the ID used for the request",
                        }
                        .into());
            }

            infos.push(info);
        }
        infos
    };

    Ok(infos)
}

/// Returns a list of object infos for a list of object types.
///
/// # Errors
///
/// Returns an error, if
///
/// - key IDs for objects of a specific type cannot be retrieved,
/// - object infos for a specific set of object type and object ID cannot be retrieved
fn get_object_infos_for_object_types(
    runner: &ScenarioRunner,
    credentials: &Credentials,
    object_types: &[ObjectType],
) -> Result<Vec<Info>, crate::Error> {
    debug!(
        "Retrieve object infos for objects of the types {}",
        object_types
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let output = {
        let mut output = Vec::new();
        for object_type in object_types {
            let ids = get_key_ids(runner, credentials, *object_type)?;
            let mut infos = get_object_infos_for_object_ids(
                runner,
                credentials,
                &ids.iter()
                    .map(|id| ObjectId::from((*object_type, *id)))
                    .collect::<Vec<_>>(),
            )?;
            output.append(&mut infos);
        }
        output
    };

    Ok(output)
}

/// A list of user mappings and their credentials for a YubiHSM2.
///
/// # Note
///
/// This type does not inherently distinguish between user mappings for administrative and
/// non-administrative users!
///
/// To create this struct for non-administrative user mappings, use [`Self::new_from_non_admin`] and
#[derive(Clone, Debug)]
struct UserMappingsAndCredentials<'config, 'creds>(
    Vec<(&'config YubiHsm2UserMapping, &'creds Credentials)>,
);

impl<'config, 'creds> UserMappingsAndCredentials<'config, 'creds> {
    /// Creates a new [`UserMappingsAndCredentials`] for the non-administrative user mappings in a
    /// [`YubiHsm2Config`] and a list of [`Credentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - there are duplicates in `creds`
    /// - not every user mapping has credentials assigned to it
    /// - not every credentials have user mappings assigned to them
    pub fn new_from_non_admin(
        config: &'config YubiHsm2Config,
        creds: &'creds [Credentials],
    ) -> Result<Self, crate::Error> {
        let mappings = config
            .mappings()
            .iter()
            .filter(|mapping| !matches!(mapping, YubiHsm2UserMapping::Admin { .. }))
            .collect::<HashSet<_>>();

        Self::try_from((&mappings, creds))
    }

    /// Creates a new [`UserMappingsAndCredentials`] for the administrative user mappings in a
    /// [`YubiHsm2Config`] and the administrative credentials of a [`YubiHsm2AdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - there are duplicates in `creds`
    /// - not every user mapping has credentials assigned to it
    /// - not every credentials have user mappings assigned to them
    pub fn new_from_admin(
        config: &'config YubiHsm2Config,
        creds: &'creds YubiHsm2AdminCredentials,
    ) -> Result<Self, crate::Error> {
        let mappings = config
            .mappings()
            .iter()
            .filter(|mapping| matches!(mapping, YubiHsm2UserMapping::Admin { .. }))
            .collect::<HashSet<_>>();
        let creds = creds.administrators();

        Self::try_from((&mappings, creds))
    }
}

impl<'config, 'creds> TryFrom<(&'config YubiHsm2Config, &'creds YubiHsm2AdminCredentials)>
    for UserMappingsAndCredentials<'config, 'creds>
{
    type Error = crate::Error;

    /// Creates a new [`UserMappingsAndCredentials`] from a [`YubiHsm2Config`] and a
    /// [`YubiHsm2AdminCredentials`].
    ///
    /// Extracts all [`YubiHsm2UserMapping::Admin`] variants from the provided [`YubiHsm2Config`]
    /// and the list of administrator [`Credentials`] from the provided
    /// [`YubiHsm2AdminCredentials`].
    ///
    /// # Errors
    ///
    /// Returns an error if creating the [`UserMappingsAndCredentials`] from the extracted
    /// `(&[&'config YubiHsm2UserMapping], &'creds [Credentials])` fails.
    fn try_from(
        value: (&'config YubiHsm2Config, &'creds YubiHsm2AdminCredentials),
    ) -> Result<Self, Self::Error> {
        let mappings = value
            .0
            .mappings()
            .iter()
            .filter(|mapping| !matches!(mapping, YubiHsm2UserMapping::Admin { .. }))
            .collect::<HashSet<_>>();
        let creds = value.1.administrators();

        Self::try_from((&mappings, creds))
    }
}

impl<'config, 'creds>
    TryFrom<(
        &HashSet<&'config YubiHsm2UserMapping>,
        &'creds [Credentials],
    )> for UserMappingsAndCredentials<'config, 'creds>
{
    type Error = crate::Error;

    /// Creates a new [`UserMappingsAndCredentials`] from user mappings and credentials.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - there are duplicate [`Credentials`]
    /// - not every user mapping has credentials assigned to it
    /// - not every credentials have user mappings assigned to them
    fn try_from(
        value: (
            &HashSet<&'config YubiHsm2UserMapping>,
            &'creds [Credentials],
        ),
    ) -> Result<Self, Self::Error> {
        let (mappings, creds) = value;

        // Ensure, that there are no duplicate credentials.
        {
            let mut dupes = HashSet::new();
            for credentials in creds {
                if creds
                    .iter()
                    .filter(|creds| creds.id() == credentials.id())
                    .count()
                    > 1
                {
                    dupes.insert(credentials.id());
                }
            }
            if !dupes.is_empty() {
                let duplicates = {
                    let mut duplicates = Vec::from_iter(dupes);
                    duplicates.sort_unstable();
                    duplicates
                };
                return Err(Error::DuplicateCredentials {
                    context: "creating a validated set of user mappings and respective credentials",
                    duplicates,
                }
                .into());
            }
        }

        // Ensure, that each user mapping has credentials assigned to it.
        {
            let mut ids = Vec::new();
            for mapping in mappings.iter() {
                if !creds
                    .iter()
                    .any(|creds| mapping.backend_user_id() == creds.id())
                {
                    ids.push(mapping.backend_user_id());
                }
            }
            if !ids.is_empty() {
                return Err(Error::UserMappingWithoutCredentials {
                    context: "creating a validated set of user mappings and respective credentials",
                    ids,
                }
                .into());
            }
        }

        // Ensure, that each set of credentials has a user mapping assigned to it.
        {
            let mut ids = Vec::new();
            for credentials in creds {
                if !mappings
                    .iter()
                    .any(|mapping| mapping.backend_user_id() == credentials.id())
                {
                    ids.push(credentials.id());
                }
            }
            if !ids.is_empty() {
                return Err(Error::CredentialsWithoutUserMapping {
                    context: "creating a validated set of user mappings and respective credentials",
                    ids,
                }
                .into());
            }
        }

        // Create list of user mappings and matching credentials.
        let output = {
            let mut output = Vec::new();
            for user_mapping in mappings {
                let Some(matching_creds) = creds
                    .iter()
                    .find(|credentials| credentials.id() == user_mapping.backend_user_id())
                else {
                    return Err(Error::UserMappingWithoutCredentials {
                        context: "creating a validated set of user mappings and respective credentials",
                        ids: vec![user_mapping.backend_user_id()],
                    }
                    .into());
                };
                output.push((*user_mapping, matching_creds));
            }

            output
        };

        Ok(Self(output))
    }
}

impl<'config, 'creds> AsRef<[(&'config YubiHsm2UserMapping, &'creds Credentials)]>
    for UserMappingsAndCredentials<'config, 'creds>
{
    fn as_ref(&self) -> &[(&'config YubiHsm2UserMapping, &'creds Credentials)] {
        &self.0
    }
}

/// A YubiHSM2 backend that provides control over a YubiHSM2 and its data.
///
/// Using a specific [`Connector`], it is possible to synchronize a YubiHSM2 with the data provided
/// by a [`YubiHsm2AdminCredentials`] and a [`YubiHsm2Config`].
pub struct YubiHsm2Backend<'admin_creds, 'config> {
    runner: ScenarioRunner,
    admin_credentials: &'admin_creds YubiHsm2AdminCredentials,
    yubihsm2_config: &'config YubiHsm2Config,
    admin_user_mappings_and_creds: UserMappingsAndCredentials<'config, 'admin_creds>,
    /// Indication whether the default credentials are in use currently.
    default_credentials: RefCell<bool>,
}

impl<'admin_creds, 'config> YubiHsm2Backend<'admin_creds, 'config> {
    /// Creates a new [`YubiHsm2Backend`].
    ///
    /// Returns `Ok(None)` if `signstar_config` contains no [`YubiHsm2Config`].
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
    ) -> Result<Option<Self>, crate::Error> {
        debug!("Create a new YubiHSM2 backend for Signstar config");

        let Some(yubihsm2_config) = signstar_config.yubihsm2() else {
            return Ok(None);
        };

        // Ensure that the iterations of administrative credentials and signstar config match.
        if admin_credentials.iteration() != signstar_config.system().iteration() {
            return Err(crate::Error::IterationMismatch {
                admin_creds: admin_credentials.iteration(),
                signstar_config: signstar_config.system().iteration(),
            });
        }

        let admin_user_mappings_and_creds =
            UserMappingsAndCredentials::new_from_admin(yubihsm2_config, admin_credentials)?;

        let backend = Self {
            runner: ScenarioRunner::new(connector),
            admin_credentials,
            yubihsm2_config,
            admin_user_mappings_and_creds,
            default_credentials: RefCell::new(true),
        };
        backend.check_set_default_credentials();

        Ok(Some(backend))
    }

    /// Returns whether the default administrative credentials are in use.
    ///
    /// # Note
    ///
    /// The default administrative credentials are considered no longer in use, if logging in with
    /// them failed once.
    pub fn default_credentials_in_use(&self) -> bool {
        *self.default_credentials.borrow()
    }

    /// Checks whether the default credentials are in use and sets up [`YubiHsm2Backend`]
    /// accordingly.
    ///
    /// Returns `true`, if [`YubiHsm2AdminCredentials::default_credentials`] can be used to connect
    /// to the YubiHSM2 and the authentication key object contains the required capabilities and
    /// domains. Returns `false` in all other cases.
    fn check_set_default_credentials(&self) -> bool {
        info!("Checking whether the default credentials are still set...");

        let object_infos = match get_object_infos_for_object_ids(
            &self.runner,
            &YubiHsm2AdminCredentials::default_credentials(),
            &[ObjectId::AuthenticationKey(
                YubiHsm2AdminCredentials::default_id(),
            )],
        ) {
            Ok(object_infos) => object_infos,
            Err(error) => {
                *self.default_credentials.borrow_mut() = false;
                error!("{error}");
                return *self.default_credentials.borrow();
            }
        };
        let Some(info) = object_infos.first() else {
            *self.default_credentials.borrow_mut() = false;
            error!(
                "{}",
                crate::Error::YubiHsm2Backend(Error::ScenarioLogic {
                    context: "there is no object info for the default credentials",
                })
            );
            return *self.default_credentials.borrow();
        };

        let temp_admin_mapping = YubiHsm2UserMapping::Admin {
            authentication_key_id: YubiHsm2AdminCredentials::default_id(),
        };

        // Ensure, that the capabilities for the object match at least the ones that we require.
        let capabilities = temp_admin_mapping.capabilities();
        let device_capabilities = Capabilities::from(info.capabilities);
        if !capabilities
            .as_ref()
            .is_subset(device_capabilities.as_ref())
        {
            *self.default_credentials.borrow_mut() = false;
            error!(
                "The default credentials are valid, but the authentication key has differing non-default capabilities assigned to it!\nDefault capabilities: {capabilities}\nDevice capabilities: {device_capabilities}"
            );
            return *self.default_credentials.borrow();
        }

        // Ensure, that the domains for the object match at least the ones that we require.
        let device_domains = Domains::from(info.domains);
        if let Some(domains) = temp_admin_mapping.domains()
            && !domains.as_ref().is_subset(device_domains.as_ref())
        {
            *self.default_credentials.borrow_mut() = false;
            error!(
                "The default credentials are valid, but the authentication key has non-default domains assigned to it!\nDefault domains: {domains}\nDevice domains: {device_domains}"
            );
            return *self.default_credentials.borrow();
        }

        *self.default_credentials.borrow_mut() = true;
        *self.default_credentials.borrow()
    }

    /// Syncs the state of a Signstar configuration with the backend using credentials for users in
    /// non-administrative roles.
    pub fn sync(&self, user_credentials: &[Credentials]) -> Result<(), crate::Error> {
        let non_admin_users_and_creds =
            UserMappingsAndCredentials::new_from_non_admin(self.yubihsm2_config, user_credentials)?;
        debug!(
            "valid mappings and their creds: {}",
            non_admin_users_and_creds
                .as_ref()
                .iter()
                .map(|(mapping, creds)| format!("{mapping:?}: {creds:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );

        self.add_admin_users()?;

        // TODO: Add backup (wrap) key
        // TODO: add non-admin users
        // TODO: add keys
        // TODO: add certificates

        // Get current list of user states.
        let user_states = self.user_states();
        debug!("{:?}", user_states);

        // Get current list of key states.
        let key_states = self.key_states();
        debug!("{:?}", key_states);

        Ok(())
    }

    /// Sets up all admin users on the backend
    fn add_admin_users(&self) -> Result<(), crate::Error> {
        info!("Setting up administrative users...");

        let current_admin_credentials = self.admin_credentials();

        {
            let mut commands = Vec::new();
            // First, opportunistically add all administrative credentials, except the one currently
            // in use and the default credentials.
            for (mapping, creds) in
                self.admin_user_mappings_and_creds
                    .0
                    .iter()
                    .filter(|(mapping, ..)| {
                        mapping.backend_user_id() != YubiHsm2AdminCredentials::default_id()
                            && mapping.backend_user_id() != current_admin_credentials.id()
                    })
            {
                let Some(domains) = mapping.domains() else {
                    return Err(Error::Generic {
                        context: "retrieving the domains of an administrative user",
                    }
                    .into());
                };
                commands.push(Command::PutAuthenticationKey {
                    info: KeyInfo {
                        key_id: creds.id(),
                        domains,
                        caps: mapping.capabilities(),
                    },
                    delegated_caps: mapping.capabilities(),
                    authentication_key: AuthenticationKey::try_from(creds.passphrase())?,
                });
            }
            if !commands.is_empty() {
                let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(
                    self.admin_credentials(),
                    commands,
                )]);
                self.runner.run(&scenario)?;
            }
        }

        // If the default credentials are still available in the backend, either replace
        // them with matching ones from the admin credentials or delete them.
        //
        // NOTE: At this point the currently used admin credentials may either be the defaults, or
        // another, valid set of admin credentials!
        if self.default_credentials_in_use() {
            let mut commands = Vec::new();

            // If the default admin ID exists in our mappings and admin credentials, use them to
            // replace the default passphrase in the backend.
            if let Some((mapping, creds)) =
                self.admin_user_mappings_and_creds
                    .as_ref()
                    .iter()
                    .find(|(mapping, ..)| {
                        mapping.backend_user_id() == YubiHsm2AdminCredentials::default_id()
                    })
            {
                debug!(
                    "Replacing the default backend credentials with those from the administrative credentials..."
                );

                commands.push(Command::DeleteObject(ObjectId::AuthenticationKey(
                    YubiHsm2AdminCredentials::default_id(),
                )));

                let Some(domains) = mapping.domains() else {
                    return Err(Error::Generic {
                        context: "retrieving the domains of an administrative user",
                    }
                    .into());
                };
                commands.push(Command::PutAuthenticationKey {
                    info: KeyInfo {
                        key_id: creds.id(),
                        domains,
                        caps: mapping.capabilities(),
                    },
                    delegated_caps: mapping.capabilities(),
                    authentication_key: AuthenticationKey::try_from(creds.passphrase())?,
                });
            // Otherwise, remove the default credentials in the backend.
            } else {
                debug!("Removing the default administrative credentials...");

                commands.push(Command::DeleteObject(ObjectId::AuthenticationKey(
                    YubiHsm2AdminCredentials::default_id(),
                )));
            }

            let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(
                self.admin_credentials(),
                commands,
            )]);
            self.runner.run(&scenario)?;

            // Check whether the default credentials are still in use (they shouldn't be at this
            // point) and set the internal state accordingly.
            self.check_set_default_credentials();
        }

        Ok(())
    }

    /// Returns the currently usable credentials for an administrative user.
    fn admin_credentials(&self) -> Credentials {
        if self.default_credentials_in_use() {
            YubiHsm2AdminCredentials::default_credentials()
        } else {
            // TODO: this should be the first _usable_ admin creds instead!
            self.admin_credentials.first_administrator().clone()
        }
    }

    /// Returns the list of [`UserState`] objects present in the backend.
    pub(crate) fn user_states(&self) -> Result<Vec<UserState>, crate::Error> {
        let credentials = self.admin_credentials();
        // Get the list of all authentication key IDs.
        let infos = get_object_infos_for_object_types(
            &self.runner,
            &credentials,
            &[ObjectType::AuthenticationKey],
        )?;

        let user_states = {
            let mut user_states = Vec::new();

            for info in infos {
                debug!("{info:?}");
                user_states.push(UserState {
                    id: info.object_id.try_into()?,
                    capabilities: info.capabilities.into(),
                    domains: info.domains.into(),
                })
            }

            user_states
        };

        Ok(user_states)
    }

    /// Returns the list of [`KeyState`] objects present in the backend.
    pub(crate) fn key_states(&self) -> Result<Vec<KeyState>, crate::Error> {
        let credentials = self.admin_credentials();
        // Get the list of IDs for all objects that are not authentication keys.
        let object_types = [
            ObjectType::AsymmetricKey,
            ObjectType::HmacKey,
            ObjectType::Opaque,
            ObjectType::OtpAeakey,
            ObjectType::Template,
            ObjectType::WrapKey,
        ];
        let infos = get_object_infos_for_object_types(&self.runner, &credentials, &object_types)?;

        let key_states = {
            let mut key_states = Vec::new();

            for info in infos {
                debug!("{info:?}");
                key_states.push(KeyState {
                    id: info.object_id.try_into()?,
                    object_type: info.object_type.into(),
                    capabilities: info.capabilities.into(),
                    domains: info.domains.into(),
                    algorithm: info.algorithm.into(),
                    label: info.label.into(),
                    length: info.length,
                })
            }

            key_states
        };

        Ok(key_states)
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

/// The state of a user in a [`YubiHsm2Backend`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct UserState {
    /// The ID of the user.
    pub id: Id,

    /// The capabilities of the user.
    pub capabilities: Capabilities,

    /// The domains of the user.
    pub domains: Domains,
}

impl Display for UserState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (capabilities: {}; domains: {})",
            self.id, self.capabilities, self.domains
        )
    }
}

/// The state of a key in a [`YubiHsm2Backend`].
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct KeyState {
    /// The ID of the signing key.
    // TODO: change to ObjectId?
    pub id: Id,

    /// The type of object.
    pub object_type: ObjectType,

    /// The capabilities of the signing key.
    pub capabilities: Capabilities,

    /// The domain of the signing key.
    pub domains: Domains,

    /// The object's algorithm.
    pub algorithm: ObjectAlgorithm,

    /// The object's label.
    pub label: Label,

    /// The object's size in bytes.
    pub length: u16,
}

impl Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (capabilities: {}; domains: {}; ",
            self.id, self.capabilities, self.domains,
        )?;
        // TODO: add further fields to the output
        // write!(f, "type: {}; ", self.key_setup.key_type())?;
        // write!(
        //     f,
        //     "mechanisms: {}; ",
        //     self.key_setup
        //         .key_mechanisms()
        //         .iter()
        //         .map(|mechanism| mechanism.to_string())
        //         .collect::<Vec<String>>()
        //         .join(", ")
        // )?;
        // write!(f, "context: {}", self.key_setup.key_context())?;
        write!(f, ")")?;

        Ok(())
    }
}

/// The state of a [`YubiHsm2Backend`].
///
/// This tracks two lists of data in the backend:
///
/// - the authentication keys ("user credentials"), their capabilities and domains
/// - all other key types, their capabilities, domains, algorithms, labels and lengths
#[derive(Debug, Eq, PartialEq)]
pub struct YubiHsm2BackendState {
    /// The user states.
    pub(crate) user_states: Vec<UserState>,

    /// The key states.
    pub(crate) key_states: Vec<KeyState>,
}

impl YubiHsm2BackendState {
    /// The name of the origin for the state.
    pub const STATE_NAME: &'static str = "YubiHSM2 backend";
}

impl<'admin_creds, 'config> TryFrom<YubiHsm2Backend<'admin_creds, 'config>>
    for YubiHsm2BackendState
{
    type Error = crate::Error;

    /// Creates a new [`YubiHsm2BackendState`] from a [`YubiHsm2Backend`].
    ///
    /// # Errors
    ///
    /// Returns an error if retrieving the user or key states from the backend fails.
    fn try_from(value: YubiHsm2Backend<'admin_creds, 'config>) -> Result<Self, Self::Error> {
        debug!(
            "Retrieve state of the YubiHSM2 backend at {}",
            value
                .yubihsm2_config
                .connections()
                .iter()
                .map(|connection| format!("{connection:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        );

        Ok(Self {
            user_states: value.user_states()?,
            key_states: value.key_states()?,
        })
    }
}

impl StateOriginInfo for YubiHsm2BackendState {
    fn state_name(&self) -> &str {
        Self::STATE_NAME
    }

    fn state_origin(&self) -> crate::state::StateOrigin {
        StateOrigin::Backend
    }
}

#[cfg(test)]
#[cfg(feature = "_yubihsm2-mockhsm")]
mod tests {
    use std::collections::BTreeSet;

    use log::LevelFilter;
    use rstest::{fixture, rstest};
    use signstar_common::logging::setup_logging;
    use signstar_crypto::{
        key::{
            CryptographicKeyContext,

            SigningKeySetup,
            base::{KeyMechanism, KeyType, SignatureType},
        },
        openpgp::OpenPgpUserIdList,
        passphrase::Passphrase,
    };
    use signstar_yubihsm2::{Connection, object::Domain};
    use testresult::TestResult;

    use super::*;
    use crate::{
        config::{ConfigBuilder, SystemConfig},
        yubihsm2::{YubiHsm2Config, YubiHsm2UserMapping},
    };

    /// Creates a MockHSM [`Connector`].
    #[fixture]
    fn connector() -> Connector {
        Connector::mockhsm()
    }

    /// Creates a default [`YubiHsm2Config`] for testing purposes.
    #[fixture]
    fn yubihsm2_config() -> TestResult<YubiHsm2Config> {
        Ok(YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: "1".parse()? },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: "3".parse()?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: "2".parse()?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: "1".parse()?,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: "4".parse()?,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: "5".parse()?,
                    signing_key_id: "1".parse()?,
                    key_setup: SigningKeySetup::new(
                        KeyType::Curve25519,
                        vec![KeyMechanism::EdDsaSignature],
                        None,
                        SignatureType::EdDsa,
                        CryptographicKeyContext::OpenPgp {
                            user_ids: OpenPgpUserIdList::new(vec![
                                "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                            ])?,
                            version: "v4".parse()?,
                        },
                    )?,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                    system_user: "yubihsm2-signing-user".parse()?,
                    domain: Domain::One,
                }
            ]),
        )?)
    }

    /// Creates a simple [`Config`] with [`YubiHsm2Config`].
    #[fixture]
    fn signstar_config(yubihsm2_config: TestResult<YubiHsm2Config>) -> TestResult<Config> {
        let yubihsm2_config = yubihsm2_config?;
        let config = ConfigBuilder::new(SystemConfig::new(
            1,
            signstar_crypto::AdministrativeSecretHandling::Plaintext,
            signstar_crypto::NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::from_iter([]),
        )?)
        .set_yubihsm2_config(yubihsm2_config)
        .finish()?;

        Ok(config)
    }

    #[fixture]
    fn admin_credentials() -> TestResult<YubiHsm2AdminCredentials> {
        let admin_creds = YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![
                Credentials::new("1".parse()?, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
            ]
        )?;
        Ok(admin_creds)
    }

    /// Creates a new [`YubiHsm2Backend`].
    ///
    /// # Errors
    ///
    /// Returns an error, if [`YubiHsm2Backend::new`] fails.
    ///
    /// # Panics
    ///
    /// Panics if [`YubiHsm2Backend::new`] returns [`Option::None`].
    fn create_yubihsm2_backend<'admin_creds, 'config>(
        connector: Connector,
        admin_credentials: &'admin_creds YubiHsm2AdminCredentials,
        signstar_config: &'config Config,
    ) -> TestResult<YubiHsm2Backend<'admin_creds, 'config>> {
        setup_logging(LevelFilter::Debug)?;
        let Some(backend) = YubiHsm2Backend::new(connector, admin_credentials, signstar_config)?
        else {
            panic!("The Config did not contain a YubiHsm2Config.");
        };

        Ok(backend)
    }

    /// Ensures, that [`YubiHsm2Backend::sync`] can be executed successfully (against a MockHSM
    /// backend).
    #[rstest]
    fn yubihsm2_backend_sync_succeeds(
        connector: Connector,
        admin_credentials: TestResult<YubiHsm2AdminCredentials>,
        signstar_config: TestResult<Config>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        let signstar_config = signstar_config?;
        let admin_credentials = admin_credentials?;

        let Some(backend) = YubiHsm2Backend::new(connector, &admin_credentials, &signstar_config)?
        else {
            panic!("oops");
        };
        let credentials = vec![
            Credentials::new("2".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("3".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("4".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("5".parse()?, Passphrase::generate(Some(50))),
        ];
        backend.sync(&credentials)?;
        // TODO: re-run sync (only possible after switching to our own, new yubihsm2 crate)
        backend.sync(&credentials)?;

        Ok(())
    }

    /// Ensures that creating a [`YubiHsm2BackendState`] from the default [`YubiHsm2Backend`]
    /// succeeds.
    #[rstest]
    fn yubihsm2_backend_state_try_from_yubihsm2_backend_succeeds(
        connector: Connector,
        admin_credentials: TestResult<YubiHsm2AdminCredentials>,
        signstar_config: TestResult<Config>,
    ) -> TestResult {
        let signstar_config = signstar_config?;
        let admin_credentials = admin_credentials?;
        let backend = create_yubihsm2_backend(connector, &admin_credentials, &signstar_config)?;

        let _state = YubiHsm2BackendState::try_from(backend)?;

        Ok(())
    }
}
