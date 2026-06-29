//! Backend handling for YubiHSM2.
//!
//! Using this module, a YubiHSM2 can be synchronized against a Signstar configuration file,
//! describing its desired state.
//!
//! While the configuration allows for setting up administrative and non-administrative users of the
//! backend in a declarative fashion, there are also certain implicit elements, which this module
//! takes care of.
//! Most notably, the wrap key, used for backups is always stored using the ID `1`.
//! Further, certificates created using a specific asymmetric key are always stored as opaque
//! objects using the same ID as the asymmetric key.
use std::{cell::RefCell, collections::HashSet, fmt::Debug};

use log::{debug, error, info, warn};
use pgp::types::Timestamp;
use signstar_crypto::{
    key::CryptographicKeyContext,
    openpgp::OpenPgpKeyUsageFlags,
    signer::openpgp::add_certificate,
    traits::UserWithPassphrase,
};
use signstar_yubihsm2::{
    Credentials,
    YubiHsm2SigningKey,
    automation::{
        AuthenticatedCommandChain,
        Command,
        CommandName,
        CommandReturnValue,
        ListObjectFilter,
        ObjectType,
        OpaqueData,
        OpaqueDataAlgorithm,
        OpaqueDataCapabilities,
        Scenario,
        ScenarioRunner,
    },
    backup::Label,
    object::{
        AuthenticationKey,
        Capabilities,
        Domains,
        KeyInfo,
        ObjectId,
        WrapKey,
        WrapKeyFromPassphrase,
        WrapKeyKind,
    },
    yubihsm::{Client, Connector, Id, Info},
};

use crate::{
    admin_credentials::AdminCredentials,
    config::Config,
    yubihsm2::{
        Error,
        YubiHsm2Config,
        YubiHsm2UserMapping,
        admin_credentials::YubiHsm2AdminCredentials,
    },
};

/// Return `true` if given administrative credentials are currently usable.
///
/// Returns `false` if the `credentials` cannot be used, have no object information, or do not match
/// the capabilities or domains they should have.
fn are_admin_creds_usable(runner: &ScenarioRunner, credentials: &Credentials) -> bool {
    info!(
        "Checking whether the authentication key {} is usable...",
        credentials.id()
    );

    let object_infos = match get_object_infos_for_object_ids(
        runner,
        credentials,
        &[ObjectId::AuthenticationKey(credentials.id())],
    ) {
        Ok(object_infos) => object_infos,
        Err(error) => {
            warn!("{error}");
            return false;
        }
    };

    let Some(info) = object_infos.first() else {
        warn!(
            "{}",
            crate::Error::YubiHsm2Backend(Error::ScenarioLogic {
                context: format!(
                    "there is no object info for the authentication key ID {}",
                    credentials.id()
                ),
            })
        );
        return false;
    };

    let temp_admin_mapping = YubiHsm2UserMapping::Admin {
        authentication_key_id: credentials.id(),
    };

    // Ensure, that the capabilities for the object match at least the ones that we require.
    let admin_capabilities = temp_admin_mapping.capabilities();
    let device_capabilities = Capabilities::from(info.capabilities);
    if !admin_capabilities
        .as_ref()
        .is_subset(device_capabilities.as_ref())
    {
        error!(
            "The admin credentials for authentication key ID {} are valid, but its capabilities ({device_capabilities}) do not include all of the necessary ones ({admin_capabilities})!",
            credentials.id(),
        );
        return false;
    }

    // Ensure, that the domains for the object match at least the ones that we require.
    let admin_domains = temp_admin_mapping.domains();
    let device_domains = Domains::from(info.domains);
    if !admin_domains.as_ref().is_subset(device_domains.as_ref()) {
        error!(
            "The admin credentials for authentication key ID {} are valid, but its domains ({device_domains}) do not include all of the necessary ones ({admin_domains})!",
            credentials.id(),
        );
        return false;
    }

    true
}

/// Returns a list of [`Id`]s that are of a specific [`ObjectType`].
///
/// # Note
///
/// Only [`Id`]s of keys visible to the provided [`Credentials`] are returned.
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
            context: format!("there are no command return values when retrieving the list of keys for the object type {object_type}"),
        }
        .into());
    };
    let Some(command_return_value) = command_return_values.first() else {
        return Err(Error::ScenarioLogic {
            context: format!("there is no command return value when retrieving the list of keys for the object type {object_type}"),
        }
        .into());
    };
    let CommandReturnValue::ListObjects(entries) = command_return_value else {
        return Err(Error::ScenarioLogic {
            context: format!("there are no entries when retrieving the list of keys for the object type {object_type}"),
        }
        .into());
    };

    Ok(entries
        .iter()
        .map(|entry| entry.object_id)
        .collect::<Vec<_>>())
}

/// Returns a list of [`Info`] objects for a list of [`ObjectId`] objects.
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
                    context: format!("there are no command return values when retrieving object infos for the objects {}",
                        object_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")),
                }
                .into());
        };
        if return_values_iter.next().is_some() {
            return Err(Error::ScenarioLogic {
                context: format!("there are more command return values than there were chains of commands when retrieving object infos for the objects {}",
                        object_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                ),
            }
            .into());
        }
        if command_return_values.len() != object_ids.len() {
            return Err(Error::ScenarioLogic {
                    context: format!("the number of returned object infos ({}) does not match the number of requested ones ({}) when retrieving object infos for the objects {}",
                        command_return_values.len(),
                        object_ids.len(),
                        object_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                    ),
                }
                .into());
        }

        command_return_values
    };

    let infos = {
        let mut infos = Vec::new();

        for (command_return_value, object_id) in command_return_values.into_iter().zip(object_ids) {
            let CommandReturnValue::GetObjectInfo(info) = command_return_value else {
                return Err(Error::ScenarioLogic {
                            context: format!("something different from object information was returned when requesting object information for the objects {}",
                                object_ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", "),
                            ),
                        }
                        .into());
            };

            if object_id.id() != info.object_id {
                return Err(Error::ScenarioLogic {
                    context: format!(
                        "the retrieved object information with ID {} does not match the object {object_id} used for the request", info.object_id
                    ),
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
/// Use [`Self::new_from_non_admin`] to create this struct for non-administrative user mappings and
/// [`Self::new_from_admin`] to create it for administrative user mappings.
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
#[derive(Debug)]
pub struct YubiHsm2Backend<'admin_creds, 'config> {
    connector: Connector,
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
    /// - the iteration of the `admin_credentials` does not match that of the `signstar_config`
    /// - a set of administrative user mappings and corresponding credentials cannot be created from
    ///   the `admin_credentials` and `signstar_config`
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
            connector: connector.clone(),
            runner: ScenarioRunner::new(connector),
            admin_credentials,
            yubihsm2_config,
            admin_user_mappings_and_creds,
            default_credentials: RefCell::new(true),
        };
        backend.check_set_default_credentials();

        Ok(Some(backend))
    }

    /// Returns a reference to the [`YubiHsm2Config`] used for the backend.
    pub fn yubihsm2_config(&self) -> &YubiHsm2Config {
        self.yubihsm2_config
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

        *self.default_credentials.borrow_mut() = are_admin_creds_usable(
            &self.runner,
            &YubiHsm2AdminCredentials::default_credentials(),
        );

        *self.default_credentials.borrow()
    }

    /// Syncs the state of a Signstar configuration with the backend using credentials for users in
    /// non-administrative roles.
    pub fn sync(&self, user_credentials: &[Credentials]) -> Result<(), crate::Error> {
        info!("Syncing the YubiHSM2 backend with the Signstar configuration...");

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
        self.add_wrap_key()?;
        self.add_non_admin_users(&non_admin_users_and_creds)?;
        self.add_signing_keys()?;
        self.add_openpgp_certificates(&non_admin_users_and_creds)?;

        Ok(())
    }

    /// Adds the OpenPGP certificates for keys that use them.
    ///
    /// # Note
    ///
    /// Does **not** overwrite existing data!
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - a usable administrative authentication key cannot be found
    /// - retrieving of opaque data info fails
    /// - creating an OpenPGP certificate for a signgin key fails
    /// - the scenario of adding OpenPGP certificates as opaque data fails
    /// - the return values of the scenario do not match the requested actions
    fn add_openpgp_certificates(
        &self,
        non_admin_user_mappings_and_creds: &UserMappingsAndCredentials,
    ) -> Result<(), crate::Error> {
        info!("Adding OpenPGP certificates for signing keys...");

        let credentials = self.usable_admin_creds()?;

        let (commands, ids) = {
            let opaque_data_infos = get_object_infos_for_object_types(
                &self.runner,
                &credentials,
                &[ObjectType::Opaque],
            )?;
            let mut commands = Vec::new();
            let mut ids = Vec::new();

            for (mapping, credentials) in non_admin_user_mappings_and_creds.as_ref() {
                // NOTE: We are disregarding the key information here, because we currently only
                // consider ed25519 keys.
                if let YubiHsm2UserMapping::Signing {
                    domain,
                    signing_key_id,
                    key_setup,
                    ..
                } = mapping
                {
                    let CryptographicKeyContext::OpenPgp { user_ids, version } =
                        key_setup.key_context()
                    else {
                        debug!(
                            "Skipping the generation of an OpenPGP certificate for signing key {signing_key_id}, because it is not setup for use with OpenPGP..."
                        );
                        continue;
                    };

                    if opaque_data_infos
                        .iter()
                        .any(|info| info.object_id == *signing_key_id)
                    {
                        warn!(
                            "Skipping the generation of an OpenPGP certificate for signing key {signing_key_id}, because data exists already..."
                        );
                        continue;
                    }

                    let client = Client::create(self.connector.clone(), (*credentials).into())
                        .map_err(|source| signstar_yubihsm2::Error::Client { context: "creating a client for adding OpenPGP certificates for a signing key", source })?;
                    let signer = YubiHsm2SigningKey::new(client, *signing_key_id);
                    let flags = {
                        let mut flags = OpenPgpKeyUsageFlags::default();
                        flags.set_sign();
                        flags
                    };
                    let certificate = add_certificate(
                        &signer,
                        flags,
                        user_ids.as_ref(),
                        Timestamp::now(),
                        *version,
                    )?;
                    signer.close_session()?;

                    commands.push(Command::PutOpaque {
                        id: *signing_key_id,
                        label: Label::from(&[0u8; 40]),
                        domains: Domains::from(*domain),
                        capabilities: OpaqueDataCapabilities::ExportableUnderWrap,
                        algorithm: OpaqueDataAlgorithm::OpaqueData,
                        data: OpaqueData::new(certificate)?,
                    });
                    ids.push(*signing_key_id);
                }
            }

            (commands, ids)
        };

        // If there is nothing to do, exit early.
        if commands.is_empty() {
            return Ok(());
        }

        let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(credentials, commands)]);
        let scenario_result = self.runner.run(&scenario)?;

        // Ensure that the requested and returned authentication key IDs match.
        let Some(command_return_values) = scenario_result.chains().first() else {
            return Err(Error::ScenarioLogic {
                context: format!(
                    "there are no command return values when adding OpenPGP certificates for signing keys {}",
                    ids.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
            .into());
        };
        if command_return_values.len() != ids.len() {
            return Err(Error::ScenarioLogic {
            context: format!("the number of command return values ({}) does not match the number of requested IDs ({}) when adding OpenPGP certificates for signing keys {}",
                command_return_values.len(),
                ids.len(),
                ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
        }
        .into());
        };

        for (command_return_value, requested_id) in command_return_values.iter().zip(ids.iter()) {
            let returned_id = match command_return_value {
                CommandReturnValue::PutOpaque(returned_id) => *returned_id,
                command => {
                    let command_name = CommandName::from(command);
                    return Err(Error::ScenarioLogic {
                        context: format!("instead of the command return value for adding an OpenPGP certificate for signing key {requested_id} the return value for {command_name} was returned"),
                    }
                    .into());
                }
            };

            if *requested_id != returned_id {
                return Err(Error::ScenarioLogic {
                    context: format!("the returned signing key ID ({returned_id}) does not match the requested one ({requested_id}) when adding OpenPGP certificates for the signing keys {}",
                        ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    ),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Adds the asymmetric signing keys.
    ///
    /// # Note
    ///
    /// Does **not** overwrite existing signing keys!
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - a usable administrative authentication key cannot be found
    /// - retrieving of signing key info fails
    /// - the scenario of generating asymmetric signging keys fails
    /// - the return values of the scenario do not match the requested actions
    fn add_signing_keys(&self) -> Result<(), crate::Error> {
        info!("Adding asymmetric signing keys...");

        let credentials = self.usable_admin_creds()?;
        let (commands, ids) = {
            let signing_key_infos = get_object_infos_for_object_types(
                &self.runner,
                &credentials,
                &[ObjectType::AsymmetricKey],
            )?;
            let mut commands = Vec::new();
            let mut ids = Vec::new();

            for mapping in self.yubihsm2_config.mappings() {
                // NOTE: We are disregarding the key information here, because we only ever consider
                // ed25519 keys.
                if let YubiHsm2UserMapping::Signing {
                    domain,
                    signing_key_id,
                    ..
                } = mapping
                {
                    // Do not replace already existing signing keys.
                    if signing_key_infos
                        .iter()
                        .any(|info| info.object_id == *signing_key_id)
                    {
                        warn!("Not adding signing key {signing_key_id}, as it exists already...");
                        continue;
                    }

                    commands.push(Command::GenerateAsymmetricKey {
                        info: KeyInfo {
                            key_id: *signing_key_id,
                            domains: Domains::from(*domain),
                            caps: mapping.capabilities(),
                        },
                    });
                    ids.push(*signing_key_id);
                }
            }

            (commands, ids)
        };

        // If there is nothing to do, exit early.
        if commands.is_empty() {
            return Ok(());
        }

        let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(credentials, commands)]);
        let scenario_result = self.runner.run(&scenario)?;

        let Some(command_return_values) = scenario_result.chains().first() else {
            return Err(Error::ScenarioLogic {
                context: format!(
                    "there are no command return values when adding the signing keys {}",
                    ids.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
            .into());
        };
        if command_return_values.len() != ids.len() {
            return Err(Error::ScenarioLogic {
            context: format!("the number of command return values ({}) does not match the number of requested IDs ({}) when adding the signing keys {}",
                command_return_values.len(),
                ids.len(),
                ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
        }
        .into());
        };

        for (number, command_return_value) in command_return_values.iter().enumerate() {
            let Some(id) = ids.get(number) else {
                return Err(Error::ScenarioLogic {
                    context: format!("the signing key ID number {number} does not exist in the list of signing keys {}",
                        ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    ),
                }
                .into());
            };
            let CommandReturnValue::GenerateAsymmetricKey(returned_id) = command_return_value
            else {
                return Err(Error::ScenarioLogic {
                    context: format!("the command return value when adding the signing key {id} is that of a different action"),
                }
                .into());
            };
            if id != returned_id {
                return Err(Error::ScenarioLogic {
                    context: format!("the returned signing key ID ({returned_id}) does not match the requested one ({id}) when adding the signing keys {}",
                        ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    ),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Adds non-administrative users.
    ///
    /// # Note
    ///
    /// Existing authentication keys are replaced!
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - a usable administrative authentication key cannot be found
    /// - the list of authentication key objects cannot be retrieved from the backend
    /// - a new authentication key cannot be created
    /// - the scenario cannot be run successfully
    /// - one or more return values of the scenario do not match the requested actions
    fn add_non_admin_users(
        &self,
        non_admin_user_mappings_and_creds: &UserMappingsAndCredentials,
    ) -> Result<(), crate::Error> {
        info!("Setting up non-administrative users...");

        let credentials = self.usable_admin_creds()?;

        let (commands, ids) = {
            let authentication_key_infos = get_object_infos_for_object_types(
                &self.runner,
                &credentials,
                &[ObjectType::AuthenticationKey],
            )?;
            let mut commands = Vec::new();
            let mut ids = Vec::new();

            for (mapping, creds) in non_admin_user_mappings_and_creds.as_ref() {
                let id = mapping.backend_user_id();

                if authentication_key_infos
                    .iter()
                    .any(|info| info.object_id == id)
                {
                    warn!("The existing authentication key {id} will be replaced...");
                    commands.push(Command::DeleteObject(ObjectId::AuthenticationKey(id)));
                }

                commands.push(Command::PutAuthenticationKey {
                    info: mapping.authentication_key_info(),
                    delegated_caps: Capabilities::from(vec![].as_slice()),
                    authentication_key: AuthenticationKey::try_from(creds.passphrase())
                        .map_err(crate::Error::SignstarYubiHsm2)?,
                });
                ids.push(id);
            }

            (commands, ids)
        };

        // If there is nothing to do, exit early.
        if commands.is_empty() {
            return Ok(());
        }

        let number_of_commands = commands.len();
        let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(credentials, commands)]);
        let scenario_result = self.runner.run(&scenario)?;

        // Validate the return values against the acclaimed actions.
        let Some(command_return_values) = scenario_result.chains().first() else {
            return Err(Error::ScenarioLogic {
                context: format!("there are no command return values when adding the non-administrative users {}",
                    ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                ),
            }
            .into());
        };
        if command_return_values.len() != number_of_commands {
            return Err(Error::ScenarioLogic {
            context: format!("the number of command return values ({}) does not match the number of requested IDs ({number_of_commands}) when adding the non-administrative users {}",
                command_return_values.len(),
                ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
            ),
        }
        .into());
        };

        // Ensure that the requested and returned authentication key IDs match.
        for (number, command_return_value) in command_return_values
            .iter()
            .filter(|command_return_value| {
                matches!(
                    command_return_value,
                    CommandReturnValue::PutAuthenticationKey(_)
                )
            })
            .enumerate()
        {
            let Some(id) = ids.get(number) else {
                return Err(Error::ScenarioLogic {
                    context: format!("the authentication key ID number {number} does not exist in the list of non-administrative users {}",
                        ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    ),
                }
                .into());
            };
            let CommandReturnValue::PutAuthenticationKey(returned_id) = command_return_value else {
                return Err(Error::ScenarioLogic {
                    context: format!("the command return value when adding the non-administrative user {id} is that of a different action"),
                }
                .into());
            };
            if id != returned_id {
                return Err(Error::ScenarioLogic {
                    context: format!("the returned authentication key ID ({returned_id}) does not match the requested one ({id}) when adding the non-administrative users {}",
                        ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                    ),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Adds a wrap key based on the backup passphrase.
    ///
    /// # Note
    ///
    /// Existing wrap keys are replaced!
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - usable administrative credentials cannot be found
    /// - infos about wrap keys cannot be retrieved from the backend
    /// - a wrap key cannot be created from the backup passphrase
    /// - running the scenario against the backend fails
    /// - the scenario's return values do not match the request
    fn add_wrap_key(&self) -> Result<(), crate::Error> {
        info!("Setting up wrapping key...");

        let credentials = self.usable_admin_creds()?;

        let commands = {
            let wrap_key_infos = get_object_infos_for_object_types(
                &self.runner,
                &credentials,
                &[ObjectType::WrapKey],
            )?;
            let mut commands = Vec::new();

            // If the wrap key exists already, delete it first.
            if wrap_key_infos
                .iter()
                .any(|info| info.object_id == YubiHsm2Config::WRAP_KEY_ID)
            {
                warn!(
                    "The existing wrapping key ({}) will be replaced...",
                    YubiHsm2Config::WRAP_KEY_ID
                );
                commands.push(Command::DeleteObject(ObjectId::WrappingKey(
                    YubiHsm2Config::WRAP_KEY_ID,
                )))
            }

            let passphrase = self.admin_credentials.backup_passphrase();
            let wrapping_key: WrapKey =
                WrapKeyFromPassphrase::new(passphrase, WrapKeyKind::Aes256)?.try_into()?;
            commands.push(Command::PutWrapKey {
                info: KeyInfo {
                    key_id: YubiHsm2Config::WRAP_KEY_ID,
                    domains: Domains::all(),
                    caps: Capabilities::from(YubiHsm2UserMapping::CAP_BACKUP),
                },
                delegated_caps: Capabilities::from(YubiHsm2UserMapping::CAP_BACKUP),
                wrapping_key,
            });
            commands
        };
        let number_of_commands = commands.len();

        let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(
            credentials.clone(),
            commands,
        )]);
        let scenario_return_value = self.runner.run(&scenario)?;

        // Validate the return values against the acclaimed actions.
        let command_return_values = {
            let return_values: Vec<Vec<CommandReturnValue>> = scenario_return_value.into();
            let return_values_len = return_values.len();
            let mut return_values_iter = return_values.into_iter();

            let Some(command_return_values) = return_values_iter.next() else {
                return Err(Error::ScenarioLogic {
                    context: format!(
                        "there are no command return values when adding the wrap key {}",
                        YubiHsm2Config::WRAP_KEY_ID
                    ),
                }
                .into());
            };
            if return_values_iter.next().is_some() {
                return Err(Error::ScenarioLogic {
                    context: format!("there are {} return value lists when adding the wrap key {}, but we expected exactly 1",
                        return_values_len,
                        YubiHsm2Config::WRAP_KEY_ID
                    ),
                }
                .into());
            }
            command_return_values
        };
        let returned_id = {
            match command_return_values.len() {
                2 => {
                    let Some(CommandReturnValue::DeleteObject) = command_return_values.first()
                    else {
                        return Err(Error::ScenarioLogic {
                            context: format!(
                                "there is no return value for removing a previously existing wrap key {}",
                                YubiHsm2Config::WRAP_KEY_ID
                            ),
                        }
                        .into());
                    };
                    let Some(CommandReturnValue::PutWrapKey(id)) = command_return_values.get(1)
                    else {
                        return Err(Error::ScenarioLogic {
                            context: format!(
                                "there is no return value for adding the wrap key {}",
                                YubiHsm2Config::WRAP_KEY_ID
                            ),
                        }
                        .into());
                    };
                    *id
                }
                1 => {
                    let Some(CommandReturnValue::PutWrapKey(id)) = command_return_values.first()
                    else {
                        return Err(Error::ScenarioLogic {
                            context: format!(
                                "there is no return value for adding the wrap key {}",
                                YubiHsm2Config::WRAP_KEY_ID
                            ),
                        }
                        .into());
                    };
                    *id
                }
                _ => {
                    return Err(Error::ScenarioLogic {
                        context: format!("there are {} return values when removing and/or adding the wrap key {}, but we expected exactly {number_of_commands}",
                            command_return_values.len(),
                            YubiHsm2Config::WRAP_KEY_ID
                        ),
                    }
                    .into());
                }
            }
        };
        if returned_id != YubiHsm2Config::WRAP_KEY_ID {
            return Err(Error::ScenarioLogic {
                context: format!("the returned key ID ({returned_id}) does not match the requested one when adding the wrap key {}",
                    YubiHsm2Config::WRAP_KEY_ID
                ),
            }
            .into());
        }

        Ok(())
    }

    /// Sets up all admin users in the backend.
    ///
    /// # Note
    ///
    /// Existing authentication keys are replaced!
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - no usable administrative credentials can be found
    /// - currently used authentication keys cannot be retrieved from the backend
    /// - the currently used credentials cannot be found in the set of available credentials
    /// - the scenario for removing and/or adding all relevant administrative authentication keys
    ///   fails
    /// - the return values for the scenario do not match the requested actions
    /// - the default admin credentials are still usable at the end of this function
    fn add_admin_users(&self) -> Result<(), crate::Error> {
        info!("Setting up administrative users...");

        let credentials = self.usable_admin_creds()?;
        let (commands, ids) = {
            let authentication_key_infos = get_object_infos_for_object_types(
                &self.runner,
                &credentials,
                &[ObjectType::AuthenticationKey],
            )?;
            let mut commands = Vec::new();
            let mut ids = Vec::new();

            // Delete and/or put all administrative credentials, except the one currently in use.
            for (mapping, creds) in self
                .admin_user_mappings_and_creds
                .as_ref()
                .iter()
                .filter(|(mapping, ..)| mapping.backend_user_id() != credentials.id())
            {
                let id = mapping.backend_user_id();

                if authentication_key_infos
                    .iter()
                    .any(|info| info.object_id == id)
                {
                    warn!("Replacing the existing authentication key {id}...");
                    commands.push(Command::DeleteObject(ObjectId::AuthenticationKey(id)));
                    ids.push(id);
                }

                commands.push(Command::PutAuthenticationKey {
                    info: KeyInfo {
                        key_id: creds.id(),
                        domains: mapping.domains(),
                        caps: mapping.capabilities(),
                    },
                    delegated_caps: mapping.capabilities(),
                    authentication_key: AuthenticationKey::try_from(creds.passphrase())?,
                });
                ids.push(id);
            }

            // Remove the default administrative authentication key, if an authentication key with
            // its ID is available in the backend, but the ID is not used in the Signstar
            // configuration.
            if authentication_key_infos
                .iter()
                .any(|info| info.object_id == YubiHsm2AdminCredentials::DEFAULT_ID)
                && !self
                    .admin_user_mappings_and_creds
                    .as_ref()
                    .iter()
                    .any(|(mapping, _)| {
                        mapping.backend_user_id() == YubiHsm2AdminCredentials::DEFAULT_ID
                    })
            {
                warn!(
                    "Removing the default authentication key {}...",
                    YubiHsm2AdminCredentials::DEFAULT_ID
                );
                commands.push(Command::DeleteObject(ObjectId::AuthenticationKey(
                    YubiHsm2AdminCredentials::DEFAULT_ID,
                )));
                ids.push(YubiHsm2AdminCredentials::DEFAULT_ID)
            }

            // Change the currently used authentication key, if it is setup in the administrative
            // credentials/ configuration.
            if let Some((_, current_credentials)) = self
                .admin_user_mappings_and_creds
                .as_ref()
                .iter()
                .find(|(mapping, ..)| mapping.backend_user_id() == credentials.id())
            {
                warn!(
                    "Changing the authentication key {}, which is currently used...",
                    current_credentials.id()
                );
                commands.push(Command::ChangeAuthenticationKey {
                    key_id: current_credentials.id(),
                    authentication_key: AuthenticationKey::try_from(
                        current_credentials.passphrase(),
                    )?,
                });
                ids.push(current_credentials.id());
            }

            (commands, ids)
        };

        // If there is nothing to do, exit early.
        if commands.is_empty() {
            return Ok(());
        }

        let scenario = Scenario::new(vec![AuthenticatedCommandChain::new(credentials, commands)]);
        let scenario_result = self.runner.run(&scenario)?;

        // Validate the return values against the acclaimed actions.
        let Some(command_return_values) = scenario_result.chains().first() else {
            return Err(Error::ScenarioLogic {
                context: format!(
                    "there are no command return values when adding the administrative users {}",
                    ids.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
            .into());
        };
        if command_return_values.len() != ids.len() {
            return Err(Error::ScenarioLogic {
                context: format!("the number of command return values ({}) does not match the number of requested commands ({}) when removing and/or adding the administrative users {}",
                    command_return_values.len(),
                    ids.len(),
                    ids.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                ),
            }
            .into());
        };

        // Ensure that the requested and returned authentication key IDs match.
        for (command_return_value, requested_id) in command_return_values.iter().zip(ids.iter()) {
            match command_return_value {
                CommandReturnValue::PutAuthenticationKey(returned_id) => {
                    if returned_id != requested_id {
                        return Err(Error::ScenarioLogic {
                        context: format!("the returned authentication key ID ({returned_id}) does not match the requested one ({requested_id}) when adding the administrative user"),
                    }
                    .into());
                    }
                }
                CommandReturnValue::DeleteObject => {
                    // NOTE: There is nothing to match here.
                }
                CommandReturnValue::ChangeAuthenticationKey(returned_id) => {
                    if returned_id != requested_id {
                        return Err(Error::ScenarioLogic {
                        context: format!("the returned authentication key ID ({returned_id}) does not match the requested one ({requested_id}) when changing the administrative user"),
                    }
                    .into());
                    }
                }
                _ => return Err(Error::ScenarioLogic {
                    context: format!("the command return value is not for adding, removing or changing the administrative user {requested_id}: {command_return_value:?}"),
                }
                .into()),
            }
        }

        info!("Successfully added all admins");

        // Check whether the default credentials are still in use (they shouldn't be at this
        // point) and set the internal state accordingly.
        if self.check_set_default_credentials() {
            return Err(Error::DefaultAdminStillUsable.into());
        }

        Ok(())
    }

    /// Returns the currently usable credentials for an administrative user.
    ///
    /// # Errors
    ///
    /// Returns an error, if no usable administrative credentials are found.
    fn usable_admin_creds(&self) -> Result<Credentials, crate::Error> {
        info!("Finding usable administrative credentials...");

        let credentials = if self.default_credentials_in_use() {
            YubiHsm2AdminCredentials::default_credentials()
        } else {
            let Some(credentials) = self
                .admin_credentials
                .administrators()
                .iter()
                .find(|credentials| are_admin_creds_usable(&self.runner, credentials))
            else {
                return Err(Error::NoUsableAdmin.into());
            };

            credentials.clone()
        };

        info!(
            "Using administrative credentials with authentication ID {}",
            credentials.id()
        );

        Ok(credentials)
    }
}

#[cfg(all(test, feature = "_yubihsm2-mockhsm"))]
mod tests {
    use std::collections::BTreeSet;

    use log::LevelFilter;
    use rstest::{fixture, rstest};
    use signstar_common::logging::setup_logging;
    use signstar_crypto::{
        AdministrativeSecretHandling,
        NonAdministrativeSecretHandling,
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
        yubihsm2::{YubiHsm2Config, YubiHsm2UserMapping, state::YubiHsm2BackendState},
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
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::Admin { authentication_key_id: 6 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
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
                Credentials::new(1, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
                Credentials::new(6, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
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
    #[case::single_admin_uses_default_id(
        YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![
                Credentials::new(1, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
            ]
        )?,
        YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
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
        )?
    )]
    #[case::single_admin_does_not_use_default_id(
        YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![
                Credentials::new(6, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
            ]
        )?,
        YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 6 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
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
        )?
    )]
    #[case::multiple_admins_do_not_use_default_id(
        YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![
                Credentials::new(6, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
                Credentials::new(7, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
            ]
        )?,
        YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 6 },
                YubiHsm2UserMapping::Admin { authentication_key_id: 7 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
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
        )?
    )]
    #[case::multiple_admins_one_uses_default_id(
        YubiHsm2AdminCredentials::new(
            1,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![
                Credentials::new(1, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
                Credentials::new(7, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
            ]
        )?,
        YubiHsm2Config::new(
            BTreeSet::from_iter([
                Connection::Mock
            ]),
            BTreeSet::from_iter([
                YubiHsm2UserMapping::Admin { authentication_key_id: 1 },
                YubiHsm2UserMapping::Admin { authentication_key_id: 7 },
                YubiHsm2UserMapping::AuditLog {
                    authentication_key_id: 3,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                    system_user: "yubihsm2-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Backup{
                    authentication_key_id: 2,
                    ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOOCMo+ODRchqIiXm89TxF7avi+LXRtqWZdBAvJ1SG5g user@host".parse()?,
                    system_user: "yubihsm2-backup-user".parse()?,
                    wrapping_key_id: 1,
                },
                YubiHsm2UserMapping::HermeticAuditLog {
                    authentication_key_id: 4,
                    system_user: "yubihsm2-hermetic-metrics-user".parse()?,
                },
                YubiHsm2UserMapping::Signing {
                    authentication_key_id: 5,
                    signing_key_id: 1,
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
        )?
    )]
    fn yubihsm2_backend_sync_succeeds(
        connector: Connector,
        #[case] admin_credentials: YubiHsm2AdminCredentials,
        #[case] yubihsm2_config: YubiHsm2Config,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let config = ConfigBuilder::new(SystemConfig::new(
            1,
            AdministrativeSecretHandling::Plaintext,
            NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::from_iter([]),
        )?)
        .set_yubihsm2_config(yubihsm2_config)
        .finish()?;
        let Some(backend) = YubiHsm2Backend::new(connector, &admin_credentials, &config)? else {
            panic!("No YubiHsm2Config in the provided Signstar config");
        };
        let credentials = vec![
            Credentials::new("2".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("3".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("4".parse()?, Passphrase::generate(Some(50))),
            Credentials::new("5".parse()?, Passphrase::generate(Some(50))),
        ];

        backend.sync(&credentials)?;

        // Re-run the sync
        backend.sync(&credentials)?;

        Ok(())
    }

    /// Ensures, that creating a `UserMappingsAndCredentials` fails on duplicate credentials.
    #[test]
    fn user_mappings_and_credentials_try_from_mappings_and_credentials_fails_on_duplicate_creds()
    -> TestResult {
        let user_mappings = HashSet::new();
        let creds = vec![
            Credentials::new(1, Passphrase::generate(Some(50))),
            Credentials::new(1, Passphrase::generate(Some(50))),
        ];
        match UserMappingsAndCredentials::try_from((&user_mappings, creds.as_slice())) {
            Err(crate::Error::YubiHsm2Backend(crate::yubihsm2::Error::DuplicateCredentials {
                ..
            })) => {}
            Err(error) => panic!(
                "Expected to fail with Error::DuplicateCredentials but failed with a different error: {error}"
            ),
            Ok(_) => {
                panic!("Expected to fail with Error::DuplicateCredentials but succeeded instead!")
            }
        }

        Ok(())
    }

    /// Ensures, that creating a `UserMappingsAndCredentials` fails on missing credentials for
    /// mappings.
    #[test]
    fn user_mappings_and_credentials_try_from_mappings_and_credentials_fails_on_missing_creds_for_mappings()
    -> TestResult {
        let user_mappings_list = [
            YubiHsm2UserMapping::Admin {
                authentication_key_id: 1,
            },
            YubiHsm2UserMapping::Admin {
                authentication_key_id: 2,
            },
        ];
        let user_mappings = HashSet::from_iter(user_mappings_list.iter());
        let creds = vec![Credentials::new(1, Passphrase::generate(Some(50)))];
        match UserMappingsAndCredentials::try_from((&user_mappings, creds.as_slice())) {
            Err(crate::Error::YubiHsm2Backend(
                crate::yubihsm2::Error::UserMappingWithoutCredentials { .. },
            )) => {}
            Err(error) => panic!(
                "Expected to fail with Error::UserMappingWithoutCredentials but failed with a different error: {error}"
            ),
            Ok(_) => {
                panic!(
                    "Expected to fail with Error::UserMappingWithoutCredentials but succeeded instead!"
                )
            }
        }

        Ok(())
    }

    /// Ensures, that creating a `UserMappingsAndCredentials` fails on missing mappings for
    /// credentials.
    #[test]
    fn user_mappings_and_credentials_try_from_mappings_and_credentials_fails_on_missing_mappings_for_creds()
    -> TestResult {
        let user_mappings_list = [YubiHsm2UserMapping::Admin {
            authentication_key_id: 1,
        }];
        let user_mappings = HashSet::from_iter(user_mappings_list.iter());
        let creds = vec![
            Credentials::new(1, Passphrase::generate(Some(50))),
            Credentials::new(2, Passphrase::generate(Some(50))),
        ];
        match UserMappingsAndCredentials::try_from((&user_mappings, creds.as_slice())) {
            Err(crate::Error::YubiHsm2Backend(
                crate::yubihsm2::Error::CredentialsWithoutUserMapping { .. },
            )) => {}
            Err(error) => panic!(
                "Expected to fail with Error::CredentialsWithoutUserMapping but failed with a different error: {error}"
            ),
            Ok(_) => {
                panic!(
                    "Expected to fail with Error::CredentialsWithoutUserMapping but succeeded instead!"
                )
            }
        }

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

        let _state = YubiHsm2BackendState::try_from(&backend)?;

        Ok(())
    }

    /// Ensures that creating a [`YubiHsm2Backend`] fails if the iterations of
    /// [`YubiHsm2AdminCredentials`] and [`Config`] do not match.
    #[rstest]
    fn yubihsm2_backend_new_fails_on_mismatching_iterations(
        connector: Connector,
        signstar_config: TestResult<Config>,
    ) -> TestResult {
        let signstar_config = signstar_config?;
        let admin_credentials = YubiHsm2AdminCredentials::new(
            2,
            Passphrase::new("backup-passphrase-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-really".to_string()),
            vec![
                Credentials::new(1, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
                Credentials::new(6, Passphrase::new("admin-passphrase-really-just-for-testing-i-promise".to_string())),
            ]
        )?;
        match YubiHsm2Backend::new(connector, &admin_credentials, &signstar_config) {
            Err(crate::Error::IterationMismatch { .. }) => {}
            Err(error) => panic!(
                "Expected to fail with Error::IterationMismatch, but failed differently instead: {error}"
            ),
            Ok(_) => {
                panic!("Expected to fail with Error::IterationMismatch, but succeeded instead")
            }
        }

        Ok(())
    }

    /// Ensures that creating a [`YubiHsm2Backend`] fails if iteration of
    /// [`YubiHsm2AdminCredentials`] and [`Config`] do not match.
    #[rstest]
    fn yubihsm2_backend_new_fails_on_missing_yubihsm2_config(
        connector: Connector,
        admin_credentials: TestResult<YubiHsm2AdminCredentials>,
    ) -> TestResult {
        let admin_credentials = admin_credentials?;
        let signstar_config = ConfigBuilder::new(SystemConfig::new(
            1,
            signstar_crypto::AdministrativeSecretHandling::Plaintext,
            signstar_crypto::NonAdministrativeSecretHandling::Plaintext,
            BTreeSet::from_iter([]),
        )?)
        .finish()?;

        match YubiHsm2Backend::new(connector, &admin_credentials, &signstar_config) {
            Ok(None) => {}
            Ok(Some(_)) => {
                panic!("Expected to succeed with None, but succeeded with Some instead")
            }
            Err(error) => panic!("Expected to succeed with None, but failed instead: {error}"),
        }

        Ok(())
    }
}
