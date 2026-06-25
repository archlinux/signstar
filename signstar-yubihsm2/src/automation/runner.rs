//! Scenario runner

#[cfg(feature = "serde")]
use std::io::Write;
use std::{fmt::Debug, fs::write, time::Duration};

use log::{debug, error, info};
#[cfg(feature = "serde")]
use serde::Serialize;
use yubihsm::{
    Client,
    Connector,
    Credentials,
    asymmetric::Algorithm as AsymmetricAlgorithm,
    command::Code as CommandCode,
    device::Info as DeviceInfo,
    ed25519::Signature,
    object::{Handle, Id as YubiHsmObjectId, Info as ObjectInfo},
    response::Code as ResponseCode,
    wrap::{Algorithm as WrapAlgorithm, Message},
};

use crate::{
    Error,
    automation::{
        Command,
        Error as AutomationError,
        FileBackedCommand,
        FileBackedScenario,
        Scenario,
        error::FileBackedScenarioReturnValueMismatch,
    },
    object::KeyInfo,
};

/// Signature made using the ed25519 signing algorithm.
///
/// # Note
///
/// This type exists to augment [`yubihsm::ed25519::Signature`], which does not use serde.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(
    any(
        all(not(feature = "serde"), feature = "_yubihsm2-mockhsm"),
        all(
            not(feature = "serde"),
            not(feature = "_yubihsm2-mockhsm"),
            not(feature = "cli")
        )
    ),
    allow(unused)
)]
pub struct Ed25519Signature {
    /// Raw bytes of the `R` component of the signature.
    r: Vec<u8>,
    /// Raw bytes of the `S` component of the signature.
    s: Vec<u8>,
}

impl From<Signature> for Ed25519Signature {
    fn from(value: Signature) -> Self {
        Self {
            r: value.r_bytes().to_vec(),
            s: value.s_bytes().to_vec(),
        }
    }
}

/// Response from [`Client::get_log_entries`].
///
/// # Note
///
/// This type exists to augment a non-public return type of a public function.
/// <https://github.com/iqlusioninc/yubihsm.rs/issues/617>
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LogEntries {
    /// Number of boot events which weren't logged (if buffer is full and audit enforce is set)
    pub unlogged_boot_events: u16,

    /// Number of unlogged authentication events (if buffer is full and audit enforce is set)
    pub unlogged_auth_events: u16,

    /// Number of entries in the response
    pub num_entries: u8,

    /// Entries in the log
    pub entries: Vec<LogEntry>,
}

/// Entry in the log response.
///
/// # Note
///
/// This type exists to augment a non-public return type of a public function.
/// <https://github.com/iqlusioninc/yubihsm.rs/issues/617>
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LogEntry {
    /// Entry number
    pub item: u16,

    /// Command type
    pub cmd: CommandCode,

    /// Command length
    pub length: u16,

    /// Session key ID
    pub session_key: YubiHsmObjectId,

    /// Target key ID
    pub target_key: YubiHsmObjectId,

    /// Second key affected
    pub second_key: YubiHsmObjectId,

    /// Result of the operation
    pub result: ResponseCode,

    /// Tick count of the HSM's internal clock
    pub tick: u32,

    /// 16-byte truncated SHA-256 digest of this log entry and the digest of the previous entry
    pub digest: LogDigest,
}

/// Size of a truncated digest in the log
///
/// # Note
///
/// This type exists to augment a non-public return type of a public function.
/// <https://github.com/iqlusioninc/yubihsm.rs/issues/617>
pub const LOG_DIGEST_SIZE: usize = 16;

/// Truncated SHA-256 digest of a log entry and the previous log digest
///
/// # Note
///
/// This type exists to augment a non-public return type of a public function.
/// <https://github.com/iqlusioninc/yubihsm.rs/issues/617>
#[derive(Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct LogDigest(pub [u8; LOG_DIGEST_SIZE]);

impl AsRef<[u8]> for LogDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for LogDigest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LogDigest(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{byte:02x}")?;
            write!(f, "{}", if i == LOG_DIGEST_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}

/// Serializes an `object` to JSON, suffixed by a newline.
///
/// # Errors
///
/// Returns an error if
/// - serialization fails
/// - writing to the `writer` fails
#[cfg(feature = "serde")]
fn serialize_with_newline(mut writer: &mut dyn Write, object: impl Serialize) -> Result<(), Error> {
    serde_json::to_writer(&mut writer, &object).map_err(|source| Error::Json {
        context: "serializing response",
        source,
    })?;
    writer.write_all(b"\n").map_err(|source| Error::Io {
        context: "writing record delimiter",
        source,
    })?;
    Ok(())
}

/// The return value of a [`Command`].
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CommandReturnValue {
    /// The return value of [`Client::device_info`].
    DeviceInfo(DeviceInfo),

    /// The return value of [`Client::reset_device_and_reconnect`].
    ResetDeviceAndReconnect,

    /// The return value of [`Client::put_authentication_key`].
    PutAuthenticationKey(YubiHsmObjectId),

    /// The return value of [`Client::generate_asymmetric_key`]
    GenerateAsymmetricKey(YubiHsmObjectId),

    /// The return value of [`Client::sign_ed25519`].
    SignEd25519(Ed25519Signature),

    /// The return value of [`Client::put_wrap_key`].
    PutWrapKey(YubiHsmObjectId),

    /// The return value of [`Client::export_wrapped`].
    ExportWrapped(Message),

    /// The return value of [`Client::import_wrapped`].
    ImportWrapped(Handle),

    /// The return value of [`Client::delete_object`].
    DeleteObject,

    /// The return value of [`Client::get_object_info`].
    GetObjectInfo(ObjectInfo),

    /// The return value of [`Client::set_force_audit_option`].
    SetForceAuditOption,

    /// The return value of [`Client::set_command_audit_option`].
    SetCommandAuditOption,

    /// The return value of [`Client::get_log_entries`].
    GetLogEntries(LogEntries),
}

impl PartialEq<Command> for &CommandReturnValue {
    /// Compares [`CommandReturnValue`] and [`Command`].
    ///
    /// # Note
    ///
    /// Comparison is done using the enum variants on a best effort basis.
    /// No data is compared directly.
    fn eq(&self, other: &Command) -> bool {
        match (self, other) {
            (CommandReturnValue::DeviceInfo(_), Command::DeviceInfo)
            | (CommandReturnValue::ResetDeviceAndReconnect, Command::ResetDeviceAndReconnect)
            | (CommandReturnValue::PutAuthenticationKey(_), Command::PutAuthenticationKey { .. })
            | (
                CommandReturnValue::GenerateAsymmetricKey(_),
                Command::GenerateAsymmetricKey { .. },
            )
            | (CommandReturnValue::SignEd25519(_), Command::SignEd25519 { .. })
            | (CommandReturnValue::PutWrapKey(_), Command::PutWrapKey { .. })
            | (CommandReturnValue::ExportWrapped(_), Command::ExportWrapped { .. })
            | (CommandReturnValue::ImportWrapped(_), Command::ImportWrapped { .. })
            | (CommandReturnValue::DeleteObject, Command::DeleteObject(_))
            | (CommandReturnValue::GetObjectInfo(_), Command::GetObjectInfo(_))
            | (CommandReturnValue::SetForceAuditOption, Command::SetForceAuditOption(_))
            | (CommandReturnValue::SetCommandAuditOption, Command::SetCommandAuditOption { .. })
            | (CommandReturnValue::GetLogEntries(_), Command::GetLogEntries) => true,
            (CommandReturnValue::DeviceInfo(_), _)
            | (CommandReturnValue::ResetDeviceAndReconnect, _)
            | (CommandReturnValue::PutAuthenticationKey(_), _)
            | (CommandReturnValue::GenerateAsymmetricKey(_), _)
            | (CommandReturnValue::SignEd25519(_), _)
            | (CommandReturnValue::PutWrapKey(_), _)
            | (CommandReturnValue::ExportWrapped(_), _)
            | (CommandReturnValue::ImportWrapped(_), _)
            | (CommandReturnValue::DeleteObject, _)
            | (CommandReturnValue::GetObjectInfo(_), _)
            | (CommandReturnValue::SetForceAuditOption, _)
            | (CommandReturnValue::SetCommandAuditOption, _)
            | (CommandReturnValue::GetLogEntries(_), _) => false,
        }
    }
}

impl PartialEq<FileBackedCommand> for &CommandReturnValue {
    /// Compares [`CommandReturnValue`] and [`FileBackedCommand`].
    ///
    /// # Note
    ///
    /// Comparison is done using the enum variants on a best effort basis.
    /// No data is compared directly.
    fn eq(&self, other: &FileBackedCommand) -> bool {
        match (self, other) {
            (CommandReturnValue::DeviceInfo(_), FileBackedCommand::DeviceInfo)
            | (
                CommandReturnValue::ResetDeviceAndReconnect,
                FileBackedCommand::ResetDeviceAndReconnect,
            )
            | (
                CommandReturnValue::PutAuthenticationKey(_),
                FileBackedCommand::PutAuthenticationKey { .. },
            )
            | (
                CommandReturnValue::GenerateAsymmetricKey(_),
                FileBackedCommand::GenerateAsymmetricKey { .. },
            )
            | (CommandReturnValue::SignEd25519(_), FileBackedCommand::SignEd25519 { .. })
            | (CommandReturnValue::PutWrapKey(_), FileBackedCommand::PutWrapKey { .. })
            | (CommandReturnValue::ExportWrapped(_), FileBackedCommand::ExportWrapped { .. })
            | (CommandReturnValue::ImportWrapped(_), FileBackedCommand::ImportWrapped { .. })
            | (CommandReturnValue::DeleteObject, FileBackedCommand::DeleteObject(_))
            | (CommandReturnValue::GetObjectInfo(_), FileBackedCommand::GetObjectInfo(_))
            | (
                CommandReturnValue::SetForceAuditOption,
                FileBackedCommand::SetForceAuditOption(_),
            )
            | (
                CommandReturnValue::SetCommandAuditOption,
                FileBackedCommand::SetCommandAuditOption { .. },
            )
            | (CommandReturnValue::GetLogEntries(_), FileBackedCommand::GetLogEntries) => true,
            (CommandReturnValue::DeviceInfo(_), _)
            | (CommandReturnValue::ResetDeviceAndReconnect, _)
            | (CommandReturnValue::PutAuthenticationKey(_), _)
            | (CommandReturnValue::GenerateAsymmetricKey(_), _)
            | (CommandReturnValue::SignEd25519(_), _)
            | (CommandReturnValue::PutWrapKey(_), _)
            | (CommandReturnValue::ExportWrapped(_), _)
            | (CommandReturnValue::ImportWrapped(_), _)
            | (CommandReturnValue::DeleteObject, _)
            | (CommandReturnValue::GetObjectInfo(_), _)
            | (CommandReturnValue::SetForceAuditOption, _)
            | (CommandReturnValue::SetCommandAuditOption, _)
            | (CommandReturnValue::GetLogEntries(_), _) => false,
        }
    }
}

/// The return value of a [`Scenario`].
///
/// Tracks the return value for each command executed as part of a [`Scenario`].
#[derive(Debug)]
pub struct ScenarioReturnValue {
    authenticated_command_chains: Vec<Vec<CommandReturnValue>>,
}

impl ScenarioReturnValue {
    /// Compares this [`ScenarioReturnValue`] with a [`FileBackedScenario`].
    fn compare_with_file_backed_scenario(
        &self,
        file_backed_scenario: &FileBackedScenario,
    ) -> Result<(), Error> {
        debug!(
            "Comparing the return values of the scenario with the requested commands of the file backed scenario"
        );

        let mut mismatches = Vec::new();

        if file_backed_scenario.as_ref().len() != self.authenticated_command_chains.len() {
            return Err(
                AutomationError::MismatchingNumberOfAuthenticatedCommandChains {
                    scenario: file_backed_scenario.as_ref().len(),
                    scenario_return_value: self.authenticated_command_chains.len(),
                }
                .into(),
            );
        }

        for (file_backed_authenticated_command_chain, command_return_values) in file_backed_scenario
            .as_ref()
            .iter()
            .zip(self.authenticated_command_chains.iter())
        {
            if file_backed_authenticated_command_chain.commands.len() != command_return_values.len()
            {
                return Err(AutomationError::MismatchingNumberOfCommands {
                    authenticated_command_chain: file_backed_authenticated_command_chain
                        .commands
                        .len(),
                    command_return_values: command_return_values.len(),
                }
                .into());
            }

            for (file_backed_command, command_return_value) in
                file_backed_authenticated_command_chain
                    .commands
                    .iter()
                    .zip(command_return_values.iter())
            {
                if command_return_value.ne(file_backed_command) {
                    mismatches.push(FileBackedScenarioReturnValueMismatch {
                        file_backed_scenario_command: file_backed_command.into(),
                        command_return_value: command_return_value.into(),
                    });
                }
            }
        }

        if !mismatches.is_empty() {
            return Err(
                AutomationError::MismatchingReturnValueForFileBackedScenario { mismatches }.into(),
            );
        }

        Ok(())
    }

    /// Persists the data of a [`ScenarioReturnValue`] according to a [`FileBackedScenario`].
    pub fn persist_file_backed_scenario(
        &self,
        file_backed_scenario: &FileBackedScenario,
    ) -> Result<(), Error> {
        self.compare_with_file_backed_scenario(file_backed_scenario)?;

        for (file_backed_authenticated_command_chain, command_return_values) in file_backed_scenario
            .as_ref()
            .iter()
            .zip(self.authenticated_command_chains.iter())
        {
            for (file_backed_command, command_return_value) in
                file_backed_authenticated_command_chain
                    .commands
                    .iter()
                    .zip(command_return_values.iter())
            {
                if let (
                    FileBackedCommand::ExportWrapped { wrapped_file, .. },
                    CommandReturnValue::ExportWrapped(message),
                ) = (file_backed_command, command_return_value)
                {
                    write(wrapped_file.as_path(), message.clone().into_vec()).map_err(|source| {
                        Error::IoPath {
                            path: wrapped_file.clone(),
                            context: "writing an encrypted message to the file",
                            source,
                        }
                    })?
                }
            }
        }

        Ok(())
    }
}

/// Runs commands against a physical or in-memory YubiHSM2 token.
pub struct ScenarioRunner {
    #[cfg_attr(
        any(
            all(not(feature = "serde"), feature = "_yubihsm2-mockhsm"),
            all(
                not(feature = "serde"),
                not(feature = "_yubihsm2-mockhsm"),
                not(feature = "cli")
            )
        ),
        allow(unused)
    )]
    connector: Connector,
}

impl Debug for ScenarioRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Client is not Debug so we cannot derive Debug for ScenarioRunner
        f.debug_struct("ScenarioRunner").finish()
    }
}

impl ScenarioRunner {
    /// Creates a new [`ScenarioRunner`] for a [`Connector`].
    pub fn new(connector: Connector) -> Self {
        Self { connector }
    }

    /// Runs a [`Scenario`].
    ///
    /// # Errors
    ///
    /// Returns an error if executing one of the commands in the scenario fails.
    ///
    /// Before returning the error, the return values of successfully executed commands will be
    /// emitted in an error message to the log.
    pub fn run(&self, scenario: &Scenario) -> Result<ScenarioReturnValue, Error> {
        let mut authenticated_command_chains = Vec::new();

        for authenticated_commands in scenario.as_ref().iter() {
            let mut client = Client::open(
                self.connector.clone(),
                Credentials::from(authenticated_commands.auth()),
                true,
            )
            .map_err(|source| Error::Client {
                context: "opening new client",
                source,
            })?;
            let mut command_return_values = Vec::new();

            for command in authenticated_commands.commands().iter() {
                info!("Executing {command:?}");
                match self.run_command(&mut client, command) {
                    Ok(return_value) => command_return_values.push(return_value),
                    Err(error) => {
                        // Emit the already collected output as an error.
                        error!(
                            "{}",
                            authenticated_command_chains
                                .iter()
                                .flatten()
                                .map(|return_value| format!("{return_value:?}"))
                                .chain(
                                    command_return_values
                                        .iter()
                                        .map(|return_value| format!("{return_value:?}"))
                                )
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                        return Err(error);
                    }
                }
            }

            authenticated_command_chains.push(command_return_values);
        }

        Ok(ScenarioReturnValue {
            authenticated_command_chains,
        })
    }

    /// Runs a [`Scenario`].
    ///
    /// The `writer` will receive [JSONL]-formatted responses for commands which generate them.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - executing the scenario fails
    /// - the return value of a command cannot be serialized and written to the writer.
    ///
    /// [JSONL]: https://jsonlines.org/
    #[cfg(feature = "serde")]
    pub fn run_with_writer(
        &self,
        scenario: &Scenario,
        writer: &mut dyn Write,
    ) -> Result<ScenarioReturnValue, Error> {
        let scenario_return_value = self.run(scenario)?;
        for return_value in scenario_return_value
            .authenticated_command_chains
            .iter()
            .flatten()
        {
            serialize_with_newline(writer, return_value)?;
        }

        Ok(scenario_return_value)
    }

    /// Runs a single [`Command`] and returns a [`CommandReturnValue`] for it.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - executing the command on device fails
    /// - reading or writing associated files fails
    fn run_command(
        &self,
        client: &mut Client,
        command: &Command,
    ) -> Result<CommandReturnValue, Error> {
        Ok(match command {
            Command::DeviceInfo => {
                CommandReturnValue::DeviceInfo(client.device_info().map_err(|source| {
                    Error::Client {
                        context: "executing device info command",
                        source,
                    }
                })?)
            }
            Command::ResetDeviceAndReconnect => {
                client
                    .reset_device_and_reconnect(Duration::from_secs(2))
                    .map_err(|source| Error::Client {
                        context: "executing device info command",
                        source,
                    })?;
                CommandReturnValue::ResetDeviceAndReconnect
            }
            Command::PutAuthenticationKey {
                info:
                    KeyInfo {
                        key_id,
                        domains,
                        caps,
                    },
                delegated_caps,
                authentication_key,
            } => CommandReturnValue::PutAuthenticationKey(
                client
                    .put_authentication_key(
                        key_id.into(),
                        Default::default(),
                        domains.into(),
                        caps.into(),
                        delegated_caps.into(),
                        Default::default(),
                        authentication_key,
                    )
                    .map_err(|source| Error::Client {
                        context: "putting authentication key",
                        source,
                    })?,
            ),
            Command::GenerateAsymmetricKey {
                info:
                    KeyInfo {
                        key_id,
                        domains,
                        caps,
                    },
            } => CommandReturnValue::GenerateAsymmetricKey(
                client
                    .generate_asymmetric_key(
                        key_id.into(),
                        Default::default(),
                        domains.into(),
                        caps.into(),
                        AsymmetricAlgorithm::Ed25519,
                    )
                    .map_err(|source| Error::Client {
                        context: "generating asymmetric key",
                        source,
                    })?,
            ),
            Command::SignEd25519 { key_id, data } => CommandReturnValue::SignEd25519(
                client
                    .sign_ed25519(key_id.into(), &data[..])
                    .map_err(|source| Error::Client {
                        context: "signing with ed25519 key",
                        source,
                    })?
                    .into(),
            ),
            Command::PutWrapKey {
                info:
                    KeyInfo {
                        key_id,
                        domains,
                        caps,
                    },
                delegated_caps,
                wrapping_key,
            } => CommandReturnValue::PutWrapKey(
                client
                    .put_wrap_key(
                        key_id.into(),
                        Default::default(),
                        domains.into(),
                        caps.into(),
                        delegated_caps.into(),
                        WrapAlgorithm::Aes256Ccm,
                        wrapping_key,
                    )
                    .map_err(|source| Error::Client {
                        context: "putting wrap key",
                        source,
                    })?,
            ),
            Command::ExportWrapped {
                wrap_key_id,
                object,
            } => CommandReturnValue::ExportWrapped(
                client
                    .export_wrapped(wrap_key_id.into(), object.object_type(), object.id().into())
                    .map_err(|source| Error::Client {
                        context: "exporting wrapped key",
                        source,
                    })?,
            ),
            Command::ImportWrapped {
                wrap_key_id,
                message,
            } => CommandReturnValue::ImportWrapped(
                client
                    .import_wrapped(wrap_key_id.into(), message.clone())
                    .map_err(|source| Error::Client {
                        context: "importing wrapped key",
                        source,
                    })?,
            ),
            Command::DeleteObject(object) => {
                client
                    .delete_object(object.id().into(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "deleting object",
                        source,
                    })?;
                CommandReturnValue::DeleteObject
            }
            Command::GetObjectInfo(object) => CommandReturnValue::GetObjectInfo(
                client
                    .get_object_info(object.id().into(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "getting object info",
                        source,
                    })?,
            ),
            Command::SetForceAuditOption(setting) => {
                client
                    .set_force_audit_option((*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting force audit option",
                        source,
                    })?;
                CommandReturnValue::SetForceAuditOption
            }
            Command::SetCommandAuditOption { command, setting } => {
                client
                    .set_command_audit_option(*command, (*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting command audit option",
                        source,
                    })?;
                CommandReturnValue::SetCommandAuditOption
            }
            Command::GetLogEntries => {
                let log_entries = client.get_log_entries().map_err(|source| Error::Client {
                    context: "getting log entries",
                    source,
                })?;

                CommandReturnValue::GetLogEntries(LogEntries {
                    unlogged_boot_events: log_entries.unlogged_boot_events,
                    unlogged_auth_events: log_entries.unlogged_auth_events,
                    num_entries: log_entries.num_entries,
                    entries: log_entries
                        .entries
                        .into_iter()
                        .map(|entry| LogEntry {
                            item: entry.item,
                            cmd: entry.cmd,
                            length: entry.length,
                            session_key: entry.session_key,
                            target_key: entry.target_key,
                            second_key: entry.second_key,
                            result: entry.result,
                            tick: entry.tick,
                            digest: LogDigest(entry.digest.0),
                        })
                        .collect::<Vec<_>>(),
                })
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_signature() {
        let signature = Ed25519Signature {
            r: vec![],
            s: vec![],
        };

        println!("r: {:?}, s: {:?}", signature.r, signature.s);
    }

    #[cfg(all(feature = "_yubihsm2-mockhsm", feature = "serde"))]
    mod scenario {
        use std::{
            fs::File,
            io::stdout,
            path::{Path, PathBuf},
        };

        use rstest::rstest;
        use testresult::TestResult;

        use super::*;
        use crate::automation::{FileBackedScenario, Scenario};

        #[cfg(all(feature = "_yubihsm2-mockhsm", feature = "serde"))]
        fn run_scenario(scenario_file: impl AsRef<Path>) -> TestResult {
            let scenario_file = scenario_file.as_ref();
            eprintln!(
                "Running scenario file {scenario_file}",
                scenario_file = scenario_file.display()
            );
            let file_backed_scenario: FileBackedScenario =
                serde_json::from_reader(File::open(scenario_file)?)?;
            let runner = ScenarioRunner::new(Connector::mockhsm());
            let return_value = runner
                .run_with_writer(&Scenario::try_from(&file_backed_scenario)?, &mut stdout())?;
            return_value.persist_file_backed_scenario(&file_backed_scenario)?;

            Ok(())
        }

        #[cfg(all(feature = "_yubihsm2-mockhsm", feature = "serde"))]
        #[rstest]
        fn scenario_test(#[files("tests/scenarios/*.json")] scenario_file: PathBuf) -> TestResult {
            run_scenario(scenario_file)?;
            Ok(())
        }

        #[cfg(all(feature = "_yubihsm2-mockhsm", feature = "serde"))]
        #[test]
        fn wrapping_test() -> TestResult {
            // these two need to run in order: first exporting to a file, then importing that file
            run_scenario("tests/scenarios/wrapping/export-wrapped.json")?;
            run_scenario("tests/scenarios/wrapping/import-wrapped.json")?;
            Ok(())
        }
    }
}
