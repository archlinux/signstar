//! Scenario runner

#[cfg(feature = "serde")]
use std::io::Write;
use std::{fmt::Debug, fs::write, time::Duration};

use log::{error, info};
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
    automation::{Command, Scenario},
    object::{AuthenticationKey, KeyInfo},
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
    pub fn run(&self, scenario: &Scenario) -> Result<Vec<CommandReturnValue>, Error> {
        let mut output = Vec::new();

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

            for command in authenticated_commands.commands().iter() {
                info!("Executing {command:?}");
                match self.run_command(&mut client, command) {
                    Ok(return_value) => output.push(return_value),
                    Err(error) => {
                        // Emit the already collected output as an error.
                        error!(
                            "{}",
                            output
                                .iter()
                                .map(|return_value| format!("{return_value:?}"))
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                        return Err(error);
                    }
                }
            }
        }

        Ok(output)
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
    ) -> Result<Vec<CommandReturnValue>, Error> {
        let return_values = self.run(scenario)?;
        for return_value in return_values.iter() {
            serialize_with_newline(writer, return_value)?;
        }

        Ok(return_values)
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
            Command::Info => {
                CommandReturnValue::DeviceInfo(client.device_info().map_err(|source| {
                    Error::Client {
                        context: "executing device info command",
                        source,
                    }
                })?)
            }
            Command::Reset => {
                client
                    .reset_device_and_reconnect(Duration::from_secs(2))
                    .map_err(|source| Error::Client {
                        context: "executing device info command",
                        source,
                    })?;
                CommandReturnValue::ResetDeviceAndReconnect
            }
            Command::PutAuthKey {
                info:
                    KeyInfo {
                        key_id,
                        domains,
                        caps,
                    },
                delegated_caps,
                passphrase_file,
            } => {
                let key = AuthenticationKey::try_from(passphrase_file.as_path())?;
                CommandReturnValue::PutAuthenticationKey(
                    client
                        .put_authentication_key(
                            key_id.into(),
                            Default::default(),
                            domains.into(),
                            caps.into(),
                            delegated_caps.into(),
                            Default::default(),
                            key,
                        )
                        .map_err(|source| Error::Client {
                            context: "putting authentication key",
                            source,
                        })?,
                )
            }
            Command::GenerateKey {
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
                passphrase_file,
            } => {
                let key = AuthenticationKey::try_from(passphrase_file.as_path())?;
                CommandReturnValue::PutWrapKey(
                    client
                        .put_wrap_key(
                            key_id.into(),
                            Default::default(),
                            domains.into(),
                            caps.into(),
                            delegated_caps.into(),
                            WrapAlgorithm::Aes256Ccm,
                            key.as_ref().as_secret_slice(),
                        )
                        .map_err(|source| Error::Client {
                            context: "putting wrap key",
                            source,
                        })?,
                )
            }
            Command::ExportWrapped {
                wrap_key_id,
                object,
                wrapped_file,
            } => {
                let wrapped = client
                    .export_wrapped(wrap_key_id.into(), object.object_type(), object.id().into())
                    .map_err(|source| Error::Client {
                        context: "exporting wrapped key",
                        source,
                    })?;

                write(wrapped_file, wrapped.clone().into_vec()).map_err(|source| {
                    Error::IoPath {
                        context: "writing wrapped file",
                        source,
                        path: wrapped_file.into(),
                    }
                })?;

                CommandReturnValue::ExportWrapped(wrapped)
            }
            Command::ImportWrapped {
                wrap_key_id,
                wrapped_file,
            } => {
                let wrapped = Message::from_vec(std::fs::read(wrapped_file).map_err(|source| {
                    Error::IoPath {
                        context: "reading wrapped file",
                        source,
                        path: wrapped_file.into(),
                    }
                })?)
                .map_err(|source| Error::InvalidWrap {
                    context: "reading the wrapped file",
                    source,
                })?;
                CommandReturnValue::ImportWrapped(
                    client
                        .import_wrapped(wrap_key_id.into(), wrapped)
                        .map_err(|source| Error::Client {
                            context: "importing wrapped key",
                            source,
                        })?,
                )
            }
            Command::Delete(object) => {
                client
                    .delete_object(object.id().into(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "deleting object",
                        source,
                    })?;
                CommandReturnValue::DeleteObject
            }
            Command::GetInfo(object) => CommandReturnValue::GetObjectInfo(
                client
                    .get_object_info(object.id().into(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "getting object info",
                        source,
                    })?,
            ),
            Command::ForceAudit(setting) => {
                client
                    .set_force_audit_option((*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting force audit option",
                        source,
                    })?;
                CommandReturnValue::SetForceAuditOption
            }
            Command::CommandAudit { command, setting } => {
                client
                    .set_command_audit_option(*command, (*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting command audit option",
                        source,
                    })?;
                CommandReturnValue::SetCommandAuditOption
            }
            Command::GetLog => {
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
        use crate::automation::Scenario;

        #[cfg(all(feature = "_yubihsm2-mockhsm", feature = "serde"))]
        fn run_scenario(scenario_file: impl AsRef<Path>) -> TestResult {
            use crate::automation::scenario::FileBackedScenario;

            let scenario_file = scenario_file.as_ref();
            eprintln!(
                "Running scenario file {scenario_file}",
                scenario_file = scenario_file.display()
            );
            let scenario: FileBackedScenario = serde_json::from_reader(File::open(scenario_file)?)?;
            let runner = ScenarioRunner::new(Connector::mockhsm());
            runner.run_with_writer(&Scenario::try_from(scenario)?, &mut stdout())?;
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
