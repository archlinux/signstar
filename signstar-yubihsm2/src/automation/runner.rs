//! Scenario runner

use std::fmt::Debug;
#[cfg(feature = "serde")]
use std::{fs::write, io::Write, time::Duration};

#[cfg(feature = "serde")]
use log::info;
#[cfg(feature = "serde")]
use serde::Serialize;
#[cfg(feature = "serde")]
use yubihsm::{
    Client,
    Credentials,
    asymmetric::Algorithm as AsymmetricAlgorithm,
    wrap::{Algorithm as WrapAlgorithm, Message},
};
use yubihsm::{Connector, ed25519::Signature};

#[cfg(feature = "serde")]
use crate::{
    Error,
    automation::{Command, command::AuthenticatedCommandChain},
    object::{AuthenticationKey, KeyInfo, ObjectId},
};

/// Signature made using the ed25519 signing algorithm.
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
struct Ed25519Signature {
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

    /// Runs a list of [`AuthenticatedCommandChain`] objects.
    ///
    /// The `writer` will receive [JSONL]-formatted responses for commands which generate them.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - executing the command fails
    ///
    /// [JSONL]: https://jsonlines.org/
    #[cfg(feature = "serde")]
    pub fn run_steps(
        &self,
        chains: &[AuthenticatedCommandChain],
        writer: &mut dyn Write,
    ) -> Result<(), Error> {
        for authenticated_commands in chains.iter() {
            let credentials = Credentials::try_from(authenticated_commands.auth())?;

            let mut client =
                Client::open(self.connector.clone(), credentials, true).map_err(|source| {
                    Error::Client {
                        context: "opening new client",
                        source,
                    }
                })?;

            for command in authenticated_commands.commands().iter() {
                info!("Executing {command:?}");
                self.run_command(&mut client, command, writer)?;
            }
        }
        Ok(())
    }

    /// Runs a single [`Command`].
    ///
    /// The `writer` will receive [JSONL]-formatted responses for commands which generate them.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - executing the command on device fails
    /// - serializing the response to JSON fails
    /// - writing the response to the `writer` fails
    /// - reading or writing associated files fails
    ///
    /// [JSONL]: https://jsonlines.org/
    #[cfg(feature = "serde")]
    fn run_command(
        &self,
        client: &mut Client,
        command: &Command,
        writer: &mut dyn Write,
    ) -> Result<(), Error> {
        match command {
            Command::Info => {
                serialize_with_newline(
                    writer,
                    &client.device_info().map_err(|source| Error::Client {
                        context: "executing device info command",
                        source,
                    })?,
                )?;
            }
            Command::Reset => {
                client
                    .reset_device_and_reconnect(Duration::from_secs(2))
                    .map_err(|source| Error::Client {
                        context: "executing device info command",
                        source,
                    })?;
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
                    })?;
            }
            Command::GenerateKey {
                info:
                    KeyInfo {
                        key_id,
                        domains,
                        caps,
                    },
            } => {
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
                    })?;
            }
            Command::SignEd25519 { key_id, data } => {
                let sig = client
                    .sign_ed25519(key_id.into(), &data[..])
                    .map_err(|source| Error::Client {
                        context: "signing with ed25519 key",
                        source,
                    })?;
                serialize_with_newline(writer, Ed25519Signature::from(sig))?;
            }
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
                    })?;
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

                serialize_with_newline(writer, &wrapped)?;
                write(wrapped_file, wrapped.into_vec()).map_err(|source| Error::IoPath {
                    context: "writing wrapped file",
                    source,
                    path: wrapped_file.into(),
                })?;
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
                let imported =
                    client
                        .import_wrapped(wrap_key_id.into(), wrapped)
                        .map_err(|source| Error::Client {
                            context: "importing wrapped key",
                            source,
                        })?;

                serialize_with_newline(writer, ObjectId::try_from(imported)?)?;
            }
            Command::Delete(object) => {
                client
                    .delete_object(object.id().into(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "deleting object",
                        source,
                    })?;
            }
            Command::GetInfo(object) => {
                let info = client
                    .get_object_info(object.id().into(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "getting object info",
                        source,
                    })?;

                serialize_with_newline(writer, &info)?;
            }
            Command::ForceAudit(setting) => {
                client
                    .set_force_audit_option((*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting force audit option",
                        source,
                    })?;
            }
            Command::CommandAudit { command, setting } => {
                client
                    .set_command_audit_option(*command, (*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting command audit option",
                        source,
                    })?;
            }
            Command::GetLog => {
                let log = client.get_log_entries().map_err(|source| Error::Client {
                    context: "getting log entries",
                    source,
                })?;

                serialize_with_newline(writer, &log)?;
            }
        }
        Ok(())
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
            let scenario_file = scenario_file.as_ref();
            eprintln!(
                "Running scenario file {scenario_file}",
                scenario_file = scenario_file.display()
            );
            let scenario: Scenario = serde_json::from_reader(File::open(scenario_file)?)?;
            let runner = ScenarioRunner::new(Connector::mockhsm());
            runner.run_steps(scenario.as_ref(), &mut stdout())?;
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
