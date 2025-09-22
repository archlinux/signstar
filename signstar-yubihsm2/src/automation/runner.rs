//! Scenario runner

use std::{fmt::Debug, fs::read_to_string, io::Write, path::Path, time::Duration};

use log::info;
use serde::Serialize;
use signstar_crypto::passphrase::Passphrase;
use yubihsm::{
    Client,
    Connector,
    Credentials,
    authentication,
    ed25519::Signature,
    wrap::{self, Message},
};

use crate::{
    Error,
    automation::{Auth, Command},
    object::{KeyInfo, ObjectId},
};

/// Derives an authentication key from a UTF-8-encoded file.
///
/// # Errors
///
/// Returns an error if `path` cannot be read to [`String`].
fn derive_key_from_file(path: impl AsRef<Path>) -> Result<authentication::Key, Error> {
    let passphrase = read_to_string(&path).map_err(|source| Error::IoPath {
        path: path.as_ref().into(),
        context: "reading key from file",
        source,
    })?;
    let passphrase = Passphrase::new(passphrase);
    let key = authentication::Key::derive_from_password(passphrase.expose_borrowed().as_bytes());
    Ok(key)
}

/// Signature made using the ed25519 signing algorithm.
#[derive(Debug, Serialize)]
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
    client: Client,
}

impl Debug for ScenarioRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Client is not Debug so we cannot derive Debug for ScenarioRunner
        f.debug_struct("ScenarioRunner").finish()
    }
}

impl ScenarioRunner {
    /// Creates a new [`ScenarioRunner`] for given `connector` and `auth`.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - deriving authentication key fails
    /// - opening the connection to the client fails
    pub fn new(connector: Connector, auth: Auth) -> Result<Self, Error> {
        let user = auth.user;
        let passphrase_file = auth.passphrase_file;
        let credentials = Credentials::new(user, derive_key_from_file(passphrase_file)?);
        let client =
            Client::open(connector, credentials, true).map_err(|source| Error::Client {
                context: "connecting to client for running a scenario",
                source,
            })?;
        Ok(Self { client })
    }

    /// Runs a list of [`Command`] objects.
    ///
    /// The `writer` will receive [JSONL]-formatted responses for commands which generate them.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - executing the command fails
    ///
    /// [JSONL]: https://jsonlines.org/
    pub fn run_steps(&mut self, steps: &[Command], writer: &mut dyn Write) -> Result<(), Error> {
        for command in steps.iter() {
            info!("Executing {command:?}");
            self.run_command(command, writer)?;
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
    fn run_command(&mut self, command: &Command, writer: &mut dyn Write) -> Result<(), Error> {
        match command {
            Command::Info => {
                serialize_with_newline(
                    writer,
                    &self.client.device_info().map_err(|source| Error::Client {
                        context: "executing device info command",
                        source,
                    })?,
                )?;
            }
            Command::Reset => {
                self.client
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
                        domain,
                        caps,
                    },
                delegated_caps,
                passphrase_file,
            } => {
                let key = derive_key_from_file(passphrase_file)?;
                self.client
                    .put_authentication_key(
                        *key_id,
                        Default::default(),
                        (*domain).into(),
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
                        domain,
                        caps,
                    },
            } => {
                self.client
                    .generate_asymmetric_key(
                        *key_id,
                        Default::default(),
                        (*domain).into(),
                        caps.into(),
                        yubihsm::asymmetric::Algorithm::Ed25519,
                    )
                    .map_err(|source| Error::Client {
                        context: "generating asymmetric key",
                        source,
                    })?;
            }
            Command::SignEd25519 { key_id, data } => {
                let sig = self
                    .client
                    .sign_ed25519(*key_id, &data[..])
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
                        domain,
                        caps,
                    },
                delegated_caps,
                passphrase_file,
            } => {
                let key = derive_key_from_file(passphrase_file)?;
                self.client
                    .put_wrap_key(
                        *key_id,
                        Default::default(),
                        (*domain).into(),
                        caps.into(),
                        delegated_caps.into(),
                        wrap::Algorithm::Aes256Ccm,
                        key.as_secret_slice(),
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
                let wrapped = self
                    .client
                    .export_wrapped(*wrap_key_id, object.object_type(), object.id())
                    .map_err(|source| Error::Client {
                        context: "exporting wrapped key",
                        source,
                    })?;

                serialize_with_newline(writer, &wrapped)?;
                std::fs::write(wrapped_file, wrapped.into_vec()).map_err(|source| {
                    Error::IoPath {
                        context: "writing wrapped file",
                        source,
                        path: wrapped_file.into(),
                    }
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
                    self.client
                        .import_wrapped(*wrap_key_id, wrapped)
                        .map_err(|source| Error::Client {
                            context: "importing wrapped key",
                            source,
                        })?;

                serialize_with_newline(writer, ObjectId::from(imported))?;
            }
            Command::Auth(Auth {
                user,
                passphrase_file,
            }) => {
                let credentials = Credentials::new(*user, derive_key_from_file(passphrase_file)?);

                self.client = Client::open(self.client.connector().clone(), credentials, true)
                    .map_err(|source| Error::Client {
                        context: "opening new client",
                        source,
                    })?;
            }
            Command::Delete(object) => {
                self.client
                    .delete_object(object.id(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "deleting object",
                        source,
                    })?;
            }
            Command::GetInfo(object) => {
                let info = self
                    .client
                    .get_object_info(object.id(), object.object_type())
                    .map_err(|source| Error::Client {
                        context: "getting object info",
                        source,
                    })?;

                serialize_with_newline(writer, &info)?;
            }
            Command::ForceAudit(setting) => {
                self.client
                    .set_force_audit_option((*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting force audit option",
                        source,
                    })?;
            }
            Command::CommandAudit { command, setting } => {
                self.client
                    .set_command_audit_option(*command, (*setting).into())
                    .map_err(|source| Error::Client {
                        context: "setting command audit option",
                        source,
                    })?;
            }
            Command::GetLog => {
                let log = self
                    .client
                    .get_log_entries()
                    .map_err(|source| Error::Client {
                        context: "getting log entries",
                        source,
                    })?;

                serialize_with_newline(writer, &log)?;
            }
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "mockhsm"))]
mod tests {
    use std::path::PathBuf;
    use std::{fs::File, io::stdout};

    use rstest::rstest;
    use testresult::TestResult;

    use super::*;
    use crate::automation::Scenario;

    fn run_scenario(scenario_file: impl AsRef<Path>) -> TestResult {
        let scenario_file = scenario_file.as_ref();
        eprintln!(
            "Running scenario file {scenario_file}",
            scenario_file = scenario_file.display()
        );
        let scenario: Scenario = serde_json::from_reader(File::open(scenario_file)?)?;
        let mut runner = ScenarioRunner::new(Connector::mockhsm(), scenario.auth)?;
        runner.run_steps(&scenario.steps, &mut stdout())?;
        Ok(())
    }

    #[rstest]
    fn scenario_test(#[files("tests/scenarios/*.json")] scenario_file: PathBuf) -> TestResult {
        run_scenario(scenario_file)?;
        Ok(())
    }

    #[test]
    fn wrapping_test() -> TestResult {
        // these two need to run in order: first exporting to a file, then importing that file
        run_scenario("tests/scenarios/wrapping/export-wrapped.json")?;
        run_scenario("tests/scenarios/wrapping/import-wrapped.json")?;
        Ok(())
    }
}
