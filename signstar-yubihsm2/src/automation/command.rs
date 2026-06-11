//! Scenario commands.

use std::{fs::read, path::PathBuf};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use yubihsm::{command::Code, wrap::Message};

use crate::{
    Credentials,
    automation::CommandReturnValue,
    object::{AuthenticationKey, Capabilities, Id, KeyInfo, ObjectId},
    user::FileBackedCredentials,
};

/// Indicates the setting of the auditing.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum AuditOption {
    /// Auditing is enabled but can be disabled.
    On,

    /// Auditing is disabled.
    Off,

    /// Auditing is permanently enabled and cannot be disabled.
    Fix,
}

impl From<AuditOption> for yubihsm::AuditOption {
    fn from(value: AuditOption) -> Self {
        match value {
            AuditOption::On => Self::On,
            AuditOption::Off => Self::Off,
            AuditOption::Fix => Self::Fix,
        }
    }
}

/// The printable name of a [`Command`].
#[derive(Debug, strum::Display)]
#[strum(serialize_all = "snake_case")]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum CommandName {
    /// Query the device state.
    DeviceInfo,

    /// Reset the device to factory settings and reconnect afterwards.
    ResetDeviceAndReconnect,

    /// Query the command log of the device and print it to standard output.
    GetLogEntries,

    /// Change audit settings.
    SetForceAuditOption,

    /// Changes command audit settings.
    SetCommandAuditOption,

    /// Put authentication key on the device.
    PutAuthenticationKey,

    /// Generates a new asymmetric key on the device.
    GenerateAsymmetricKey,

    /// Signs data using a `ed25519` key.
    SignEd25519,

    /// Puts new wrapping key on the device.
    PutWrapKey,

    /// Export object under wrap (encrypted).
    ExportWrapped,

    /// Imports objects under wrap (encrypted).
    ImportWrapped,

    /// Permanently remove an object from the device.
    DeleteObject,

    /// Query data about the object and print it to standard output.
    GetObjectInfo,
}

impl From<&Command> for CommandName {
    fn from(value: &Command) -> Self {
        match value {
            Command::DeviceInfo => Self::DeviceInfo,
            Command::ResetDeviceAndReconnect => Self::ResetDeviceAndReconnect,
            Command::GetLogEntries => Self::GetLogEntries,
            Command::SetForceAuditOption(_) => Self::SetForceAuditOption,
            Command::SetCommandAuditOption { .. } => Self::SetCommandAuditOption,
            Command::PutAuthenticationKey { .. } => Self::PutAuthenticationKey,
            Command::GenerateAsymmetricKey { .. } => Self::GenerateAsymmetricKey,
            Command::SignEd25519 { .. } => Self::SignEd25519,
            Command::PutWrapKey { .. } => Self::PutWrapKey,
            Command::ExportWrapped { .. } => Self::ExportWrapped,
            Command::ImportWrapped { .. } => Self::ImportWrapped,
            Command::DeleteObject(_) => Self::DeleteObject,
            Command::GetObjectInfo(_) => Self::GetObjectInfo,
        }
    }
}

impl From<&CommandReturnValue> for CommandName {
    fn from(value: &CommandReturnValue) -> Self {
        match value {
            CommandReturnValue::DeviceInfo(_) => Self::DeviceInfo,
            CommandReturnValue::ResetDeviceAndReconnect => Self::ResetDeviceAndReconnect,
            CommandReturnValue::GetLogEntries(_) => Self::GetLogEntries,
            CommandReturnValue::SetForceAuditOption => Self::SetForceAuditOption,
            CommandReturnValue::SetCommandAuditOption => Self::SetCommandAuditOption,
            CommandReturnValue::PutAuthenticationKey { .. } => Self::PutAuthenticationKey,
            CommandReturnValue::GenerateAsymmetricKey { .. } => Self::GenerateAsymmetricKey,
            CommandReturnValue::SignEd25519 { .. } => Self::SignEd25519,
            CommandReturnValue::PutWrapKey { .. } => Self::PutWrapKey,
            CommandReturnValue::ExportWrapped { .. } => Self::ExportWrapped,
            CommandReturnValue::ImportWrapped { .. } => Self::ImportWrapped,
            CommandReturnValue::DeleteObject => Self::DeleteObject,
            CommandReturnValue::GetObjectInfo(_) => Self::GetObjectInfo,
        }
    }
}

impl From<&FileBackedCommand> for CommandName {
    fn from(value: &FileBackedCommand) -> Self {
        match value {
            FileBackedCommand::DeviceInfo => Self::DeviceInfo,
            FileBackedCommand::ResetDeviceAndReconnect => Self::ResetDeviceAndReconnect,
            FileBackedCommand::GetLogEntries => Self::GetLogEntries,
            FileBackedCommand::SetForceAuditOption(_) => Self::SetForceAuditOption,
            FileBackedCommand::SetCommandAuditOption { .. } => Self::SetCommandAuditOption,
            FileBackedCommand::PutAuthenticationKey { .. } => Self::PutAuthenticationKey,
            FileBackedCommand::GenerateAsymmetricKey { .. } => Self::GenerateAsymmetricKey,
            FileBackedCommand::SignEd25519 { .. } => Self::SignEd25519,
            FileBackedCommand::PutWrapKey { .. } => Self::PutWrapKey,
            FileBackedCommand::ExportWrapped { .. } => Self::ExportWrapped,
            FileBackedCommand::ImportWrapped { .. } => Self::ImportWrapped,
            FileBackedCommand::DeleteObject(_) => Self::DeleteObject,
            FileBackedCommand::GetObjectInfo(_) => Self::GetObjectInfo,
        }
    }
}

/// A single command that is atomically executed against a YubiHSM2.
#[derive(Debug)]
pub enum Command {
    /// Query the device state.
    DeviceInfo,

    /// Reset the device to factory settings and reconnect afterwards.
    ///
    /// Note that this is a destructive operation and the authenticating user will need to have
    /// appropriate capabilities.
    ResetDeviceAndReconnect,

    /// Query the command log of the device and print it to standard output.
    GetLogEntries,

    /// Change audit settings.
    ///
    /// This mode prevents the device from performing additional operations when the Logs and Error
    /// Codes is full.
    ///
    /// See [Force Audit](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#force-audit) for more details.
    SetForceAuditOption(AuditOption),

    /// Changes command audit settings.
    ///
    /// This is used to manage auditing options for specific commands. By default all commands are
    /// logged.
    ///
    /// See [Force Audit](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#command-audit) for more details.
    #[allow(clippy::enum_variant_names)]
    SetCommandAuditOption {
        /// Command of which the setting should be changed.
        command: Code,

        /// New setting value.
        setting: AuditOption,
    },

    /// Put authentication key on the device.
    ///
    /// This command is used to append new authentication keys.
    PutAuthenticationKey {
        /// The key identity and capabilities.
        info: KeyInfo,

        /// Additional delegated capabilities which would apply to objects that are created or
        /// imported.
        delegated_caps: Capabilities,

        /// The authentication key to put onto the YubiHSM2.
        authentication_key: AuthenticationKey,
    },

    /// Generates new `ed25519` signing key on the device.
    GenerateAsymmetricKey {
        /// The key identity and capabilities.
        info: KeyInfo,
    },

    /// Signs data using provided `ed25519` key.
    SignEd25519 {
        /// The key to be used for signing.
        key_id: Id,

        /// Raw data blob which should be signed.
        data: Vec<u8>,
    },

    /// Puts new wrapping key on the device.
    ///
    /// This command is used to append new wrapping keys which serve as encryption keys for other
    /// objects.
    PutWrapKey {
        /// The key identity and capabilities.
        info: KeyInfo,

        /// Additional delegated capabilities which would apply to objects that are created or
        /// imported.
        delegated_caps: Capabilities,

        /// The wrapping key.
        wrapping_key: AuthenticationKey,
    },

    /// Export object under wrap (encrypted).
    ExportWrapped {
        /// Wrapping key which should encrypt the exported object.
        wrap_key_id: Id,

        /// Object that will be exported.
        object: ObjectId,
    },

    /// Imports objects under wrap (encrypted).
    ImportWrapped {
        /// Wrapping key which would decrypt the imported object.
        wrap_key_id: Id,

        /// The encrypted message which should be imported.
        message: Message,
    },

    /// Permanently remove an object from the device.
    DeleteObject(ObjectId),

    /// Query data about the object and print it to standard output.
    GetObjectInfo(ObjectId),
}

impl TryFrom<&FileBackedCommand> for Command {
    type Error = crate::Error;

    /// Creates a new [`Command`] from this [`FileBackedCommand`].
    ///
    /// # Errors
    ///
    /// Returns an error, if reading/creating the required data from input files fails.
    fn try_from(value: &FileBackedCommand) -> Result<Self, Self::Error> {
        Ok(match value {
            FileBackedCommand::DeviceInfo => Command::DeviceInfo,
            FileBackedCommand::ResetDeviceAndReconnect => Command::ResetDeviceAndReconnect,
            FileBackedCommand::GetLogEntries => Command::GetLogEntries,
            FileBackedCommand::SetForceAuditOption(audit_option) => {
                Command::SetForceAuditOption(*audit_option)
            }
            FileBackedCommand::SetCommandAuditOption { command, setting } => {
                Command::SetCommandAuditOption {
                    command: (*command),
                    setting: (*setting),
                }
            }
            FileBackedCommand::PutAuthenticationKey {
                info,
                delegated_caps,
                passphrase_file,
            } => Command::PutAuthenticationKey {
                info: info.clone(),
                delegated_caps: delegated_caps.clone(),
                authentication_key: AuthenticationKey::try_from(passphrase_file.as_path())?,
            },
            FileBackedCommand::GenerateAsymmetricKey { info } => {
                Command::GenerateAsymmetricKey { info: info.clone() }
            }
            FileBackedCommand::SignEd25519 { key_id, data } => Command::SignEd25519 {
                key_id: (*key_id),
                data: data.to_vec(),
            },
            FileBackedCommand::PutWrapKey {
                info,
                delegated_caps,
                passphrase_file,
            } => Command::PutWrapKey {
                info: info.clone(),
                delegated_caps: delegated_caps.clone(),
                wrapping_key: AuthenticationKey::try_from(passphrase_file.as_path())?,
            },
            FileBackedCommand::ExportWrapped {
                wrap_key_id,
                object,
                wrapped_file: _,
            } => Command::ExportWrapped {
                wrap_key_id: (*wrap_key_id),
                object: (*object),
            },
            FileBackedCommand::ImportWrapped {
                wrap_key_id,
                wrapped_file,
            } => {
                let message =
                    Message::from_vec(read(wrapped_file.as_path()).map_err(|source| {
                        Self::Error::IoPath {
                            path: wrapped_file.clone(),
                            context: "reading a file under wrap",
                            source,
                        }
                    })?)
                    .map_err(|source| Self::Error::InvalidWrap {
                        context: "reading the wrapped file",
                        source,
                    })?;

                Command::ImportWrapped {
                    wrap_key_id: (*wrap_key_id),
                    message,
                }
            }
            FileBackedCommand::DeleteObject(id) => Command::DeleteObject(*id),
            FileBackedCommand::GetObjectInfo(id) => Command::GetObjectInfo(*id),
        })
    }
}

/// A single command that is atomically executed against a YubiHSM2.
///
/// Different from [`Command`], this enum does not assign data directly in its variants, but instead
/// relies on paths to files to read from or write to.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FileBackedCommand {
    /// Query the device state.
    DeviceInfo,

    /// Reset the device to factory settings and reconnect afterwards.
    ///
    /// Note that this is a destructive operation and the authenticating user will need to have
    /// appropriate capabilities.
    ResetDeviceAndReconnect,

    /// Query the command log of the device and print it to standard output.
    GetLogEntries,

    /// Change audit settings.
    ///
    /// This mode prevents the device from performing additional operations when the Logs and Error
    /// Codes is full.
    ///
    /// See [Force Audit](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#force-audit) for more details.
    SetForceAuditOption(AuditOption),

    /// Changes command audit settings.
    ///
    /// This is used to manage auditing options for specific commands. By default all commands are
    /// logged.
    ///
    /// See [Force Audit](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#command-audit) for more details.
    #[allow(clippy::enum_variant_names)]
    SetCommandAuditOption {
        /// Command of which the setting should be changed.
        command: Code,

        /// New setting value.
        setting: AuditOption,
    },

    /// Put authentication key on the device.
    ///
    /// This command is used to append new authentication keys.
    PutAuthenticationKey {
        /// The key identity and capabilities.
        #[cfg_attr(feature = "serde", serde(flatten))]
        info: KeyInfo,

        /// Additional delegated capabilities which would apply to objects that are created or
        /// imported.
        delegated_caps: Capabilities,

        /// The file containing passphrase of the authenticating user.
        passphrase_file: PathBuf,
    },

    /// Generates new `ed25519` signing key on the device.
    GenerateAsymmetricKey {
        /// The key identity and capabilities.
        #[cfg_attr(feature = "serde", serde(flatten))]
        info: KeyInfo,
    },

    /// Signs data using provided `ed25519` key.
    SignEd25519 {
        /// The key to be used for signing.
        key_id: Id,

        /// Raw data blob which should be signed.
        data: Vec<u8>,
    },

    /// Puts new wrapping key on the device.
    ///
    /// This command is used to append new wrapping keys which serve as encryption keys for other
    /// objects.
    PutWrapKey {
        /// The key identity and capabilities.
        #[cfg_attr(feature = "serde", serde(flatten))]
        info: KeyInfo,

        /// Additional delegated capabilities which would apply to objects that are created or
        /// imported.
        delegated_caps: Capabilities,

        /// The file containing raw value of the wrapping key.
        passphrase_file: PathBuf,
    },

    /// Export object under wrap (encrypted).
    ExportWrapped {
        /// Wrapping key which should encrypt the exported object.
        wrap_key_id: Id,

        /// Object that will be exported.
        #[cfg_attr(feature = "serde", serde(flatten))]
        object: ObjectId,

        /// Output file which will contain the exported object encrypted with the wrapping key.
        wrapped_file: PathBuf,
    },

    /// Imports objects under wrap (encrypted).
    ImportWrapped {
        /// Wrapping key which would decrypt the imported object.
        wrap_key_id: Id,

        /// Input file which contains the imported object encrypted with the wrapping key.
        wrapped_file: PathBuf,
    },

    /// Permanently remove an object from the device.
    DeleteObject(ObjectId),

    /// Query data about the object and print it to standard output.
    GetObjectInfo(ObjectId),
}

/// A list of [`Command`]s that are run with a specific authentication.
///
/// A single [`Credentials`] is used for authentication of each command towards the YubiHSM2
/// backend.
#[derive(Debug)]
pub struct AuthenticatedCommandChain {
    auth: Credentials,
    commands: Vec<Command>,
}

impl AuthenticatedCommandChain {
    /// Creates a new [`AuthenticatedCommandChain`] from authentication data and a list of commands.
    pub fn new(auth: Credentials, commands: Vec<Command>) -> Self {
        Self { auth, commands }
    }

    /// Returns the authentication details for the authenticated commands.
    pub fn auth(&self) -> &Credentials {
        &self.auth
    }

    /// Returns the commands for the authenticated commands.
    pub fn commands(&self) -> &[Command] {
        &self.commands
    }
}

/// A list of [`Command`]s that are run with a specific authentication.
///
/// A single [`FileBackedCredentials`] is used for authentication of each command towards the
/// YubiHSM2 backend.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct FileBackedAuthenticatedCommandChain {
    pub(crate) auth: FileBackedCredentials,
    pub(crate) commands: Vec<FileBackedCommand>,
}
