//! Scenario commands.

#[cfg(feature = "cli")]
use std::{
    fs::{File, read},
    io::Read,
    path::{Path, PathBuf},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "cli")]
use signstar_crypto::passphrase::Passphrase;
use yubihsm::{
    Capability as YubiHsmCapability,
    command::Code,
    object::{Filter, Id, Type},
    opaque::Algorithm,
    wrap::Message,
};

use crate::{
    Credentials,
    automation::CommandReturnValue,
    backup::Label,
    object::{AuthenticationKey, Capabilities, Domains, KeyInfo, ObjectId, WrapKey},
};
#[cfg(feature = "cli")]
use crate::{
    object::{WrapKeyFromPassphrase, WrapKeyKind},
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

    /// Puts opaque data on the device.
    PutOpaque,

    /// Retrieves opaque data from the device.
    GetOpaque,

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

    /// Lists objects visible from the authenticated session based on a list of filters.
    ListObjects,
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
            Command::PutOpaque { .. } => Self::PutOpaque,
            Command::GetOpaque { .. } => Self::GetOpaque,
            Command::PutWrapKey { .. } => Self::PutWrapKey,
            Command::ExportWrapped { .. } => Self::ExportWrapped,
            Command::ImportWrapped { .. } => Self::ImportWrapped,
            Command::DeleteObject(_) => Self::DeleteObject,
            Command::GetObjectInfo(_) => Self::GetObjectInfo,
            Command::ListObjects(_) => Self::ListObjects,
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
            CommandReturnValue::PutOpaque { .. } => Self::PutOpaque,
            CommandReturnValue::GetOpaque { .. } => Self::GetOpaque,
            CommandReturnValue::PutWrapKey { .. } => Self::PutWrapKey,
            CommandReturnValue::ExportWrapped { .. } => Self::ExportWrapped,
            CommandReturnValue::ImportWrapped { .. } => Self::ImportWrapped,
            CommandReturnValue::DeleteObject => Self::DeleteObject,
            CommandReturnValue::GetObjectInfo(_) => Self::GetObjectInfo,
            CommandReturnValue::ListObjects(_) => Self::ListObjects,
        }
    }
}

#[cfg(feature = "cli")]
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
            FileBackedCommand::PutOpaque { .. } => Self::PutOpaque,
            FileBackedCommand::GetOpaque { .. } => Self::GetOpaque,
            FileBackedCommand::PutWrapKey { .. } => Self::PutWrapKey,
            FileBackedCommand::ExportWrapped { .. } => Self::ExportWrapped,
            FileBackedCommand::ImportWrapped { .. } => Self::ImportWrapped,
            FileBackedCommand::DeleteObject(_) => Self::DeleteObject,
            FileBackedCommand::GetObjectInfo(_) => Self::GetObjectInfo,
            FileBackedCommand::ListObjects(_) => Self::ListObjects,
        }
    }
}

/// An object type in the YubiHSM2.
///
/// # Note
///
/// This type is only needed because [`Type`] uses a custom serde implementation based on bytes.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[derive(Clone, Copy, Debug, strum::Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[strum(serialize_all = "kebab-case")]
pub enum ObjectType {
    /// Raw data.
    Opaque,

    /// Authentication keys.
    AuthenticationKey,

    /// Asymmetric private keys.
    AsymmetricKey,

    /// Key for exporting and importing of keys and data.
    WrapKey,

    /// HMAC private key.
    HmacKey,

    /// A template for validating SSH certificate requests.
    Template,

    /// A Yubike-AES OTP encryption and decryption key.
    OtpAeakey,
}

impl From<Type> for ObjectType {
    fn from(value: Type) -> Self {
        match value {
            Type::Opaque => Self::Opaque,
            Type::AuthenticationKey => Self::AuthenticationKey,
            Type::AsymmetricKey => Self::AsymmetricKey,
            Type::WrapKey => Self::WrapKey,
            Type::HmacKey => Self::HmacKey,
            Type::Template => Self::Template,
            Type::OtpAeadKey => Self::OtpAeakey,
        }
    }
}

impl From<&ObjectType> for Type {
    fn from(value: &ObjectType) -> Self {
        match value {
            ObjectType::Opaque => Self::Opaque,
            ObjectType::AuthenticationKey => Self::AuthenticationKey,
            ObjectType::AsymmetricKey => Self::AsymmetricKey,
            ObjectType::WrapKey => Self::WrapKey,
            ObjectType::HmacKey => Self::HmacKey,
            ObjectType::Template => Self::Template,
            ObjectType::OtpAeakey => Self::OtpAeadKey,
        }
    }
}

/// A filter to apply when retrieving information about objects in a YubiHSM2.
///
/// # Note
///
/// This type is only needed because [`Filter`] neither implements [`Debug`] nor serde: <https://github.com/iqlusioninc/yubihsm.rs/pull/672>.
///
/// In addition, we only implement a subset of the [`Filter`].
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[derive(Clone, Debug)]
pub enum ListObjectFilter {
    /// Filter by capabilities.
    Capabilities(Capabilities),

    /// Filter by domains.
    Domains(Domains),

    /// Filter by ID.
    Id(Id),

    /// Filter by type.
    Type(ObjectType),
}

impl From<&ListObjectFilter> for Filter {
    fn from(value: &ListObjectFilter) -> Self {
        match value {
            ListObjectFilter::Capabilities(capabilities) => {
                Filter::Capabilities(capabilities.into())
            }
            ListObjectFilter::Domains(domains) => Filter::Domains(domains.into()),
            ListObjectFilter::Id(id) => Filter::Id(*id),
            ListObjectFilter::Type(typ) => Filter::Type(typ.into()),
        }
    }
}

/// A file containing opaque data.
///
/// The file is guaranteed to be not larger than [`OpaqueData::MAX_DATA_SIZE`] bytes during time
/// of creation.
#[derive(Clone, Debug)]
#[cfg(feature = "cli")]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(try_from = "PathBuf", into = "PathBuf"))]
pub struct OpaqueDataFile(PathBuf);

#[cfg(feature = "cli")]
impl OpaqueDataFile {
    /// Creates a new [`OpaqueDataFile`] from a path.
    ///
    /// # Error
    ///
    /// Returns an error, if
    ///
    /// - `path` is not a file
    /// - `path` cannot be opened for reading
    /// - the file size of `path` is larger than [`OpaqueData::MAX_DATA_SIZE`]
    pub fn new(path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(crate::automation::Error::OpaqueDataNotAFile {
                path: path.to_path_buf(),
            }
            .into());
        }
        let file = File::open(path).map_err(|source| crate::Error::IoPath {
            path: path.to_path_buf(),
            context: "opening an opaque data file for reading",
            source,
        })?;
        let data_length = file
            .metadata()
            .map_err(|source| crate::Error::IoPath {
                path: path.to_path_buf(),
                context: "retrieving metadata of an opaque data file",
                source,
            })?
            .len() as usize;
        if data_length > OpaqueData::MAX_DATA_SIZE {
            return Err(crate::automation::Error::OpaqueDataFileLength {
                path: path.to_path_buf(),
                data_length,
            }
            .into());
        }

        Ok(Self(path.to_path_buf()))
    }
}

#[cfg(feature = "cli")]
impl TryFrom<PathBuf> for OpaqueDataFile {
    type Error = crate::Error;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::new(&value)
    }
}

#[cfg(feature = "cli")]
impl From<OpaqueDataFile> for PathBuf {
    fn from(value: OpaqueDataFile) -> Self {
        value.0
    }
}

#[cfg(feature = "cli")]
impl TryFrom<&OpaqueDataFile> for Vec<u8> {
    type Error = crate::Error;

    /// Creates a new vector of bytes from a [`OpaqueDataFile`].
    ///
    /// # Note
    ///
    /// This conversion does not fail on `value` tracking a file that is larger than
    /// [`OpaqueData::MAX_DATA_SIZE`] bytes.
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - the file tracked by `value` cannot be opened for reading
    /// - the file tracked by `value` cannot be read
    fn try_from(value: &OpaqueDataFile) -> Result<Self, Self::Error> {
        let mut file = File::open(value.0.as_path()).map_err(|source| crate::Error::IoPath {
            path: value.0.clone(),
            context: "opening an opaque data file for reading",
            source,
        })?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|source| crate::Error::IoPath {
                path: value.0.clone(),
                context: "reading the contents of an opaque data file",
                source,
            })?;

        Ok(buffer)
    }
}

/// Data for an opaque object, which is guaranteed to be not larger than
/// [`OpaqueData::MAX_DATA_SIZE`] bytes.
///
/// # Note
///
/// The [`PUT OPAQUE` command] documentation states, that the maximum message size is 2048 bytes
/// (including message headers).
///
/// [`PUT OPAQUE` command]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#put-opaque-command
#[derive(Clone, Debug)]
pub struct OpaqueData(Vec<u8>);

impl OpaqueData {
    /// The maximum allowed message size.
    ///
    /// # Note
    ///
    /// According to the documentation, the maximum message size
    /// [`MAX_MSG_SIZE`][`yubihsm::command::MAX_MSG_SIZE`] includes the headers for a message.
    /// After testing, we concluded, that the headers do not take up more than 54 bytes.
    pub const MAX_DATA_SIZE: usize = 1980;

    /// Creates a new [`OpaqueData`] from a byte vector.
    ///
    /// # Errors
    ///
    /// Returns an error, if `data` is longer than [`Self::MAX_DATA_SIZE`].
    pub fn new(data: Vec<u8>) -> Result<Self, crate::Error> {
        if data.len() > OpaqueData::MAX_DATA_SIZE {
            return Err(crate::automation::Error::OpaqueDataLength {
                data_length: data.len(),
            }
            .into());
        }

        Ok(Self(data))
    }
}

#[cfg(feature = "cli")]
impl TryFrom<&OpaqueDataFile> for OpaqueData {
    type Error = crate::Error;

    fn try_from(value: &OpaqueDataFile) -> Result<Self, Self::Error> {
        let data: Vec<u8> = value.try_into()?;
        Self::new(data)
    }
}

impl From<&OpaqueData> for Vec<u8> {
    fn from(value: &OpaqueData) -> Self {
        value.0.clone()
    }
}

/// The "algorithm" (or type) of an opaque data object.
///
/// This type is required when putting opaque data onto a YubiHSM2 (using the [`PUT OPAQUE`
/// command]) and is returned when retrieving object info (using the [`GET OBJECT INFO` command]).
///
/// [`PUT OPAQUE` command]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#put-opaque-command
/// [`GET OBJECT INFO` command]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#get-object-info-command
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum OpaqueDataAlgorithm {
    /// Opaque data.
    OpaqueData,

    /// An X590 certificate.
    OpaqueX590Certificate,
}

impl From<Algorithm> for OpaqueDataAlgorithm {
    fn from(value: Algorithm) -> Self {
        match value {
            Algorithm::Data => Self::OpaqueData,
            Algorithm::X509Certificate => Self::OpaqueX590Certificate,
        }
    }
}

impl From<&OpaqueDataAlgorithm> for Algorithm {
    fn from(value: &OpaqueDataAlgorithm) -> Self {
        match value {
            OpaqueDataAlgorithm::OpaqueData => Self::Data,
            OpaqueDataAlgorithm::OpaqueX590Certificate => Self::X509Certificate,
        }
    }
}

/// The valid capabilities for an opaque data object.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum OpaqueDataCapabilities {
    /// No capabilities.
    None,

    /// The opaque data is exportable under wrap.
    ExportableUnderWrap,
}

impl From<&OpaqueDataCapabilities> for YubiHsmCapability {
    fn from(value: &OpaqueDataCapabilities) -> Self {
        match value {
            OpaqueDataCapabilities::None => YubiHsmCapability::empty(),
            OpaqueDataCapabilities::ExportableUnderWrap => YubiHsmCapability::EXPORTABLE_UNDER_WRAP,
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
        wrapping_key: WrapKey,
    },

    /// Stores opaque data (e.g. a certificate) in the device.
    ///
    /// # Note
    ///
    /// The size of the object is limited to 2028 bytes, which is the maximum message size.
    PutOpaque {
        /// The ID of the object.
        id: Id,

        /// A label describing the object.
        label: Label,

        /// The domains the opaque data will be available in.
        domains: Domains,

        /// The capabilities which will apply to the opaque data.
        capabilities: OpaqueDataCapabilities,

        /// The type of data.
        algorithm: OpaqueDataAlgorithm,

        /// The data.
        data: OpaqueData,
    },

    /// Retrieves an opaque data object.
    GetOpaque {
        /// The ID of the opaque data object to retrieve.
        id: Id,
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

    /// Lists objects visible from the authenticated session based on a list of filters.
    ListObjects(Vec<ListObjectFilter>),
}

#[cfg(feature = "cli")]
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
            FileBackedCommand::PutOpaque {
                id,
                label,
                domains,
                capabilities,
                algorithm,
                data_file,
            } => Command::PutOpaque {
                id: *id,
                label: label.clone(),
                domains: domains.clone(),
                capabilities: *capabilities,
                algorithm: *algorithm,
                data: OpaqueData::try_from(data_file)?,
            },
            FileBackedCommand::GetOpaque { id, .. } => Command::GetOpaque { id: *id },
            FileBackedCommand::PutWrapKey {
                info,
                delegated_caps,
                passphrase_file,
            } => Command::PutWrapKey {
                info: info.clone(),
                delegated_caps: delegated_caps.clone(),
                wrapping_key: WrapKey::try_from(WrapKeyFromPassphrase::new(
                    &Passphrase::try_from(passphrase_file.as_path())?,
                    WrapKeyKind::Aes256,
                )?)?,
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
            FileBackedCommand::ListObjects(filters) => Command::ListObjects(filters.clone()),
        })
    }
}

/// A single command that is atomically executed against a YubiHSM2.
///
/// Different from [`Command`], this enum does not assign data directly in its variants, but instead
/// relies on paths to files to read from or write to.
#[derive(Debug)]
#[cfg(feature = "cli")]
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

    /// Stores opaque data (e.g. a certificate) in the device.
    ///
    /// # Note
    ///
    /// The size of the object is limited to 2028 bytes, which is the maximum message size.
    PutOpaque {
        /// The ID of the object.
        id: Id,

        /// A label describing the object.
        label: Label,

        /// The domains the opaque data will be available in.
        domains: Domains,

        /// The capabilities which will apply to the opaque data.
        capabilities: OpaqueDataCapabilities,

        /// The type of data.
        algorithm: OpaqueDataAlgorithm,

        /// The file containing the data.
        data_file: OpaqueDataFile,
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

        /// The file containing the passphrase from which the wrapping key is generated.
        passphrase_file: PathBuf,
    },

    /// Retrieves an opaque data object.
    GetOpaque {
        /// The path to write the data to.
        data_file: PathBuf,

        /// The ID of the opaque data object to retrieve.
        id: Id,
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

    /// Lists objects visible from the authenticated session based on a list of filters.
    ListObjects(Vec<ListObjectFilter>),
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
#[cfg(feature = "cli")]
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct FileBackedAuthenticatedCommandChain {
    pub(crate) auth: FileBackedCredentials,
    pub(crate) commands: Vec<FileBackedCommand>,
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "cli")]
    use std::io::Write;

    #[cfg(feature = "cli")]
    use tempfile::{NamedTempFile, TempDir};
    use testresult::TestResult;

    use super::*;

    const LARGE_DATA_LENGTH: usize = OpaqueData::MAX_DATA_SIZE + 1;

    /// Ensures, that [`OpaqueData::new`] fails on input data that is too large.
    #[test]
    fn opaque_data_new_fails_on_large_data() -> TestResult {
        let data = Vec::from_iter([1; LARGE_DATA_LENGTH]);
        match OpaqueData::new(data) {
            Err(crate::Error::Automation(crate::automation::Error::OpaqueDataLength {
                ..
            })) => {}
            Err(error) => panic!(
                "Expected to fail with Error::OpaqueDataLength, but got a different error instead: {error}"
            ),
            Ok(opaque_data) => panic!(
                "Expected to fail with Error::OpaqueDataLength, succeeded instead: {opaque_data:?}"
            ),
        };

        Ok(())
    }

    /// Ensures, that a [`PathBuf`] can be created from an [`OpaqueDataFile`].
    #[cfg(feature = "cli")]
    #[test]
    fn path_from_opaque_data_file() -> TestResult {
        let data_file = {
            let mut data_file = NamedTempFile::new()?;
            let data: Vec<u8> = Vec::from_iter([1; 1]);
            data_file.write_all(data.as_slice())?;
            data_file
        };
        let opaque_data_file = OpaqueDataFile::new(data_file.path())?;
        let _path: PathBuf = opaque_data_file.into();

        Ok(())
    }

    /// Ensures, that [`OpaqueDataFile::new`] fails on file path being a directory.
    #[cfg(feature = "cli")]
    #[test]
    fn opaque_data_file_new_fails_on_dir() -> TestResult {
        let temp_dir = TempDir::new()?;

        match OpaqueDataFile::new(temp_dir.path()) {
            Err(crate::Error::Automation(crate::automation::Error::OpaqueDataNotAFile {
                ..
            })) => {}
            Err(error) => panic!(
                "Expected to fail with Error::OpaqueDataNotAFile, but got a different error instead: {error}"
            ),
            Ok(opaque_data) => panic!(
                "Expected to fail with Error::OpaqueDataNotAFile, succeeded instead: {opaque_data:?}"
            ),
        };

        Ok(())
    }

    /// Ensures, that [`OpaqueDataFile::new`] fails on file path of a file that is too large.
    #[cfg(feature = "cli")]
    #[test]
    fn opaque_data_file_new_fails_on_large_data() -> TestResult {
        let data_file = {
            let mut data_file = NamedTempFile::new()?;
            let data: Vec<u8> = Vec::from_iter([1; LARGE_DATA_LENGTH]);
            data_file.write_all(data.as_slice())?;
            data_file
        };

        match OpaqueDataFile::new(data_file.path()) {
            Err(crate::Error::Automation(crate::automation::Error::OpaqueDataFileLength {
                ..
            })) => {}
            Err(error) => panic!(
                "Expected to fail with Error::OpaqueDataFileLength, but got a different error instead: {error}"
            ),
            Ok(opaque_data) => panic!(
                "Expected to fail with Error::OpaqueDataFileLength, succeeded instead: {opaque_data:?}"
            ),
        };

        Ok(())
    }
}
