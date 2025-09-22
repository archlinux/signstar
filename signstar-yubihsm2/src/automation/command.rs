//! Scenario commands.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use yubihsm::command::Code;

use crate::{object::Capabilities, object::KeyInfo, object::ObjectId};

/// Authentication data: login and a location of the passphrase file.
#[derive(Debug, Deserialize, Serialize)]
pub struct Auth {
    /// The identifier of the authentication key to use.
    pub user: u16,

    /// The file containing passphrase of the authenticating user.
    pub passphrase_file: PathBuf,
}

/// Indicates the setting of the auditing.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
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

/// A single command that is atomically executed against a YubiHSM2.
#[derive(Debug, Deserialize, Serialize)]
pub enum Command {
    /// Query the device state.
    Info,

    /// Reset the device to factory settings and reconnect afterwards.
    ///
    /// Note that this is a destructive operation and the authenticating user will need to have
    /// appropriate capabilities.
    Reset,

    /// Query the command log of the device and print it to standard output.
    GetLog,

    /// Authenticate against the device.
    ///
    /// This command *must* be used as a first command in the scenario file as it is not possible to
    /// connect to the device without any credentials.
    Auth(Auth),

    /// Change audit settings.
    ///
    /// This mode prevents the device from performing additional operations when the Logs and Error
    /// Codes is full.
    ///
    /// See [Force Audit](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#force-audit) for more details.
    ForceAudit(AuditOption),

    /// Changes command audit settings.
    ///
    /// This is used to manage auditing options for specific commands. By default all commands are
    /// logged.
    ///
    /// See [Force Audit](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#command-audit) for more details.
    #[allow(clippy::enum_variant_names)]
    CommandAudit {
        /// Command of which the setting should be changed.
        command: Code,

        /// New setting value.
        setting: AuditOption,
    },

    /// Put authentication key on the device.
    ///
    /// This command is used to append new authentication keys.
    PutAuthKey {
        /// The key identity and capabilities.
        #[serde(flatten)]
        info: KeyInfo,

        /// Additional delegated capabilities which would apply to objects that are created or
        /// imported.
        delegated_caps: Capabilities,

        /// The file containing passphrase of the authenticating user.
        passphrase_file: PathBuf,
    },

    /// Generates new `ed25519` signing key on the device.
    GenerateKey {
        /// The key identity and capabilities.
        #[serde(flatten)]
        info: KeyInfo,
    },

    /// Signs data using provided `ed25519` key.
    SignEd25519 {
        /// The key to be used for signing.
        key_id: u16,

        /// Raw data blob which should be signed.
        data: Vec<u8>,
    },

    /// Puts new wrapping key on the device.
    ///
    /// This command is used to append new wrapping keys which serve as encryption keys for other
    /// objects.
    PutWrapKey {
        /// The key identity and capabilities.
        #[serde(flatten)]
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
        wrap_key_id: u16,

        /// Object that will be exported.
        #[serde(flatten)]
        object: ObjectId,

        /// Output file which will contain the exported object encrypted with the wrapping key.
        wrapped_file: PathBuf,
    },

    /// Imports objects under wrap (encrypted).
    ImportWrapped {
        /// Wrapping key which would decrypt the imported object.
        wrap_key_id: u16,

        /// Input file which contains the imported object encrypted with the wrapping key.
        wrapped_file: PathBuf,
    },

    /// Permanently remove an object from the device.
    Delete(ObjectId),

    /// Query data about the object and print it to standard output.
    GetInfo(ObjectId),
}
