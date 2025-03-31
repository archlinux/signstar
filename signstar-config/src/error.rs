//! Common, top-level error type for all components of signstar-config.

use std::{
    path::PathBuf,
    process::{ExitCode, ExitStatus},
    string::FromUtf8Error,
};

/// An error that may occur when using Signstar config.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error specific to administrative secret handling.
    #[error("Error with administrative secret handling:\n{0}")]
    AdminSecretHandling(#[from] crate::admin_credentials::Error),

    /// An error specific to Signstar config handling.
    /// Applying permissions to a file or directory failed.
    #[error("Unable to apply permissions from mode {mode} to {path}:\n{source}")]
    ApplyPermissions {
        /// The path to a file for which permissions can not be applied.
        path: PathBuf,
        /// The file mode that should be applied for `path`.
        mode: u32,
        /// The source error.
        source: std::io::Error,
    },

    /// The ownership of a path can not be changed.
    #[error("Changing ownership of {path} to user {user} failed:\n{source}")]
    Chown {
        /// The path to a file for which ownership can not be changed.
        path: PathBuf,
        /// The system user that should be the new owner of `path`.
        user: String,
        /// The source error.
        source: std::io::Error,
    },

    /// Unable to attach to stdin of a command.
    #[error("Unable to attach to stdin of command \"{command}\"")]
    CommandAttachToStdin {
        /// The command for which attaching to stdin failed.
        command: String,
    },

    /// A command exited unsuccessfully.
    #[error("The command \"{command}\" could not be started in the background:\n{source}")]
    CommandBackground {
        /// The command that could not be started in the background.
        command: String,
        /// The source error.
        source: std::io::Error,
    },

    /// A command could not be executed.
    #[error("The command \"{command}\" could not be executed:\n{source}")]
    CommandExec {
        /// The command that could not be executed.
        command: String,
        /// The source error.
        source: std::io::Error,
    },

    /// A command exited unsuccessfully.
    #[error(
        "The command \"{command}\" exited with non-zero status code \"{exit_status}\":\nstderr:\n{stderr}"
    )]
    CommandNonZero {
        /// The command that exited with a non-zero exit code.
        command: String,
        /// The exit status of `command`.
        exit_status: ExitStatus,
        /// The stderr of `command`.
        stderr: String,
    },

    /// Unable to write to stdin of a command.
    #[error("Unable to write to stdin of command \"{command}\"")]
    CommandWriteToStdin {
        /// The command for which writing to stdin failed.
        command: String,
        /// The source error.
        source: std::io::Error,
    },

    /// Configuration errors.
    #[error("Signstar config error:\n{0}")]
    Config(#[from] crate::config::Error),

    /// A NetHSM error.
    #[error("NetHSM error:\n{0}")]
    NetHsm(#[from] nethsm::Error),

    /// A NetHSM backend error
    ///
    /// This variant is used when actions for a NetHSM backend fail.
    #[error("NetHSM backend error:\n{0}")]
    NetHsmBackend(#[from] crate::NetHsmBackendError),

    /// An error specific to non-administrative secret handling.
    #[error("Error with non-administrative secret handling:\n{0}")]
    NonAdminSecretHandling(#[from] crate::non_admin_credentials::Error),

    /// Low-level administrative credentials handling in signstar-common failed.
    #[error("Handling of administrative credentials failed:\n{0}")]
    SignstarCommonAdminCreds(#[from] signstar_common::admin_credentials::Error),

    /// Joining a thread returned an error.
    #[error("Thread error while {context}")]
    Thread {
        /// The context in which the failed thread ran.
        ///
        /// Should complete the sentence "Thread error while ".
        context: String,
    },

    /// A UTF-8 error occurred when trying to convert a byte vector to a string.
    #[error("Converting contents of {path} to string failed while {context}:\n{source}")]
    Utf8String {
        /// The path to a file for which conversion to UTF-8 string failed.
        path: PathBuf,
        /// The context in which the error occurred.
        ///
        /// Should complete the sentence "Converting contents of `path` to string failed while "
        context: String,
        /// The source error.
        source: FromUtf8Error,
    },

    /// A utility function returned an error.
    #[error("Utility function error: {0}")]
    Utils(#[from] crate::utils::Error),
}

/// Mapping for relevant [`Error`] variants to an [`ExitCode`].
#[derive(Clone, Copy, Debug, Eq, num_enum::IntoPrimitive, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ErrorExitCode {
    /// Mapping for [`crate::admin_credentials::Error::AdministratorMissing`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsAdministratorMissing = 100,

    /// Mapping for [`crate::admin_credentials::Error::AdministratorNoDefault`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsAdministratorNoDefault = 101,

    /// Mapping for [`crate::admin_credentials::Error::ConfigFromToml`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsConfigFromToml = 102,

    /// Mapping for [`crate::admin_credentials::Error::ConfigLoad`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsConfigLoad = 103,

    /// Mapping for [`crate::admin_credentials::Error::ConfigStore`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsConfigStore = 104,

    /// Mapping for [`crate::admin_credentials::Error::ConfigToToml`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsConfigToToml = 105,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileCreate`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileCreate = 106,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileMissing`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileMissing = 107,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileNotAFile`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileNotAFile = 108,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileWrite`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileWrite = 109,

    /// Mapping for [`crate::admin_credentials::Error::PassphraseTooShort`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsPassphraseTooShort = 110,

    /// Mapping for [`Error::ApplyPermissions`].
    ApplyPermissions = 10,

    /// Mapping for [`Error::Chown`].
    Chown = 11,

    /// Mapping for [`Error::CommandAttachToStdin`].
    CommandAttachToStdin = 12,

    /// Mapping for [`Error::CommandBackground`].
    CommandBackground = 13,

    /// Mapping for [`Error::CommandExec`].
    CommandExec = 14,

    /// Mapping for [`Error::CommandNonZero`].
    CommandNonZero = 15,

    /// Mapping for [`Error::CommandWriteToStdin`].
    CommandWriteToStdin = 16,

    /// Mapping for [`crate::config::Error::ConfigMissing`] wrapped in [`Error::Config`].
    ConfigConfigMissing = 120,

    /// Mapping for [`crate::config::Error::NetHsmConfig`] wrapped in [`Error::Config`].
    ConfigNetHsmConfig = 121,

    /// Mapping for [`crate::Error::NetHsm`].
    NetHsm = 17,

    /// Mapping for [`crate::Error::NetHsmBackend`].
    NetHsmBackend = 18,

    /// Mapping for [`crate::non_admin_credentials::Error::CredentialsLoading`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsCredentialsLoading = 140,

    /// Mapping for [`crate::non_admin_credentials::Error::CredentialsMissing`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsCredentialsMissing = 141,

    /// Mapping for [`crate::non_admin_credentials::Error::NoSystemUser`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsNoSystemUser = 142,

    /// Mapping for [`crate::non_admin_credentials::Error::NotSigningUser`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsNotSigningUser = 143,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsDirCreate`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsDirCreate = 144,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFileCreate`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFileCreate = 145,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFileMetadata`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFileMetadata = 146,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFileMissing`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFileMissing = 147,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFileNotAFile`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFileNotAFile = 148,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFilePermissions`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFilePermissions = 149,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFileRead`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFileRead = 150,

    /// Mapping for [`crate::non_admin_credentials::Error::SecretsFileWrite`] wrapped in
    /// [`Error::NonAdminSecretHandling`].
    NonAdminCredentialsSecretsFileWrite = 151,

    /// Mapping for [`signstar_common::admin_credentials::Error::ApplyPermissions`] wrapped in
    /// [`Error::SignstarCommonAdminCreds`].
    SignstarCommonAdminCredsApplyPermissions = 170,

    /// Mapping for [`signstar_common::admin_credentials::Error::CreateDirectory`] wrapped in
    /// [`Error::SignstarCommonAdminCreds`].
    SignstarCommonAdminCredsCreateDirectory = 171,

    /// Mapping for [`signstar_common::admin_credentials::Error::DirChangeOwner`] wrapped in
    /// [`Error::SignstarCommonAdminCreds`].
    SignstarCommonAdminCredsDirChangeOwner = 172,

    /// Mapping for [`Error::Thread`].
    Thread = 19,

    /// Mapping for [`Error::Utf8String`].
    Utf8String = 20,

    /// Mapping for [`crate::utils::Error::ExecutableNotFound`] wrapped in [`Error::Utils`].
    UtilsExecutableNotFound = 190,

    /// Mapping for [`crate::utils::Error::MappingSystemUserGet`] wrapped in [`Error::Utils`].
    UtilsMappingSystemUserGet = 191,

    /// Mapping for [`crate::utils::Error::SystemUserData`] wrapped in [`Error::Utils`].
    UtilsSystemUserData = 192,

    /// Mapping for [`crate::utils::Error::SystemUserLookup`] wrapped in [`Error::Utils`].
    UtilsSystemUserLookup = 193,

    /// Mapping for [`crate::utils::Error::SystemUserMismatch`] wrapped in [`Error::Utils`].
    UtilsSystemUserMismatch = 194,

    /// Mapping for [`crate::utils::Error::SystemUserNotRoot`] wrapped in [`Error::Utils`].
    UtilsSystemUserNotRoot = 195,

    /// Mapping for [`crate::utils::Error::SystemUserRoot`] wrapped in [`Error::Utils`].
    UtilsSystemUserRoot = 196,
}

impl From<Error> for ErrorExitCode {
    fn from(value: Error) -> Self {
        match value {
            // admin credentials related errors and their exit codes
            Error::AdminSecretHandling(error) => match error {
                crate::admin_credentials::Error::AdministratorMissing => {
                    Self::AdminCredentialsAdministratorMissing
                }
                crate::admin_credentials::Error::AdministratorNoDefault => {
                    Self::AdminCredentialsAdministratorNoDefault
                }
                crate::admin_credentials::Error::ConfigFromToml { .. } => {
                    Self::AdminCredentialsConfigFromToml
                }
                crate::admin_credentials::Error::ConfigLoad { .. } => {
                    Self::AdminCredentialsConfigLoad
                }
                crate::admin_credentials::Error::ConfigStore { .. } => {
                    Self::AdminCredentialsConfigStore
                }
                crate::admin_credentials::Error::ConfigToToml(_) => {
                    Self::AdminCredentialsConfigToToml
                }
                crate::admin_credentials::Error::CredsFileCreate { .. } => {
                    Self::AdminCredentialsCredsFileCreate
                }
                crate::admin_credentials::Error::CredsFileMissing { .. } => {
                    Self::AdminCredentialsCredsFileMissing
                }
                crate::admin_credentials::Error::CredsFileNotAFile { .. } => {
                    Self::AdminCredentialsCredsFileNotAFile
                }
                crate::admin_credentials::Error::CredsFileWrite { .. } => {
                    Self::AdminCredentialsCredsFileWrite
                }
                crate::admin_credentials::Error::PassphraseTooShort { .. } => {
                    Self::AdminCredentialsPassphraseTooShort
                }
            },
            // config related errors
            Error::Config(error) => match error {
                crate::config::Error::ConfigMissing => Self::ConfigConfigMissing,
                crate::config::Error::NetHsmConfig(_) => Self::ConfigNetHsmConfig,
            },
            // NetHSM related errors
            Error::NetHsm(_) => Self::NetHsm,
            // NetHSM backend related errors
            Error::NetHsmBackend(_) => Self::NetHsmBackend,
            // non-admin credentials related errors and their exit codes
            Error::NonAdminSecretHandling(error) => match error {
                crate::non_admin_credentials::Error::CredentialsLoading { .. } => {
                    Self::NonAdminCredentialsCredentialsLoading
                }
                crate::non_admin_credentials::Error::CredentialsMissing { .. } => {
                    Self::NonAdminCredentialsCredentialsMissing
                }
                crate::non_admin_credentials::Error::NoSystemUser => {
                    Self::NonAdminCredentialsNoSystemUser
                }
                crate::non_admin_credentials::Error::NotSigningUser => {
                    Self::NonAdminCredentialsNotSigningUser
                }
                crate::non_admin_credentials::Error::SecretsDirCreate { .. } => {
                    Self::NonAdminCredentialsSecretsDirCreate
                }
                crate::non_admin_credentials::Error::SecretsFileCreate { .. } => {
                    Self::NonAdminCredentialsSecretsFileCreate
                }
                crate::non_admin_credentials::Error::SecretsFileMetadata { .. } => {
                    Self::NonAdminCredentialsSecretsFileMetadata
                }
                crate::non_admin_credentials::Error::SecretsFileMissing { .. } => {
                    Self::NonAdminCredentialsSecretsFileMissing
                }
                crate::non_admin_credentials::Error::SecretsFileNotAFile { .. } => {
                    Self::NonAdminCredentialsSecretsFileNotAFile
                }
                crate::non_admin_credentials::Error::SecretsFilePermissions { .. } => {
                    Self::NonAdminCredentialsSecretsFilePermissions
                }
                crate::non_admin_credentials::Error::SecretsFileRead { .. } => {
                    Self::NonAdminCredentialsSecretsFileRead
                }
                crate::non_admin_credentials::Error::SecretsFileWrite { .. } => {
                    Self::NonAdminCredentialsSecretsFileWrite
                }
            },
            // signstar-common admin credentials related errors
            Error::SignstarCommonAdminCreds(error) => match error {
                signstar_common::admin_credentials::Error::ApplyPermissions { .. } => {
                    Self::SignstarCommonAdminCredsApplyPermissions
                }
                signstar_common::admin_credentials::Error::CreateDirectory { .. } => {
                    Self::SignstarCommonAdminCredsCreateDirectory
                }
                signstar_common::admin_credentials::Error::DirChangeOwner { .. } => {
                    Self::SignstarCommonAdminCredsDirChangeOwner
                }
            },
            // utils related errors
            Error::Utils(error) => match error {
                crate::utils::Error::ExecutableNotFound { .. } => Self::UtilsExecutableNotFound,
                crate::utils::Error::MappingSystemUserGet(_) => Self::UtilsMappingSystemUserGet,
                crate::utils::Error::SystemUserData { .. } => Self::UtilsSystemUserData,
                crate::utils::Error::SystemUserLookup { .. } => Self::UtilsSystemUserLookup,
                crate::utils::Error::SystemUserMismatch { .. } => Self::UtilsSystemUserMismatch,
                crate::utils::Error::SystemUserNotRoot { .. } => Self::UtilsSystemUserNotRoot,
                crate::utils::Error::SystemUserRoot => Self::UtilsSystemUserRoot,
            },
            // top-level errors and their exit codes
            Error::ApplyPermissions { .. } => Self::ApplyPermissions,
            Error::CommandAttachToStdin { .. } => Self::CommandAttachToStdin,
            Error::Chown { .. } => Self::Chown,
            Error::CommandBackground { .. } => Self::CommandBackground,
            Error::CommandExec { .. } => Self::CommandExec,
            Error::CommandNonZero { .. } => Self::CommandNonZero,
            Error::Thread { .. } => Self::Thread,
            Error::Utf8String { .. } => Self::Utf8String,
            Error::CommandWriteToStdin { .. } => Self::CommandWriteToStdin,
        }
    }
}

impl From<ErrorExitCode> for ExitCode {
    fn from(value: ErrorExitCode) -> Self {
        Self::from(std::convert::Into::<u8>::into(value))
    }
}

impl From<ErrorExitCode> for i32 {
    fn from(value: ErrorExitCode) -> Self {
        Self::from(std::convert::Into::<u8>::into(value))
    }
}
