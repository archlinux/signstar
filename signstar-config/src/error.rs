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
        path: PathBuf,
        mode: u32,
        source: std::io::Error,
    },

    /// Unable to attach to stdin of a command.
    #[error("Unable to attach to stdin of command \"{command}\"")]
    AttachToStdin { command: String },

    /// The ownership of a path can not be changed.
    #[error("Changing ownership of {path} to user {user} failed:\n{source}")]
    Chown {
        path: PathBuf,
        user: String,
        source: std::io::Error,
    },

    /// A command exited unsuccessfully.
    #[error("The command \"{command}\" could not be started in the background:\n{source}")]
    CommandBackground {
        command: String,
        source: std::io::Error,
    },

    /// A command exited unsuccessfully.
    #[error("The command \"{command}\" could not be executed:\n{source}")]
    CommandExec {
        command: String,
        source: std::io::Error,
    },

    /// A command exited unsuccessfully.
    #[error(
        "The command \"{command}\" exited with non-zero status code \"{exit_status}\":\nstderr:\n{stderr}"
    )]
    CommandNonZero {
        command: String,
        exit_status: ExitStatus,
        stderr: String,
    },

    /// Configuration errors.
    #[error("Signstar config error:\n{0}")]
    Config(#[from] crate::config::Error),

    /// An error specific to non-administrative secret handling.
    #[error("Error with non-administrative secret handling:\n{0}")]
    NonAdminSecretHandling(#[from] crate::non_admin_credentials::Error),

    /// Low-level administrative credentials handling in signstar-common failed.
    #[error("Handling of administrative credentials failed:\n{0}")]
    SignstarCommonAdminCreds(#[from] signstar_common::admin_credentials::Error),

    /// Joining a thread returned an error.
    #[error("Thread error while {context}")]
    Thread { context: String },

    /// A UTF-8 error occurred when trying to convert a byte vector to a string.
    #[error("Converting contents of {path} to string ({context}) failed:\n{source}")]
    Utf8String {
        path: PathBuf,
        context: String,
        source: FromUtf8Error,
    },

    /// A utility function returned an error.
    #[error("Utility function error: {0}")]
    Utils(#[from] crate::utils::Error),

    /// Unable to write to stdin of a command.
    #[error("Unable to write to stdin of command \"{command}\"")]
    WriteToStdin {
        command: String,
        source: std::io::Error,
    },
}

#[derive(Clone, Copy, Debug, num_enum::IntoPrimitive, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ErrorExitCode {
    AdminCredentialsConfigFromToml = 100,
    AdminCredentialsConfigLoad = 101,
    AdminCredentialsConfigStore = 102,
    AdminCredentialsConfigToToml = 103,
    AdminCredentialsCredsFileCreate = 104,
    AdminCredentialsCredsFileMissing = 105,
    AdminCredentialsCredsFileNotAFile = 106,
    AdminCredentialsCredsFileWrite = 107,
    ApplyPermissions = 10,
    AttachToStdin = 11,
    Chown = 12,
    CommandBackground = 13,
    CommandExec = 14,
    CommandNonZero = 15,
    ConfigConfigMissing = 120,
    ConfigNetHsmConfig = 121,
    NonAdminCredentialsCredentialsLoading = 140,
    NonAdminCredentialsCredentialsMissing = 141,
    NonAdminCredentialsNoSystemUser = 142,
    NonAdminCredentialsNotSigningUser = 143,
    NonAdminCredentialsSecretsDirCreate = 144,
    NonAdminCredentialsSecretsFileCreate = 145,
    NonAdminCredentialsSecretsFileMetadata = 146,
    NonAdminCredentialsSecretsFileMissing = 147,
    NonAdminCredentialsSecretsFileNotAFile = 148,
    NonAdminCredentialsSecretsFilePermissions = 149,
    NonAdminCredentialsSecretsFileRead = 150,
    NonAdminCredentialsSecretsFileWrite = 151,
    SignstarCommonAdminCredsApplyPermissions = 170,
    SignstarCommonAdminCredsCreateDirectory = 171,
    SignstarCommonAdminCredsDirChangeOwner = 172,
    Thread = 16,
    Utf8String = 17,
    UtilsExecutableNotFound = 190,
    UtilsSystemUserLookup = 191,
    UtilsMappingSystemUserGet = 192,
    UtilsSystemUserData = 193,
    UtilsSystemUserMismatch = 194,
    UtilsSystemUserNotRoot = 195,
    UtilsSystemUserRoot = 196,
    WriteToStdin = 18,
}

impl From<Error> for ErrorExitCode {
    fn from(value: Error) -> Self {
        match value {
            // admin credentials related errors and their exit codes
            Error::AdminSecretHandling(error) => match error {
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
            },
            // config related errors
            Error::Config(error) => match error {
                crate::config::Error::ConfigMissing => Self::ConfigConfigMissing,
                crate::config::Error::NetHsmConfig(_) => Self::ConfigNetHsmConfig,
            },
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
            Error::AttachToStdin { .. } => Self::AttachToStdin,
            Error::Chown { .. } => Self::Chown,
            Error::CommandBackground { .. } => Self::CommandBackground,
            Error::CommandExec { .. } => Self::CommandExec,
            Error::CommandNonZero { .. } => Self::CommandNonZero,
            Error::Thread { .. } => Self::Thread,
            Error::Utf8String { .. } => Self::Utf8String,
            Error::WriteToStdin { .. } => Self::WriteToStdin,
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
