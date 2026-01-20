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
    Config(#[from] crate::ConfigError),

    /// An I/O error occurred for a file.
    #[error("I/O error for file {path} while {context}: {source}")]
    IoPath {
        /// The path to the file for which the error occurred.
        path: PathBuf,
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence "I/O error for file {path} while ".
        context: &'static str,
        /// The error source.
        source: std::io::Error,
    },

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

    /// A [`signstar_crypto::Error`] occurred.
    #[error(transparent)]
    SignstarCrypto(#[from] signstar_crypto::Error),

    /// Joining a thread returned an error.
    #[error("Thread error while {context}")]
    Thread {
        /// The context in which the failed thread ran.
        ///
        /// Should complete the sentence "Thread error while ".
        context: String,
    },

    /// TOML error while reading a file.
    #[error("TOML read error for file {path} while {context}: {source}")]
    TomlRead {
        /// The path to a file that fails to read.
        path: PathBuf,
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence " error for file {path} while ".
        context: &'static str,
        /// The error source.
        source: Box<toml::de::Error>,
    },

    /// TOML error while writing a file.
    #[error("TOML write error for file {path} while {context}: {source}")]
    TomlWrite {
        /// The path to a file that fails to read.
        path: PathBuf,
        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence " error for file {path} while ".
        context: &'static str,
        /// The error source.
        source: toml::ser::Error,
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

    /// A garde validation error occurred.
    #[error("Validation error while {context}: {source}")]
    Validation {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Validation error while ".
        context: String,

        /// The error source.
        source: garde::Report,
    },

    /// A NetHSM configuration object error occurred.
    #[error("NetHSM configuration object error: {0}")]
    NetHsmConfig(#[from] crate::nethsm::NetHsmConfigError),
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

    /// Mapping for [`crate::admin_credentials::Error::CredsFileCreate`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileCreate = 102,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileMissing`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileMissing = 103,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileNotAFile`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileNotAFile = 104,

    /// Mapping for [`crate::admin_credentials::Error::CredsFileWrite`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsCredsFileWrite = 105,

    /// Mapping for [`crate::admin_credentials::Error::PassphraseTooShort`] wrapped in
    /// [`Error::AdminSecretHandling`].
    AdminCredentialsPassphraseTooShort = 106,

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

    /// Mapping for [`crate::ConfigError::ConfigIsMissing`] wrapped in [`Error::Config`].
    ConfigConfigMissing = 120,

    /// Mapping for [`crate::ConfigError::DuplicateNetHsmUserId`] wrapped in
    /// [`Error::Config`].
    ConfigDuplicateNetHsmUserId = 121,

    /// Mapping for [`crate::ConfigError::DuplicateSshPublicKey`] wrapped in
    /// [`Error::Config`].
    ConfigDuplicateSshPublicKey = 122,

    /// Mapping for [`crate::ConfigError::DuplicateKeyId`] wrapped in [`Error::Config`].
    ConfigDuplicateKeyId = 123,

    /// Mapping for [`crate::ConfigError::DuplicateSystemUserId`] wrapped in
    /// [`Error::Config`].
    ConfigDuplicateSystemUserId = 124,

    /// Mapping for [`crate::ConfigError::DuplicateTag`] wrapped in [`Error::Config`].
    ConfigDuplicateTag = 125,

    /// Mapping for [`crate::ConfigError::InvalidSystemUserName`] wrapped in
    /// [`Error::Config`].
    ConfigInvalidSystemUserName = 126,

    /// Mapping for [`crate::ConfigError::InvalidAuthorizedKeyEntry`] wrapped in
    /// [`Error::Config`].
    ConfigInvalidAuthorizedKeyEntry = 127,

    /// Mapping for [`crate::ConfigError::MetricsAlsoOperator`] wrapped in
    /// [`Error::Config`].
    ConfigMetricsAlsoOperator = 128,

    /// Mapping for [`crate::ConfigError::MissingAdministrator`] wrapped in
    /// [`Error::Config`].
    ConfigMissingAdministrator = 129,

    /// Mapping for [`crate::ConfigError::MissingShareDownloadSystemUser`] wrapped in
    /// [`Error::Config`].
    ConfigMissingShareDownloadSystemUser = 130,

    /// Mapping for [`crate::ConfigError::MissingShareUploadSystemUser`] wrapped in
    /// [`Error::Config`].
    ConfigMissingShareUploadSystemUser = 131,

    /// Mapping for [`crate::ConfigError::NoAuthorizedKeys`] wrapped in [`Error::Config`].
    ConfigNoAuthorizedKeys = 132,

    /// Mapping for [`crate::ConfigError::NoMatchingMappingForSystemUser`] wrapped in
    /// [`Error::Config`].
    ConfigNoMatchingMappingForSystemUser = 133,

    /// Mapping for [`crate::ConfigError::NoSssButShareUsers`] wrapped in [`Error::Config`].
    ConfigNoSssButShareUsers = 134,

    /// Mapping for [`crate::ConfigError::SshKey`] wrapped in [`Error::Config`].
    ConfigSshKey = 135,

    /// Mapping for [`crate::ConfigError::User`] wrapped in [`Error::Config`].
    ConfigUser = 136,

    /// Mapping for [`crate::Error::NetHsm`].
    IoPath = 17,

    /// Mapping for [`crate::Error::NetHsm`].
    NetHsm = 18,

    /// Mapping for [`crate::Error::NetHsmBackend`].
    NetHsmBackend = 19,

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

    /// Mapping for [`Error::SignstarCrypto`]
    SignstarCrypto = 20,

    /// Mapping for [`Error::Thread`].
    Thread = 21,

    /// Mapping for [`Error::TomlRead`].
    TomlRead = 22,

    /// Mapping for [`Error::TomlWrite`].
    TomlWrite = 23,

    /// Mapping for [`Error::Utf8String`].
    Utf8String = 24,

    /// Mapping for [`Error::Validation`].
    Validation = 25,

    /// Mapping for [`Error::NetHsmConfig`].
    NetHsmConfig = 26,

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
                crate::ConfigError::ConfigIsMissing => Self::ConfigConfigMissing,
                crate::ConfigError::DuplicateNetHsmUserId { .. } => {
                    Self::ConfigDuplicateNetHsmUserId
                }
                crate::ConfigError::DuplicateSshPublicKey { .. } => {
                    Self::ConfigDuplicateSshPublicKey
                }
                crate::ConfigError::DuplicateKeyId { .. } => Self::ConfigDuplicateKeyId,
                crate::ConfigError::DuplicateSystemUserId { .. } => {
                    Self::ConfigDuplicateSystemUserId
                }
                crate::ConfigError::DuplicateTag { .. } => Self::ConfigDuplicateTag,
                crate::ConfigError::InvalidSystemUserName { .. } => {
                    Self::ConfigInvalidSystemUserName
                }
                crate::ConfigError::InvalidAuthorizedKeyEntry { .. } => {
                    Self::ConfigInvalidAuthorizedKeyEntry
                }
                crate::ConfigError::MetricsAlsoOperator { .. } => Self::ConfigMetricsAlsoOperator,
                crate::ConfigError::MissingAdministrator { .. } => Self::ConfigMissingAdministrator,
                crate::ConfigError::MissingShareDownloadSystemUser => {
                    Self::ConfigMissingShareDownloadSystemUser
                }
                crate::ConfigError::MissingShareUploadSystemUser => {
                    Self::ConfigMissingShareUploadSystemUser
                }
                crate::ConfigError::NoAuthorizedKeys => Self::ConfigNoAuthorizedKeys,
                crate::ConfigError::NoMatchingMappingForSystemUser { .. } => {
                    Self::ConfigNoMatchingMappingForSystemUser
                }
                crate::ConfigError::NoSssButShareUsers { .. } => Self::ConfigNoSssButShareUsers,
                crate::ConfigError::SshKey(_) => Self::ConfigSshKey,
                crate::ConfigError::User(_) => Self::ConfigUser,
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
            Error::CommandWriteToStdin { .. } => Self::CommandWriteToStdin,
            Error::IoPath { .. } => Self::IoPath,
            Error::SignstarCrypto { .. } => Self::SignstarCrypto,
            Error::Thread { .. } => Self::Thread,
            Error::TomlRead { .. } => Self::TomlRead,
            Error::TomlWrite { .. } => Self::TomlWrite,
            Error::Utf8String { .. } => Self::Utf8String,
            Error::Validation { .. } => Self::Validation,
            Error::NetHsmConfig { .. } => Self::NetHsmConfig,
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
