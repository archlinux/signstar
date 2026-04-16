//! Common, top-level error type for all components of signstar-config.

use std::{path::PathBuf, process::ExitStatus, string::FromUtf8Error};

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
    #[cfg(feature = "nethsm")]
    #[error("NetHSM error:\n{0}")]
    NetHsm(#[from] nethsm::Error),

    /// A NetHSM backend error
    ///
    /// This variant is used when actions for a NetHSM backend fail.
    #[cfg(feature = "nethsm")]
    #[error("NetHSM backend error:\n{0}")]
    NetHsmBackend(#[from] crate::nethsm::Error),

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

    /// An error occurred when using a Signstar config trait.
    #[error(transparent)]
    Traits(#[from] crate::config::TraitsError),

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
    #[cfg(feature = "nethsm")]
    #[error("NetHSM configuration object error: {0}")]
    NetHsmConfig(#[from] crate::nethsm::NetHsmConfigError),

    /// A YubiHSM2 configuration object error occurred.
    #[cfg(feature = "yubihsm2")]
    #[error("YubiHSM2 configuration object error: {0}")]
    YubiHsm2Config(#[from] crate::yubihsm2::YubiHSM2ConfigError),
}
