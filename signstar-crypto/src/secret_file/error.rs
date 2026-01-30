//! Error type for secret file writing and reading.

use std::{path::PathBuf, process::ExitStatus, string::FromUtf8Error};

use signstar_common::common::SECRET_FILE_MODE;

/// An error that may occur when working with cryptographic types for Signstar.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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

    /// An I/O error occurred at a path.
    #[error("I/O error at {path} while {context}: {source}")]
    IoPath {
        /// The path to the file for which the error occurred.
        path: PathBuf,

        /// The context in which the error occurs.
        ///
        /// This is meant to complete the sentence "I/O error at path {path} while ".
        context: &'static str,

        /// The error source.
        source: std::io::Error,
    },

    /// The current user is an unprivileged user, but should be root.
    #[error("Not running as root while {context}")]
    NotRunningAsRoot {
        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Not running as root while ".
        context: String,
    },

    /// The current user is root, but should be an unprivileged user.
    #[error("Running as root instead of user {target_user} while {context}")]
    RunningAsRoot {
        /// The unprivileged system user which should have been used instead.
        target_user: String,

        /// The context in which the error occurred.
        ///
        /// This is meant to complete the sentence "Running as root instead of user {target_user}
        /// while ".
        context: String,
    },

    /// A passphrase directory can not be created.
    #[error("Passphrase directory {path} for user {system_user} can not be created:\n{source}")]
    SecretsDirCreate {
        /// The path to a secrets directory that could not be created.
        path: PathBuf,
        /// The system user in whose home directory `path` could not be created.
        system_user: String,
        /// The source error.
        source: std::io::Error,
    },

    /// A secrets file can not be created.
    #[error("The secrets file {path} can not be created for user {system_user}:\n{source}")]
    SecretsFileCreate {
        /// The path to a secrets file that could not be created.
        path: PathBuf,
        /// The system user in whose home directory `path` could not be created.
        system_user: String,
        /// The source error.
        source: std::io::Error,
    },

    /// The file metadata of a secrets file cannot be retrieved.
    #[error("File metadata of secrets file {path} cannot be retrieved")]
    SecretsFileMetadata {
        /// The path to a secrets file for which metadata could not be retrieved.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },

    /// A secrets file does not exist.
    #[error("Secrets file not found: {path}")]
    SecretsFileMissing {
        /// The path to a secrets file that is missing.
        path: PathBuf,
    },

    /// A secrets file is not a file.
    #[error("Secrets file is not a file: {path}")]
    SecretsFileNotAFile {
        /// The path to a secrets file that is not a file.
        path: PathBuf,
    },

    /// A secrets file does not have the correct permissions.
    #[error("Secrets file {path} has permissions {mode}, but {SECRET_FILE_MODE} is required")]
    SecretsFilePermissions {
        /// The path to a secrets file for which permissions could not be set.
        path: PathBuf,
        /// The file mode that should be applied to the file at `path`.
        mode: u32,
    },

    /// A secrets file cannot be read.
    #[error("Failed reading secrets file {path}:\n{source}")]
    SecretsFileRead {
        /// The path to a secrets file that could not be read.
        path: PathBuf,
        /// The source error.
        source: std::io::Error,
    },

    /// A secrets file can not be written to.
    #[error("The secrets file {path} can not be written to for user {system_user}: {source}")]
    SecretsFileWrite {
        /// The path to a secrets file that could not be written to.
        path: PathBuf,
        /// The system user in whose home directory `path` resides.
        system_user: String,
        /// The source error.
        source: std::io::Error,
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
}
