//! Common, top-level error type for all components.

use std::{path::PathBuf, process::ExitStatus, string::FromUtf8Error};

/// An error that may occur when handling administrative credentials for a NetHSM backend.
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

    /// An error specific to NetHsm config handling.
    #[error("Error with NetHSM config handling:\n{0}")]
    NetHsmConfig(#[from] nethsm_config::Error),

    /// An error specific to non-administrative secret handling.
    #[error("Error with non-administrative secret handling:\n{0}")]
    NonAdminSecretHandling(#[from] crate::non_admin_credentials::Error),

    /// Low-level administrative credentials handling in signstar-common failed.
    #[error("Handling of administrative credentials failed:\n{0}")]
    SignstarCommonAdminCreds(#[from] signstar_common::admin_credentials::Error),

    #[error("Error with Signstar config handling:\n{0}")]
    SignstarConfig(#[from] crate::nethsm_config::Error),

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
