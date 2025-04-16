//! Common errors.

use std::process::ExitStatus;

/// An error that may occur when using Signstar config.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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

    /// An executable that is supposed to be called, is not found.
    #[error("Unable to to find executable \"{command}\"")]
    ExecutableNotFound {
        /// The executable that could not be found.
        command: String,
        /// The source error.
        source: which::Error,
    },
}
