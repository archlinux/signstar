//! Error handling for automation actions.

use std::fmt::Display;

use crate::automation::command::CommandName;

/// A mismatch between a file backed scenario and its return value.
///
/// The mismatch is based on the [`CommandName`] used by the file backed scenario and the return
/// value.
#[derive(Debug)]
pub struct FileBackedScenarioReturnValueMismatch {
    /// The command name of the file backed scenario.
    pub(crate) file_backed_scenario_command: CommandName,

    /// The command name of the return value.
    pub(crate) command_return_value: CommandName,
}

impl Display for FileBackedScenarioReturnValueMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} -> {}",
            self.file_backed_scenario_command, self.command_return_value
        )
    }
}

/// The error that may occur when automating actions against a YubiHSM2 device.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// There are mismatches between commands in a file backed scenario and command return values.
    #[error(
        "Mismatches between commands in file backed scenarios and the collected return values exist:\n{}",
        mismatches
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n")
    )]
    MismatchingReturnValueForFileBackedScenario {
        /// The mismatches between file backed scenarios and their respective return values.
        mismatches: Vec<FileBackedScenarioReturnValueMismatch>,
    },

    /// The number of authenticated command chains differ in a scenario and scenario return value.
    #[error(
        "The scenario tracks {scenario} authenticated command chains and the scenario return value {scenario_return_value}"
    )]
    MismatchingNumberOfAuthenticatedCommandChains {
        /// The number of authenticated command chains in a scenario.
        scenario: usize,

        /// The number of authenticated command chains in a scenario return values.
        scenario_return_value: usize,
    },

    /// The number of commands in an authenticated command chain differ from those in a list of
    /// command return values.
    #[error(
        "The authenticated command chain tracks {authenticated_command_chain} commands while the list of command return values is {command_return_values}"
    )]
    MismatchingNumberOfCommands {
        /// The number of commands in an authenticated command chain.
        authenticated_command_chain: usize,

        /// The number of authenticated command chains in a scenario return values.
        command_return_values: usize,
    },
}
