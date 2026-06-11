//! Provisioning scenarios.

#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::{
    Credentials,
    automation::Command,
    automation::command::{AuthenticatedCommandChain, FileBackedAuthenticatedCommandChain},
};

/// A list of authenticated chains of commands executed against a YubiHSM2.
///
/// Each chain of commands is authenticated using in-memory credentials.
#[derive(Debug)]
pub struct Scenario(Vec<AuthenticatedCommandChain>);

impl AsRef<[AuthenticatedCommandChain]> for Scenario {
    fn as_ref(&self) -> &[AuthenticatedCommandChain] {
        self.0.as_slice()
    }
}

/// A list of authenticated chains of commands executed against a YubiHSM2.
///
/// Each chain of commands is authenticated using file-backed credentials.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct FileBackedScenario(Vec<FileBackedAuthenticatedCommandChain>);

impl AsRef<[FileBackedAuthenticatedCommandChain]> for FileBackedScenario {
    fn as_ref(&self) -> &[FileBackedAuthenticatedCommandChain] {
        self.0.as_slice()
    }
}

impl TryFrom<&FileBackedScenario> for Scenario {
    type Error = crate::Error;

    fn try_from(value: &FileBackedScenario) -> Result<Self, Self::Error> {
        let mut output = Vec::new();

        for authenticated_command_chain in value.0.iter() {
            let creds = Credentials::try_from(&authenticated_command_chain.auth)?;
            let commands = {
                let mut commands = Vec::new();
                for file_backed_command in authenticated_command_chain.commands.iter() {
                    commands.push(Command::try_from(file_backed_command)?);
                }
                commands
            };
            output.push(AuthenticatedCommandChain::new(creds, commands));
        }

        Ok(Self(output))
    }
}
