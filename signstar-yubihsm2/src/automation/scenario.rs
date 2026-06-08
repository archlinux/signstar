//! Provisioning scenarios.

#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::{
    Credentials,
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

impl TryFrom<FileBackedScenario> for Scenario {
    type Error = crate::Error;

    fn try_from(value: FileBackedScenario) -> Result<Self, Self::Error> {
        let mut output = Vec::new();

        for commands in value.0 {
            let creds = Credentials::try_from(&commands.auth)?;
            output.push(AuthenticatedCommandChain::new(creds, commands.commands));
        }

        Ok(Self(output))
    }
}
