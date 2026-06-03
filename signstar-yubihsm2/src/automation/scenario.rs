//! Provisioning scenarios.

#[cfg(feature = "serde")]
use serde::Deserialize;

use crate::automation::command::AuthenticatedCommandChain;

/// A list of authenticated chains of commands executed against a YubiHSM2.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct Scenario(Vec<AuthenticatedCommandChain>);

impl AsRef<[AuthenticatedCommandChain]> for Scenario {
    fn as_ref(&self) -> &[AuthenticatedCommandChain] {
        self.0.as_slice()
    }
}
