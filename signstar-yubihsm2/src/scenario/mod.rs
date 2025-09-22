//! Provisioning scenarios.

use serde::Deserialize;

use crate::command::{Auth, Command};

/// Describes a series of commands to be executed against a device.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Scenario {
    /// Authentication data.
    pub auth: Auth,

    /// Commands to be executed.
    pub steps: Vec<Command>,
}
