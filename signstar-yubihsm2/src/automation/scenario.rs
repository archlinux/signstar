//! Provisioning scenarios.

use serde::Deserialize;

use crate::automation::{Auth, Command};

/// Describes a series of commands to be executed against a YubiHSM2.
///
/// The `auth` parameter indicates initial authentication data.
/// The set of commands to be executed is processed in a sequential manner.
/// The additional [Auth] command may be used to re-authenticate as another user while executing the
/// scenario.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Scenario {
    /// Initial authentication data required to establish the connection to a YubiHSM2.
    pub auth: Auth,

    /// Commands to be executed.
    pub steps: Vec<Command>,
}
