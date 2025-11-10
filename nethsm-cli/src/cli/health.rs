use clap::{Parser, Subcommand};
use expression_format::ex_format;
use nethsm::SystemState::{Locked, Operational, Unprovisioned};

/// The "netshm health" command.
#[derive(Debug, Subcommand)]
#[command(
    about = "Retrieve health information for a device",
    long_about = "Retrieve health information for a device

Retrieve alive, ready and state information."
)]
pub enum HealthCommand {
    /// The "netshm health alive" command.
    Alive(AliveCommand),
    /// The "netshm health ready" command.
    Ready(ReadyCommand),
    /// The "netshm health state" command.
    State(StateCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Check whether a device is in locked or unprovisioned state",
    long_about = ex_format!("Check whether a device is in locked or unprovisioned state

Returns an error if the target device is not in state \"{Locked}\" or \"{Unprovisioned}\".

Requires no authentication."
    )
)]
pub struct AliveCommand;

#[derive(Debug, Parser)]
#[command(
    about = "Check whether a device is in operational state",
    long_about = ex_format!("Check whether a device is in operational state

Returns an error if the target device is not state \"{Operational}\".

Requires no authentication.")
)]
pub struct ReadyCommand;

#[derive(Debug, Parser)]
#[command(
    about = "Retrieve the state for a device",
    long_about = ex_format!("Retrieve the state for a device

* \"{Operational}\" if the target device is in operational state
* \"{Locked}\" if the target device is locked
* \"{Unprovisioned}\" if the target device is not yet provisioned

Requires no authentication.")
)]
pub struct StateCommand;
