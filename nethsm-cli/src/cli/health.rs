use clap::{Parser, Subcommand};
use nethsm::SystemState;

#[derive(Debug, Subcommand)]
#[command(
    about = "Retrieve health information for a device",
    long_about = "Retrieve health information for a device

Retrieve alive, ready and state information."
)]
pub enum HealthCommand {
    Alive(AliveCommand),
    Ready(ReadyCommand),
    State(StateCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Check whether a device is in locked or unprovisioned state",
    long_about = format!("Check whether a device is in locked or unprovisioned state

Returns an error if the target device is not in state \"{:?}\" or \"{:?}\".

Requires no authentication.",
        SystemState::Locked,
        SystemState::Unprovisioned,
    )
)]
pub struct AliveCommand;

#[derive(Debug, Parser)]
#[command(
    about = "Check whether a device is in operational state",
    long_about = format!("Check whether a device is in operational state

Returns an error if the target device is not state \"{:?}\".

Requires no authentication.", SystemState::Operational)
)]
pub struct ReadyCommand;

#[derive(Debug, Parser)]
#[command(
    about = "Retrieve the state for a device",
    long_about = format!("Retrieve the state for a device

* \"{:?}\" if the target device is in operational state
* \"{:?}\" if the target device is locked
* \"{:?}\" if the target device is not yet provisioned

Requires no authentication.",
        SystemState::Operational,
        SystemState::Locked,
        SystemState::Unprovisioned,
    )
)]
pub struct StateCommand;
