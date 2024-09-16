use clap::Parser;
use expression_format::ex_format;
use nethsm::{SystemState, UserRole};

#[derive(Debug, Parser)]
#[command(
    about = "Lock a device",
    long_about = ex_format!("Lock a device

After locking, the target device is in state \"{:?SystemState::Locked}\" and the unlock passphrase needs to be provided to return to state \"{:?SystemState::Operational}\".

Requires authentication of a system-wide user in the \"{UserRole::Administrator}\" role."),
)]
pub struct LockCommand;
