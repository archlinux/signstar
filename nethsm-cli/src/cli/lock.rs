use clap::Parser;
use nethsm::{SystemState, UserRole};

#[derive(Debug, Parser)]
#[command(
    about = "Lock a device",
    long_about = format!("Lock a device

After locking, the target device is in state \"{:?}\" and the unlock passphrase needs to be provided to return to state \"{:?}\".

Requires authentication of a system-wide user in the \"{}\" role.",
        SystemState::Locked,
        SystemState::Operational,
        UserRole::Administrator,
    ),
)]
pub struct LockCommand;
