use clap::Parser;
use nethsm::{SystemState, UserRole};

use crate::passphrase_file::PassphraseFile;

#[derive(Debug, Parser)]
#[command(
    about = "Unlock a device",
    long_about = format!("Unlock a device using the unlock passphrase

The device must be in state \"{:?}\".

If no passphrase is provided it is prompted for interactively.

Requires authentication of a user in the \"{}\" role.", SystemState::Locked, UserRole::Administrator),
)]
pub struct UnlockCommand {
    #[arg(
        env = "NETHSM_UNLOCK_PASSPHRASE_FILE",
        help = "The path to a file containing the unlock passphrase",
        long_help = "The path to a file containing the unlock passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short = 'U'
    )]
    pub unlock_passphrase_file: Option<PassphraseFile>,
}
