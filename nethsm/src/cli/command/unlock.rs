use clap::Parser;
use expression_format::ex_format;

use crate::{SystemState::Locked, UserRole::Administrator, cli::PassphraseFile};

/// The "nethsm unlock" command.
#[derive(Debug, Parser)]
#[command(
    about = "Unlock a device",
    long_about = ex_format!("Unlock a device using the unlock passphrase

The device must be in state \"{Locked}\".

If no passphrase is provided it is prompted for interactively.

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UnlockCommand {
    /// The optional path to a file containing the unlock passphrase.
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
