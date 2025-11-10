use chrono::{DateTime, Utc};
use clap::Parser;
use expression_format::ex_format;
use nethsm::SystemState::Unprovisioned;

use crate::passphrase_file::PassphraseFile;

/// The "nethsm provision" command.
#[derive(Debug, Parser)]
#[command(
    about = "Provision a device",
    long_about = ex_format!("Provision a device

Does initial provisioning of a device in state \"{Unprovisioned}\" by setting unlock passphrase, admin passphrase and system time.
If none of the values are provided, the passwords are prompted for interactively, while the caller's system time is used to derive the current timestamp.

Requires no authentication.")
)]
pub struct ProvisionCommand {
    /// The optional path to a file containing an admin passphrase.
    #[arg(
        env = "NETHSM_ADMIN_PASSPHRASE_FILE",
        help = "The path to a file containing the admin passphrase",
        long_help = "The path to a file containing the admin passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short = 'A'
    )]
    pub admin_passphrase_file: Option<PassphraseFile>,

    /// The optional system time to use.
    #[arg(
        env = "NETHSM_SYSTEM_TIME",
        help = "The initial system time for the device",
        long_help = "The initial system time for the device

Must be provided as an ISO 8601 formatted UTC timestamp.",
        long,
        short
    )]
    pub system_time: Option<DateTime<Utc>>,

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
