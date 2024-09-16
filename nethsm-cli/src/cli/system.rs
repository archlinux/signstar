use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use expression_format::ex_format;
use nethsm::{
    SystemState::{Locked, Operational, Unprovisioned},
    UserRole::{Administrator, Backup},
};

use super::BIN_NAME;
use crate::passphrase_file::PassphraseFile;

#[derive(Debug, Subcommand)]
#[command(about = "Do system actions for a device")]
pub enum SystemCommand {
    Backup(SystemBackupCommand),
    FactoryReset(SystemFactoryResetCommand),
    Info(SystemInfoCommand),
    Reboot(SystemRebootCommand),
    Restore(SystemRestoreCommand),
    Shutdown(SystemShutdownCommand),
    UploadUpdate(SystemUploadUpdateCommand),
    CancelUpdate(SystemCancelUpdateCommand),
    CommitUpdate(SystemCommitUpdateCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Backup the key store of a device",
    long_about = ex_format!("Backup the key store of a device

Writes an encrypted backup to a file in the current working directory, named after the device label in the configuration file and the current time.
Optionally, a specific output file can be provided.

Note: Requires setting the backup passphrase using \"{BIN_NAME} config set backup-passphrase\" first!

Requires authentication of a system-wide user in the \"{Backup}\" role.")
)]
pub struct SystemBackupCommand {
    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_BACKUP_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Reset the device to factory settings",
    long_about = ex_format!("Reset the device to factory settings

Triggers a factory reset for the device.

**WARNING**: This action deletes all user and system data! Make sure to create a backup using \"{BIN_NAME} system backup\" first!

Requires authentication of a system-wide user in the \"{Administrator}\" role.")
)]
pub struct SystemFactoryResetCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Retrieve system information of a device",
    long_about = ex_format!("Retrieve system information of a device

Provides information on software version, software build, firmware version, hardware version, device ID and information related to TPM and PCR.

Requires authentication of a system-wide user in the \"{Administrator}\" role.")
)]
pub struct SystemInfoCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Reboot the device",
    long_about = ex_format!("Reboot the device

Requires authentication of a user in the \"{Administrator}\" role.")
)]
pub struct SystemRebootCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Restore the device from a backup",
    long_about = ex_format!("Restore the device from a backup

The device may be in state \"{:?Operational}\" or \"{:?Unprovisioned}\".
In both cases, the users and keys from the backup replace those on the device (if any).

If the device is in state \"{:?Unprovisioned}\", any credentials provided for authentication are ignored, the system configuration
(e.g. TLS certificate, unlock passphrase, etc.) from the backup is used as well, the device is rebooted and ends up in
\"{:?Locked}\" state.

If no new system time is provided, it is derived from the caller's system time.
If no backup passphrase is provided specifically, it is prompted for interactively.

Requires authentication of a system-wide user in the \"{Administrator}\" role only if the device is in \"{:?Operational}\" state.")
)]
pub struct SystemRestoreCommand {
    #[arg(
        env = "NETHSM_BACKUP_FILE",
        help = "The path to a valid NetHSM backup file"
    )]
    pub input: PathBuf,

    #[arg(
        env = "NETHSM_BACKUP_PASSPHRASE_FILE",
        help = "The path to a file containing the backup passphrase",
        long,
        short
    )]
    pub backup_passphrase_file: Option<PassphraseFile>,

    #[arg(
        env = "NETHSM_SYSTEM_TIME",
        help = "The new system time for the device",
        long_help = "The new system time for the device

Must be provided as an ISO 8601 formatted UTC timestamp.",
        long,
        short
    )]
    pub system_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Shut down the device",
    long_about = ex_format!("Shut down the device

The device must be in state \"{:?Operational}\".

Requires authentication of a system-wide user in the \"{Administrator}\" role.")
)]
pub struct SystemShutdownCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Upload an update to the device",
    long_about = ex_format!("Upload an update to the device

Requires authentication of a user in the \"{Administrator}\" role.")
)]
pub struct SystemUploadUpdateCommand {
    #[arg(env = "NETHSM_UPDATE_FILE", help = "The path to an update file")]
    pub input: PathBuf,
}

#[derive(Debug, Parser)]
#[command(
    about = "Cancel an uploaded update on the device",
    long_about = ex_format!("Cancel an uploaded update on the device

The device must be in state \"{:?Operational}\" and an update file must have been uploaded first!

Requires authentication of a system-wide user in the \"{Administrator}\" role.")
)]
pub struct SystemCancelUpdateCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Commit an uploaded update on the device",
    long_about = ex_format!("Commit an uploaded update on the device

The device must be in state \"{:?Operational}\" and an update file must have been uploaded first!

Requires authentication of a system-wide user in the \"{Administrator}\" role.")
)]
pub struct SystemCommitUpdateCommand {}
