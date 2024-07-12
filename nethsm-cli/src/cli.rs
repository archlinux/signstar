// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::path::PathBuf;

use clap::Parser;
pub use config::{ConfigCommand, ConfigGetCommand, ConfigSetCommand};
pub use env::{EnvAddCommand, EnvCommand, EnvDeleteCommand};
pub use health::HealthCommand;
pub use info::InfoCommand;
pub use key::{KeyCertCommand, KeyCommand};
pub use lock::LockCommand;
pub use metrics::MetricsCommand;
pub use provision::ProvisionCommand;
pub use random::RandomCommand;
pub use system::SystemCommand;
pub use unlock::UnlockCommand;
pub use user::UserCommand;

use crate::passphrase_file::PassphraseFile;

mod config;
mod env;
mod health;
mod info;
mod key;
mod lock;
mod metrics;
mod provision;
mod random;
mod system;
mod unlock;
mod user;

/// Errors related to the CLI
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An option is missing
    #[error("The \"{0}\" option must be provided for this command if more than one environment is defined.")]
    OptionMissing(String),
}

#[derive(Debug, Parser)]
pub struct Cli {
    #[arg(
        env = "NETHSM_AUTH_PASSPHRASE_FILE",
        global = true,
        help = "The path to a file containing a passphrase for authentication",
        long_help = "The path to a file containing a passphrase for authentication

The passphrase provided in the file must be the one for the user chosen for the command.",
        long,
        short
    )]
    pub auth_passphrase_file: Option<PassphraseFile>,

    #[arg(
        env = "NETHSM_CONFIG",
        global = true,
        help = "The path to a custom configuration file",
        long_help = "The path to a custom configuration file

If specified, the custom configuration file is used instead of the default configuration file location.",
        long,
        short
    )]
    pub config: Option<PathBuf>,

    #[arg(
        env = "NETHSM_LABEL",
        global = true,
        help = "A label uniquely identifying a device in the configuration file",
        long_help = "A label uniquely identifying a device in the configuration file

Must be provided if more than one device is setup in the configuration file.",
        long,
        short
    )]
    pub label: Option<String>,

    #[arg(
        env = "NETHSM_USER",
        global = true,
        help = "A user name which is used for the command",
        long_help = "A user name which is used for a command

Can be provided, if no user name is setup in the configuration file for a device.
Must be provided, if several user names of the same target role are setup in the configuration file for a device.",
        long,
        short
    )]
    pub user: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
#[command(about, author, version)]
pub enum Command {
    #[command(subcommand)]
    Config(ConfigCommand),

    #[command(subcommand)]
    Env(EnvCommand),

    #[command(subcommand)]
    Health(HealthCommand),

    Info(InfoCommand),

    #[command(subcommand)]
    Key(KeyCommand),

    Lock(LockCommand),

    Metrics(MetricsCommand),

    Provision(ProvisionCommand),

    Random(RandomCommand),

    #[command(subcommand)]
    System(SystemCommand),

    Unlock(UnlockCommand),

    #[command(subcommand)]
    User(UserCommand),
}