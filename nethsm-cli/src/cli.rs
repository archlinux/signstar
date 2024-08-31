use std::path::PathBuf;

use clap::Parser;
pub use config::{ConfigCommand, ConfigGetCommand, ConfigSetCommand};
pub use env::{EnvAddCommand, EnvCommand, EnvDeleteCommand};
pub use health::HealthCommand;
pub use info::InfoCommand;
pub use key::{KeyCertCommand, KeyCommand};
pub use lock::LockCommand;
pub use metrics::MetricsCommand;
pub use namespace::NamespaceCommand;
use nethsm::UserId;
pub use openpgp::OpenPgpCommand;
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
mod namespace;
mod openpgp;
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
#[command(name = "nethsm")]
pub struct Cli {
    #[arg(
        env = "NETHSM_AUTH_PASSPHRASE_FILE",
        global = true,
        help = "The path to a file containing a passphrase for authentication",
        long_help = "The path to a file containing a passphrase for authentication

The passphrase provided in the file must be the one for the user chosen for the command.

This option can be provided multiple times, which is needed for commands that require multiple roles at once.
With multiple passphrase files ordering matters, as the files are assigned to the respective user provided by the \"--user\" option.",
        long,
        short
    )]
    pub auth_passphrase_file: Vec<PassphraseFile>,

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
Must be provided, if several user names of the same target role are setup in the configuration file for a device.

This option can be provided multiple times, which is needed for commands that require multiple roles at once.
",
        long,
        short
    )]
    pub user: Vec<UserId>,

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

    #[command(subcommand)]
    Namespace(NamespaceCommand),

    #[command(subcommand, name = "openpgp")]
    OpenPgp(OpenPgpCommand),

    Provision(ProvisionCommand),

    Random(RandomCommand),

    #[command(subcommand)]
    System(SystemCommand),

    Unlock(UnlockCommand),

    #[command(subcommand)]
    User(UserCommand),
}
