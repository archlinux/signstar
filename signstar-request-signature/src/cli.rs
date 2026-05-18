//! Command line interface.

use std::path::PathBuf;

use clap::Parser;
use clap_verbosity_flag::Verbosity;

use crate::ssh::client::CONFIG_ORDER;

/// Command line arguments for signing.
#[derive(Debug, Parser)]
pub struct Cli {
    /// Global processing log verbosity.
    #[command(flatten)]
    pub verbosity: Verbosity,

    /// Command to be executed.
    #[command(subcommand)]
    pub command: Command,
}

/// Command line arguments for signing.
#[derive(Debug, Parser)]
pub enum Command {
    /// Prepare signing request for a file.
    Prepare(PrepareCommand),

    /// Send signing request over SSH.
    Send(SendCommand),
}

/// Signing request input parameters.
#[derive(Debug, Parser)]
pub struct PrepareCommand {
    /// The path to a file being signed
    #[arg(env = "SIGNSTAR_REQUEST_FILE")]
    pub input: PathBuf,
}

/// Sending signing request input parameters.
#[derive(Debug, Parser)]
pub struct SendCommand {
    /// Configuration file to use.
    #[arg(long, env = "SIGNSTAR_REQUEST_CONFIG", long_help = format!("Configuration file to use.

If unspecified, one of the following configuration files is used if it exists, in the following order:

{paths}", paths = CONFIG_ORDER.iter().map(|path| format!("- {path}")).collect::<Vec<_>>().join("\n")))]
    pub config: Option<PathBuf>,

    /// The user to use for connecting.
    ///
    /// If this option is set only connections with matching username are considered.
    #[arg(long)]
    pub user: Option<String>,

    /// The path to a file being signed
    #[arg(env = "SIGNSTAR_REQUEST_FILE")]
    pub input: PathBuf,
}
