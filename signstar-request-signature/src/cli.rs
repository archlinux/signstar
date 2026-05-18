//! Command line interface.

use std::path::PathBuf;

use clap::Parser;
use clap_verbosity_flag::Verbosity;

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
    #[arg(long)]
    pub config: PathBuf,

    /// The path to a file being signed
    #[arg(env = "SIGNSTAR_REQUEST_FILE")]
    pub input: PathBuf,
}
