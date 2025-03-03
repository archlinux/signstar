//! Command line interface.

use std::path::PathBuf;

use clap::Parser;

/// Command line arguments for signing.
#[derive(Debug, Parser)]
pub enum Cli {
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
    /// Signstar host.
    #[arg(long)]
    pub host: String,

    /// Signstar port.
    #[clap(default_value_t = 22)]
    #[arg(long)]
    pub port: u16,

    /// Signstar user.
    #[arg(long)]
    pub user: String,

    /// Path to the agent socket used for user authentication.
    #[arg(long)]
    pub agent_socket: PathBuf,

    /// Public key of a user.
    #[arg(long)]
    pub user_public_key: String,

    /// Path of a known hosts file which contains public keys of the serevr.
    #[arg(long)]
    pub known_hosts: PathBuf,

    /// The path to a file being signed
    #[arg(env = "SIGNSTAR_REQUEST_FILE")]
    pub input: PathBuf,
}
