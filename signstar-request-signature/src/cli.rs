//! Command line interface.

use std::path::PathBuf;

use clap::Parser;

/// Command line arguments for signing.
#[derive(Debug, Parser)]
pub enum Cli {
    /// Prepare signing request for a file.
    Prepare(PrepareCommand),
}

/// Signing request input parameters.
#[derive(Debug, Parser)]
pub struct PrepareCommand {
    /// The path to a file being signed
    #[arg(env = "SIGNSTAR_REQUEST_FILE")]
    pub input: PathBuf,
}
