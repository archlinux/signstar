//! Command line interface.

use std::path::PathBuf;

use clap::Parser;

/// Command line arguments for signing.
#[derive(Debug, Parser)]
pub struct Cli {
    /// The path to a file being signed
    #[arg(env = "SIGNSTAR_REQUEST_FILE")]
    pub input: PathBuf,
}
