//! Command line interface for `signstar-download-key-certificates`.

use clap::Parser;
use clap_verbosity_flag::Verbosity;

/// Command line arguments for certificate retrieval.
#[derive(Debug, Parser)]
#[command(about = "Print stored key certificates as structured data.")]
pub struct Cli {
    /// Global processing log verbosity.
    #[command(flatten)]
    pub verbosity: Verbosity,
}
