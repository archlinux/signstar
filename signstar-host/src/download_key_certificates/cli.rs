//! Command line interface for `signstar-download-key-certificates`.

use clap::Parser;
use clap_verbosity_flag::Verbosity;

/// Command line arguments for certificate retrieval.
#[derive(Debug, Parser)]
#[command(
    about = "Return certificates of signing keys as structured data.",
    name = "signstar-download-key-certificates",
    version
)]
pub struct Cli {
    /// Global processing log verbosity.
    #[command(flatten)]
    pub verbosity: Verbosity,
}
