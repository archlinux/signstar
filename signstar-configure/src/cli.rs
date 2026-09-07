//! Command line interface for `signstar-configure`.

use clap::Parser;
use clap_verbosity_flag::Verbosity;

/// Command line arguments for configuring Signstar hosts.
#[derive(Debug, Parser)]
#[command(
    about = "Configure a Signstar host and its HSM backends.",
    long_about = "Configure a Signstar host and its HSM backends.

Reads the Signstar configuration file of the current system.
Afterwards attempts to synchronize the state of all available HSM backends with that of the configuration file.

Returns a non-zero exit code and an error message on stderr if any of the above fails.
"
)]
pub struct Cli {
    /// Global processing log verbosity.
    #[command(flatten)]
    pub verbosity: Verbosity,
}
