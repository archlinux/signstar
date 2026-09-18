//! Command line interface for `signstar-sign`.

use clap::Parser;
use clap_verbosity_flag::Verbosity;

/// Command line arguments for signing.
#[derive(Debug, Parser)]
#[command(
    about = "Sign a signing request and return it as structured data.",
    long_about = "Sign a signing request and return it as structured data.

Signing requests, following the request specification, are accepted on `stdin`:
https://signstar.archlinux.page/signstar-request-signature/request.html

The signature is returned on `stdout`, in accordance with the response specification:
https://signstar.archlinux.page/signstar-request-signature/response.html
"
)]
pub struct Cli {
    /// Global processing log verbosity.
    #[command(flatten)]
    pub verbosity: Verbosity,
}
