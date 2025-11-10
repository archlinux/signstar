use std::path::PathBuf;

use clap::Parser;
use expression_format::ex_format;
use nethsm::UserRole::Operator;

/// The "nethsm random" command.
#[derive(Debug, Parser)]
#[command(
    about = "Get random bytes from a device",
    long_about = ex_format!("Get random bytes from a device

Unless a specific output file is chosen, writes a given number of random bytes to stdout.

Requires authentication of a user in the \"{Operator}\" role.")
)]
pub struct RandomCommand {
    /// The number of random bytes to get.
    #[arg(
        env = "NETHSM_RANDOM_LENGTH",
        help = "The number of random bytes to return"
    )]
    pub length: u32,

    /// Whether to override the output file if it exists.
    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    /// The optional path to an output file.
    #[arg(
        env = "NETHSM_RANDOM_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}
