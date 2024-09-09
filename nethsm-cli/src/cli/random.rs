use std::path::PathBuf;

use clap::Parser;
use nethsm::UserRole;

#[derive(Debug, Parser)]
#[command(
    about = "Get random bytes from a device",
    long_about = format!("Get random bytes from a device

Unless a specific output file is chosen, writes a given number of random bytes to stdout.

Requires authentication of a user in the \"{}\" role.", UserRole::Operator)
)]
pub struct RandomCommand {
    #[arg(
        env = "NETHSM_RANDOM_LENGTH",
        help = "The number of random bytes to return"
    )]
    pub length: u32,
    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_RANDOM_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}
