#![doc = include_str!("../README.md")]

use std::process::ExitCode;

use clap::Parser;
use signstar_config::SignstarConfig;
use signstar_configure_build::{Error, cli::Cli, create_system_users, ensure_root};

fn run_command(cli: Cli) -> Result<(), Error> {
    ensure_root()?;

    let config = SignstarConfig::new_from_file(Some(cli.config.unwrap_or_default().as_ref()))?;

    create_system_users(&config)?;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = run_command(cli);

    if let Err(error) = result {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
