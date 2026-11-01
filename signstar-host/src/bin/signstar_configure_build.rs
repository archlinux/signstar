//! Executable to configure a Signstar host during build of an OS image.

use std::process::ExitCode;

use clap::Parser;
use signstar_common::logging::{
    setup_systemd_journal_logging_when_connected,
    setup_terminal_logging,
};
use signstar_config::config::Config;
use signstar_host::{
    Error,
    configure_build::{cli::Cli, create_system_users, ensure_root},
};

fn run_command(cli: Cli) -> Result<(), Error> {
    ensure_root()?;
    let config =
        Config::from_file_path(cli.config.unwrap_or_default().as_ref()).map_err(Box::new)?;

    create_system_users(&config)?;

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if let Err(error) = setup_systemd_journal_logging_when_connected(cli.verbosity) {
        eprintln!(
            "Unable to log output to systemd journal: {error}\nFalling back to logging to terminal..."
        );
        if let Err(error) = setup_terminal_logging(cli.verbosity) {
            eprintln!("Unable to log output to terminal: {error}");
            return ExitCode::FAILURE;
        };
    }

    let result = run_command(cli);

    if let Err(error) = result {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
