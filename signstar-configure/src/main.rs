//! Executable for configuring Signstar hosts and their backends.

use std::process::ExitCode;

use clap::Parser;
use log::error;
use signstar_common::logging::setup_logging;
use signstar_configure::{BackendSync, Cli, Error, load_config};

/// Runs the command.
///
/// # Errors
///
/// Returns an error, if
///
/// - loading the Signstar configuration fails
/// - syncing the HSM backends fails
fn run_command() -> Result<(), Error> {
    let config = load_config()?;
    let backend_sync = BackendSync::new(&config);
    backend_sync.sync()?;

    Ok(())
}

/// Runs the `signstar-configure` command.
fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = setup_logging(args.verbosity) {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    if let Err(error) = run_command() {
        error!("Configuring Signstar host failed: {error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
