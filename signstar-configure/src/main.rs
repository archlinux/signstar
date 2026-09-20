//! Executable for configuring Signstar hosts and their backends.

use std::process::{ExitCode, Termination};

use clap::Parser;
use log::error;
use signstar_common::logging::{
    setup_systemd_journal_logging_when_connected,
    setup_terminal_logging,
};
use signstar_configure::{Cli, ConfigurationResult, Error, HostConfiguration, load_config};

/// Runs the command.
///
/// # Errors
///
/// Returns an error, if
///
/// - loading the Signstar configuration fails
/// - syncing the HSM backends fails
fn run_command() -> Result<ConfigurationResult, Error> {
    let config = load_config()?;
    let backend_sync = HostConfiguration::new(&config);
    backend_sync.sync()
}

/// Runs the `signstar-configure` command.
///
/// # Note
///
/// The command may return a non-zero [`ExitCode`], that is considered a success.
/// These special exit codes are described in [`ConfigurationResult`].
fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = setup_systemd_journal_logging_when_connected(args.verbosity) {
        eprintln!(
            "Unable to log output to systemd journal: {error}\nFalling back to logging to terminal..."
        );
        if let Err(error) = setup_terminal_logging(args.verbosity) {
            eprintln!("Unable to log output to terminal: {error}");
            return ExitCode::FAILURE;
        };
    }

    match run_command() {
        Err(error) => {
            error!("Configuring Signstar host failed: {error}");
            ExitCode::FAILURE
        }
        Ok(configuration_result) => configuration_result.report(),
    }
}
