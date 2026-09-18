//! Application for the retrieval of key certificates.

use std::{
    io::{Write, stdout},
    process::ExitCode,
};

use clap::Parser;
use log::error;
use serde_json::to_writer_pretty;
use signstar_common::logging::{setup_systemd_journal_logging, setup_terminal_logging};
use signstar_download_key_certificates::{Certificates, cli::Cli, error::Error, load_certificates};

fn write_certificates(writer: impl Write) -> Result<(), Error> {
    let certs = load_certificates()?;
    to_writer_pretty(writer, &Certificates { certs })?;
    Ok(())
}

/// Signs the signing request on standard input and returns a signing response on standard output.
fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = setup_systemd_journal_logging(args.verbosity) {
        eprintln!(
            "Unable to log output to systemd journal: {error}\nFalling back to logging to terminal..."
        );
        if let Err(error) = setup_terminal_logging(args.verbosity) {
            eprintln!("Unable to log output to terminal: {error}");
            return ExitCode::FAILURE;
        };
    }

    let result = write_certificates(stdout());

    if let Err(error) = result {
        error!(error:err; "Processing certificate retrieval request failed: {error:#?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
