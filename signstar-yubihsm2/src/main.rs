//! Command line interface for the provisioning of a YubiHSM2.

/// Module for the behavior with default features enabled.
#[cfg(not(feature = "_yubihsm2-mockhsm"))]
mod impl_default {
    use super::*;

    /// Returns a [`Connector`] using an optional [`SerialNumber`].
    ///
    /// # Errors
    ///
    /// Returns an error, if `serial_number` is [`None`].
    pub fn get_connector(serial_number: Option<SerialNumber>) -> Result<Connector, Error> {
        if serial_number.is_some() {
            Ok(Connector::usb(&UsbConfig {
                serial: serial_number,
                timeout_ms: UsbConfig::DEFAULT_TIMEOUT_MILLIS,
            }))
        } else {
            Err(Error::MockHsmUnavailable)
        }
    }
}

/// Module for the behavior with "mockhsm" feature enabled.
#[cfg(feature = "_yubihsm2-mockhsm")]
mod impl_mockhsm {
    use super::*;

    /// Returns a [`Connector`] using an optional [`SerialNumber`].
    ///
    /// # Note
    ///
    /// If `serial_number` is [`None`], returns a mockhsm [`Connector`]
    pub fn get_connector(serial_number: Option<SerialNumber>) -> Result<Connector, Error> {
        Ok(if serial_number.is_some() {
            Connector::usb(&UsbConfig {
                serial: serial_number,
                timeout_ms: UsbConfig::DEFAULT_TIMEOUT_MILLIS,
            })
        } else {
            Connector::mockhsm()
        })
    }
}

use std::{fs::File, io::stdout, path::PathBuf, process::ExitCode};

use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;
#[cfg(not(feature = "_yubihsm2-mockhsm"))]
use impl_default::get_connector;
#[cfg(feature = "_yubihsm2-mockhsm")]
use impl_mockhsm::get_connector;
use log::error;
use signstar_common::logging::setup_logging;
use signstar_yubihsm2::{
    Error,
    automation::{Scenario, ScenarioRunner},
};
use yubihsm::{Connector, UsbConfig, device::SerialNumber};

/// YubiHSM2 command line interface.
#[derive(Debug, Parser)]
struct Cli {
    /// Global processing log verbosity.
    #[command(flatten)]
    pub verbosity: Verbosity,

    #[command(subcommand)]
    subcommand: Subcommands,
}

/// Subcommands of Signstar YubiHSM2 tool.
#[derive(Debug, Subcommand)]
enum Subcommands {
    /// Scenario runner.
    #[command(subcommand)]
    Scenario(ScenarioSubcommands),
}

/// Scenario runner subcommands.
#[derive(Debug, Subcommand)]
enum ScenarioSubcommands {
    /// Runs a single JSON scenario.
    Run {
        /// A path to the scenario file which contains JSON instructions to execute against a
        /// YubiHSM2.
        scenario: PathBuf,

        /// Serial number of the YubiHSM2 to target.
        ///
        /// If this serial number is not provided, and this binary has been compiled with the
        /// `--debug` option (`yubihsm.rs` limitation) then a MockHSM instance will be
        /// started. This is useful for tests.
        #[clap(env = "SIGNSTAR_YUBIHSM_SN")]
        serial_number: Option<SerialNumber>,
    },
}

/// Run a single scenario file.
///
/// # Errors
///
/// Returns an error if
/// - parsing the serial number fails
/// - reading the scenario file fails
/// - the commands themselves return an error
fn run_scenario(serial_number: Option<SerialNumber>, scenario_file: PathBuf) -> Result<(), Error> {
    let connector = get_connector(serial_number)?;

    let scenario: Scenario =
        serde_json::from_reader(File::open(&scenario_file).map_err(|source| Error::IoPath {
            context: "reading scenario file",
            path: scenario_file,
            source,
        })?)
        .map_err(|source| Error::Json {
            context: "parsing scenario file",
            source,
        })?;
    let mut runner = ScenarioRunner::new(connector, scenario.auth)?;
    runner.run_steps(&scenario.steps, &mut stdout())?;

    Ok(())
}

/// Signs the signing request on standard input and returns a signing response on standard output.
fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = setup_logging(args.verbosity) {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    let result = match args.subcommand {
        Subcommands::Scenario(subcommand) => match subcommand {
            ScenarioSubcommands::Run {
                scenario,
                serial_number,
            } => run_scenario(serial_number, scenario),
        },
    };

    if let Err(error) = result {
        error!(error:err; "Running command failed: {error:#?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
