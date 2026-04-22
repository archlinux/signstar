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

use std::{
    fs::{File, read, read_to_string},
    io::stdout,
    path::{Path, PathBuf},
    process::ExitCode,
};

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
    backup::{InnerFormat, Label, YubiHsm2Wrap, wrap_ed25519},
    object::{Capabilities, Capability, Domain, Domains, Id},
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

    /// Backup-related features.
    #[command(subcommand)]
    Backup(BackupSubcommands),
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

/// Backup-related subcommands.
#[derive(Debug, Subcommand)]
enum BackupSubcommands {
    /// Decrypts a backup file using a wrapping key and prints its data.
    Dump {
        /// The path to the YHW backup file (a base64-encoded wrap file).
        backup_file: PathBuf,

        /// The path to a file which contains a raw (binary) wrapping key.
        wrapping_key: PathBuf,
    },
    /// Wraps an ed25519 private key and returns it in YHW format.
    ///
    /// A wrapping key is used to encrypt the ed25519 private key.
    /// Additional data about the target use of the key under wrap must be provided using options.
    WrapEd25519 {
        /// The path to a file containing a raw (binary) private ed25519 key.
        private_key_file: PathBuf,

        /// The path to a file which contains a raw (binary) wrapping key.
        wrapping_key: PathBuf,

        /// The capabilities for the key under wrap.
        #[clap(long, value_enum, value_delimiter = ',')]
        capabilities: Vec<Capability>,

        /// An identifier for the key under wrap.
        #[clap(long)]
        id: Id,

        /// The domains for the key under wrap.
        #[clap(long, value_enum, value_delimiter = ',')]
        domains: Vec<Domain>,

        /// A label for the key under wrap.
        #[clap(long)]
        label: Label,

        /// The optional path to a specific output file.
        #[arg(long, short)]
        output: Option<PathBuf>,
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

/// Decrypts a backup file using a wrapping key and prints its data.
///
/// The data of the inner format is printed, which contains an object-level representation of the
/// data contained in the backup.
///
/// # Errors
///
/// Returns an error if
/// - reading the backup file fails
/// - reading the wrapping key file fails
/// - decryption of the backup fails (e.g. the wrapping key is incorrect)
/// - the inner format structure is incorrect
fn dump_backup(backup_file: PathBuf, wrapping_key_file: impl AsRef<Path>) -> Result<(), Error> {
    let wrapping_key_file = wrapping_key_file.as_ref();
    let backup = read_to_string(&backup_file).map_err(|source| Error::IoPath {
        path: backup_file,
        context: "reading backup file",
        source,
    })?;
    let wrap = YubiHsm2Wrap::from_yhw(&backup)?;
    let wrapping_key = read(wrapping_key_file).map_err(|source| Error::IoPath {
        path: wrapping_key_file.into(),
        context: "reading wrapping key file",
        source,
    })?;
    let decrypted = wrap.decrypt(&wrapping_key)?;
    let inner = InnerFormat::parse(&decrypted)?;
    println!("{inner:#?}");
    Ok(())
}

/// Returns a writer to the specified output.
///
/// If `output` is [`None`] then the writer will append to standard output, otherwise it will write
/// to the named file.
///
/// # Errors
///
/// Returns an error if
/// - creating the file fails
fn get_writer(output: Option<PathBuf>) -> Result<Box<dyn std::io::Write>, Error> {
    Ok(if let Some(output) = output {
        Box::new(File::create(&output).map_err(|source| Error::IoPath {
            path: output,
            context: "creating the output file",
            source,
        })?)
    } else {
        Box::new(stdout())
    })
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
        Subcommands::Backup(subcommand) => match subcommand {
            BackupSubcommands::Dump {
                backup_file,
                wrapping_key,
            } => dump_backup(backup_file, wrapping_key),
            BackupSubcommands::WrapEd25519 {
                private_key_file,
                wrapping_key,
                id,
                domains,
                label,
                capabilities,
                output,
            } => wrap_ed25519(
                private_key_file,
                wrapping_key,
                id,
                Domains::from(&domains[..]),
                Capabilities::from(&capabilities[..]),
                label,
            )
            .and_then(|yhw| {
                let mut writer = get_writer(output)?;
                write!(writer, "{}", yhw).map_err(|source| Error::Io {
                    context: "writing a wrapped key to output",
                    source,
                })
            }),
        },
    };

    if let Err(error) = result {
        error!(error:err; "Running command failed: {error:#?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
