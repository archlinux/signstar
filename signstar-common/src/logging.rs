//! Logging utilities.

use log::{LevelFilter, SetLoggerError, set_max_level};
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use systemd_journal_logger::{JournalLog, connected_to_journal};

/// Logging setup error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The process is not connected to the systemd journal.
    #[error("The process is not connected to the system journal")]
    JournalNotConnected,

    /// Journal initialization error.
    #[error("Journal initialization error: {0}")]
    Journal(std::io::Error),

    /// Logger initialization error.
    #[error("Logger initialization error: {0}")]
    Logger(#[from] SetLoggerError),
}

/// Sets up a global terminal logger based on a maximum logging level filter.
///
/// # Errors
///
/// Returns an error, if [`TermLogger::init`] fails.
pub fn setup_terminal_logging(max_level: impl Into<LevelFilter>) -> Result<(), crate::Error> {
    TermLogger::init(
        max_level.into(),
        Default::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .map_err(|error| Error::Logger(error).into())
}

/// Sets up a global systemd journal logger based on a maximum logging level filter.
///
/// # Errors
///
/// Returns an error, if globally installing a [`JournalLog`] fails.
pub fn setup_systemd_journal_logging(
    max_level: impl Into<LevelFilter>,
) -> Result<(), crate::Error> {
    JournalLog::new()
        .map_err(Error::Journal)?
        .with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))])
        .install()
        .map_err(Error::Logger)?;

    set_max_level(max_level.into());

    Ok(())
}

/// Sets up a global systemd journal logger based on a maximum logging level filter, when connected
/// to the journal.
///
/// # Note
///
/// Only sets up logging, if the current process is connected to the journal (see `JOURNAL_STREAM`
/// in [systemd.exec(5)]). This is particularly useful e.g. in [systemd.service(5)] files in which
/// the executed command is connected to the journal with the help of the `StandardOutput` and
/// `StandardError` [logging and standard input/output settings].
///
/// # Errors
///
/// Returns an error, if
///
/// - the process is not connected to the systemd journal
/// - globally installing a [`JournalLog`] fails
///
/// [systemd.exec(5)]: https://man.archlinux.org/man/systemd.exec.5
/// [systemd.service(5)]: https://man.archlinux.org/man/systemd.service.5
/// [logging and standard input/output settings]: https://man.archlinux.org/man/systemd.exec.5#LOGGING_AND_STANDARD_INPUT/OUTPUT
pub fn setup_systemd_journal_logging_when_connected(
    max_level: impl Into<LevelFilter>,
) -> Result<(), crate::Error> {
    if !connected_to_journal() {
        return Err(Error::JournalNotConnected.into());
    }

    JournalLog::new()
        .map_err(Error::Journal)?
        .with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))])
        .install()
        .map_err(Error::Logger)?;

    set_max_level(max_level.into());

    Ok(())
}
