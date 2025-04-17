//! Logging utilities.

use log::{LevelFilter, Log};
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use systemd_journal_logger::{JournalLog, connected_to_journal};

/// Logging setup error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Journal initialization error.
    #[error("Journal initialization error: {0}")]
    Journal(std::io::Error),

    /// Logger initialization error.
    #[error("Logger initialization error: {0}")]
    Logger(#[from] log::SetLoggerError),
}

/// Sets up logging facilities.
///
/// # Errors
///
/// An error is returned if a logger has already been set.
pub fn setup_logging(max_level: impl Into<LevelFilter>) -> Result<(), Error> {
    if connected_to_journal()
        && let Ok(log) = JournalLog::new().map(|log| {
            Box::new(log.with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))]))
                as Box<dyn Log>
        })
    {
        log::set_boxed_logger(log)?;
        log::set_max_level(max_level.into());
        return Ok(());
    }
    TermLogger::init(
        max_level.into(),
        Default::default(),
        // simplelog needs to be explicitly instructed to always use stderr
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;
    Ok(())
}
