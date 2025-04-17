//! Command-line functions

use simple_logger::SimpleLogger;
use systemd_journal_logger::{JournalLog, connected_to_journal};

/// Command-line error
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
pub fn setup_logging() -> Result<(), Error> {
    let logger = SimpleLogger::new().env();
    log::set_max_level(logger.max_level());
    log::set_boxed_logger(if connected_to_journal() {
        Box::new(
            JournalLog::new()
                .map_err(Error::Journal)?
                .with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))]),
        )
    } else {
        Box::new(logger)
    })?;
    Ok(())
}
