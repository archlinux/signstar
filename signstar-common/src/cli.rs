//! Command-line functions

use log::{LevelFilter, Log};
use systemd_journal_logger::JournalLog;

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
    // This minimal logger is used only when the systemd journal is not available
    // e.g. during containerized tests
    struct MiniLogger;
    impl Log for MiniLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            eprintln!("LOG: {}", record.args());
        }

        fn flush(&self) {
            // no-op
        }
    }

    let log = JournalLog::new()
        .map(|log| {
            Box::new(log.with_extra_fields(vec![("VERSION", env!("CARGO_PKG_VERSION"))]))
                as Box<dyn Log>
        })
        .unwrap_or(Box::new(MiniLogger));

    log::set_boxed_logger(log)?;
    log::set_max_level(LevelFilter::Info);
    Ok(())
}
