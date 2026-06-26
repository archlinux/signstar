//! Provides utilities for YubiHSM automation.

mod command;
mod error;
mod runner;
mod scenario;

#[cfg(feature = "cli")]
pub use command::FileBackedCommand;
pub use command::{AuditOption, AuthenticatedCommandChain, Command, CommandName};
pub use error::Error;
#[cfg(feature = "cli")]
pub use error::FileBackedScenarioReturnValueMismatch;
pub use runner::{
    CommandReturnValue,
    Ed25519Signature,
    LOG_DIGEST_SIZE,
    LogDigest,
    LogEntries,
    LogEntry,
    ScenarioReturnValue,
    ScenarioRunner,
};
#[cfg(feature = "cli")]
pub use scenario::FileBackedScenario;
pub use scenario::Scenario;
