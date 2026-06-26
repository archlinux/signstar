//! Provides utilities for YubiHSM automation.

mod command;
mod error;
mod runner;
mod scenario;

pub use command::{
    AuditOption,
    AuthenticatedCommandChain,
    Command,
    CommandName,
    FileBackedCommand,
};
pub use error::{Error, FileBackedScenarioReturnValueMismatch};
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
pub use scenario::{FileBackedScenario, Scenario};
