//! Provides utilities for YubiHSM automation.

mod command;
mod runner;
mod scenario;

pub use command::{AuditOption, AuthenticatedCommandChain, Command};
pub use runner::{
    CommandReturnValue,
    Ed25519Signature,
    LOG_DIGEST_SIZE,
    LogDigest,
    LogEntries,
    LogEntry,
    ScenarioRunner,
};
pub use scenario::{FileBackedScenario, Scenario};
