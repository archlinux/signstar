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
    ListObjectFilter,
    ObjectType,
    OpaqueData,
    OpaqueDataAlgorithm,
    OpaqueDataCapabilities,
};
#[cfg(feature = "cli")]
pub use command::{FileBackedCommand, OpaqueDataFile};
pub use error::Error;
#[cfg(feature = "cli")]
pub use error::FileBackedScenarioReturnValueMismatch;
pub use runner::{
    CommandReturnValue,
    Ed25519Signature,
    LOG_DIGEST_SIZE,
    LogDigest,
    ScenarioReturnValue,
    ScenarioRunner,
};
#[cfg(feature = "cli")]
pub use scenario::FileBackedScenario;
pub use scenario::Scenario;
