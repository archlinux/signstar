//! Integration for the `nethsm` CLI.

mod command;
mod config;
mod error;
mod passphrase_file;

pub use command::{
    Cli,
    Command,
    ConfigCommand,
    ConfigGetCommand,
    ConfigSetCommand,
    EnvAddCommand,
    EnvCommand,
    EnvDeleteCommand,
    HealthCommand,
    KeyCertCommand,
    KeyCommand,
    NamespaceCommand,
    OpenPgpCommand,
    SystemCommand,
    UserCommand,
};
pub use config::{
    Config,
    ConfigCredentials,
    ConfigInteractivity,
    ConfigName,
    ConfigSettings,
    DeviceConfig,
    Error as ConfigError,
    PassphrasePrompt,
    UserPrompt,
};
pub use error::Error;
pub use passphrase_file::PassphraseFile;
