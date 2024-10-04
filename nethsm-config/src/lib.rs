//! A library for working with application configuration files for [Nitrokey NetHSM] devices
//!
//! Provides configuration file management for custom applications designed around working with
//! [Nitrokey NetHSM] devices or containers.
//! Configuration settings allow for individualizing the configuration use and its use-cases
//! (interactive or non-interactive).
//!
//! A module for interactive prompts provides extra convenience around creating applications that
//! may request further data from their users interactively.
//!
//! # Examples
//!
//! ```
//! use nethsm::{ConnectionSecurity, UserRole};
//! use nethsm_config::{Config, ConfigCredentials, ConfigInteractivity, ConfigSettings};
//!
//! # fn main() -> testresult::TestResult {
//! // a configuration for a non-interactive application called "my_app"
//! let config_settings = ConfigSettings::new(
//!     "my_app".to_string(),
//!     ConfigInteractivity::NonInteractive,
//!     None,
//! );
//!
//! // let's assume a custom configuration file path
//! let tmpfile = testdir::testdir!().join("my_app.conf");
//! let config = Config::new(config_settings, Some(&tmpfile))?;
//!
//! // add a first device to commnicate with
//! config.add_device(
//!     "nethsm1".to_string(),
//!     "https://example.org/api/v1".parse()?,
//!     ConnectionSecurity::Unsafe,
//! )?;
//!
//! // add credentials to communicate with the the device
//! config.add_credentials(
//!     "nethsm1".to_string(),
//!     ConfigCredentials::new(
//!         UserRole::Administrator,
//!         "admin1".parse()?,
//!         Some("my-passphrase".to_string()),
//!     ),
//! )?;
//!
//! // write configuration to file
//! config.store(Some(&tmpfile))?;
//! # Ok(())
//! # }
//! ```
//! [Nitrokey NetHSM]: https://docs.nitrokey.com/nethsm/
mod config;
mod credentials;
mod mapping;
mod prompt;

pub use config::{
    Config,
    ConfigInteractivity,
    ConfigName,
    ConfigSettings,
    Connection,
    DeviceConfig,
    Error,
    HermeticParallelConfig,
};
pub use credentials::{
    AuthorizedKeyEntry,
    AuthorizedKeyEntryList,
    ConfigCredentials,
    SystemUserId,
    SystemWideUserId,
};
pub use mapping::{NetHsmMetricsUsers, UserMapping};
pub use prompt::{PassphrasePrompt, UserPrompt};
