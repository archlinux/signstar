//! Containerized integration tests for loading Signstar configs in `signstar-configure`.
#![cfg(feature = "_containerized-integration-test")]

use log::LevelFilter;
use signstar_common::logging::setup_logging;
use signstar_config::test::{
    ConfigFileConfig,
    ConfigFileLocation,
    ConfigFileVariant,
    SystemPrepareConfig,
};
use signstar_configure::load_config;
use testresult::TestResult;

/// Ensures, that [`load_config`] succeeds if a Signstar configuration file is present in one of
/// the default system location.
#[test]
fn load_config_succeeds() -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    let system_prepare_config = SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: Some(ConfigFileLocation::UsrShare),
            variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
            system_user_config: None,
        },
    };
    system_prepare_config.apply()?;

    let config = load_config()?;

    assert_eq!(
        config,
        ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext.to_config()?
    );

    Ok(())
}

/// Ensures, that [`load_config`] fails, if no Signstar configuration file is present in one of the
/// default system location.
#[test]
fn load_config_fails() -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    let system_prepare_config = SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: None,
            variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
            system_user_config: None,
        },
    };
    system_prepare_config.apply()?;

    if let Ok(config) = load_config() {
        panic!(
            "Expected to fail reading a Signstar configuration file from a default location, but found a config: {config:#?}"
        );
    };

    Ok(())
}
