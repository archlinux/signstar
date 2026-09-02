//! Containerized integration tests for `signstar-configure` with only a NetHSM backend.
#![cfg(all(
    feature = "nethsm",
    feature = "_containerized-integration-test",
    not(feature = "yubihsm2")
))]
use log::LevelFilter;
use signstar_common::logging::setup_logging;
use signstar_config::test::{
    ConfigFileConfig,
    ConfigFileLocation,
    ConfigFileVariant,
    SystemPrepareConfig,
    SystemUserConfig,
};
use signstar_configure::{ConfigurationResult, HostConfiguration, load_config};
use testresult::TestResult;

/// Ensures, that [`HostConfiguration::sync`] aborts if a Signstar configuration file is present
/// in one of the default system locations but no physical NetHSM backend is available.
#[test]
fn host_configuration_sync_aborts_on_unavailable_connections() -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    let system_prepare_config = SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: Some(ConfigFileLocation::UsrShare),
            variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminPlaintext,
            system_user_config: Some(SystemUserConfig {
                create_secrets: false,
                create_ssh_authorized_keys: true,
            }),
        },
    };
    system_prepare_config.apply()?;

    let config = load_config()?;
    let host_configuration = HostConfiguration::new(&config);
    let configuration_result = host_configuration.sync()?;

    assert_eq!(
        configuration_result,
        ConfigurationResult::NoAvailableBackendConnection
    );

    Ok(())
}
