//! Containerized integration tests for `signstar-configure` with a YubiHSM2 backend.
#![cfg(all(
    feature = "_yubihsm2-mockhsm",
    feature = "_containerized-integration-test"
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
use signstar_configure::{BackendSync, load_config};
use testresult::TestResult;

/// Ensures, that [`BackendSync::sync`] succeeds if a Signstar configuration file is present in one
/// of the default system locations and a YubiHSM2 mockhsm backend is used.
#[test]
fn backend_sync_sync_succeeds() -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    let system_prepare_config = SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: Some(ConfigFileLocation::UsrShare),
            variant: ConfigFileVariant::OnlyYubiHsm2MockHsmBackendAdminPlaintextNonAdminPlaintext,
            system_user_config: Some(SystemUserConfig {
                create_secrets: false,
                create_ssh_authorized_keys: true,
            }),
        },
    };
    system_prepare_config.apply()?;

    let config = load_config()?;
    let backend_sync = BackendSync::new(&config);
    backend_sync.sync()?;

    Ok(())
}
