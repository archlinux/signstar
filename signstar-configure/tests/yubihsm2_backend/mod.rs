//! Containerized integration tests for `signstar-configure` with a YubiHSM2 backend.
#![cfg(all(
    feature = "yubihsm2",
    feature = "_containerized-integration-test",
    not(feature = "nethsm")
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

/// Ensures, that [`HostConfiguration::sync`] succeeds if a Signstar configuration file is present
/// in one of the default system locations and a YubiHSM2 mockhsm backend is used.
#[test]
#[cfg(feature = "_yubihsm2-mockhsm")]
fn host_configuration_sync_succeeds_on_host_without_admin_creds_and_mockhsm() -> TestResult {
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
    let host_configuration = HostConfiguration::new(&config);
    let configuration_result = host_configuration.sync()?;

    assert_eq!(configuration_result, ConfigurationResult::SyncSucceeded);

    Ok(())
}

/// Ensures, that [`HostConfiguration::sync`] aborts if a Signstar configuration file is present
/// in one of the default system locations but no physical YubiHSM2 backend is available.
#[test]
fn host_configuration_sync_aborts_on_unavailable_connections() -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    let system_prepare_config = SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: Some(ConfigFileLocation::UsrShare),
            variant: ConfigFileVariant::OnlyYubiHsm2BackendAdminPlaintextNonAdminPlaintext,
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

#[cfg(feature = "cli")]
mod cli {
    use std::process::{ExitCode, Termination};

    use assert_cmd::cargo::cargo_bin_cmd;

    use super::*;

    /// Ensures, that calling the `signstar-configure` CLI succeeds if a Signstar configuration
    /// file is present in one of the default system locations and a YubiHSM2 mockhsm
    /// backend is used.
    #[test]
    #[cfg(feature = "_yubihsm2-mockhsm")]
    fn succeeds_on_host_without_admin_creds_and_mockhsm() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let system_prepare_config = SystemPrepareConfig {
            machine_id: false,
            credentials_socket: false,
            signstar_config: ConfigFileConfig {
                location: Some(ConfigFileLocation::UsrShare),
                variant:
                    ConfigFileVariant::OnlyYubiHsm2MockHsmBackendAdminPlaintextNonAdminPlaintext,
                system_user_config: Some(SystemUserConfig {
                    create_secrets: false,
                    create_ssh_authorized_keys: true,
                }),
            },
        };
        system_prepare_config.apply()?;

        let exit_code = {
            let mut command = cargo_bin_cmd!();
            let output = command
                .arg("--verbose")
                .arg("--verbose")
                .arg("--verbose")
                .output()?;

            ExitCode::from(u8::try_from(
                output.status.code().expect("there to be an exit code"),
            )?)
        };

        assert_eq!(exit_code, ConfigurationResult::SyncSucceeded.report());

        Ok(())
    }

    /// Ensures, that calling the `signstar-configure` CLI aborts on unavailable backend
    /// connections.
    #[test]
    fn abort_on_unavailable_backend_connections() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let system_prepare_config = SystemPrepareConfig {
            machine_id: false,
            credentials_socket: false,
            signstar_config: ConfigFileConfig {
                location: Some(ConfigFileLocation::UsrShare),
                variant: ConfigFileVariant::OnlyYubiHsm2BackendAdminPlaintextNonAdminPlaintext,
                system_user_config: Some(SystemUserConfig {
                    create_secrets: false,
                    create_ssh_authorized_keys: true,
                }),
            },
        };
        system_prepare_config.apply()?;

        let exit_code = {
            let mut command = cargo_bin_cmd!();
            let output = command
                .arg("--verbose")
                .arg("--verbose")
                .arg("--verbose")
                .output()?;

            ExitCode::from(u8::try_from(
                output.status.code().expect("there to be an exit code"),
            )?)
        };

        assert_eq!(
            exit_code,
            ConfigurationResult::NoAvailableBackendConnection.report()
        );

        Ok(())
    }

    /// Ensures, that calling the `signstar-configure` CLI fails on no configuration file.
    #[test]
    fn fail_on_no_configuration_file() -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        let system_prepare_config = SystemPrepareConfig {
            machine_id: false,
            credentials_socket: false,
            signstar_config: ConfigFileConfig {
                location: None,
                variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
                system_user_config: Some(SystemUserConfig {
                    create_secrets: false,
                    create_ssh_authorized_keys: true,
                }),
            },
        };
        system_prepare_config.apply()?;

        let exit_code = {
            let mut command = cargo_bin_cmd!();
            let output = command
                .arg("--verbose")
                .arg("--verbose")
                .arg("--verbose")
                .output()?;

            ExitCode::from(u8::try_from(
                output.status.code().expect("there to be an exit code"),
            )?)
        };

        assert_eq!(exit_code, ExitCode::FAILURE);

        Ok(())
    }
}
