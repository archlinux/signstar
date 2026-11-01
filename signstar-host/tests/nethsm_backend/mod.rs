//! Containerized integration tests for `signstar-configure` with only a NetHSM backend.
#![cfg(all(
    feature = "nethsm",
    feature = "_containerized-integration-test",
    not(feature = "yubihsm2")
))]

/// Tests for `signstar-configure`.
mod configure {
    use log::LevelFilter;
    use signstar_common::logging::setup_terminal_logging;
    use signstar_config::test::{
        ConfigFileConfig,
        ConfigFileLocation,
        ConfigFileVariant,
        SystemPrepareConfig,
        SystemUserConfig,
        SystemUserConfigSettings,
    };
    use signstar_host::{
        config::load_config,
        configure::{ConfigurationResult, HostConfiguration},
    };
    use testresult::TestResult;

    /// Ensures, that [`HostConfiguration::sync`] aborts if a Signstar configuration file is present
    /// in one of the default system locations but no physical NetHSM backend is available.
    #[test]
    fn host_configuration_sync_aborts_on_unavailable_connections() -> TestResult {
        setup_terminal_logging(LevelFilter::Debug)?;

        let mut system_prepare_config = SystemPrepareConfig {
            machine_id: false,
            credentials_socket: false,
            signstar_config: ConfigFileConfig {
                location: Some(ConfigFileLocation::UsrShare),
                variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminPlaintext,
                system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                    create_secrets: false,
                    create_ssh_authorized_keys: true,
                })),
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

        /// Ensures, that calling the `signstar-configure` CLI aborts on unavailable backend
        /// connections.
        #[test]
        fn abort_on_unavailable_backend_connections() -> TestResult {
            setup_terminal_logging(LevelFilter::Debug)?;

            let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: Some(ConfigFileLocation::UsrShare),
                    variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
            system_prepare_config.apply()?;

            let exit_code = {
                let mut command = cargo_bin_cmd!("signstar-configure");
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
            setup_terminal_logging(LevelFilter::Debug)?;

            let mut system_prepare_config = SystemPrepareConfig {
                machine_id: false,
                credentials_socket: false,
                signstar_config: ConfigFileConfig {
                    location: None,
                    variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
                    system_user_config: Some(SystemUserConfig::new(SystemUserConfigSettings {
                        create_secrets: false,
                        create_ssh_authorized_keys: true,
                    })),
                },
            };
            system_prepare_config.apply()?;

            let exit_code = {
                let mut command = cargo_bin_cmd!("signstar-configure");
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
}
