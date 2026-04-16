//! Integration tests for [`signstar_config::config`].
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use std::{collections::HashMap, io::Write, str::FromStr};
use std::{
    fs::{File, create_dir_all},
    path::PathBuf,
};

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use change_user_run::{CommandOutput, create_users, run_command_as_user};
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use log::{LevelFilter, debug};
use nix::unistd::{User, geteuid};
use rstest::rstest;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_common::{logging::setup_logging, system_user::get_home_base_dir_path};
use signstar_config::config::{Config, SystemUserId};
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_config::{
    config::ConfigSystemUserIds,
    test::{start_credentials_socket, write_machine_id},
};
use testresult::TestResult;

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use crate::{ENV_LIST, LLVM_PROFILE_FILE, collect_coverage_files};

/// The example executable to call during tests.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
const PAYLOAD: &str = "/usr/local/bin/examples/config-non-admin-backend-user-secrets";

/// Ensure that [`SystemUserId`] can be created from the current Unix user ("root").
#[cfg(target_os = "linux")]
#[test]
fn system_user_id_from_unix_user() -> TestResult {
    let current_user = User::from_uid(geteuid())?.expect("root is a valid system user");
    assert_eq!(
        SystemUserId::new("root".to_string())?,
        SystemUserId::try_from(current_user)?
    );
    Ok(())
}

/// Ensures, that [`Config::first_existing_system_path`] reports a file in the correct location.
#[rstest]
#[case(Config::DEFAULT_CONFIG_DIR)]
#[case(Config::RUN_OVERRIDE_CONFIG_DIR)]
#[case(Config::ETC_OVERRIDE_CONFIG_DIR)]
fn config_first_existing_system_path(#[case] dir: &str) -> TestResult {
    create_dir_all(dir)?;
    let _file = File::create(PathBuf::from(dir).join(format!("{}.yaml", Config::CONFIG_NAME)));

    assert_eq!(
        Config::first_existing_system_path()?,
        PathBuf::from(dir).join(format!("{}.yaml", Config::CONFIG_NAME))
    );

    Ok(())
}

/// Ensures, that [`Config::first_existing_system_path`] fails on missing configuration file.
#[test]
fn config_first_existing_system_path_fails_on_missing_config() -> TestResult {
    match Config::first_existing_system_path() {
        Ok(config) => panic!(
            "Expected to fail with ConfigError::ConfigIsMissing but succeeded instead:\n{config:?}"
        ),
        Err(signstar_config::Error::Config(signstar_config::ConfigError::ConfigIsMissing)) => {}
        Err(error) => panic!(
            "Expected to fail with ConfigError::ConfigIsMissing but failed with a different error instead:\n{error}"
        ),
    }

    Ok(())
}

/// Tests for when using only the NetHSM backend.
#[cfg(all(feature = "nethsm", not(feature = "yubihsm2")))]
mod nethsm_backend {
    use super::*;

    /// Creates secrets for all configured non-administrative backend users.
    ///
    /// Afterwards, loads the secrets of each configured backend user by calling as the specific
    /// configured system user associated.
    #[rstest]
    fn create_and_load_non_admin_secrets(
        #[files("../fixtures/config/nethsm_backend/*.yaml")]
        #[exclude("sss")]
        #[mode = str]
        config: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        write_machine_id()?;
        let _socket = start_credentials_socket()?;

        // Write config to default location
        create_dir_all(Config::DEFAULT_CONFIG_DIR)?;
        let mut file = File::create(Config::default_system_path())?;
        file.write_all(config.as_bytes())?;

        let config = Config::from_str(config)?;

        // Create all Unix users and their homes.
        let users = config
            .system_user_ids()
            .iter()
            .cloned()
            .map(|id| id.as_ref())
            .collect::<Vec<_>>();
        create_users(&users, Some(&get_home_base_dir_path()), None)?;

        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
        } = run_command_as_user(
            PAYLOAD,
            &["create"],
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            "root",
        )?;
        debug!("{stdout}");

        if !status.success() {
            panic!(
                "{}",
                signstar_config::Error::CommandNonZero {
                    command,
                    exit_status: status,
                    stderr,
                }
            );
        }

        collect_coverage_files("/tmp")?;

        for user in users {
            let CommandOutput {
                status,
                command,
                stderr,
                stdout,
            } = run_command_as_user(
                PAYLOAD,
                &["load", user],
                None,
                ENV_LIST,
                Some(HashMap::from([(
                    "LLVM_PROFILE_FILE".to_string(),
                    LLVM_PROFILE_FILE.to_string(),
                )])),
                user,
            )?;
            debug!("{stdout}");

            if !status.success() {
                panic!(
                    "{}",
                    signstar_config::Error::CommandNonZero {
                        command,
                        exit_status: status,
                        stderr,
                    }
                );
            }

            collect_coverage_files("/tmp")?;
        }

        Ok(())
    }
}

/// Tests for when using only the YubiHSM2 backend.
#[cfg(all(feature = "yubihsm2", not(feature = "nethsm")))]
mod yubihsm2_backend {
    use super::*;

    /// Creates secrets for all configured non-administrative backend users.
    ///
    /// Afterwards, loads the secrets of each configured backend user by calling as the specific
    /// configured system user associated.
    #[rstest]
    fn create_and_load_non_admin_secrets(
        #[files("../fixtures/config/yubihsm2_backend/*.yaml")]
        #[exclude("sss")]
        #[mode = str]
        config: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        write_machine_id()?;
        let _socket = start_credentials_socket()?;

        // Write config to default location
        create_dir_all(Config::DEFAULT_CONFIG_DIR)?;
        let mut file = File::create(Config::default_system_path())?;
        file.write_all(config.as_bytes())?;

        let config = Config::from_str(config)?;

        // Create all Unix users and their homes.
        let users = config
            .system_user_ids()
            .iter()
            .cloned()
            .map(|id| id.as_ref())
            .collect::<Vec<_>>();
        create_users(&users, Some(&get_home_base_dir_path()), None)?;

        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
        } = run_command_as_user(
            PAYLOAD,
            &["create"],
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            "root",
        )?;
        debug!("{stdout}");

        if !status.success() {
            panic!(
                "{}",
                signstar_config::Error::CommandNonZero {
                    command,
                    exit_status: status,
                    stderr,
                }
            );
        }

        collect_coverage_files("/tmp")?;

        for user in users {
            let CommandOutput {
                status,
                command,
                stderr,
                stdout,
            } = run_command_as_user(
                PAYLOAD,
                &["load", user],
                None,
                ENV_LIST,
                Some(HashMap::from([(
                    "LLVM_PROFILE_FILE".to_string(),
                    LLVM_PROFILE_FILE.to_string(),
                )])),
                user,
            )?;
            debug!("{stdout}");

            if !status.success() {
                panic!(
                    "{}",
                    signstar_config::Error::CommandNonZero {
                        command,
                        exit_status: status,
                        stderr,
                    }
                );
            }

            collect_coverage_files("/tmp")?;
        }

        Ok(())
    }
}

/// Tests for when using all backends at the same time.
#[cfg(all(feature = "nethsm", feature = "yubihsm2"))]
mod all_backends {
    use super::*;

    /// Creates secrets for all configured non-administrative backend users.
    ///
    /// Afterwards, loads the secrets of each configured backend user by calling as the specific
    /// configured system user associated.
    #[rstest]
    fn create_and_load_non_admin_secrets(
        #[files("../fixtures/config/all_backends/*.yaml")]
        #[exclude("sss")]
        #[mode = str]
        config: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        write_machine_id()?;
        let _socket = start_credentials_socket()?;

        // Write config to default location
        create_dir_all(Config::DEFAULT_CONFIG_DIR)?;
        let mut file = File::create(Config::default_system_path())?;
        file.write_all(config.as_bytes())?;

        let config = Config::from_str(config)?;

        // Create all Unix users and their homes.
        let users = config
            .system_user_ids()
            .iter()
            .cloned()
            .map(|id| id.as_ref())
            .collect::<Vec<_>>();
        create_users(&users, Some(&get_home_base_dir_path()), None)?;

        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
        } = run_command_as_user(
            PAYLOAD,
            &["create"],
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            "root",
        )?;
        debug!("{stdout}");

        if !status.success() {
            panic!(
                "{}",
                signstar_config::Error::CommandNonZero {
                    command,
                    exit_status: status,
                    stderr,
                }
            );
        }

        collect_coverage_files("/tmp")?;

        for user in users {
            let CommandOutput {
                status,
                command,
                stderr,
                stdout,
            } = run_command_as_user(
                PAYLOAD,
                &["load", user],
                None,
                ENV_LIST,
                Some(HashMap::from([(
                    "LLVM_PROFILE_FILE".to_string(),
                    LLVM_PROFILE_FILE.to_string(),
                )])),
                user,
            )?;
            debug!("{stdout}");

            if !status.success() {
                panic!(
                    "{}",
                    signstar_config::Error::CommandNonZero {
                        command,
                        exit_status: status,
                        stderr,
                    }
                );
            }

            collect_coverage_files("/tmp")?;
        }

        Ok(())
    }
}
