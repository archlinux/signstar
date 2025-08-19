//! Integration tests for [`signstar_config::non_admin_credentials`].
use std::{
    fs::{File, Permissions, remove_file, set_permissions},
    io::Write,
    os::unix::fs::{PermissionsExt, chown},
};

use change_user_run::{CommandOutput, create_users, run_command_as_user};
use log::LevelFilter;
use rstest::rstest;
use signstar_common::{
    common::{SECRET_FILE_MODE, get_data_home},
    config::get_default_config_file_path,
    logging::setup_logging,
    system_user::{get_home_base_dir_path, get_systemd_creds_secret_file, get_user_secrets_dir},
};
use signstar_config::{
    error::ErrorExitCode,
    test::{list_files_in_dir, prepare_system_with_config},
};
use testresult::TestResult;

/// Plaintext configuration
const SIGNSTAR_CONFIG_PLAINTEXT: &[u8] =
    include_bytes!("../fixtures/signstar-config-plaintext.toml");

/// Full configuration
const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");

const GET_CREDENTIALS_PAYLOAD: &str = "/usr/local/bin/examples/get-nethsm-credentials";

/// Loading credentials for unprivileged system users succeeds.
///
/// Tests integration with `systemd-creds` encrypted secrets and plaintext secrets.
#[rstest]
#[case(SIGNSTAR_CONFIG_FULL)]
#[case(SIGNSTAR_CONFIG_PLAINTEXT)]
fn load_credentials_for_user(#[case] config_data: &[u8]) -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, _credentials_socket) = prepare_system_with_config(config_data)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Create secrets for each system user and their backend users
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status,
                command,
                stderr,
                ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;

            if !status.success() {
                return Err(signstar_config::Error::CommandNonZero {
                    command,
                    exit_status: status,
                    stderr,
                }
                .into());
            }
        }
    }

    Ok(())
}

/// Loading credentials for unprivileged system users fails on missing Signstar configuration.
#[rstest]
fn load_credentials_for_user_fails_on_missing_signstar_config() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, _credentials_socket) = prepare_system_with_config(SIGNSTAR_CONFIG_FULL)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Create secrets for each system user and their backend users
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Remove signstar config from default location
    remove_file(get_default_config_file_path())?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status, command, ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;
            if !status.success() {
                let Some(exit_code) = status.code() else {
                    panic!("There should be an exit code for {command}!")
                };
                assert_eq!(
                    exit_code,
                    std::convert::Into::<i32>::into(ErrorExitCode::ConfigConfigMissing)
                );
            } else {
                panic!("The command {command} should have failed!")
            }
        }
    }

    Ok(())
}

/// Loading credentials for unprivileged system users fails on /run/systemd/io.systemd.Credentials
/// socket not being available.
#[rstest]
fn load_credentials_for_user_fails_on_credentials_socket() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, mut credentials_socket) = prepare_system_with_config(SIGNSTAR_CONFIG_FULL)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Create secrets for each system user and their backend users
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Kill socket /run/systemd/io.systemd.Credentials and `systemd-creds` process to not leak the
    // subprocess
    credentials_socket.kill()?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status, command, ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;

            if !status.success() {
                let Some(exit_code) = status.code() else {
                    panic!("There should be an exit code for {command}!")
                };
                assert_eq!(
                    exit_code,
                    std::convert::Into::<i32>::into(
                        ErrorExitCode::NonAdminCredentialsCredentialsLoading
                    )
                );
            } else {
                panic!("The command {command} should have failed!")
            }
        }
    }

    Ok(())
}

/// Loading credentials for unprivileged system users fails on missing secrets dir.
#[rstest]
fn load_credentials_for_user_fails_on_missing_secrets_dir() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, _credentials_socket) = prepare_system_with_config(SIGNSTAR_CONFIG_FULL)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status, command, ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;

            if !status.success() {
                let Some(exit_code) = status.code() else {
                    panic!("There should be an exit code for {command}!")
                };
                assert_eq!(
                    exit_code,
                    std::convert::Into::<i32>::into(
                        ErrorExitCode::NonAdminCredentialsCredentialsLoading
                    )
                );
            } else {
                panic!("The command {command} should have failed!")
            }
        }
    }

    Ok(())
}

/// Loading credentials for unprivileged system users fails on missing secrets file.
#[rstest]
fn load_credentials_for_user_fails_on_missing_secrets_file() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, _credentials_socket) = prepare_system_with_config(SIGNSTAR_CONFIG_FULL)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Only create secret dir for each system user.
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status, command, ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;

            if !status.success() {
                let Some(exit_code) = status.code() else {
                    panic!("There should be an exit code for {command}!")
                };
                assert_eq!(
                    exit_code,
                    std::convert::Into::<i32>::into(
                        ErrorExitCode::NonAdminCredentialsCredentialsLoading
                    )
                );
            } else {
                panic!("The command {command} should have failed!")
            }
        }
    }

    Ok(())
}

/// Loading credentials for unprivileged system users fails on inaccessible secrets file.
#[rstest]
fn load_credentials_for_user_fails_on_inaccessible_secrets_file() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, _credentials_socket) = prepare_system_with_config(SIGNSTAR_CONFIG_FULL)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Create secrets file for each system user (and then render it inaccessible).
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
        if let Some(user) = mapping.get_user_mapping().get_system_user() {
            let secrets_dir = get_user_secrets_dir(user.as_ref());
            chown(secrets_dir.as_path(), Some(0), Some(0))?;
            set_permissions(
                secrets_dir.as_path(),
                Permissions::from_mode(SECRET_FILE_MODE),
            )?;
        }
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status, command, ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;

            if !status.success() {
                let Some(exit_code) = status.code() else {
                    panic!("There should be an exit code for {command}!")
                };
                assert_eq!(
                    exit_code,
                    std::convert::Into::<i32>::into(
                        ErrorExitCode::NonAdminCredentialsCredentialsLoading
                    )
                );
            } else {
                panic!("The command {command} should have failed!")
            }
        }
    }

    Ok(())
}

/// Loading credentials for unprivileged system users fails on garbage "encrypted" secrets file.
#[rstest]
fn load_credentials_for_user_fails_on_garbage_secrets_file() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (creds_mapping, _credentials_socket) = prepare_system_with_config(SIGNSTAR_CONFIG_FULL)?;
    // Get all system users
    let system_users = creds_mapping
        .iter()
        .filter_map(|mapping| {
            mapping
                .get_user_mapping()
                .get_system_user()
                .map(|user| user.to_string())
        })
        .collect::<Vec<String>>();
    // Create all system users and their homes
    create_users(
        &system_users
            .iter()
            .map(|user| user.as_str())
            .collect::<Vec<_>>(),
        Some(&get_home_base_dir_path()),
        None,
    )?;
    // Create secrets file for each system user (and then write garbage to them).
    for mapping in &creds_mapping {
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
        if let Some(user) = mapping.get_user_mapping().get_system_user() {
            for backend_user in mapping.get_user_mapping().get_nethsm_users() {
                let secrets_file =
                    get_systemd_creds_secret_file(user.as_ref(), &backend_user.to_string());
                let mut output = File::create(secrets_file.as_path())?;
                write!(output, "GARBAGE")?;
            }
        }
    }
    // List all files and directories in the data home.
    list_files_in_dir(get_data_home())?;

    // Retrieve backend credentials for each system user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            let CommandOutput {
                status, command, ..
            } = run_command_as_user(
                GET_CREDENTIALS_PAYLOAD,
                &[],
                None,
                &[],
                None,
                system_user_id.as_ref(),
            )?;

            if !status.success() {
                let Some(exit_code) = status.code() else {
                    panic!("There should be an exit code for {command}!")
                };
                assert_eq!(
                    exit_code,
                    std::convert::Into::<i32>::into(
                        ErrorExitCode::NonAdminCredentialsCredentialsLoading
                    )
                );
            } else {
                panic!("The command {command} should have failed!")
            }
        }
    }

    Ok(())
}
