//! Integration tests for implementations of
//! [`signstar_config::config::traits::MappingSystemUserId`].

use std::{collections::HashMap, thread::current};

use change_user_run::{CommandOutput, create_users, run_command_as_user};
use insta::{assert_snapshot, with_settings};
use log::LevelFilter;
use rstest::rstest;
use signstar_common::{logging::setup_logging, system_user::get_home_base_dir_path};
use testresult::TestResult;

use crate::{ENV_LIST, LLVM_PROFILE_FILE, collect_coverage_files};

const PAYLOAD: &str = "/usr/local/bin/examples/usermapping-system-user-info";
const SNAPSHOT_PATH: &str = "/test/tests/usermapping/fixtures/";

mod nethsm {
    use super::*;

    /// Retrieve the Unix user information (if any) of a user mapping succeeds.
    #[rstest]
    #[case("nethsm-admin", None)]
    #[case("nethsm-backup", Some("backup"))]
    #[case("nethsm-hermetic-metrics", Some("hermetic-metrics"))]
    #[case("nethsm-metrics", Some("metrics"))]
    #[case("nethsm-signing", Some("signing"))]
    fn get_unix_user_information_succeeds(
        #[case] backend_kind: &str,
        #[case] user: Option<&str>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        // Create unix user and its home
        if let Some(user) = user {
            create_users(&[user], Some(&get_home_base_dir_path()), None)?;
        }

        let options = {
            let mut options = vec![backend_kind];
            if let Some(user) = user {
                options.push(user);
            }
            options.push("--exists");
            options.push("--current-user");
            options
        };

        let CommandOutput {
            status,
            command,
            stderr,
            ..
        } = run_command_as_user(
            PAYLOAD,
            &options,
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            user.unwrap_or("root"),
        )?;

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

        Ok(())
    }

    /// Fails on matching the configured system user against the Unix user of the current process.
    #[rstest]
    #[case("nethsm-backup", "backup")]
    #[case("nethsm-hermetic-metrics", "hermetic-metrics")]
    #[case("nethsm-metrics", "metrics")]
    #[case("nethsm-signing", "signing")]
    fn get_unix_user_information_fails_wrong_system_user(
        #[case] backend_kind: &str,
        #[case] user: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        // Create a mismatching Unix user and its home.
        let unix_user = "wrong-user";
        create_users(&[unix_user], Some(&get_home_base_dir_path()), None)?;

        // Call the command with the mismatching Unix user.
        let CommandOutput {
            status,
            command,
            stderr,
            ..
        } = run_command_as_user(
            PAYLOAD,
            &[backend_kind, user, "--current-user"],
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            unix_user,
        )?;

        assert!(!status.success());

        with_settings!({
            description => format!("Calling Unix user != usermapping system user ({command})"),
            filters => vec![(r"\b[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\b", "TIMESTAMP")],
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), stderr);
        });

        collect_coverage_files("/tmp")?;

        Ok(())
    }
}

#[cfg(feature = "yubihsm2")]
mod yubihsm2 {
    use super::*;

    /// Retrieve the Unix user information (if any) of a user mapping succeeds.
    #[rstest]
    #[case("yubihsm2-admin", None)]
    #[case("yubihsm2-audit-log", Some("metrics"))]
    #[case("yubihsm2-backup", Some("backup"))]
    #[case("yubihsm2-hermetic-audit-log", Some("hermetic-audit-log"))]
    #[case("yubihsm2-signing", Some("signing"))]
    fn get_unix_user_information_succeeds(
        #[case] backend_kind: &str,
        #[case] user: Option<&str>,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;
        // Create unix user and its home
        if let Some(user) = user {
            create_users(&[user], Some(&get_home_base_dir_path()), None)?;
        }

        let options = {
            let mut options = vec![backend_kind];
            if let Some(user) = user {
                options.push(user);
            }
            options.push("--exists");
            options.push("--current-user");
            options
        };

        let CommandOutput {
            status,
            command,
            stderr,
            ..
        } = run_command_as_user(
            PAYLOAD,
            &options,
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            user.unwrap_or("root"),
        )?;

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

        Ok(())
    }

    /// Fails on matching the configured system user against the Unix user of the current process.
    #[rstest]
    #[case("yubihsm2-audit-log", "metrics")]
    #[case("yubihsm2-backup", "backup")]
    #[case("yubihsm2-hermetic-audit-log", "hermetic-audit-log")]
    #[case("yubihsm2-signing", "signing")]
    fn get_unix_user_information_fails_wrong_system_user(
        #[case] backend_kind: &str,
        #[case] user: &str,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        // Create a mismatching Unix user and its home.
        let unix_user = "wrong-user";
        create_users(&[unix_user], Some(&get_home_base_dir_path()), None)?;

        // Call the command with the mismatching Unix user.
        let CommandOutput {
            status,
            command,
            stderr,
            ..
        } = run_command_as_user(
            PAYLOAD,
            &[backend_kind, user, "--current-user"],
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            unix_user,
        )?;

        assert!(!status.success());

        with_settings!({
            description => format!("Calling Unix user != usermapping system user ({command})"),
            filters => vec![(r"\b[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\b", "TIMESTAMP")],
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), stderr);
        });

        collect_coverage_files("/tmp")?;

        Ok(())
    }
}
