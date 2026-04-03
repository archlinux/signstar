//! Integration tests for implementations of
//! [`signstar_config::config::traits::MappingSystemUserId`].

#[cfg(feature = "nethsm")]
mod nethsm {
    use std::{collections::HashMap, thread::current};

    use change_user_run::{CommandOutput, create_users, run_command_as_user};
    use insta::{assert_snapshot, with_settings};
    use log::LevelFilter;
    use rstest::rstest;
    use signstar_common::common::get_data_home;
    use signstar_common::{logging::setup_logging, system_user::get_home_base_dir_path};
    use signstar_config::test::{list_files_in_dir, start_credentials_socket, write_machine_id};
    use signstar_crypto::NonAdministrativeSecretHandling;
    use testresult::TestResult;

    use crate::{ENV_LIST, LLVM_PROFILE_FILE, collect_coverage_files};

    const NON_ADMIN_SECRETS_PAYLOAD: &str = "/usr/local/bin/examples/usermapping-non-admin-secrets";
    const PAYLOAD: &str = "/usr/local/bin/examples/usermapping-system-user-info";
    const SNAPSHOT_PATH: &str = "/test/tests/usermapping/fixtures/";

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

    /// Creates and loads the secrets for non-administrative users of a user mapping.
    #[rstest]
    #[case::admin_plaintext("nethsm-admin", None, NonAdministrativeSecretHandling::Plaintext)]
    #[case::backup_plaintext(
        "nethsm-backup",
        Some("backup"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::hermetic_metrics_plaintext(
        "nethsm-hermetic-metrics",
        Some("hermetic-metrics"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::metrics_plaintext(
        "nethsm-metrics",
        Some("metrics"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::signing_plaintext(
        "nethsm-signing",
        Some("signing"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::admin_systemd_creds(
        "nethsm-admin",
        None,
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::backup_systemd_creds(
        "nethsm-backup",
        Some("backup"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::hermetic_metrics_systemd_creds(
        "nethsm-hermetic-metrics",
        Some("hermetic-metrics"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::metrics_systemd_creds(
        "nethsm-metrics",
        Some("metrics"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::signing_systemd_creds(
        "nethsm-signing",
        Some("signing"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    fn create_and_load_non_admin_secrets_succeeds(
        #[case] backend_kind: &str,
        #[case] user: Option<&str>,
        #[case] secret_handling: NonAdministrativeSecretHandling,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        // Prepare the test environment.
        write_machine_id()?;
        let _socket = start_credentials_socket()?;
        // Create unix user and its home
        if let Some(user) = user {
            create_users(&[user], Some(&get_home_base_dir_path()), None)?;
        }

        // Create secret files.
        let create_options = {
            let mut options = vec!["--backend-mapping-kind", backend_kind];
            if let Some(user) = user {
                options.push("--system-user");
                options.push(user);
            }
            options.push("create");
            options.push("--secret-handling");
            options.push(secret_handling.as_ref());
            options
        };
        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
            ..
        } = run_command_as_user(
            NON_ADMIN_SECRETS_PAYLOAD,
            &create_options,
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            "root",
        )?;
        let create_output = stdout;
        eprintln!("{NON_ADMIN_SECRETS_PAYLOAD} stderr:\n{stderr}");

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

        // Collect coverage files for the creation of secrets.
        collect_coverage_files("/tmp")?;

        if user.is_some() {
            // List all files and directories in the data home.
            list_files_in_dir(get_data_home())?;
        }

        // Load secret files.
        let load_options = {
            let mut options = vec!["--backend-mapping-kind", backend_kind];
            if let Some(user) = user {
                options.push("--system-user");
                options.push(user);
            }
            options.push("load");
            options.push("--secret-handling");
            options.push(secret_handling.as_ref());
            options
        };

        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
            ..
        } = run_command_as_user(
            NON_ADMIN_SECRETS_PAYLOAD,
            &load_options,
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
        let load_output = stdout;

        assert_eq!(create_output, load_output);

        with_settings!({
            description => format!("Matching created and loaded passphrases for backend users ({command})"),
            filters => vec![(r"([0-9A-Za-z]+){30}", "PASSPHRASE")],
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), load_output);
        });

        // Collect coverage files for the loading of secrets.
        collect_coverage_files("/tmp")?;

        Ok(())
    }
}

#[cfg(feature = "yubihsm2")]
mod yubihsm2 {
    use std::{collections::HashMap, thread::current};

    use change_user_run::{CommandOutput, create_users, run_command_as_user};
    use insta::{assert_snapshot, with_settings};
    use log::LevelFilter;
    use rstest::rstest;
    use signstar_common::common::get_data_home;
    use signstar_common::{logging::setup_logging, system_user::get_home_base_dir_path};
    use signstar_config::test::{list_files_in_dir, start_credentials_socket, write_machine_id};
    use signstar_crypto::NonAdministrativeSecretHandling;
    use testresult::TestResult;

    use crate::{ENV_LIST, LLVM_PROFILE_FILE, collect_coverage_files};

    const NON_ADMIN_SECRETS_PAYLOAD: &str = "/usr/local/bin/examples/usermapping-non-admin-secrets";
    const PAYLOAD: &str = "/usr/local/bin/examples/usermapping-system-user-info";
    const SNAPSHOT_PATH: &str = "/test/tests/usermapping/fixtures/";

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

    /// Creates and loads the secrets for non-administrative users of a user mapping.
    #[rstest]
    #[case::admin_plaintext("yubihsm2-admin", None, NonAdministrativeSecretHandling::Plaintext)]
    #[case::backup(
        "yubihsm2-backup",
        Some("backup"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::hermetic_audit_log_plaintext(
        "yubihsm2-hermetic-audit-log",
        Some("hermetic-metrics"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::audit_log_plaintext(
        "yubihsm2-audit-log",
        Some("metrics"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::signing_plaintext(
        "yubihsm2-signing",
        Some("signing"),
        NonAdministrativeSecretHandling::Plaintext
    )]
    #[case::admin_systemd_creds(
        "yubihsm2-admin",
        None,
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::backup_systemd_creds(
        "yubihsm2-backup",
        Some("backup"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::hermetic_audit_log_systemd_creds(
        "yubihsm2-hermetic-audit-log",
        Some("hermetic-metrics"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::audit_log_systemd_creds(
        "yubihsm2-audit-log",
        Some("metrics"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    #[case::signing_systemd_creds(
        "yubihsm2-signing",
        Some("signing"),
        NonAdministrativeSecretHandling::SystemdCreds
    )]
    fn create_and_load_non_admin_secrets_succeeds(
        #[case] backend_kind: &str,
        #[case] system_user: Option<&str>,
        #[case] secret_handling: NonAdministrativeSecretHandling,
    ) -> TestResult {
        setup_logging(LevelFilter::Debug)?;

        // Prepare the test environment.
        write_machine_id()?;
        let _socket = start_credentials_socket()?;
        // Create unix user and its home
        if let Some(user) = system_user {
            create_users(&[user], Some(&get_home_base_dir_path()), None)?;
        }

        // Create secret files.
        let create_options = {
            let mut options = vec!["--backend-mapping-kind", backend_kind];
            if let Some(system_user) = system_user {
                options.push("--system-user");
                options.push(system_user);
            }
            options.push("create");
            options.push("--secret-handling");
            options.push(secret_handling.as_ref());
            options
        };
        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
            ..
        } = run_command_as_user(
            NON_ADMIN_SECRETS_PAYLOAD,
            &create_options,
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            "root",
        )?;
        let create_output = stdout;
        eprintln!("{NON_ADMIN_SECRETS_PAYLOAD} stderr:\n{stderr}");

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

        // Collect coverage files for the creation of secrets.
        collect_coverage_files("/tmp")?;

        if system_user.is_some() {
            // List all files and directories in the data home.
            list_files_in_dir(get_data_home())?;
        }

        // Load secret files.
        let load_options = {
            let mut options = vec!["--backend-mapping-kind", backend_kind];
            if let Some(user) = system_user {
                options.push("--system-user");
                options.push(user);
            }
            options.push("load");
            options.push("--secret-handling");
            options.push(secret_handling.as_ref());
            options
        };
        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
            ..
        } = run_command_as_user(
            NON_ADMIN_SECRETS_PAYLOAD,
            &load_options,
            None,
            ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            system_user.unwrap_or("root"),
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
        let load_output = stdout;

        assert_eq!(create_output, load_output);

        with_settings!({
            description => format!("Matching created and loaded passphrases for backend users ({command})"),
            filters => vec![(r"([0-9A-Za-z]+){30}", "PASSPHRASE")],
            snapshot_path => SNAPSHOT_PATH,
            prepend_module_to_snapshot => false,
        }, {
            assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), load_output);
        });

        // Collect coverage files for the loading of secrets.
        collect_coverage_files("/tmp")?;

        Ok(())
    }
}
