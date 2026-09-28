//! Integration tests for [`signstar_crypto::secret_file`].

use std::collections::HashMap;

use change_user_run::{CommandOutput, create_users, run_command_as_user};
use log::LevelFilter;
use rstest::rstest;
use signstar_common::{logging::setup_terminal_logging, system_user::get_home_base_dir_path};
use testresult::TestResult;

/// The location of cargo-llvm-cov `.profraw` files when running a command as a different user.
const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

/// Tests for the reading and writing of non-administrative secrets.
mod non_admin {
    use change_user_run::{COVERAGE_ENV_LIST, collect_coverage_data};
    use nix::unistd::User;
    use signstar_crypto::{
        NonAdministrativeSecretHandling,
        passphrase::Passphrase,
        secret_file::write_passphrase_to_secrets_file,
        test::start_credentials_socket,
    };

    use super::*;

    const PAYLOAD: &str = "/usr/local/bin/examples/load-non-admin-secret";
    const SYSTEM_USER: &str = "test-user";
    const BACKEND_USER: &str = "backend";
    const DUMMY_PASSPHRASE: &str = "DUMMY-PASSPHRASE";

    /// Ensures that a passphrase can be written to a secrets file and read from it again.
    ///
    /// Tests integration with `systemd-creds` encrypted secrets and plaintext secrets.
    #[rstest]
    #[case::plaintext(NonAdministrativeSecretHandling::Plaintext)]
    #[case::systemd_creds(NonAdministrativeSecretHandling::SystemdCreds)]
    fn load_credentials_for_user_succeeds(
        #[case] secret_handling: NonAdministrativeSecretHandling,
    ) -> TestResult {
        setup_terminal_logging(LevelFilter::Debug)?;

        let _credentials_socket = start_credentials_socket()?;
        let passphrase = Passphrase::new(DUMMY_PASSPHRASE.to_string());

        // Create non-administrative system user.
        create_users(&[SYSTEM_USER], Some(&get_home_base_dir_path()), None)?;
        let system_user = User::from_name(SYSTEM_USER)?.expect("a valid username");

        // Write passphrase to secrets file as user.
        write_passphrase_to_secrets_file(secret_handling, &system_user, BACKEND_USER, &passphrase)?;

        // Read secrets file as the non-administrative user.
        let CommandOutput {
            status,
            command,
            stderr,
            stdout,
        } = run_command_as_user(
            PAYLOAD,
            &[secret_handling.as_ref(), BACKEND_USER],
            None,
            COVERAGE_ENV_LIST,
            Some(HashMap::from([(
                "LLVM_PROFILE_FILE".to_string(),
                LLVM_PROFILE_FILE.to_string(),
            )])),
            &system_user.name,
        )?;

        if !status.success() {
            panic!(
                "{}",
                signstar_crypto::secret_file::Error::CommandNonZero {
                    command,
                    exit_status: status,
                    stderr,
                }
            );
        }

        assert_eq!(stdout, DUMMY_PASSPHRASE);

        collect_coverage_data("/tmp")?;

        Ok(())
    }
}
