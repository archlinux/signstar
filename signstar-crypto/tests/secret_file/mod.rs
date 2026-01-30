//! Integration tests for [`signstar_crypto::secret_file`].

use std::{
    collections::HashMap,
    env::var,
    fs::copy,
    os::unix::fs::chown,
    path::{Path, PathBuf},
};

use change_user_run::{CommandOutput, create_users, run_command_as_user};
use log::{LevelFilter, debug};
use rstest::rstest;
use signstar_common::{logging::setup_logging, system_user::get_home_base_dir_path};
use testresult::TestResult;

/// Environment variables that are passed in to a command call as a different user.
const ENV_LIST: &[&str] = &[
    "LLVM_PROFILE_FILE",
    "CARGO_LLVM_COV",
    "CARGO_LLVM_COV_SHOW_ENV",
    "CARGO_LLVM_COV_TARGET_DIR",
    "RUSTFLAGS",
    "RUSTDOCFLAGS",
];
/// The location of cargo-llvm-cov `.profraw` files when running a command as a different user.
const LLVM_PROFILE_FILE: &str = "/tmp/signstar-%p-%16m.profraw";

/// Collects all `.profraw` files from `path` and copies them to `CARGO_LLVM_COV_TARGET_DIR`.
///
/// Only copies files from `path` if the `CARGO_LLVM_COV_TARGET_DIR` environment variable is set.
/// Changes the ownership of files copied to `CARGO_LLVM_COV_TARGET_DIR` to root.
///
/// # Errors
///
/// Returns an error if
///
/// - `path` cannot be read,
/// - an entry in `path` cannot be read,
/// - copying a file from `path` to `CARGO_LLVM_COV_TARGET_DIR` fails,
/// - or changing the ownership permissions of a copied file in `CARGO_LLVM_COV_TARGET_DIR` to root
///   fails.
fn collect_coverage_files(path: impl AsRef<Path>) -> TestResult {
    let path = path.as_ref();

    let Ok(cov_target_dir) = var("CARGO_LLVM_COV_TARGET_DIR") else {
        return Ok(());
    };
    debug!("Found CARGO_LLVM_COV_TARGET_DIR={cov_target_dir}");
    let cov_target_dir = PathBuf::from(cov_target_dir);

    for dir_entry in path.read_dir()? {
        let dir_entry = dir_entry?;
        let from = dir_entry.path();
        let Some(file_name) = &from.file_name() else {
            continue;
        };
        if let Some(extension) = from.extension()
            && extension == "profraw"
        {
            let target_file = cov_target_dir.join(file_name);
            debug!("Copying {from:?} to {target_file:?}");
            copy(&from, &target_file)?;
            chown(&target_file, Some(0), Some(0))?;
        }
    }

    Ok(())
}

/// Tests for the reading and writing of non-administrative secrets.
mod non_admin {
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
        setup_logging(LevelFilter::Debug)?;

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
            &[&secret_handling.to_string(), BACKEND_USER],
            None,
            ENV_LIST,
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

        collect_coverage_files("/tmp")?;

        Ok(())
    }
}
