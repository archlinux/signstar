//! Integration tests for [`signstar_config::yubihsm2::admin_credentials`].

use std::{
    fs::{File, create_dir_all},
    io::Write,
};

use log::{LevelFilter, debug};
use rstest::{fixture, rstest};
use signstar_common::{
    admin_credentials::{get_plaintext_credentials_file, get_systemd_creds_credentials_file},
    logging::setup_terminal_logging,
};
use signstar_config::{
    admin_credentials::AdminCredentials,
    test::{ConfigFileConfig, ConfigFileVariant, SystemPrepareConfig},
    yubihsm2::admin_credentials::YubiHsm2AdminCredentials,
};
use signstar_crypto::AdministrativeSecretHandling;
use signstar_yubihsm2::Credentials;
use testresult::TestResult;

/// Admin credentials for a YubiHSM2.
const SIGNSTAR_ADMIN_CREDS: &[u8] = include_bytes!("../fixtures/admin_credentials/yubihsm2.toml");

#[fixture]
fn default_creds() -> TestResult<YubiHsm2AdminCredentials> {
    Ok(YubiHsm2AdminCredentials::new(
        1,
        "backup-passphras-really-just-for-testing-i-promise-but-it-is-really-really-long-sufficiently-long-reallye".parse()?,
        vec![
            Credentials::new("1".parse()?, "admin-passphrase-really-just-for-testing-i-promise".parse()?),
            Credentials::new("2".parse()?, "other-admin-passphrase-really-just-for-testing-i-promise".parse()?),
        ],
    )?)
}

/// Ensures that loading fails if the target is not a file.
#[test]
fn fail_to_load_on_path_not_a_file() -> TestResult {
    // Instead of a file, create a directory.
    let credentials_file = get_plaintext_credentials_file();
    create_dir_all(&credentials_file)?;

    match YubiHsm2AdminCredentials::load(AdministrativeSecretHandling::Plaintext) {
        Err(signstar_config::Error::AdminSecretHandling(
            signstar_config::admin_credentials::Error::CredsFileNotAFile { .. },
        )) => {}
        Ok(creds) => {
            panic!("Should have failed with Error::CredsFileNotAFile but succeeded:\n{creds:?}")
        }
        Err(error) => panic!(
            "Should have failed with Error::CredsFileNotAFile but returned different error:\n{error}"
        ),
    }

    Ok(())
}

/// Ensures that loading fails if the target file does not exist.
#[test]
fn fail_to_load_on_missing_file() -> TestResult {
    match YubiHsm2AdminCredentials::load(AdministrativeSecretHandling::Plaintext) {
        Err(signstar_config::Error::AdminSecretHandling(
            signstar_config::admin_credentials::Error::CredsFileMissing { .. },
        )) => {}
        Ok(creds) => {
            panic!("Should have failed with Error::CredsFileMissing but succeeded:\n{creds:?}")
        }
        Err(error) => panic!(
            "Should have failed with Error::CredsFileMissing but returned different error:\n{error}"
        ),
    }

    Ok(())
}

/// Ensures that the admin credentials can be stored in the default location and read from it.
#[rstest]
#[case::plaintext(AdministrativeSecretHandling::Plaintext)]
#[case::systemd_creds(AdministrativeSecretHandling::SystemdCreds)]
fn store_to_and_load_from_default_location(
    #[case] handling: AdministrativeSecretHandling,
    default_creds: TestResult<YubiHsm2AdminCredentials>,
) -> TestResult {
    setup_terminal_logging(LevelFilter::Debug)?;
    // Prepare the environment.
    let config = SystemPrepareConfig {
        machine_id: true,
        credentials_socket: true,
        signstar_config: ConfigFileConfig {
            location: None,
            variant: ConfigFileVariant::NoBackendAdminPlaintextNonAdminPlaintext,
            system_user_config: None,
        },
    };
    let _socket = config.apply()?;

    let default_creds = default_creds?;
    let config_path = match handling {
        AdministrativeSecretHandling::Plaintext => {
            let config_path = get_plaintext_credentials_file();
            debug!("config path: {config_path:?}");
            if let Some(path) = config_path.parent() {
                create_dir_all(path)?;
            }

            // Check if the plaintext representation matches the fixture
            let mut file = File::create(&config_path)?;
            file.write_all(SIGNSTAR_ADMIN_CREDS)?;
            let creds = YubiHsm2AdminCredentials::load(handling)?;
            assert_eq!(format!("{creds:?}"), format!("{default_creds:?}"));

            config_path
        }
        AdministrativeSecretHandling::SystemdCreds => get_systemd_creds_credentials_file(),
        AdministrativeSecretHandling::ShamirsSecretSharing { .. } => {
            unimplemented!("SSS is not yet supported")
        }
    };

    default_creds.store(handling)?;

    let creds = YubiHsm2AdminCredentials::load(handling)?;
    assert_eq!(format!("{creds:?}"), format!("{default_creds:?}"));

    let creds = YubiHsm2AdminCredentials::load_from_file(&config_path, handling)?;
    assert_eq!(format!("{creds:?}"), format!("{default_creds:?}"));

    Ok(())
}
