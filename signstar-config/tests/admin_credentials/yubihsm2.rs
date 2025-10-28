//! Integration tests for [`signstar_config::yubihsm2::admin_credentials`].

use std::{
    fs::{File, create_dir_all},
    io::Write,
};

use rstest::{fixture, rstest};
use signstar_common::admin_credentials::{
    create_credentials_dir,
    get_plaintext_credentials_file,
    get_systemd_creds_credentials_file,
};
use signstar_config::{
    AdminCredentials,
    AdministrativeSecretHandling,
    test::write_machine_id,
    yubihsm2::admin_credentials::YubiHsm2AdminCredentials,
};
use signstar_yubihsm2::Credentials;
use testresult::TestResult;

/// Admin credentials for a YubiHSM2.
const SIGNSTAR_ADMIN_CREDS: &[u8] = include_bytes!("../fixtures/admin_credentials/yubihsm2.toml");

#[fixture]
fn default_creds() -> TestResult<YubiHsm2AdminCredentials> {
    Ok(YubiHsm2AdminCredentials::new(
        1,
        "backup-passphrase".parse()?,
        vec![
            Credentials::new(1, "admin-passphrase".parse()?),
            Credentials::new(2, "other-admin-passphrase".parse()?),
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
            return Err(format!(
                "Should have failed with Error::CredsFileNotAFile but succeeded:\n{creds:?}"
            )
            .into());
        }
        Err(error) => {
            return Err(format!(
                "Should have failed with Error::CredsFileNotAFile but returned different error:\n{error}"
            )
            .into());
        }
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
            return Err(format!(
                "Should have failed with Error::CredsFileMissing but succeeded:\n{creds:?}"
            )
            .into());
        }
        Err(error) => {
            return Err(format!(
                "Should have failed with Error::CredsFileMissing but returned different error:\n{error}"
            )
            .into());
        }
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
    // Prepare the environment.
    write_machine_id()?;
    create_credentials_dir()?;

    let default_creds = default_creds?;
    let config_path = match handling {
        AdministrativeSecretHandling::Plaintext => {
            let config_path = get_plaintext_credentials_file();

            // Check if the plaintext representation matches the fixture
            let mut file = File::create(&config_path)?;
            file.write_all(SIGNSTAR_ADMIN_CREDS)?;
            let creds = YubiHsm2AdminCredentials::load(handling)?;
            assert_eq!(format!("{creds:?}"), format!("{default_creds:?}"));

            config_path
        }
        AdministrativeSecretHandling::SystemdCreds => get_systemd_creds_credentials_file(),
        AdministrativeSecretHandling::ShamirsSecretSharing => {
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
