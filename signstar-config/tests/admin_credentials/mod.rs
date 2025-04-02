//! Integration tests for [`signstar_config::admin_credentials`].
use std::fs::{copy, create_dir_all, read_to_string};

use nethsm::FullCredentials;
use nethsm_config::AdministrativeSecretHandling;
use rstest::rstest;
use signstar_common::admin_credentials::{
    create_credentials_dir,
    get_credentials_dir,
    get_plaintext_credentials_file,
    get_systemd_creds_credentials_file,
};
use signstar_config::admin_credentials::AdminCredentials;
use signstar_test::{get_tmp_config, write_machine_id};
use testresult::TestResult;

use crate::utils::SIGNSTAR_ADMIN_CREDS_SIMPLE;

#[rstest]
fn fail_to_load_on_path_not_a_file() -> TestResult {
    let credentials_file = get_plaintext_credentials_file();
    create_dir_all(&credentials_file)?;
    let error = AdminCredentials::load(AdministrativeSecretHandling::Plaintext)
        .expect_err("Did not return an error!");
    if let signstar_config::Error::AdminSecretHandling(
        signstar_config::admin_credentials::Error::CredsFileNotAFile { path },
    ) = error
    {
        assert_eq!(credentials_file, path)
    } else {
        panic!("Did not return an the correct error variant!")
    }

    Ok(())
}

/// Copies a plaintext TOML containing admin credentials to the default location and loads it.
#[rstest]
fn load_plaintext_toml() -> TestResult {
    create_credentials_dir()?;
    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;

    copy(config_file, get_plaintext_credentials_file())?;

    let creds = AdminCredentials::load(AdministrativeSecretHandling::Plaintext)?;
    println!("{creds:?}");
    Ok(())
}

/// Stores as plaintext TOML in the default location and compares to a fixture.
#[rstest]
fn store_plaintext_toml() -> TestResult {
    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;
    let creds = AdminCredentials::new(
        1,
        "backup-passphrase".parse()?,
        "unlock-passphrase".parse()?,
        vec![FullCredentials::new(
            "admin".parse()?,
            "admin-passphrase".parse()?,
        )],
        vec![FullCredentials::new(
            "ns1~admin".parse()?,
            "ns1-admin-passphrase".parse()?,
        )],
    )?;
    creds.store(AdministrativeSecretHandling::Plaintext)?;

    let creds_string = read_to_string(get_plaintext_credentials_file())?;
    let fixture_string = read_to_string(config_file)?;
    assert_eq!(creds_string, fixture_string);
    Ok(())
}

/// Stores as systemd-creds encrypted TOML in the default location and compares to a fixture.
#[rstest]
fn store_and_load_systemd_creds() -> TestResult {
    write_machine_id()?;

    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;

    // load AdminCredentials from plaintext fixture
    let creds =
        AdminCredentials::load_from_file(&config_file, AdministrativeSecretHandling::Plaintext)?;

    println!("Store systemd-creds encrypted");
    creds.store(AdministrativeSecretHandling::SystemdCreds)?;

    println!("Load systemd-creds encrypted");
    let read_creds = AdminCredentials::load(AdministrativeSecretHandling::SystemdCreds)?;

    println!("Write systemd-creds encrypted to plaintext");
    read_creds.store(AdministrativeSecretHandling::Plaintext)?;

    println!("Compare plaintext of roundtripped and fixture");
    let creds_string = read_to_string(get_plaintext_credentials_file())?;
    let fixture_string = read_to_string(&config_file)?;
    assert_eq!(creds_string, fixture_string);
    Ok(())
}

#[rstest]
#[case(AdministrativeSecretHandling::Plaintext)]
#[case(AdministrativeSecretHandling::SystemdCreds)]
fn load_admin_creds_from_default_location(
    #[case] handling: AdministrativeSecretHandling,
) -> TestResult {
    write_machine_id()?;
    create_credentials_dir()?;
    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;

    match handling {
        AdministrativeSecretHandling::Plaintext => {
            // make sure a dummy plaintext file exists
            copy(config_file, get_plaintext_credentials_file())?;
        }
        AdministrativeSecretHandling::SystemdCreds => {
            // load AdminCredentials from plaintext fixture and store it systemd-creds encrypted
            let creds = AdminCredentials::load_from_file(
                &config_file,
                AdministrativeSecretHandling::Plaintext,
            )?;
            creds.store(AdministrativeSecretHandling::SystemdCreds)?;
        }
        AdministrativeSecretHandling::ShamirsSecretSharing => {
            unimplemented!("Shamir's Secret Sharing is not yet implemented!");
        }
    }
    AdminCredentials::load(handling)?;

    Ok(())
}

#[rstest]
#[case(AdministrativeSecretHandling::Plaintext)]
#[case(AdministrativeSecretHandling::SystemdCreds)]
fn store_admin_creds_to_default_location(
    #[case] handling: AdministrativeSecretHandling,
) -> TestResult {
    write_machine_id()?;

    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;

    // load credentials from plaintext fixture
    let admin_creds =
        AdminCredentials::load_from_file(&config_file, AdministrativeSecretHandling::Plaintext)?;

    // force remove any files that may be present in the persistent location
    let _remove = std::fs::remove_dir_all(get_credentials_dir());
    admin_creds.store(handling)?;

    match handling {
        AdministrativeSecretHandling::Plaintext => {
            assert!(get_plaintext_credentials_file().exists());
        }
        AdministrativeSecretHandling::SystemdCreds => {
            assert!(get_systemd_creds_credentials_file().exists());
        }
        AdministrativeSecretHandling::ShamirsSecretSharing => {
            unimplemented!("Shamir's Secret Sharing is not yet implemented!");
        }
    }

    Ok(())
}

#[rstest]
fn fail_to_load_on_missing_file() -> TestResult {
    let credentials_file = get_plaintext_credentials_file();
    let error = AdminCredentials::load(AdministrativeSecretHandling::Plaintext)
        .expect_err("Did not return an error!");
    if let signstar_config::Error::AdminSecretHandling(
        signstar_config::admin_credentials::Error::CredsFileMissing { path },
    ) = error
    {
        assert_eq!(credentials_file, path)
    } else {
        panic!("Did not return an the correct error variant!")
    }

    Ok(())
}
