use std::fs::{copy, create_dir_all, read_to_string};

use nethsm::UserId;
use nethsm_config::AdministrativeSecretHandling;
use rstest::rstest;
use signstar_common::admin_credentials::{
    create_credentials_dir,
    get_credentials_dir,
    get_plaintext_credentials_file,
    get_systemd_creds_credentials_file,
};
use signstar_config::admin_credentials::{
    AdminCredentials,
    User,
    load_admin_creds,
    store_admin_creds,
};
use tempfile::NamedTempFile;
use testresult::TestResult;

use super::utils::write_machine_id;
use crate::utils::{SIGNSTAR_ADMIN_CREDS_SIMPLE, get_tmp_config};

#[rstest]
fn fail_to_load_on_path_not_a_file() -> TestResult {
    let credentials_file = get_plaintext_credentials_file();
    create_dir_all(&credentials_file)?;
    if let Err(error) = AdminCredentials::load(&credentials_file) {
        if let signstar_config::Error::AdminSecretHandling(
            signstar_config::admin_credentials::Error::CredsFileNotAFile { path },
        ) = error
        {
            assert_eq!(credentials_file, path)
        } else {
            panic!("Did not return an the correct error variant!")
        }
    } else {
        panic!("Did not return an error!")
    }
    Ok(())
}

/// Copies a plaintext TOML containing admin credentials to the default location and loads it.
#[rstest]
fn load_plaintext_toml() -> TestResult {
    create_credentials_dir()?;
    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;

    copy(config_file, get_plaintext_credentials_file())?;

    let creds = AdminCredentials::load_plaintext()?;
    println!("{creds:?}");
    Ok(())
}

/// Stores as plaintext TOML in the default location and compares to a fixture.
#[rstest]
fn store_plaintext_toml() -> TestResult {
    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;
    let creds = AdminCredentials::new(
        1,
        "backup-passphrase".to_string(),
        "unlock-passphrase".to_string(),
        vec![User::new(
            UserId::new("admin".to_string())?,
            "admin-passphrase".to_string(),
        )],
        vec![User::new(
            UserId::new("ns1~admin".to_string())?,
            "ns1-admin-passphrase".to_string(),
        )],
    );
    creds.store_plaintext()?;

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
    let creds = AdminCredentials::load(&config_file)?;

    println!("Store systemd-creds encrypted");
    creds.store_systemd_creds()?;

    println!("Load systemd-creds encrypted");
    let read_creds = AdminCredentials::load_systemd_creds()?;

    println!("Write systemd-creds encrypted to plaintext");
    let tmp_file = NamedTempFile::new()?;
    read_creds.store(tmp_file.path())?;

    println!("Compare plaintext of roundtripped and fixture");
    let creds_string = read_to_string(tmp_file.path())?;
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

    let config_file = get_tmp_config(SIGNSTAR_ADMIN_CREDS_SIMPLE)?;

    // force remove any files that may be present in the persistent location
    let _remove = std::fs::remove_dir_all(get_credentials_dir());
    create_credentials_dir()?;
    println!("fixture config: {config_file:?}");

    match handling {
        AdministrativeSecretHandling::Plaintext => {
            // make sure a dummy plaintext file exists
            copy(config_file, get_plaintext_credentials_file())?;

            load_admin_creds(handling)?;
        }
        AdministrativeSecretHandling::SystemdCreds => {
            // load AdminCredentials from plaintext fixture and store it systemd-creds encrypted
            let creds = AdminCredentials::load(&config_file)?;
            println!("Store systemd-creds encrypted ");
            creds.store_systemd_creds()?;

            load_admin_creds(handling)?;
        }
        AdministrativeSecretHandling::ShamirsSecretSharing => {
            unimplemented!("Shamir's Secret Sharing is not yet implemented!");
        }
    }

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
    let admin_creds = AdminCredentials::load(&config_file)?;

    // force remove any files that may be present in the persistent location
    let _remove = std::fs::remove_dir_all(get_credentials_dir());

    match handling {
        AdministrativeSecretHandling::Plaintext => {
            store_admin_creds(admin_creds, handling)?;
            assert!(get_plaintext_credentials_file().exists());
        }
        AdministrativeSecretHandling::SystemdCreds => {
            store_admin_creds(admin_creds, handling)?;
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
    if let Err(error) = AdminCredentials::load(credentials_file.as_path()) {
        if let signstar_config::Error::AdminSecretHandling(
            signstar_config::admin_credentials::Error::CredsFileMissing { path },
        ) = error
        {
            assert_eq!(credentials_file, path)
        } else {
            panic!("Did not return an the correct error variant!")
        }
    } else {
        panic!("Did not return an error!")
    }
    Ok(())
}
