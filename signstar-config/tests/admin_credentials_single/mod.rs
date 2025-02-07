use std::{
    fs::{copy, create_dir_all, read_to_string},
    path::PathBuf,
};

use nethsm::UserId;
use nethsm_config::AdministrativeSecretHandling;
use rstest::rstest;
use signstar_config::admin_credentials::{
    AdminCredentials,
    User,
    load_admin_creds,
    store_admin_creds,
};
use signstar_core::admin_credentials::{
    create_credentials_dir,
    get_credentials_dir,
    get_plaintext_credentials_file,
    get_systemd_creds_credentials_file,
};
use tempfile::NamedTempFile;
use testresult::TestResult;

use super::utils::write_machine_id;

#[rstest]
fn fail_to_load_on_path_not_a_file() -> TestResult {
    let credentials_file = get_plaintext_credentials_file();
    create_dir_all(&credentials_file)?;
    if let Err(error) = AdminCredentials::load(&credentials_file) {
        assert_eq!(
            error.to_string(),
            format!("The credentials path is not a file: {credentials_file:?}")
        );
    } else {
        panic!("Did not return an error!")
    }
    Ok(())
}

/// Copies a plaintext TOML containing admin credentials to the default location and loads it.
#[rstest]
fn load_plaintext_toml(
    #[files("creds.toml")]
    #[base_dir = "tests/admin_credentials_single/fixtures/"]
    config_file: PathBuf,
) -> TestResult {
    create_credentials_dir()?;

    copy(config_file, get_plaintext_credentials_file())?;

    let creds = AdminCredentials::load_plaintext()?;
    println!("{creds:?}");
    Ok(())
}

/// Stores as plaintext TOML in the default location and compares to a fixture.
#[rstest]
fn store_plaintext_toml(
    #[files("creds.toml")]
    #[base_dir = "tests/admin_credentials_single/fixtures/"]
    config_file: PathBuf,
) -> TestResult {
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
fn store_and_load_systemd_creds(
    #[files("creds.toml")]
    #[base_dir = "tests/admin_credentials_single/fixtures/"]
    config_file: PathBuf,
) -> TestResult {
    write_machine_id()?;

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
    #[files("creds.toml")]
    #[base_dir = "tests/admin_credentials_single/fixtures/"]
    config_file: PathBuf,
    #[case] handling: AdministrativeSecretHandling,
) -> TestResult {
    write_machine_id()?;

    // force remove any files that may be present in the persistent location
    let _remove = std::fs::remove_dir_all(get_credentials_dir());
    create_credentials_dir()?;

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
    #[files("creds.toml")]
    #[base_dir = "tests/admin_credentials_single/fixtures/"]
    config_file: PathBuf,
    #[case] handling: AdministrativeSecretHandling,
) -> TestResult {
    write_machine_id()?;

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
