//! Tests for system features such as backups.

use chrono::Utc;
use log::LevelFilter;
use nethsm::test::{
    ADMIN_USER_ID,
    BACKUP_USER_ID,
    NetHsmImage,
    nethsm_with_users,
    unprovisioned_nethsm,
};
use nethsm::{Connection, ConnectionSecurity, NetHsm, Passphrase, UserId};
use rstest::rstest;
use rustainers::Container;
use signstar_common::{logging::setup_logging, traits::BackendCheck};
use testdir::testdir;
use testresult::TestResult;

#[rstest]
#[tokio::test]
async fn create_backup_and_restore(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let backup_file = testdir!().join("nethsm-backup");
    let initial_passphrase = "";
    let new_backup_passphrase = "just-a-backup-passphrase";
    let admin_user_id: UserId = ADMIN_USER_ID.parse()?;
    let backup_user_id: UserId = BACKUP_USER_ID.parse()?;

    // users in Backup role can receive backups
    nethsm.use_credentials(&backup_user_id)?;
    // fails because the backup passphrase is not yet set!
    assert!(nethsm.backup().is_err());

    // set backup passphrase
    nethsm.use_credentials(&admin_user_id)?;
    nethsm.set_backup_passphrase(
        Passphrase::new(initial_passphrase.to_string()),
        Passphrase::new(new_backup_passphrase.to_string()),
    )?;

    nethsm.use_credentials(&backup_user_id)?;
    // write backup file
    let backup = nethsm.backup()?;
    std::fs::write(&backup_file, backup.clone())?;
    println!("Written NetHSM backup file: {:?}", backup_file);

    // use the admin user again for the restore call
    nethsm.use_credentials(&admin_user_id)?;
    nethsm.restore(
        Passphrase::new(new_backup_passphrase.to_string()),
        Utc::now(),
        std::fs::read(backup_file)?,
    )?;

    Ok(())
}

#[rstest]
#[tokio::test]
async fn system_info(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = unprovisioned_nethsm.await?;
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("Retrieving system info for unprovisioned device...");
    assert!(unprovisioned_nethsm.system_info().is_err());

    println!("Retrieving system info for operational device...");
    assert!(nethsm.system_info().is_ok());
    println!("{:?}", nethsm.system_info()?);

    Ok(())
}

/// Ensures, that if a NetHSM container is available at a URL, [`Connection::is_available`] returns
/// `true`.
#[rstest]
#[tokio::test]
async fn connection_is_available_succeeds(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (nethsm, _container) = unprovisioned_nethsm.await?;
    let connection = Connection::new(nethsm.get_url(), ConnectionSecurity::Unsafe);
    assert!(connection.is_available());

    Ok(())
}

/// Ensures, that if a NetHSM is not available at a URL, [`Connection::is_available`] returns
/// `false`.
#[rstest]
fn connection_is_available_fails() -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let connection = Connection::new(
        "https://127.0.0.1:12345/this/probably/does/not/exist/".parse()?,
        ConnectionSecurity::Unsafe,
    );
    assert!(!connection.is_available());

    Ok(())
}

/// Ensures, that if a NetHSM container is provisioned, [`Connection::is_provisioned`]
/// returns `false`.
#[rstest]
#[tokio::test]
async fn connection_is_provisioned_returns_false(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (nethsm, _container) = unprovisioned_nethsm.await?;
    let connection = Connection::new(nethsm.get_url(), ConnectionSecurity::Unsafe);
    assert!(connection.is_provisioned());

    Ok(())
}

/// Ensures, that if a NetHSM container is unprovisioned, [`Connection::is_provisioned`]
/// returns `false`.
#[rstest]
#[tokio::test]
async fn connection_is_provisioned_returns_true(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let (nethsm, _container) = nethsm_with_users.await?;
    let connection = Connection::new(nethsm.get_url(), ConnectionSecurity::Unsafe);
    assert!(!connection.is_provisioned());

    Ok(())
}
