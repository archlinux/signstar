use chrono::Utc;
use nethsm::{NetHsm, Passphrase, UserId};
use nethsm_tests::{
    nethsm_with_users,
    unprovisioned_nethsm,
    NetHsmImage,
    ADMIN_USER_ID,
    BACKUP_USER_ID,
};
use rstest::rstest;
use rustainers::Container;
use testdir::testdir;
use testresult::TestResult;

#[ignore = "requires Podman"]
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
    println!("Written NetHSM backup file: {:?}", &backup_file);

    // use the admin user again for the restore call
    nethsm.use_credentials(&admin_user_id)?;
    nethsm.restore(
        Passphrase::new(new_backup_passphrase.to_string()),
        Utc::now(),
        std::fs::read(backup_file)?,
    )?;

    Ok(())
}

#[ignore = "requires Podman"]
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
