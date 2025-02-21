use nethsm::{NetHsm, Passphrase, UserId};
use nethsm_backup::Backup;
use nethsm_tests::{ADMIN_USER_ID, BACKUP_USER_ID, NetHsmImage, nethsm_with_users};
use rstest::rstest;
use rustainers::Container;
use testdir::testdir;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn create_backup_and_decrypt_it(
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

    let backup = Backup::parse(std::fs::File::open(&backup_file)?)?;
    let backup = backup.decrypt(new_backup_passphrase.as_bytes())?;

    assert_eq!(backup.version()?, [0]);

    for item in backup.items_iter() {
        let key = item?.0;
        println!("{key}");
    }

    Ok(())
}
