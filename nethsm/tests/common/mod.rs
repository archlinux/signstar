use std::fs::File;
use std::path::PathBuf;

use chrono::Utc;
use nethsm::{
    ConnectionSecurity,
    Credentials,
    KeyMechanism,
    KeyType,
    NetHsm,
    Passphrase,
    Url,
    UserRole,
};
use rstest::fixture;
use rustainers::runner::Runner;
use rustainers::Container;
use testresult::TestResult;

pub static ADMIN_USER_ID: &str = "admin";
pub static ADMIN_USER_PASSPHRASE: &str = "just-an-admin-passphrase";
pub static BACKUP_PASSPHRASE: &str = "just-a-backup-passphrase";
pub static UNLOCK_PASSPHRASE: &str = "just-an-unlock-passphrase";
pub static DEFAULT_OPERATOR_USER_ID: &str = "operator1";
pub static DEFAULT_OPERATOR_USER_REAL_NAME: &str = "Some Operator";
pub static DEFAULT_OPERATOR_USER_PASSPHRASE: &str = "just-an-operator-passphrase";
pub static OTHER_OPERATOR_USER_ID: &str = "operator2";
pub static OTHER_OPERATOR_USER_REAL_NAME: &str = "Some Other Operator";
pub static OTHER_OPERATOR_USER_PASSPHRASE: &str = "just-another-operator-passphrase";
pub static BACKUP_USER_ID: &str = "backup1";
pub static BACKUP_USER_REAL_NAME: &str = "Some Backup";
pub static BACKUP_USER_PASSPHRASE: &str = "just-a-backup-passphrase";
pub static METRICS_USER_ID: &str = "metrics1";
pub static METRICS_USER_REAL_NAME: &str = "Some Metrics";
pub static METRICS_USER_PASSPHRASE: &str = "just-a-metrics-passphrase";
pub static DEFAULT_RSA_BITS: i32 = 2048;
pub static DEFAULT_KEY_ID: &str = "key1";
pub static OTHER_KEY_ID: &str = "key2";
pub static DEFAULT_TAG: &str = "tag1";
pub static OTHER_TAG: &str = "tag2";
pub static ENC_KEY_ID: &str = "enckey1";
pub static ENC_TAG: &str = "enctag1";
pub static ENC_OPERATOR_USER_ID: &str = "encoperator1";
pub static ENC_OPERATOR_USER_REAL_NAME: &str = "Some Encryption Operator";
pub static ENC_OPERATOR_USER_PASSPHRASE: &str = "just-an-encryption-passphrase";
pub static DEFAULT_AES_BITS: i32 = 128;

mod container;
pub use container::NetHsmImage;

pub async fn create_container() -> TestResult<Container<NetHsmImage>> {
    let runner = Runner::podman()?;
    let image = NetHsmImage::default();
    println!("image: {:#?}", image.image);
    let container = runner.start(image).await?;
    println!("serving URL: {}", container.url().await?);
    Ok(container)
}

pub fn create_nethsm(url: Url) -> TestResult<NetHsm> {
    Ok(NetHsm::new(
        url,
        ConnectionSecurity::Unsafe,
        Some(Credentials::new(
            ADMIN_USER_ID.parse()?,
            Some(Passphrase::new(ADMIN_USER_PASSPHRASE.to_string())),
        )),
        None,
        None,
    )?)
}

#[fixture]
pub async fn unprovisioned_nethsm() -> TestResult<(NetHsm, rustainers::Container<NetHsmImage>)> {
    let container = create_container().await?;

    Ok((create_nethsm(container.url().await?)?, container))
}

fn provision_nethsm(nethsm: &NetHsm) -> TestResult {
    nethsm.provision(
        Passphrase::new(UNLOCK_PASSPHRASE.to_string()),
        Passphrase::new(ADMIN_USER_PASSPHRASE.to_string()),
        Utc::now(),
    )?;
    nethsm.set_backup_passphrase(
        Passphrase::new("".to_string()),
        Passphrase::new(BACKUP_PASSPHRASE.to_string()),
    )?;
    Ok(())
}

fn add_users_to_nethsm(nethsm: &NetHsm) -> TestResult {
    let users = [
        (
            UserRole::Operator,
            DEFAULT_OPERATOR_USER_ID,
            DEFAULT_OPERATOR_USER_PASSPHRASE,
            DEFAULT_OPERATOR_USER_REAL_NAME,
        ),
        (
            UserRole::Operator,
            OTHER_OPERATOR_USER_ID,
            OTHER_OPERATOR_USER_PASSPHRASE,
            OTHER_OPERATOR_USER_REAL_NAME,
        ),
        (
            UserRole::Operator,
            ENC_OPERATOR_USER_ID,
            ENC_OPERATOR_USER_PASSPHRASE,
            ENC_OPERATOR_USER_REAL_NAME,
        ),
        (
            UserRole::Metrics,
            METRICS_USER_ID,
            METRICS_USER_PASSPHRASE,
            METRICS_USER_REAL_NAME,
        ),
        (
            UserRole::Backup,
            BACKUP_USER_ID,
            BACKUP_USER_PASSPHRASE,
            BACKUP_USER_REAL_NAME,
        ),
    ];

    println!("Adding users to NetHSM...");
    for (role, user_id, passphrase, real_name) in users.into_iter() {
        nethsm.add_user(
            real_name.to_string(),
            role,
            Passphrase::new(passphrase.to_string()),
            Some(user_id.parse()?),
        )?;
    }
    println!("users: {:?}", nethsm.get_users()?);
    Ok(())
}

fn add_keys_to_nethsm(nethsm: &NetHsm) -> TestResult {
    let keys = [
        (
            vec![KeyMechanism::EdDsaSignature],
            KeyType::Curve25519,
            None,
            DEFAULT_KEY_ID,
            DEFAULT_TAG,
            DEFAULT_OPERATOR_USER_ID,
        ),
        (
            vec![
                KeyMechanism::RsaSignaturePkcs1,
                KeyMechanism::RsaDecryptionPkcs1,
            ],
            KeyType::Rsa,
            Some(DEFAULT_RSA_BITS),
            OTHER_KEY_ID,
            OTHER_TAG,
            OTHER_OPERATOR_USER_ID,
        ),
        (
            vec![
                KeyMechanism::AesDecryptionCbc,
                KeyMechanism::AesEncryptionCbc,
            ],
            KeyType::Generic,
            Some(DEFAULT_AES_BITS),
            ENC_KEY_ID,
            ENC_TAG,
            ENC_OPERATOR_USER_ID,
        ),
    ];

    println!("Adding keys to NetHSM...");
    for (mechanisms, key_type, length, key_id, tag, user_id) in keys {
        nethsm.generate_key(key_type, mechanisms, length, Some(key_id.to_string()), None)?;
        nethsm.add_key_tag(key_id, tag)?;
        nethsm.add_user_tag(&user_id.parse()?, tag)?;
        // skip symmetric keys, as for those we do not have a public key
        if key_type != KeyType::Generic {
            nethsm.import_key_certificate(key_id, nethsm.get_public_key(key_id)?.into_bytes())?;
        }
    }

    println!("users: {:?}", nethsm.get_users()?);
    println!("keys: {:?}", nethsm.get_keys(None)?);
    Ok(())
}

#[fixture]
pub async fn provisioned_nethsm() -> TestResult<(NetHsm, Container<NetHsmImage>)> {
    let container = create_container().await?;
    let nethsm = create_nethsm(container.url().await?)?;
    println!("Provisioning container...");
    provision_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

#[fixture]
pub async fn nethsm_with_users() -> TestResult<(NetHsm, Container<NetHsmImage>)> {
    let container = create_container().await?;
    let nethsm = create_nethsm(container.url().await?)?;
    println!("Provisioning container...");
    provision_nethsm(&nethsm)?;
    println!("Adding users to container...");
    add_users_to_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

#[fixture]
pub async fn nethsm_with_keys(
    #[future] provisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult<(NetHsm, Container<NetHsmImage>)> {
    let (nethsm, container) = provisioned_nethsm.await?;

    println!("Adding users and keys to container...");
    add_users_to_nethsm(&nethsm)?;
    add_keys_to_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

#[fixture]
pub fn update_file() -> TestResult<PathBuf> {
    let file_name = "update.img.bin";
    let update_link = format!(
        "https://raw.githubusercontent.com/Nitrokey/nethsm-sdk-py/main/tests/{}",
        file_name
    );
    let download_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let file = download_dir.join(file_name);

    if !file.exists() {
        let mut file_bytes = ureq::get(&update_link).call()?.into_reader();
        let mut file_writer = File::create(&file)?;
        std::io::copy(&mut file_bytes, &mut file_writer)?;
        assert!(file.exists());
    }

    println!("Update file downloaded: {:?}", file);
    Ok(file)
}
