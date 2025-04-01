#![doc = include_str!("../README.md")]

use std::fs::File;
use std::path::PathBuf;

use chrono::Utc;
use nethsm::{
    Connection,
    ConnectionSecurity,
    Credentials,
    KeyId,
    KeyMechanism,
    KeyType,
    NetHsm,
    Passphrase,
    Url,
    UserRole,
};
use rstest::fixture;
use rustainers::Container;
use rustainers::runner::Runner;
use testresult::TestResult;

/// Identifier for an admin user.
pub static ADMIN_USER_ID: &str = "admin";

/// Sample admin passphrase.
pub static ADMIN_USER_PASSPHRASE: &str = "just-an-admin-passphrase";

/// Sample unlock passphrase.
pub static UNLOCK_PASSPHRASE: &str = "just-an-unlock-passphrase";

/// Default user ID for an operator.
pub static DEFAULT_OPERATOR_USER_ID: &str = "operator1";

/// Default real name for an operator.
pub static DEFAULT_OPERATOR_USER_REAL_NAME: &str = "Some Operator";

/// Sample operator passphrase.
pub static DEFAULT_OPERATOR_USER_PASSPHRASE: &str = "just-an-operator-passphrase";

/// User ID for a different user.
pub static OTHER_OPERATOR_USER_ID: &str = "operator2";

/// Real name for a different user.
pub static OTHER_OPERATOR_USER_REAL_NAME: &str = "Some Other Operator";

/// Sample passphrase for a different user.
pub static OTHER_OPERATOR_USER_PASSPHRASE: &str = "just-another-operator-passphrase";

/// User ID for backup purposes.
pub static BACKUP_USER_ID: &str = "backup1";

/// Real name for the backup user.
pub static BACKUP_USER_REAL_NAME: &str = "Some Backup";

/// Sample passphrase for the backup user.
pub static BACKUP_USER_PASSPHRASE: &str = "just-a-backup-passphrase";

/// User ID for the metrics user.
pub static METRICS_USER_ID: &str = "metrics1";

/// Real name for the metrics user.
pub static METRICS_USER_REAL_NAME: &str = "Some Metrics";

/// Sample passphrase for the metrics user.
pub static METRICS_USER_PASSPHRASE: &str = "just-a-metrics-passphrase";

/// Default size of the RSA key in bits.
pub static DEFAULT_RSA_BITS: u32 = 2048;

/// Default ID for a key.
pub static DEFAULT_KEY_ID: &str = "key1";

/// Default ID for a different key.
pub static OTHER_KEY_ID: &str = "key2";

/// Default tag.
pub static DEFAULT_TAG: &str = "tag1";

/// Different tag.
pub static OTHER_TAG: &str = "tag2";

/// Default ID for the encryption key.
pub static ENC_KEY_ID: &str = "enckey1";

/// Default tag for the encryption key.
pub static ENC_TAG: &str = "enctag1";

/// User ID for the operator user who can access the encryption key.
pub static ENC_OPERATOR_USER_ID: &str = "encoperator1";

/// Real name for the operator user who can access the encryption key.
pub static ENC_OPERATOR_USER_REAL_NAME: &str = "Some Encryption Operator";

/// Sample passphrase for the operator user who can access the encryption key.
pub static ENC_OPERATOR_USER_PASSPHRASE: &str = "just-an-encryption-passphrase";

/// Default size for the AES key in bits.
pub static DEFAULT_AES_BITS: u32 = 128;

/// Sample namespace.
pub static NAMESPACE1: &str = "namespace1";

/// Administrator's user ID for `namespace1`.
pub static NAMESPACE1_ADMIN_USER_ID: &str = "namespace1~admin";

/// Sample passphrase for `namespace1`'s administrator.
pub static NAMESPACE1_ADMIN_USER_PASSPHRASE: &str = "just-a-namespace-admin-passphrase";

/// Real name for `namespace1`'s administrator.
pub static NAMESPACE1_ADMIN_REAL_NAME: &str = "Namespace1 Admin";

/// User ID of an operator in `namespace1`.
pub static NAMESPACE1_OPERATOR_USER_ID: &str = "namespace1~operator";

/// Sample passphrase of an operator in `namespace1`.
pub static NAMESPACE1_OPERATOR_USER_PASSPHRASE: &str = "just-a-namespace-operator-passphrase";

/// Real name of an operator in `namespace1`.
pub static NAMESPACE1_OPERATOR_REAL_NAME: &str = "Namespace1 Operator";

/// Second namespace.
pub static NAMESPACE2: &str = "namespace2";

/// Administrator's user ID for `namespace2`.
pub static NAMESPACE2_ADMIN_USER_ID: &str = "namespace2~admin";

/// Sample passphrase for `namespace2`'s administrator.
pub static NAMESPACE2_ADMIN_USER_PASSPHRASE: &str = "just-a-namespace2-admin-passphrase";

/// Real name for `namespace2`'s administrator.
pub static NAMESPACE2_ADMIN_REAL_NAME: &str = "Namespace2 Admin";

/// User ID of an operator in `namespace2`.
pub static NAMESPACE2_OPERATOR_USER_ID: &str = "namespace2~operator";

/// Sample passphrase of an operator in `namespace2`.
pub static NAMESPACE2_OPERATOR_USER_PASSPHRASE: &str = "just-a-namespace2-operator-passphrase";

/// Real name of an operator in `namespace2`.
pub static NAMESPACE2_OPERATOR_REAL_NAME: &str = "Namespace2 Operator";

mod container;
pub use container::NetHsmImage;

/// Creates and starts a new NetHSM container.
pub async fn create_container() -> TestResult<Container<NetHsmImage>> {
    let runner = Runner::podman()?;
    let image = NetHsmImage::default();
    println!("image: {:#?}", image.image);
    let container = runner.start(image).await?;
    println!("serving URL: {}", container.url().await?);
    Ok(container)
}

/// Creates a new [NetHsm] object configured with administrator credentials.
pub fn create_nethsm(url: Url) -> TestResult<NetHsm> {
    Ok(NetHsm::new(
        Connection::new(url, ConnectionSecurity::Unsafe),
        Some(Credentials::new(
            ADMIN_USER_ID.parse()?,
            Some(Passphrase::new(ADMIN_USER_PASSPHRASE.to_string())),
        )),
        None,
        None,
    )?)
}

/// Returns a new [NetHsm] object pointing to an unprovisioned NetHSM.
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
        (
            UserRole::Administrator,
            NAMESPACE1_ADMIN_USER_ID,
            NAMESPACE1_ADMIN_USER_PASSPHRASE,
            NAMESPACE1_ADMIN_REAL_NAME,
        ),
        (
            UserRole::Operator,
            NAMESPACE1_OPERATOR_USER_ID,
            NAMESPACE1_OPERATOR_USER_PASSPHRASE,
            NAMESPACE1_OPERATOR_REAL_NAME,
        ),
        (
            UserRole::Administrator,
            NAMESPACE2_ADMIN_USER_ID,
            NAMESPACE2_ADMIN_USER_PASSPHRASE,
            NAMESPACE2_ADMIN_REAL_NAME,
        ),
        (
            UserRole::Operator,
            NAMESPACE2_OPERATOR_USER_ID,
            NAMESPACE2_OPERATOR_USER_PASSPHRASE,
            NAMESPACE2_OPERATOR_REAL_NAME,
        ),
    ];

    println!("Adding users to NetHSM...");
    for (role, user_id, passphrase, real_name) in users.into_iter() {
        println!("Adding user: {}", user_id);
        nethsm.add_user(
            real_name.to_string(),
            role,
            Passphrase::new(passphrase.to_string()),
            Some(user_id.parse()?),
        )?;
    }
    println!("users: {:?}", nethsm.get_users()?);
    println!("Creating namespaces...");
    for namespace in [NAMESPACE1, NAMESPACE2] {
        println!("Creating namespace: {}", namespace);
        nethsm.add_namespace(&namespace.parse()?)?;
    }
    println!("namespaces: {:?}", nethsm.get_namespaces()?);
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
        let key_id: &KeyId = &key_id.parse()?;
        nethsm.generate_key(key_type, mechanisms, length, Some((*key_id).clone()), None)?;
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

/// Creates a new [NetHsm] object pointing at a provisioned NetHSM container.
#[fixture]
pub async fn provisioned_nethsm() -> TestResult<(NetHsm, Container<NetHsmImage>)> {
    let container = create_container().await?;
    let nethsm = create_nethsm(container.url().await?)?;
    println!("Provisioning container...");
    provision_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

/// Creates a new [NetHsm] object pointing at a NetHSM container with users.
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

/// Adds users and keys to an already provisioned NetHSM container.
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

/// Downloads an update file if it's not already present.
#[fixture]
pub fn update_file() -> TestResult<PathBuf> {
    let file_name = "update.img.bin";
    let update_link = format!(
        "https://raw.githubusercontent.com/Nitrokey/nethsm-sdk-py/main/tests/{}",
        file_name
    );
    let download_dir = PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap_or("/tmp".into()));
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
