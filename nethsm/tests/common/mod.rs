// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env::var;
use std::future::Future;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use chrono::Utc;
use futures_util::StreamExt;
use futures_util::TryStreamExt;
use nethsm::ConnectionSecurity;
use nethsm::NetHsm;
use nethsm_sdk_rs::models::KeyMechanism;
use nethsm_sdk_rs::models::KeyType;
use nethsm_sdk_rs::models::UserRole;
use nix::unistd::geteuid;
use podman_api::api::Container;
use podman_api::api::Image;
use podman_api::opts::ContainerCreateOpts;
use podman_api::opts::ImageListOpts;
use podman_api::opts::PullOpts;
use podman_api::Podman;
use reqwest::get;
use rstest::fixture;
use testresult::TestError;
use testresult::TestResult;
use tokio::time::sleep;
use uuid::timestamp::Timestamp;
use uuid::NoContext;
use uuid::Uuid;

pub static IMAGE_NAME: &str = "docker.io/nitrokey/nethsm:testing";
pub static DEFAULT_PORT: &str = "8443";
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
static START_INVERVAL: u64 = 300;
static MAX_START_TIME: u64 = 3000;

#[fixture]
fn podman() -> Podman {
    let uid = geteuid();
    if uid.is_root() {
        Podman::unix("/run/podman/podman.sock")
    } else {
        Podman::unix(format!("/run/user/{}/podman/podman.sock", geteuid()))
    }
}

#[fixture]
async fn nethsm_image(podman: Podman) -> TestResult<(Podman, Image)> {
    let events = podman
        .images()
        .pull(&PullOpts::builder().reference(IMAGE_NAME).build())
        .map(|report| {
            report.and_then(|report| {
                if let Some(error) = report.error {
                    Err(podman_api::Error::InvalidResponse(error))
                } else {
                    Ok(report)
                }
            })
        })
        .try_collect::<Vec<_>>()
        .await;

    if let Err(e) = events {
        eprintln!("event errors: {}", e);
    };

    let images = podman
        .images()
        .list(&ImageListOpts::builder().all(true).build())
        .await?;

    let image_id = if let Some(summary) = images.iter().find(|x| {
        x.names
            .as_ref()
            .is_some_and(|names| names.contains(&IMAGE_NAME.to_string()))
    }) {
        if let Some(id) = summary.id.as_ref() {
            id
        } else {
            return Err(TestError::from("Container image has no ID"));
        }
    } else {
        return Err(TestError::from("No container image found"));
    };
    println!("Container image \"{}\": {}", IMAGE_NAME, image_id);

    Ok((podman.clone(), Image::new(podman, image_id)))
}

#[fixture]
pub async fn nethsm_container(
    #[future] nethsm_image: TestResult<(Podman, Image)>,
) -> TestResult<(NetHsm, Container)> {
    let (podman, _) = nethsm_image.await?;
    let container_create = podman
        .containers()
        .create(
            &ContainerCreateOpts::builder()
                .image(IMAGE_NAME)
                .name(format!(
                    "nethsm-test-{}",
                    Uuid::new_v7(Timestamp::now(NoContext))
                ))
                .publish_image_ports(true)
                .build(),
        )
        .await?;
    println!(
        "Container created based on \"{}\": {}",
        IMAGE_NAME, container_create.id
    );
    let container = Container::new(podman.clone(), container_create.id);

    let container_host_port = start_container(&container, None, None).await?;

    let nethsm = NetHsm::new(
        format!("https://localhost:{}/api/v1", container_host_port).try_into()?,
        ConnectionSecurity::Unsafe,
        Some((
            ADMIN_USER_ID.to_string(),
            Some(ADMIN_USER_PASSPHRASE.to_string()),
        )),
        None,
        None,
    )?;

    Ok((nethsm, container))
}

/// Get the host port forwarded to the container port [`DEFAULT_PORT`]
async fn get_container_host_port(container: &Container) -> TestResult<u64> {
    let container_data = container.inspect().await?;
    let network_settings = container_data
        .network_settings
        .expect("container has network settings");
    let ports = network_settings.ports.expect("container has network ports");
    let host_ports = ports
        .get(&format!("{}/tcp", DEFAULT_PORT))
        .expect("container has default port")
        .as_ref()
        .expect("container has default port");
    let host_port = host_ports
        .iter()
        .last()
        .expect("container has default port")
        .clone()
        .host_port
        .expect("container has host port");

    Ok(u64::from_str(&host_port)?)
}

pub async fn start_container(
    container: &Container,
    interval: Option<u64>,
    max_start_time: Option<u64>,
) -> TestResult<u64> {
    let interval = interval.unwrap_or(START_INVERVAL);
    let max_start_time = max_start_time.unwrap_or(MAX_START_TIME);

    let container_host_port = get_container_host_port(container).await?;
    println!("Starting container {}", container.id());
    println!(
        "Host port {} forwarded to container port {}",
        container_host_port, DEFAULT_PORT
    );

    container.start(None).await?;

    let nethsm = NetHsm::new(
        format!("https://localhost:{}/api/v1", container_host_port).try_into()?,
        ConnectionSecurity::Unsafe,
        Some((
            ADMIN_USER_ID.to_string(),
            Some(ADMIN_USER_PASSPHRASE.to_string()),
        )),
        None,
        None,
    )?;

    let mut elapsed = 0;
    while elapsed <= max_start_time {
        if nethsm.state().is_ok() {
            println!(
                "Waited at least {}ms until container exposed NetHSM API.",
                elapsed
            );
            return Ok(container_host_port);
        }
        sleep(Duration::from_millis(interval)).await;
        elapsed += interval;
    }

    Err(TestError::from(format!(
        "Container failed to fully start within {0}ms",
        max_start_time
    )))
}

/// Stop a container
///
/// If the environment variable `KEEP_NETHSM_CONTAINER_ALIVE` is set, the
/// container is not stopped!
#[allow(dead_code)]
async fn stop_container(container: &Container) -> TestResult {
    if var("KEEP_NETHSM_CONTAINER_ALIVE").is_ok() {
        println!(
            "Keeping container {:?} alive.",
            container
                .inspect()
                .await?
                .id
                .unwrap_or("unknown".to_string())
        );
        Ok(())
    } else {
        println!(
            "Stopping container {:?}.",
            container
                .inspect()
                .await?
                .id
                .unwrap_or("unknown".to_string())
        );
        Ok(container.stop(&Default::default()).await?)
    }
}

/// Await a [`Future`] and maybe stop the [`Container`] associated with it
///
/// When the [`Future`] returns a [`Result::Error`], [`stop_container`] is
/// always called, then the [`Result::Error`] is returned. When the [`Future`]
/// returns a [`Result::Ok`] [`stop_container`] is called if `force_stop_on_ok`
/// is `true`, before the [`Result::Ok`] is returned.
#[allow(dead_code)]
pub async fn future_maybe_stop_container(
    future: impl Future<Output = TestResult>,
    force_stop_on_ok: bool,
    container: &Container,
) -> TestResult {
    if let Err(error) = future.await {
        stop_container(container).await?;
        Err(error)
    } else {
        if force_stop_on_ok {
            stop_container(container).await?;
        }
        Ok(())
    }
}

/// Based on a [`Result`] maybe stop the [`Container`] associated with it
///
/// When providing [`Result::Error`], [`stop_container`] is always called, then
/// the [`Result::Error`] is returned. When providing [`Result::Ok`]
/// [`stop_container`] is called if `force_stop_on_ok` is `true`, before the
/// [`Result::Ok`] is returned.
#[allow(dead_code)]
pub async fn result_maybe_stop_container(
    result: TestResult,
    force_stop_on_ok: bool,
    container: &Container,
) -> TestResult {
    println!("maybe stop container: {:?}", result);
    if let Err(error) = result {
        stop_container(container).await?;
        Err(error)
    } else {
        if force_stop_on_ok {
            stop_container(container).await?;
        }
        Ok(())
    }
}

fn provision_nethsm(nethsm: &NetHsm) -> TestResult {
    nethsm.provision(
        UNLOCK_PASSPHRASE.to_string(),
        ADMIN_USER_PASSPHRASE.to_string(),
        Utc::now(),
    )?;
    nethsm.set_backup_passphrase("".to_string(), BACKUP_PASSPHRASE.to_string())?;
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

    for (role, user_id, passphrase, real_name) in users.into_iter() {
        nethsm.add_user(
            real_name.to_string(),
            role,
            passphrase.to_string(),
            Some(user_id.to_string()),
        )?;
    }
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

    for (mechanisms, key_type, length, key_id, tag, user_id) in keys {
        nethsm.generate_key(key_type, mechanisms, length, Some(key_id.to_string()), None)?;
        nethsm.add_key_tag(key_id, tag)?;
        nethsm.add_user_tag(user_id, tag)?;
        // skip symmetric keys, as for those we do not have a public key
        if key_type != KeyType::Generic {
            nethsm.import_key_certificate(key_id, nethsm.get_public_key(key_id)?.into_bytes())?;
        }
    }
    Ok(())
}

#[fixture]
pub async fn provisioned_nethsm(
    #[future] nethsm_container: TestResult<(NetHsm, Container)>,
) -> TestResult<(NetHsm, Container)> {
    let (nethsm, container) = nethsm_container.await?;

    println!("Provisioning container...");
    provision_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

#[fixture]
pub async fn nethsm_with_users(
    #[future] provisioned_nethsm: TestResult<(NetHsm, Container)>,
) -> TestResult<(NetHsm, Container)> {
    let (nethsm, container) = provisioned_nethsm.await?;

    println!("Adding users to container...");
    add_users_to_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

#[fixture]
pub async fn nethsm_with_keys(
    #[future] provisioned_nethsm: TestResult<(NetHsm, Container)>,
) -> TestResult<(NetHsm, Container)> {
    let (nethsm, container) = provisioned_nethsm.await?;

    println!("Adding users and keys to container...");
    add_users_to_nethsm(&nethsm)?;
    add_keys_to_nethsm(&nethsm)?;

    Ok((nethsm, container))
}

#[fixture]
pub async fn update_file() -> TestResult<PathBuf> {
    let file_name = "update.img.bin";
    let update_link = format!(
        "https://raw.githubusercontent.com/Nitrokey/nethsm-sdk-py/main/tests/{}",
        file_name
    );
    let download_dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let file = download_dir.join(file_name);

    if !file.exists() {
        let file_bytes = get(update_link).await?.bytes().await?;
        std::fs::write(&file, file_bytes)?;
        assert!(file.exists());
    }

    println!("Update file downloaded: {:?}", file);
    Ok(file)
}
