// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;
use std::net::Ipv4Addr;
use std::path::Path;
use std::path::PathBuf;

use chrono::Utc;
use common::future_maybe_stop_container;
use common::nethsm_with_users;
use common::result_maybe_stop_container;
use common::update_file;
use common::BACKUP_PASSPHRASE;
use common::BACKUP_USER_ID;
use common::BACKUP_USER_PASSPHRASE;
use common::METRICS_USER_ID;
use common::METRICS_USER_PASSPHRASE;
use common::UNLOCK_PASSPHRASE;
use nethsm::BootMode;
use nethsm::NetHsm;
use nethsm_sdk_rs::models::DistinguishedName;
use nethsm_sdk_rs::models::LogLevel;
use nethsm_sdk_rs::models::NetworkConfig;
use nethsm_sdk_rs::models::SystemState;
use nethsm_sdk_rs::models::TlsKeyType;
use podman_api::api::Container;
use rstest::rstest;
use testdir::testdir;
use testresult::TestResult;

pub static LENGTH: i32 = 32;

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn boot_mode(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn get_and_set_boot_mode(nethsm: &NetHsm) -> TestResult {
        assert_eq!(BootMode::Attended, nethsm.get_boot_mode()?);
        nethsm.set_boot_mode(BootMode::Unattended)?;
        assert_eq!(BootMode::Unattended, nethsm.get_boot_mode()?);
        Ok(())
    }

    result_maybe_stop_container(get_and_set_boot_mode(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn tls_cert(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn get_and_set_tls_cert(nethsm: &NetHsm) -> TestResult {
        let initial_cert_file = testdir!().join("initial_cert.pem");
        let initial_cert = nethsm.get_tls_cert()?;
        println!("initial cert\n{}", initial_cert);
        std::fs::write(initial_cert_file, initial_cert)?;

        nethsm.generate_tls_cert(TlsKeyType::Rsa, Some(4096))?;

        let updated_cert_file = testdir!().join("updated_cert.pem");
        let updated_cert = nethsm.get_tls_cert()?;
        println!("updated cert\n{}", updated_cert);
        std::fs::write(updated_cert_file, updated_cert.clone())?;

        let csr_file = testdir!().join("updated_cert.csr");
        let csr = nethsm.get_tls_csr(DistinguishedName {
            country_name: Some("DE".to_string()),
            state_or_province_name: Some("Berlin".to_string()),
            locality_name: Some("Berlin".to_string()),
            organization_name: Some("Foobar Inc".to_string()),
            organizational_unit_name: Some("Department of Foo".to_string()),
            common_name: "Foobar Inc".to_string(),
            email_address: Some("foobar@mcfooface.com".to_string()),
        })?;
        println!("A TLS CSR for the NetHSM:\n{}", csr);
        std::fs::write(csr_file, csr)?;

        nethsm.set_tls_cert(&updated_cert)?;
        Ok(())
    }

    result_maybe_stop_container(get_and_set_tls_cert(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn network(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn get_and_set_network(nethsm: &NetHsm) -> TestResult {
        let network_config = nethsm.get_network()?;
        println!("NetHSM network config: {:?}", network_config);
        assert_eq!("192.168.1.1".to_string(), network_config.ip_address);

        let ip_address = String::from("192.168.1.2");
        nethsm.set_network(NetworkConfig::new(
            ip_address.clone(),
            "255.255.255.0".to_string(),
            "0.0.0.0".to_string(),
        ))?;
        let network_config = nethsm.get_network()?;
        println!("NetHSM network config: {:?}", network_config);
        assert_eq!(ip_address, network_config.ip_address);
        Ok(())
    }

    result_maybe_stop_container(get_and_set_network(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn time(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn get_and_set_time(nethsm: &NetHsm) -> TestResult {
        let time = nethsm.get_time()?;
        println!("NetHSM time: {}", time);

        let time = Utc::now();
        println!("The current time: {}", time);
        nethsm.set_time(time)?;

        let time = nethsm.get_time()?;
        println!("NetHSM time: {}", time);
        Ok(())
    }

    result_maybe_stop_container(get_and_set_time(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn lock(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn lock_and_unlock(nethsm: &NetHsm) -> TestResult {
        println!("NetHSM info: {:?}", nethsm.info()?);
        assert_eq!(SystemState::Operational, nethsm.state()?);
        nethsm.lock()?;
        assert_eq!(SystemState::Locked, nethsm.state()?);
        nethsm.unlock(UNLOCK_PASSPHRASE.to_string())?;
        assert_eq!(SystemState::Operational, nethsm.state()?);
        Ok(())
    }

    result_maybe_stop_container(lock_and_unlock(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn metrics(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;
    nethsm.add_credentials((
        METRICS_USER_ID.to_string(),
        Some(METRICS_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(METRICS_USER_ID)?;

    fn get_metrics(nethsm: &NetHsm) -> TestResult {
        println!("The NetHSM metrics: {}", nethsm.metrics()?);
        Ok(())
    }

    result_maybe_stop_container(get_metrics(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn logging(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn set_logging(nethsm: &NetHsm) -> TestResult {
        println!("NetHSM logging setup: {:?}", nethsm.get_logging()?);
        nethsm.set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)?;

        println!("NetHSM logging setup: {:?}", nethsm.get_logging()?);
        Ok(())
    }

    result_maybe_stop_container(set_logging(&nethsm), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn create_backup(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;
    let backup_file = testdir!().join("nethsm-backup");

    // change the backup passphrase
    fn alter_backup_passphrase(nethsm: &NetHsm) -> TestResult {
        let new_backup_passphrase = "totally-unsafe-passphrase".to_string();
        nethsm
            .set_backup_passphrase(BACKUP_PASSPHRASE.to_string(), new_backup_passphrase.clone())?;
        nethsm
            .set_backup_passphrase(new_backup_passphrase.clone(), BACKUP_PASSPHRASE.to_string())?;
        Ok(())
    }

    result_maybe_stop_container(alter_backup_passphrase(&nethsm), false, &container).await?;

    fn write_backup_file(nethsm: &NetHsm, backup_file: &Path) -> TestResult {
        let backup = nethsm.backup()?;
        std::fs::write(backup_file, backup.clone())?;
        println!("Written NetHSM backup file: {:?}", backup_file);
        Ok(())
    }

    nethsm.add_credentials((
        BACKUP_USER_ID.to_string(),
        Some(BACKUP_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(BACKUP_USER_ID)?;

    result_maybe_stop_container(write_backup_file(&nethsm, &backup_file), false, &container)
        .await?;

    fn wrap_restore(nethsm: &NetHsm, backup_file: &Path) -> TestResult {
        assert!(
            nethsm
                .restore(
                    BACKUP_PASSPHRASE.to_string(),
                    Utc::now(),
                    std::fs::read(backup_file)?,
                )
                .is_err(),
            "Restore from backup works again: https://github.com/Nitrokey/nethsm/issues/5"
        );
        Ok(())
    }

    result_maybe_stop_container(wrap_restore(&nethsm, &backup_file), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn factory_reset(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn wrap_factory_reset(nethsm: &NetHsm) -> TestResult {
        // NOTE: this shuts down the container!
        nethsm.factory_reset()?;
        Ok(())
    }

    result_maybe_stop_container(wrap_factory_reset(&nethsm), false, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn reboot(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn wrap_reboot(nethsm: &NetHsm) -> TestResult {
        // NOTE: this shuts down the container!
        nethsm.reboot()?;
        Ok(())
    }

    result_maybe_stop_container(wrap_reboot(&nethsm), false, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn shutdown(#[future] nethsm_with_users: TestResult<(NetHsm, Container)>) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;

    fn wrap_shutdown(nethsm: &NetHsm) -> TestResult {
        // NOTE: this shuts down the container!
        nethsm.shutdown()?;
        Ok(())
    }

    result_maybe_stop_container(wrap_shutdown(&nethsm), false, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn fail_upload_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container)>,
) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;
    let update_file = testdir!().join("bogus_update.bin");
    std::fs::write(&update_file, "this is a bogus update file")?;
    let file = std::fs::read(update_file)?;

    fn upload_update(nethsm: &NetHsm, file: Vec<u8>) -> TestResult {
        assert!(nethsm.upload_update(file).is_err());

        Ok(())
    }

    // NOTE: this shuts down the container!
    result_maybe_stop_container(upload_update(&nethsm, file), true, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn commit_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container)>,
    #[future] update_file: TestResult<PathBuf>,
) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;
    let file = std::fs::read(update_file.await?)?;

    async fn upload_and_commit_update(nethsm: &NetHsm, file: Vec<u8>) -> TestResult {
        // NOTE: uploading may fail from time to time in CI, so we try at least three times before
        // bailing out this is ugly but allows us to at least run tests
        // likely related ticket in nethsm-sdk-py: https://github.com/Nitrokey/nethsm-sdk-py/issues/93
        let max_tries = 3;
        let mut tries = 0;
        while let Err(error) = nethsm.upload_update(file.clone()) {
            eprintln!("{}", error);
            if tries < max_tries {
                tries += 1;
            } else {
                eprintln!("maximum upload failures reached!");
                if format!("{}", error).contains("(status code 400)") {
                    eprintln!("Encountered an issue with the container, bailing out...");
                    return Ok(());
                }
            }
        }

        nethsm.commit_update()?;

        Ok(())
    }

    // NOTE: this shuts down the container!
    future_maybe_stop_container(upload_and_commit_update(&nethsm, file), false, &container).await?;

    Ok(())
}

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn cancel_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container)>,
    #[future] update_file: TestResult<PathBuf>,
) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;
    let file = std::fs::read(update_file.await?)?;

    async fn upload_and_cancel_update(nethsm: &NetHsm, file: Vec<u8>) -> TestResult {
        // NOTE: uploading may fail from time to time in CI, so we try at least three times before
        // bailing out this is ugly but allows us to at least run tests
        // likely related ticket in nethsm-sdk-py: https://github.com/Nitrokey/nethsm-sdk-py/issues/93
        let max_tries = 3;
        let mut tries = 0;
        while let Err(error) = nethsm.upload_update(file.clone()) {
            eprintln!("{}", error);
            if tries < max_tries {
                tries += 1;
            } else {
                eprintln!("maximum upload failures reached!");
                if format!("{}", error).contains("(status code 400)") {
                    eprintln!("Encountered an issue with the container, bailing out...");
                    return Ok(());
                }
            }
        }

        nethsm.cancel_update()?;

        Ok(())
    }

    future_maybe_stop_container(upload_and_cancel_update(&nethsm, file), true, &container).await?;

    Ok(())
}
