// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use chrono::Utc;
use common::nethsm_with_users;
use common::update_file;
use common::NetHsmImage;
use common::BACKUP_PASSPHRASE;
use common::BACKUP_USER_ID;
use common::BACKUP_USER_PASSPHRASE;
use common::METRICS_USER_ID;
use common::METRICS_USER_PASSPHRASE;
use common::UNLOCK_PASSPHRASE;
use nethsm::{
    BootMode,
    DistinguishedName,
    LogLevel,
    NetHsm,
    NetworkConfig,
    SystemState,
    TlsKeyType,
};
use rstest::rstest;
use rustainers::Container;
use testdir::testdir;
use testresult::TestResult;

pub static LENGTH: i32 = 32;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn boot_mode(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    assert_eq!(BootMode::Attended, nethsm.get_boot_mode()?);
    nethsm.set_boot_mode(BootMode::Unattended)?;
    assert_eq!(BootMode::Unattended, nethsm.get_boot_mode()?);

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn tls_cert(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    // get and set TLS cert
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

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn network(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

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

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn time(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    let time = nethsm.get_time()?;
    println!("NetHSM time: {}", time);

    let time = Utc::now();
    println!("The current time: {}", time);
    nethsm.set_time(time)?;

    let time = nethsm.get_time()?;
    println!("NetHSM time: {}", time);
    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn lock(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("NetHSM info: {:?}", nethsm.info()?);
    assert_eq!(SystemState::Operational, nethsm.state()?);
    nethsm.lock()?;
    assert_eq!(SystemState::Locked, nethsm.state()?);
    nethsm.unlock(UNLOCK_PASSPHRASE.to_string())?;
    assert_eq!(SystemState::Operational, nethsm.state()?);
    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn metrics(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    nethsm.add_credentials((
        METRICS_USER_ID.to_string(),
        Some(METRICS_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(METRICS_USER_ID)?;

    println!("The NetHSM metrics: {}", nethsm.metrics()?);
    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn logging(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("NetHSM logging setup: {:?}", nethsm.get_logging()?);
    nethsm.set_logging(Ipv4Addr::new(192, 168, 1, 2), 513, LogLevel::Debug)?;

    println!("NetHSM logging setup: {:?}", nethsm.get_logging()?);
    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn create_backup(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let backup_file = testdir!().join("nethsm-backup");

    // set backup passphrase
    let new_backup_passphrase = "totally-unsafe-passphrase".to_string();
    nethsm.set_backup_passphrase(BACKUP_PASSPHRASE.to_string(), new_backup_passphrase.clone())?;
    nethsm.set_backup_passphrase(new_backup_passphrase.clone(), BACKUP_PASSPHRASE.to_string())?;

    nethsm.add_credentials((
        BACKUP_USER_ID.to_string(),
        Some(BACKUP_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(BACKUP_USER_ID)?;

    // write backup file
    let backup = nethsm.backup()?;
    std::fs::write(&backup_file, backup.clone())?;
    println!("Written NetHSM backup file: {:?}", &backup_file);

    // restore from backup is broken
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

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn factory_reset(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    // NOTE: this shuts down the container!
    nethsm.factory_reset()?;

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn reboot(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    // NOTE: this shuts down the container!
    nethsm.reboot()?;

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn shutdown(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    // NOTE: this shuts down the container!
    nethsm.shutdown()?;

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn fail_upload_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let update_file = testdir!().join("bogus_update.bin");
    std::fs::write(&update_file, "this is a bogus update file")?;
    let file = std::fs::read(update_file)?;

    // NOTE: this shuts down the container!
    assert!(nethsm.upload_update(file).is_err());

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn commit_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] update_file: TestResult<PathBuf>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
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
    upload_and_commit_update(&nethsm, file).await?;

    Ok(())
}

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn cancel_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] update_file: TestResult<PathBuf>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
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

    // NOTE: this shuts down the container!
    upload_and_cancel_update(&nethsm, file).await?;

    Ok(())
}
