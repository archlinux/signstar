//! Tests checking the NetHSM configuration.

use std::net::Ipv4Addr;
use std::path::PathBuf;

use chrono::Utc;
use nethsm::test::{
    ADMIN_USER_ID,
    NAMESPACE1_ADMIN_USER_ID,
    NetHsmImage,
    UNLOCK_PASSPHRASE,
    nethsm_with_users,
    unprovisioned_nethsm,
    update_file,
};
use nethsm::{
    BootMode,
    DistinguishedName,
    LogLevel,
    NetHsm,
    NetworkConfig,
    Passphrase,
    TlsKeyType,
};
use rstest::rstest;
use rustainers::Container;
use testdir::testdir;
use testresult::TestResult;

#[rstest]
#[tokio::test]
async fn boot_mode(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    assert_eq!(BootMode::Attended, nethsm.get_boot_mode()?);
    nethsm.set_boot_mode(BootMode::Unattended)?;
    assert_eq!(BootMode::Unattended, nethsm.get_boot_mode()?);

    // N-Administrators can not set the boot mode
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(nethsm.get_boot_mode().is_err());
    assert!(nethsm.set_boot_mode(BootMode::Unattended).is_err());

    Ok(())
}

#[rstest]
#[tokio::test]
async fn tls_cert(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    // N-Administrators can not get the TLS cert
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(nethsm.get_tls_cert().is_err());

    // get and set TLS cert
    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    let initial_cert_file = testdir!().join("initial_cert.pem");
    let initial_cert = nethsm.get_tls_cert()?;
    println!("initial cert\n{initial_cert}");
    std::fs::write(initial_cert_file, initial_cert)?;

    // N-Administrators can not generate a TLS cert
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(
        nethsm
            .generate_tls_cert(TlsKeyType::Rsa, Some(4096))
            .is_err()
    );

    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    nethsm.generate_tls_cert(TlsKeyType::Rsa, Some(4096))?;

    let updated_cert_file = testdir!().join("updated_cert.pem");
    let updated_cert = nethsm.get_tls_cert()?;
    println!("updated cert\n{updated_cert}");
    std::fs::write(updated_cert_file, updated_cert.clone())?;

    let csr_file = testdir!().join("updated_cert.csr");

    // N-Administrators can not a TLS CSR
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(
        nethsm
            .get_tls_csr(DistinguishedName {
                country_name: Some("DE".to_string()),
                state_or_province_name: Some("Berlin".to_string()),
                locality_name: Some("Berlin".to_string()),
                organization_name: Some("Foobar Inc".to_string()),
                organizational_unit_name: Some("Department of Foo".to_string()),
                common_name: "Foobar Inc".to_string(),
                email_address: Some("foobar@mcfooface.com".to_string()),
            })
            .is_err()
    );

    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    let csr = nethsm.get_tls_csr(DistinguishedName {
        country_name: Some("DE".to_string()),
        state_or_province_name: Some("Berlin".to_string()),
        locality_name: Some("Berlin".to_string()),
        organization_name: Some("Foobar Inc".to_string()),
        organizational_unit_name: Some("Department of Foo".to_string()),
        common_name: "Foobar Inc".to_string(),
        email_address: Some("foobar@mcfooface.com".to_string()),
    })?;
    println!("A TLS CSR for the NetHSM:\n{csr}");
    std::fs::write(csr_file, csr)?;

    // N-Administrators can not set the TLS cert
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(nethsm.set_tls_cert(&updated_cert).is_err());

    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    nethsm.set_tls_cert(&updated_cert)?;

    Ok(())
}

#[rstest]
#[tokio::test]
async fn network(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let ip_address = String::from("192.168.1.2");

    // N-Administrators can neither get nor set network settings
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(nethsm.get_network().is_err());
    assert!(
        nethsm
            .set_network(NetworkConfig::new(
                ip_address.clone(),
                "255.255.255.0".to_string(),
                "0.0.0.0".to_string(),
            ))
            .is_err()
    );

    // R-Administrators can get and set network settings
    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    let network_config = nethsm.get_network()?;
    println!("NetHSM network config: {network_config:?}");
    assert_eq!("192.168.1.1".to_string(), network_config.ip_address);

    nethsm.set_network(NetworkConfig::new(
        ip_address.clone(),
        "255.255.255.0".to_string(),
        "0.0.0.0".to_string(),
    ))?;
    let network_config = nethsm.get_network()?;
    println!("NetHSM network config: {network_config:?}");
    assert_eq!(ip_address, network_config.ip_address);
    Ok(())
}

#[rstest]
#[tokio::test]
async fn time(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    // N-Administrators can neither get nor set system time
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(nethsm.get_time().is_err());
    assert!(nethsm.set_time(Utc::now()).is_err());

    // R-Administrators can get and set system time
    nethsm.use_credentials(&ADMIN_USER_ID.parse()?)?;
    let time = nethsm.get_time()?;
    println!("NetHSM time: {time}");

    let time = Utc::now();
    println!("The current time: {time}");
    nethsm.set_time(time)?;

    let time = nethsm.get_time()?;
    println!("NetHSM time: {time}");
    Ok(())
}

#[rstest]
#[tokio::test]
async fn set_unlock_passphrase(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let new_unlock_passphrase = "just-another-unlock-passphrase";

    // R-Administrators can set the unlock passphrase
    nethsm.set_unlock_passphrase(
        Passphrase::new(UNLOCK_PASSPHRASE.to_string()),
        Passphrase::new(new_unlock_passphrase.to_string()),
    )?;
    nethsm.set_unlock_passphrase(
        Passphrase::new(new_unlock_passphrase.to_string()),
        Passphrase::new(UNLOCK_PASSPHRASE.to_string()),
    )?;
    // N-Administrators can not set the unlock passphrase
    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(
        nethsm
            .set_unlock_passphrase(
                Passphrase::new(UNLOCK_PASSPHRASE.to_string()),
                Passphrase::new(new_unlock_passphrase.to_string()),
            )
            .is_err()
    );

    Ok(())
}

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

#[rstest]
#[tokio::test]
async fn set_backup_passphrase(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let initial_passphrase = "";
    let new_backup_passphrase = "totally-unsafe-passphrase";

    nethsm.set_backup_passphrase(
        Passphrase::new(initial_passphrase.to_string()),
        Passphrase::new(new_backup_passphrase.to_string()),
    )?;
    // the passphrase is too short!
    assert!(
        nethsm
            .set_backup_passphrase(
                Passphrase::new(new_backup_passphrase.to_string()),
                Passphrase::new(initial_passphrase.to_string()),
            )
            .is_err()
    );

    Ok(())
}

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

#[rstest]
#[tokio::test]
async fn commit_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
    update_file: TestResult<PathBuf>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let file = std::fs::read(update_file?)?;

    async fn upload_and_commit_update(nethsm: &NetHsm, file: Vec<u8>) -> TestResult {
        // NOTE: uploading may fail from time to time in CI, so we try at least three times before
        // bailing out this is ugly but allows us to at least run tests
        // likely related ticket in nethsm-sdk-py: https://github.com/Nitrokey/nethsm-sdk-py/issues/93
        let max_tries = 3;
        let mut tries = 0;
        while let Err(error) = nethsm.upload_update(file.clone()) {
            eprintln!("{error}");
            if tries < max_tries {
                tries += 1;
            } else {
                eprintln!("maximum upload failures reached!");
                if format!("{error}").contains("(status code 400)") {
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

#[rstest]
#[tokio::test]
async fn cancel_update(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
    update_file: TestResult<PathBuf>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let file = std::fs::read(update_file?)?;

    async fn upload_and_cancel_update(nethsm: &NetHsm, file: Vec<u8>) -> TestResult {
        // NOTE: uploading may fail from time to time in CI, so we try at least three times before
        // bailing out this is ugly but allows us to at least run tests
        // likely related ticket in nethsm-sdk-py: https://github.com/Nitrokey/nethsm-sdk-py/issues/93
        let max_tries = 3;
        let mut tries = 0;
        while let Err(error) = nethsm.upload_update(file.clone()) {
            eprintln!("{error}");
            if tries < max_tries {
                tries += 1;
            } else {
                eprintln!("maximum upload failures reached!");
                if format!("{error}").contains("(status code 400)") {
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

#[rstest]
#[tokio::test]
async fn get_tls_public_key_of_provisioned_nethsm(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("Get TLS certificate of provisioned device...");
    println!("{}", nethsm.get_tls_public_key()?);
    assert!(nethsm.get_tls_public_key().is_ok());

    nethsm.use_credentials(&NAMESPACE1_ADMIN_USER_ID.parse()?)?;
    assert!(nethsm.get_tls_public_key().is_err());

    Ok(())
}

#[rstest]
#[tokio::test]
async fn get_tls_public_key_of_unprovisioned_nethsm(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = unprovisioned_nethsm.await?;

    println!("Get TLS certificate of unprovisioned device...");
    assert!(unprovisioned_nethsm.get_tls_public_key().is_err());

    Ok(())
}
