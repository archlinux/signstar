// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::time::Duration;

mod common;
use chrono::Utc;
use common::nethsm_container;
use common::NetHsmImage;
use common::ADMIN_USER_ID;
use common::ADMIN_USER_PASSPHRASE;
use common::UNLOCK_PASSPHRASE;
use nethsm::NetHsm;
use nethsm_sdk_rs::models::SystemState;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;
use tokio::time::sleep;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn initial_provisioning(
    #[future] nethsm_container: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_container.await?;

    nethsm.remove_credentials("admin");

    let info = nethsm.info()?;
    println!("The NetHSM info: {:?}", info);

    assert!(nethsm.state()? == SystemState::Unprovisioned);
    nethsm.provision(
        UNLOCK_PASSPHRASE.to_string(),
        ADMIN_USER_PASSPHRASE.to_string(),
        Utc::now(),
    )?;

    // poll every 200ms if system is operational, until timeout of 1s is reached
    let timeout = 1000;
    let interval = 200;
    let mut elapsed = 0;
    while elapsed <= timeout {
        if nethsm.state()? == SystemState::Operational {
            println!(
                "Waited at least {}ms until NetHSM became operational",
                elapsed
            );
            break;
        }
        sleep(Duration::from_millis(interval)).await;
        elapsed += interval;
    }

    // now the admin credentials are needed
    nethsm.add_credentials((
        ADMIN_USER_ID.to_string(),
        Some(ADMIN_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(ADMIN_USER_ID)?;

    nethsm.lock()?;
    assert!(nethsm.state()? == SystemState::Locked);
    nethsm.unlock(UNLOCK_PASSPHRASE.to_string())?;
    assert!(nethsm.state()? == SystemState::Operational);

    let new_unlock_passphrase = "just-another-unlock-passphrase";
    nethsm.set_unlock_passphrase(
        UNLOCK_PASSPHRASE.to_string(),
        new_unlock_passphrase.to_string(),
    )?;

    nethsm.lock()?;
    assert!(nethsm.state()? == SystemState::Locked);
    nethsm.unlock(new_unlock_passphrase.to_string())?;
    assert!(nethsm.state()? == SystemState::Operational);

    if elapsed > timeout {
        panic!("NetHSM did not become operational within {}ms", timeout);
    }

    Ok(())
}
