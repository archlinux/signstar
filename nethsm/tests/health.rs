// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;
use common::{nethsm_container, nethsm_with_users, NetHsmImage};
use nethsm::NetHsm;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn alive(
    #[future] nethsm_container: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = nethsm_container.await?;
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("Checking unprovisioned device...");
    assert!(unprovisioned_nethsm.alive().is_ok());
    println!("Checking operational device...");
    assert!(nethsm.alive().is_err());
    println!("Checking locked device...");
    nethsm.lock()?;
    assert!(nethsm.alive().is_ok());
    Ok(())
}
