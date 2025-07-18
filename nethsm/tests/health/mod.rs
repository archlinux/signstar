//! Tests related to NetHSM health and readiness.

use nethsm::test::{NetHsmImage, nethsm_with_users, unprovisioned_nethsm};
use nethsm::{NetHsm, SystemState};
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[rstest]
#[tokio::test]
async fn alive(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = unprovisioned_nethsm.await?;
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

#[rstest]
#[tokio::test]
async fn ready(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = unprovisioned_nethsm.await?;
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("Checking unprovisioned device...");
    assert!(unprovisioned_nethsm.ready().is_err());
    println!("Checking operational device...");
    assert!(nethsm.ready().is_ok());
    println!("Checking locked device...");
    nethsm.lock()?;
    assert!(nethsm.ready().is_err());
    Ok(())
}

#[rstest]
#[tokio::test]
async fn state(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = unprovisioned_nethsm.await?;
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("Checking unprovisioned device...");
    assert_eq!(unprovisioned_nethsm.state()?, SystemState::Unprovisioned);
    println!("Checking operational device...");
    assert_eq!(nethsm.state()?, SystemState::Operational);
    println!("Checking locked device...");
    nethsm.lock()?;
    assert_eq!(nethsm.state()?, SystemState::Locked);
    Ok(())
}
