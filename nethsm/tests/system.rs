mod common;
use common::{nethsm_with_users, unprovisioned_nethsm, NetHsmImage};
use nethsm::NetHsm;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn system_info(
    #[future] unprovisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (unprovisioned_nethsm, _container) = unprovisioned_nethsm.await?;
    let (nethsm, _container) = nethsm_with_users.await?;

    println!("Retrieving system info for unprovisioned device...");
    assert!(unprovisioned_nethsm.system_info().is_err());

    println!("Retrieving system info for operational device...");
    assert!(nethsm.system_info().is_ok());
    println!("{:?}", nethsm.system_info()?);
    Ok(())
}
