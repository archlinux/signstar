mod common;
use common::{nethsm_with_users, NetHsmImage, METRICS_USER_ID};
use nethsm::NetHsm;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn metrics(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    // system-wide metrics users can retrieve metrics
    nethsm.use_credentials(&METRICS_USER_ID.parse()?)?;
    println!("The NetHSM metrics: {}", nethsm.metrics()?);

    Ok(())
}
