//! Tests of NetHSM namespaces.

use nethsm::NetHsm;
use nethsm_tests::{NetHsmImage, nethsm_with_users};
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn namespace_lifecycle(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let namespace_test = "namespacetest";

    println!("Retrieving namespaces for operational device...");
    let init_ns_len = nethsm.get_namespaces()?.len();
    println!("Namespaces: {:?}", nethsm.get_namespaces()?);

    println!("Adding namespace {}...", namespace_test);
    nethsm.add_namespace(&namespace_test.parse()?)?;
    let add_ns_len = nethsm.get_namespaces()?.len();

    println!("Retrieving namespaces after adding namespace...");
    println!("Namespaces: {:?}", nethsm.get_namespaces());
    assert!(init_ns_len < add_ns_len);

    println!("Deleting namespace {}...", namespace_test);
    nethsm.delete_namespace(&namespace_test.parse()?)?;
    let end_ns_len = nethsm.get_namespaces()?.len();
    assert_eq!(init_ns_len, end_ns_len);

    Ok(())
}
