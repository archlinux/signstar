//! Tests of random number generator of NetHSM.

use nethsm::Credentials;
use nethsm::NetHsm;
use nethsm::Passphrase;
use nethsm::test::DEFAULT_OPERATOR_USER_ID;
use nethsm::test::DEFAULT_OPERATOR_USER_PASSPHRASE;
use nethsm::test::NetHsmImage;
use nethsm::test::nethsm_with_users;
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

static LENGTH: u32 = 32;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn get_random_bytes(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    nethsm.add_credentials(Credentials::new(
        DEFAULT_OPERATOR_USER_ID.parse()?,
        Some(Passphrase::new(
            DEFAULT_OPERATOR_USER_PASSPHRASE.to_string(),
        )),
    ));
    nethsm.use_credentials(&DEFAULT_OPERATOR_USER_ID.parse()?)?;

    let random_message = nethsm.random(LENGTH)?;
    println!("A random message from the NetHSM: {random_message:#?}");

    assert_eq!(usize::try_from(LENGTH)?, random_message.len(),);

    Ok(())
}
