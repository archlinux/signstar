// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;
use common::nethsm_with_users;
use common::DEFAULT_OPERATOR_USER_ID;
use common::DEFAULT_OPERATOR_USER_PASSPHRASE;
use nethsm::NetHsm;
use podman_api::api::Container;
use rstest::rstest;
use testresult::TestResult;

pub static LENGTH: i32 = 32;

#[ignore = "requires running Podman API service"]
#[rstest]
#[tokio::test]
async fn get_random_bytes(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container)>,
) -> TestResult {
    let (nethsm, container) = nethsm_with_users.await?;
    nethsm.add_credentials((
        DEFAULT_OPERATOR_USER_ID.to_string(),
        Some(DEFAULT_OPERATOR_USER_PASSPHRASE.to_string()),
    ));
    nethsm.use_credentials(DEFAULT_OPERATOR_USER_ID)?;

    let random_message = nethsm.random(LENGTH)?;
    println!("A random message from the NetHSM: {:#?}", random_message);

    assert_eq!(usize::try_from(LENGTH)?, random_message.len(),);

    container.stop(&Default::default()).await?;
    Ok(())
}
