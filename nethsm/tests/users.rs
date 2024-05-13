// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod common;
use common::provisioned_nethsm;
use common::NetHsmImage;
use common::DEFAULT_OPERATOR_USER_PASSPHRASE;
use common::DEFAULT_OPERATOR_USER_REAL_NAME;
use common::OTHER_OPERATOR_USER_ID;
use common::OTHER_OPERATOR_USER_PASSPHRASE;
use common::OTHER_OPERATOR_USER_REAL_NAME;
use nethsm::Passphrase;
use nethsm::{NetHsm, UserRole};
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn create_users(
    #[future] provisioned_nethsm: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = provisioned_nethsm.await?;

    assert!(nethsm.get_users()?.len() == 1);
    let operator_user = nethsm.add_user(
        DEFAULT_OPERATOR_USER_REAL_NAME.to_string(),
        UserRole::Operator,
        Passphrase::new(DEFAULT_OPERATOR_USER_PASSPHRASE.to_string()),
        None,
    )?;
    println!("Created Operator User: {}", operator_user);
    assert!(nethsm.get_users()?.len() == 2);
    println!("Operator user data: {:?}", nethsm.get_user(&operator_user)?);

    // change passphrase
    nethsm.set_user_passphrase(
        &operator_user,
        Passphrase::new("some-other-operator-passphrase".to_string()),
    )?;

    let other_operator_user = nethsm.add_user(
        OTHER_OPERATOR_USER_REAL_NAME.to_string(),
        UserRole::Operator,
        Passphrase::new(OTHER_OPERATOR_USER_PASSPHRASE.to_string()),
        Some(OTHER_OPERATOR_USER_ID.to_string()),
    )?;
    println!("Created Operator User: {}", other_operator_user);
    assert!(nethsm.get_users()?.len() == 3);
    println!(
        "Operator user data: {:?}",
        nethsm.get_user(&other_operator_user)?
    );

    nethsm.delete_user(&operator_user)?;
    nethsm.delete_user(&other_operator_user)?;
    assert!(nethsm.get_users()?.len() == 1);

    Ok(())
}
