use nethsm::{NetHsm, Passphrase, SystemState, UserId};
use nethsm_tests::{
    ADMIN_USER_ID,
    NAMESPACE1_ADMIN_USER_ID,
    NetHsmImage,
    UNLOCK_PASSPHRASE,
    nethsm_with_users,
};
use rstest::rstest;
use rustainers::Container;
use testresult::TestResult;

#[ignore = "requires Podman"]
#[rstest]
#[tokio::test]
async fn lock_and_unlock(
    #[future] nethsm_with_users: TestResult<(NetHsm, Container<NetHsmImage>)>,
) -> TestResult {
    let (nethsm, _container) = nethsm_with_users.await?;
    let namespace1_admin_user_id: UserId = NAMESPACE1_ADMIN_USER_ID.parse()?;
    let admin_user_id: UserId = ADMIN_USER_ID.parse()?;

    // N-Administrators can not lock
    nethsm.use_credentials(&namespace1_admin_user_id)?;
    assert_eq!(SystemState::Operational, nethsm.state()?);
    assert!(nethsm.lock().is_err());

    // R-Administrators can lock
    nethsm.use_credentials(&admin_user_id)?;
    assert_eq!(SystemState::Operational, nethsm.state()?);
    nethsm.lock()?;
    assert_eq!(SystemState::Locked, nethsm.state()?);

    // N-Administrators can unlock ?!
    nethsm.use_credentials(&namespace1_admin_user_id)?;
    nethsm.unlock(Passphrase::new(UNLOCK_PASSPHRASE.to_string()))?;
    assert_eq!(SystemState::Operational, nethsm.state()?);

    // R-Administrators can unlock
    nethsm.use_credentials(&admin_user_id)?;
    nethsm.lock()?;
    assert_eq!(SystemState::Locked, nethsm.state()?);
    nethsm.unlock(Passphrase::new(UNLOCK_PASSPHRASE.to_string()))?;
    assert_eq!(SystemState::Operational, nethsm.state()?);

    Ok(())
}
