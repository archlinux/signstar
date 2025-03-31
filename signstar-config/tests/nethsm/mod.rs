//! Integration tests for [`signstar_config::nethsm`] (against a NetHSM container).

use log::debug;
use nethsm::{Connection, UserId};
use nethsm_config::UserMapping;
use nethsm_tests::create_container;
use rstest::rstest;
use signstar_config::nethsm::NetHsmState;
use testresult::TestResult;

use crate::utils::{
    SIGNSTAR_ADMIN_CREDS_SIMPLE,
    SIGNSTAR_CONFIG_FULL,
    admin_credentials,
    credentials,
    signstar_config,
};

/// Test that an unprovisioned backend can be provisioned using a valid Signstar config.
#[rstest]
#[case(SIGNSTAR_CONFIG_FULL, SIGNSTAR_ADMIN_CREDS_SIMPLE)]
#[tokio::test]
async fn sync_unprovisioned_backend(
    #[case] config_data: &[u8],
    #[case] creds_data: &[u8],
) -> TestResult {
    env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .init();

    let container = create_container().await?;
    let url = container.url().await?;
    let signstar_config = signstar_config(config_data)?;
    let user_mappings = signstar_config
        .iter_user_mappings()
        .cloned()
        .collect::<Vec<UserMapping>>();
    let users = user_mappings
        .iter()
        .flat_map(|mapping| mapping.get_nethsm_users())
        .collect::<Vec<UserId>>();
    let admin_credentials = admin_credentials(creds_data)?;
    let user_credentials = credentials(users.as_slice());

    debug!("Running sync");
    NetHsmState::sync(
        Connection::new(url.clone(), nethsm::ConnectionSecurity::Unsafe),
        &admin_credentials,
        &signstar_config,
        &user_credentials,
    )?;
    debug!("Finished sync");
    debug!("Rerunning sync");
    NetHsmState::sync(
        Connection::new(url, nethsm::ConnectionSecurity::Unsafe),
        &admin_credentials,
        &signstar_config,
        &user_credentials,
    )?;
    debug!("Finished rerunning sync");

    // TODO: check that all users and keys exist
    Ok(())
}

/// Test that an unprovisioned backend can be provisioned using a valid Signstar config.
#[rstest]
#[case(SIGNSTAR_CONFIG_FULL, SIGNSTAR_ADMIN_CREDS_SIMPLE)]
#[tokio::test]
async fn sync_provisioned_backend(
    #[case] config_data: &[u8],
    #[case] creds_data: &[u8],
) -> TestResult {
    env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .init();

    let container = create_container().await?;
    let url = container.url().await?;
    let signstar_config = signstar_config(config_data)?;
    let user_mappings = signstar_config
        .iter_user_mappings()
        .cloned()
        .collect::<Vec<UserMapping>>();
    let users = user_mappings
        .iter()
        .flat_map(|mapping| mapping.get_nethsm_users())
        .collect::<Vec<UserId>>();
    let admin_credentials = admin_credentials(creds_data)?;
    let user_credentials = credentials(users.as_slice());

    NetHsmState::sync(
        Connection::new(url, nethsm::ConnectionSecurity::Unsafe),
        &admin_credentials,
        &signstar_config,
        &user_credentials,
    )?;

    // TODO: check that all users and keys exist
    Ok(())
}
