//! Integration tests for [`signstar_config::nethsm::backend`] (against a NetHSM container).

use log::{LevelFilter, debug};
use nethsm::{Connection, NetHsm, SystemState, UserId, test::create_container};
use rstest::rstest;
use signstar_common::logging::setup_logging;
use signstar_config::{
    NetHsmBackend,
    UserMapping,
    config::state::SignstarConfigNetHsmState,
    nethsm::state::NetHsmState,
    state::StateHandling,
    test::{admin_credentials, create_full_credentials, signstar_config},
};
use testresult::TestResult;

/// Full configuration
const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");

/// Simple configuration
const SIGNSTAR_ADMIN_CREDS_SIMPLE: &[u8] = include_bytes!("../fixtures/admin-creds-simple.toml");

/// Tests that an unprovisioned backend can be provisioned using a valid Signstar config.
#[rstest]
#[case(SIGNSTAR_CONFIG_FULL, SIGNSTAR_ADMIN_CREDS_SIMPLE)]
#[tokio::test]
async fn sync_unprovisioned_backend(
    #[case] config_data: &[u8],
    #[case] creds_data: &[u8],
) -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    let container = create_container().await?;
    let url = container.url().await?;
    let signstar_config = signstar_config(config_data)?;
    // Derive the acclaimed NetHSM state from the Signstar config
    let signstar_state = SignstarConfigNetHsmState::from(&signstar_config);
    let user_mappings = signstar_config
        .iter_user_mappings()
        .cloned()
        .collect::<Vec<UserMapping>>();
    let users = user_mappings
        .iter()
        .flat_map(|mapping| mapping.get_nethsm_users())
        .collect::<Vec<UserId>>();
    let admin_credentials = admin_credentials(creds_data)?;
    let user_credentials = create_full_credentials(users.as_slice());

    debug!("Creating NetHsmBackend");
    let nethsm = NetHsm::new(
        Connection::new(url.clone(), nethsm::ConnectionSecurity::Unsafe),
        None,
        None,
        None,
    )?;
    assert_eq!(nethsm.state()?, SystemState::Unprovisioned);

    let nethsm_backend = NetHsmBackend::new(nethsm, &admin_credentials, &signstar_config)?;
    debug!("Running sync");
    nethsm_backend.sync(&user_credentials)?;
    assert_eq!(nethsm_backend.nethsm().state()?, SystemState::Operational);

    nethsm_backend.nethsm().lock()?;
    assert_eq!(nethsm_backend.nethsm().state()?, SystemState::Locked);

    debug!("Retrieve state of NetHSM");
    let initial_nethsm_state = NetHsmState::try_from(&nethsm_backend)?;

    debug!("Compare state of NetHSM with that of the Signstar config");
    initial_nethsm_state.compare(&signstar_state);

    debug!("Rerunning sync");
    nethsm_backend.sync(&user_credentials)?;
    let nethsm_state = NetHsmState::try_from(&nethsm_backend)?;
    debug!("Compare state of NetHSM with that of the Signstar config");
    nethsm_state.compare(&signstar_state);
    assert_eq!(nethsm_backend.nethsm().state()?, SystemState::Operational);

    Ok(())
}
