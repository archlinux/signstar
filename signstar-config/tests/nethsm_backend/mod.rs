//! Integration tests for [`signstar_config::nethsm::backend`] (against a NetHSM container).

use log::{LevelFilter, debug};
use nethsm::{Connection, NetHsm, SystemState, UserId, UserRole, test::create_container};
use rstest::rstest;
use signstar_common::logging::setup_logging;
use signstar_config::{
    NetHsmBackend,
    config::state::SignstarConfigNetHsmState,
    nethsm::{NetHsmUserMapping, state::NetHsmState},
    state::StateHandling,
    test::{
        ConfigFileConfig,
        ConfigFileVariant,
        SystemPrepareConfig,
        admin_credentials,
        create_full_credentials,
    },
};
use testresult::TestResult;

/// Simple configuration
const SIGNSTAR_ADMIN_CREDS_SIMPLE: &[u8] = include_bytes!("../fixtures/admin-creds-simple.toml");

/// Tests that an unprovisioned backend can be provisioned using a valid Signstar config.
#[rstest]
#[case::nethsm_plain_admin(
    SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: None,
            variant: ConfigFileVariant::OnlyNetHsmBackendPlainAdmin,
            system_user_config: None
        },
    },
    SIGNSTAR_ADMIN_CREDS_SIMPLE,
)]
#[tokio::test]
async fn sync_unprovisioned_backend(
    #[case] system_prepare_config: SystemPrepareConfig,
    #[case] creds_data: &[u8],
) -> TestResult {
    setup_logging(LevelFilter::Debug)?;
    let signstar_config = system_prepare_config.signstar_config.variant.to_config()?;
    let Some(nethsm_config) = signstar_config.nethsm() else {
        panic!("This test requires a NetHSM configuration object in the Signstar config");
    };
    // Derive the acclaimed NetHSM state from the Signstar config
    let signstar_state = SignstarConfigNetHsmState::from(nethsm_config);
    let admin_credentials = admin_credentials(creds_data)?;

    let container = create_container().await?;
    let url = container.url().await?;
    let non_admin_users = nethsm_config
        .mappings()
        .iter()
        .flat_map(|mapping: &NetHsmUserMapping| {
            mapping
                .nethsm_user_data()
                .iter()
                .filter_map(|user_data| {
                    if user_data.role != UserRole::Administrator {
                        Some(user_data.user.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<UserId>>();
    let user_credentials = create_full_credentials(&non_admin_users);

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
