//! Integration tests for [`signstar_config::nethsm`] (against a NetHSM container).

use log::{LevelFilter, debug};
use nethsm::test::create_container;
use nethsm::{Connection, UserId};
use nethsm_config::UserMapping;
use rstest::rstest;
use signstar_config::FullNetHsmBackend;
use signstar_config::test::{admin_credentials, credentials, signstar_config};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};
use testresult::TestResult;

/// Full configuration
const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");

/// Simple configuration
const SIGNSTAR_ADMIN_CREDS_SIMPLE: &[u8] = include_bytes!("../fixtures/admin-creds-simple.toml");

fn init_logger() -> TestResult {
    if TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .is_err()
    {
        debug!("Not initializing another logger, as one is initialized already.");
    }

    Ok(())
}

/// Test that an unprovisioned backend can be provisioned using a valid Signstar config.
#[rstest]
#[case(SIGNSTAR_CONFIG_FULL, SIGNSTAR_ADMIN_CREDS_SIMPLE)]
#[tokio::test]
async fn sync_unprovisioned_backend(
    #[case] config_data: &[u8],
    #[case] creds_data: &[u8],
) -> TestResult {
    init_logger()?;

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

    debug!("Creating NetHsmBackend");
    let nethsm_backend = FullNetHsmBackend::new(
        Connection::new(url.clone(), nethsm::ConnectionSecurity::Unsafe),
        &admin_credentials,
        &signstar_config,
    )?;
    debug!("Running sync");
    nethsm_backend.sync(&user_credentials)?;
    debug!("Finished sync");
    debug!("Rerunning sync");
    nethsm_backend.sync(&user_credentials)?;
    debug!("Finished rerunning sync");

    // TODO: check that all users and keys exist
    Ok(())
}
