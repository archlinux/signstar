//! Integration tests for [`signstar_config::nethsm`] (against a NetHSM container).

use nethsm_tests::create_container;
use rstest::rstest;
use testresult::TestResult;

use crate::utils::{
    SIGNSTAR_ADMIN_CREDS_SIMPLE,
    SIGNSTAR_CONFIG_FULL,
    admin_credentials,
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
    let container = create_container().await?;
    let url = container.url().await?;
    let signstar_config = signstar_config(config_data)?;
    let admin_creds = admin_credentials(creds_data)?;

    // TODO
    Ok(())
}
