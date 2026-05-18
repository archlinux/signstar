//! Integration tests for [`signstar_config::nethsm::backend`] (against a NetHSM container).

use std::{collections::BTreeSet, thread::current};

use insta::{assert_snapshot, with_settings};
use log::{LevelFilter, debug, info};
use nethsm::{
    Connection,
    FullCredentials,
    NetHsm,
    SystemState,
    UserId,
    UserRole,
    test::create_container,
};
use rstest::rstest;
use signstar_common::logging::setup_logging;
use signstar_config::{
    config::{SystemUserConfigState, SystemUserDiff, SystemUserHostState},
    nethsm::{
        NetHsmAdminCredentials,
        NetHsmBackend,
        NetHsmBackendState,
        NetHsmConfig,
        NetHsmConfigState,
        NetHsmConfigStateLegacy,
        NetHsmDiff,
        NetHsmMetricsUsers,
        NetHsmUserMapping,
    },
    state::{StateDiff, StateDiffReport, StateHandling},
    test::{
        ConfigFileConfig,
        ConfigFileVariant,
        SystemPrepareConfig,
        create_full_credentials,
        nethsm_admin_credentials,
    },
};
use signstar_crypto::{
    key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
    openpgp::OpenPgpUserIdList,
};
use testresult::TestResult;

/// Simple configuration
const SIGNSTAR_ADMIN_CREDS_SIMPLE: &[u8] = include_bytes!("../fixtures/admin-creds-simple.toml");
/// The insta snapshot directory.
const SNAPSHOT_PATH: &str = "fixtures/nethsm/";

/// Tests that an unprovisioned backend can be provisioned using a valid Signstar config.
#[rstest]
#[case::nethsm_plain_admin(
    SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: None,
            variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCreds,
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
    let signstar_state = NetHsmConfigStateLegacy::from(nethsm_config);
    let nethsm_admin_credentials = nethsm_admin_credentials(creds_data)?;
    let nethsm_config_state = NetHsmConfigState::from(nethsm_config);

    // Check the system user state.
    let system_user_config_state = SystemUserConfigState::from(&signstar_config);
    let system_user_host_state = SystemUserHostState::new()?;
    let system_user_diff = SystemUserDiff {
        config: &system_user_config_state,
        system: &system_user_host_state,
    };
    debug!("Compare the state of system user config with that of the host before sync.");
    match system_user_diff.diff() {
        StateDiffReport::Failure { messages } => {
            debug!(
                "The state is supposed to be different, and these are the failures:\n{}",
                messages
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        StateDiffReport::Success => {
            panic!("The system should not be setup to have Signstar users!")
        }
    }

    let container = create_container().await?;
    let url = container.url().await?;
    let non_admin_users = nethsm_config
        .mappings()
        .iter()
        .flat_map(|mapping: &NetHsmUserMapping| {
            mapping
                .nethsm_config_user_data()
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

    let Some(nethsm_backend) =
        NetHsmBackend::new(nethsm, &nethsm_admin_credentials, &signstar_config)?
    else {
        panic!("The Signstar configuration must have a NetHSM config object.");
    };

    // Get the diff of the NetHSM config and the NetHSM backend before syncing.
    debug!("Retrieve state of the NetHSM backend before sync.");
    let nethsm_backend_state = NetHsmBackendState::try_from(&nethsm_backend)?;
    let nethsm_diff = NetHsmDiff {
        config: &nethsm_config_state,
        backend: &nethsm_backend_state,
    };
    debug!("Compare the state of NetHSM config with that of the NetHSM backend before sync.");
    match nethsm_diff.diff() {
        StateDiffReport::Success => panic!("The state should be different!"),
        StateDiffReport::Failure { messages } => debug!(
            "The state is supposed to be different, and these are the failures:\n{}",
            messages
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }

    debug!("Running sync");
    nethsm_backend.sync(&user_credentials)?;
    assert_eq!(nethsm_backend.nethsm().state()?, SystemState::Operational);

    nethsm_backend.nethsm().lock()?;
    assert_eq!(nethsm_backend.nethsm().state()?, SystemState::Locked);

    // Get the diff of the NetHSM config and the NetHSM backend after syncing.
    debug!("Retrieve state of the NetHSM backend after sync.");
    let nethsm_backend_state = NetHsmBackendState::try_from(&nethsm_backend)?;
    let nethsm_diff = NetHsmDiff {
        config: &nethsm_config_state,
        backend: &nethsm_backend_state,
    };
    debug!("Compare the state of NetHSM config with that of the NetHSM backend after sync.");
    match nethsm_diff.diff() {
        StateDiffReport::Success => {}
        StateDiffReport::Failure { messages } => panic!(
            "The state should match, but there are failures:\n{}",
            messages
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }

    debug!("Compare state of NetHSM with that of the Signstar config");
    nethsm_backend_state.compare(&signstar_state);

    debug!("Rerunning sync");
    nethsm_backend.sync(&user_credentials)?;

    // Get the diff of the NetHSM config and the NetHSM backend after re-syncing.
    debug!("Retrieve state of the NetHSM backend after re-sync.");
    let nethsm_backend_state = NetHsmBackendState::try_from(&nethsm_backend)?;
    let nethsm_diff = NetHsmDiff {
        config: &nethsm_config_state,
        backend: &nethsm_backend_state,
    };
    debug!("Compare the state of NetHSM config with that of the NetHSM backend after sync.");
    match nethsm_diff.diff() {
        StateDiffReport::Success => {}
        StateDiffReport::Failure { messages } => panic!(
            "The state should match, but there are failures:\n{}",
            messages
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }

    nethsm_backend_state.compare(&signstar_state);
    assert_eq!(nethsm_backend.nethsm().state()?, SystemState::Operational);

    Ok(())
}

/// Ensures, that [`NetHsmDiff::diff`] fails on mismatching state items in [`NetHsmBackendState`]
/// and [`NetHsmConfigState`].
#[rstest]
#[tokio::test]
async fn nethsm_diff_diff_fails_on_discrepancies() -> TestResult {
    setup_logging(LevelFilter::Debug)?;

    // Setup the system in accordance with a default config.
    let system_prepare_config = SystemPrepareConfig {
        machine_id: false,
        credentials_socket: false,
        signstar_config: ConfigFileConfig {
            location: None,
            variant: ConfigFileVariant::OnlyNetHsmBackendAdminPlaintextNonAdminSystemdCreds,
            system_user_config: None,
        },
    };
    let signstar_config = system_prepare_config.signstar_config.variant.to_config()?;
    let Some(nethsm_config) = signstar_config.nethsm() else {
        panic!("This test requires a NetHSM configuration object in the Signstar config");
    };
    let nethsm_admin_credentials = NetHsmAdminCredentials::new(
        1,
        "backup_passphrase".parse()?,
        "unlock_passphrase".parse()?,
        vec![FullCredentials::new(
            "admin".parse()?,
            "admin-passphrase".parse()?,
        )],
        vec![FullCredentials::new(
            "ns1~admin".parse()?,
            "admin-passphrase".parse()?,
        )],
    )?;
    let nethsm_config_state = NetHsmConfigState::from(nethsm_config);

    let container = create_container().await?;
    let url = container.url().await?;
    let non_admin_users = nethsm_config
        .mappings()
        .iter()
        .flat_map(|mapping: &NetHsmUserMapping| {
            mapping
                .nethsm_config_user_data()
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

    info!("Create NetHsmBackend.");
    let nethsm = NetHsm::new(
        Connection::new(url.clone(), nethsm::ConnectionSecurity::Unsafe),
        None,
        None,
        None,
    )?;
    assert_eq!(nethsm.state()?, SystemState::Unprovisioned);
    let Some(nethsm_backend) =
        NetHsmBackend::new(nethsm, &nethsm_admin_credentials, &signstar_config)?
    else {
        panic!("The Signstar configuration must have a NetHSM config object.");
    };
    nethsm_backend.sync(&user_credentials)?;

    info!("Retrieve state of the NetHSM backend after sync.");
    let nethsm_backend_state = NetHsmBackendState::try_from(&nethsm_backend)?;
    let nethsm_diff = NetHsmDiff {
        config: &nethsm_config_state,
        backend: &nethsm_backend_state,
    };
    info!("Compare the state of NetHSM config with that of the NetHSM backend after sync.");
    match nethsm_diff.diff() {
        StateDiffReport::Success => {}
        StateDiffReport::Failure { messages } => panic!(
            "The state should match, but there are failures:\n{}",
            messages
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }

    info!(
        "Compare the state of a mismatching NetHSM config with that of the NetHSM backend after sync."
    );
    let mismatching_nethsm_config = NetHsmConfig::new(
        BTreeSet::from_iter([
            Connection::new(
                "https://nethsm1.example.org/".parse()?,
                nethsm::ConnectionSecurity::Unsafe,
            ),
            Connection::new(
                "https://nethsm2.example.org/".parse()?,
                nethsm::ConnectionSecurity::Unsafe,
            ),
        ]),BTreeSet::from_iter([
            NetHsmUserMapping::Admin("admin".parse()?),
            NetHsmUserMapping::Backup{
                backend_user: "backup".parse()?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh9BTe81DC6A0YZALsq9dWcyl6xjjqlxWPwlExTFgBt user@host".parse()?,
                system_user: "backup-user".parse()?,
            },
            NetHsmUserMapping::HermeticMetrics {
                backend_users: NetHsmMetricsUsers::new("hermetickeymetrics".parse()?, vec!["hermeticmetrics".parse()?])?,
                system_user: "metrics-user".parse()?,
            },
            NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new("metrics".parse()?, vec!["keymetrics".parse()?])?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
                system_user: "hermetic-metrics-user".parse()?,
            },
            NetHsmUserMapping::Signing {
                backend_user: "signing".parse()?,
                signing_key_id: "signing1".parse()?,
                key_setup: SigningKeySetup::new(
                    KeyType::EcP521,
                    vec![KeyMechanism::EcdsaSignature],
                    None,
                    SignatureType::EcdsaP521,
                    CryptographicKeyContext::OpenPgp {
                        user_ids: OpenPgpUserIdList::new(vec![
                            "BarFoo Fooface <barfoo@fooface.org>".parse()?,
                        ])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
                system_user: "signing-user".parse()?,
                tag: "signing1".to_string(),
            }
        ])
    )?;
    let nethsm_config_state = NetHsmConfigState::from(&mismatching_nethsm_config);
    let nethsm_diff = NetHsmDiff {
        config: &nethsm_config_state,
        backend: &nethsm_backend_state,
    };
    match nethsm_diff.diff() {
        StateDiffReport::Success => {
            panic!(
                "The state of the mismatching NetHSM config should not match that of the previously setup NetHSM backend."
            )
        }
        StateDiffReport::Failure { messages } => {
            let output = messages
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            debug!("The mismatching states, had the following failures:\n{output}");

            with_settings!({
                description => "Mismatches between NetHSM config state and NetHSM backend state",
                snapshot_path => SNAPSHOT_PATH,
                prepend_module_to_snapshot => false,
            }, {
                assert_snapshot!(current().name().expect("current thread should have a name").to_string().replace("::", "__"), output);
            });
        }
    }

    Ok(())
}
