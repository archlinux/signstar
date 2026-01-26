//! Integration tests for [`signstar_config::config`].
use std::{fs::copy, path::PathBuf};

use nix::unistd::{User, geteuid};
use rstest::rstest;
use signstar_common::config::{
    create_default_config_dir,
    create_etc_override_config_dir,
    create_run_override_config_dir,
    create_usr_local_override_config_dir,
    get_default_config_dir_path,
    get_default_config_file_path,
    get_etc_override_config_file_path,
    get_etc_override_dir_path,
    get_run_override_config_file_path,
    get_run_override_dir_path,
    get_usr_local_override_config_file_path,
    get_usr_local_override_dir_path,
};
use signstar_config::{SignstarConfig, SystemUserId, test::get_tmp_config};
use testresult::TestResult;

/// Full configuration
const SIGNSTAR_CONFIG_FULL: &[u8] = include_bytes!("../fixtures/signstar-config-full.toml");

/// Ensure that [`SystemUserId`] can be created from the current Unix user ("root").
#[cfg(target_os = "linux")]
#[test]
fn system_user_id_from_unix_user() -> TestResult {
    let current_user = User::from_uid(geteuid())?.expect("root is a valid system user");
    assert_eq!(
        SystemUserId::new("root".to_string())?,
        SystemUserId::try_from(current_user)?
    );
    Ok(())
}

#[rstest]
#[case(get_default_config_dir_path())]
#[case(get_etc_override_dir_path())]
#[case(get_run_override_dir_path())]
#[case(get_usr_local_override_dir_path())]
fn load_config_from_default_location(#[case] config_dir: PathBuf) -> TestResult {
    println!("Config dir to test: {config_dir:?}");
    let config_file_fixture = get_tmp_config(SIGNSTAR_CONFIG_FULL)?;
    // force remove any files that may be present in any of the configuration dirs
    for dir in [
        get_default_config_dir_path(),
        get_etc_override_dir_path(),
        get_run_override_dir_path(),
        get_usr_local_override_dir_path(),
    ] {
        let _remove = std::fs::remove_dir_all(dir);
    }

    let config_file_path = if config_dir == get_usr_local_override_dir_path() {
        create_usr_local_override_config_dir()?;
        get_usr_local_override_config_file_path()
    } else if config_dir == get_default_config_dir_path() {
        create_default_config_dir()?;
        get_default_config_file_path()
    } else if config_dir == get_etc_override_dir_path() {
        create_etc_override_config_dir()?;
        get_etc_override_config_file_path()
    } else if config_dir == get_run_override_dir_path() {
        create_run_override_config_dir()?;
        get_run_override_config_file_path()
    } else {
        unimplemented!("No test case for config dir: {config_dir:?}")
    };

    println!("Copying {config_file_fixture:?} to {config_file_path:?}");
    copy(config_file_fixture, &config_file_path)?;

    SignstarConfig::new_from_file(None)?;

    Ok(())
}

/// Ensures that when not providing a path to [`SignstarConfig::store`], the default runtime
/// directory is written to.
#[rstest]
fn signstar_config_store_to_runtime_dir() -> TestResult {
    let config_file_fixture = get_tmp_config(SIGNSTAR_CONFIG_FULL)?;
    let config = SignstarConfig::new_from_file(Some(config_file_fixture.path()))?;

    assert!(!get_run_override_config_file_path().exists());
    config.store(None)?;

    assert!(get_run_override_config_file_path().exists());

    Ok(())
}

/// Ensures that when providing an invalid path to [`SignstarConfig::store`], the parent dir
/// creation fails.
#[rstest]
fn signstar_config_store_fails_on_parent() -> TestResult {
    let config_file_fixture = get_tmp_config(SIGNSTAR_CONFIG_FULL)?;
    let config = SignstarConfig::new_from_file(Some(config_file_fixture.path()))?;

    let config_path = "..";
    if config.store(Some(&PathBuf::from(config_path))).is_ok() {
        panic!("Creating parent of {config_path} should not be possible");
    }

    Ok(())
}
