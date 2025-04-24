//! Integration tests for [`signstar_config::config`].
use std::{fs::copy, path::PathBuf};

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
use signstar_config::config::load_config;
use signstar_config::test::get_tmp_config;
use testresult::TestResult;

use crate::utils::SIGNSTAR_CONFIG_FULL;

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

    load_config()?;

    Ok(())
}
