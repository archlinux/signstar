use std::{fs::copy, path::PathBuf};

use rstest::rstest;
use signstar_config::nethsm_config::load_config;
use signstar_core::config::{
    DEFAULT_CONFIG_DIR,
    ETC_OVERRIDE_CONFIG_DIR,
    RUN_OVERRIDE_CONFIG_DIR,
    USR_LOCAL_OVERRIDE_CONFIG_DIR,
    create_default_config_dir,
    create_etc_override_config_dir,
    create_run_override_config_dir,
    create_usr_local_override_config_dir,
    get_default_config_file,
    get_etc_override_config_file,
    get_run_override_config_file,
    get_usr_local_override_config_file,
};
use testresult::TestResult;

#[rstest]
#[case(DEFAULT_CONFIG_DIR)]
#[case(ETC_OVERRIDE_CONFIG_DIR)]
#[case(RUN_OVERRIDE_CONFIG_DIR)]
#[case(USR_LOCAL_OVERRIDE_CONFIG_DIR)]
fn load_config_from_default_location(
    #[files("config.toml")]
    #[base_dir = "tests/nethsm_config_single/fixtures/"]
    config_file_fixture: PathBuf,
    #[case] config_dir: &str,
) -> TestResult {
    println!("Config dir to test: {config_dir}");
    // force remove any files that may be present in any of the configuration dirs
    for dir in [
        DEFAULT_CONFIG_DIR,
        ETC_OVERRIDE_CONFIG_DIR,
        RUN_OVERRIDE_CONFIG_DIR,
        USR_LOCAL_OVERRIDE_CONFIG_DIR,
    ] {
        let _remove = std::fs::remove_dir_all(PathBuf::from(dir));
    }

    let config_file_str = match config_dir {
        USR_LOCAL_OVERRIDE_CONFIG_DIR => {
            create_usr_local_override_config_dir()?;
            get_usr_local_override_config_file()
        }
        DEFAULT_CONFIG_DIR => {
            create_default_config_dir()?;
            get_default_config_file()
        }
        ETC_OVERRIDE_CONFIG_DIR => {
            create_etc_override_config_dir()?;
            get_etc_override_config_file()
        }
        RUN_OVERRIDE_CONFIG_DIR => {
            create_run_override_config_dir()?;
            get_run_override_config_file()
        }
        _ => unimplemented!("No test case for config dir: {config_dir}"),
    };

    let path = PathBuf::from(&config_file_str);
    println!("Copying {config_file_fixture:?} to {config_file_str}");
    copy(config_file_fixture, &path)?;

    load_config()?;

    Ok(())
}
