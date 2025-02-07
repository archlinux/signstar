use std::{
    fs::read_dir,
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
};

use nethsm_config::{
    ConfigInteractivity,
    ConfigSettings,
    ExtendedUserMapping,
    HermeticParallelConfig,
};
use rstest::rstest;
use signstar_config::non_admin_credentials::PassphraseCreation;
use signstar_core::{common::get_data_home, config::get_default_config_file_path};
use testresult::TestResult;
use which::which;

use super::utils::write_machine_id;
use crate::utils::{create_users, run_command_as_user, start_credentials_socket};

fn list_files_in_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
    let entries = read_dir(path)?;

    for entry in entries {
        let entry = entry?;
        let meta = entry.metadata()?;

        println!(
            "{entry:?}\nmode: {}\nuid: {}\ngid: {}",
            entry.metadata()?.permissions().mode(),
            entry.metadata()?.st_uid(),
            entry.metadata()?.st_gid()
        );
        if meta.is_dir() {
            list_files_in_dir(entry.path())?;
        }
    }

    Ok(())
}

#[rstest]
fn load_systemd_creds(
    #[files("config.toml")]
    #[base_dir = "tests/non_admin_credentials_single/fixtures/"]
    config_file_fixture: PathBuf,
) -> TestResult {
    write_machine_id()?;

    // write Signstar config to default config location
    let system_config = HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            "my_app".to_string(),
            ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(config_file_fixture.as_path()),
    )?;
    system_config.store(Some(&get_default_config_file_path()))?;

    // create users and homes
    let system_users = system_config
        .iter_user_mappings()
        .filter_map(|mapping| mapping.get_system_user())
        .map(|system_user_id| system_user_id.to_string())
        .collect::<Vec<String>>();
    create_users(system_users.as_slice())?;

    // Create /run/systemd/io.systemd.Credentials
    let mut credentials_socket = start_credentials_socket()?;

    // Create dummy passphrase files for each system user and their respective NetHSM
    // credentials.
    let creds_mapping: Vec<ExtendedUserMapping> = system_config.into();
    for mapping in &creds_mapping {
        // create directory for passphrase files per user
        mapping.create_secrets_dir()?;
        mapping.create_non_administrative_secrets()?;
    }

    list_files_in_dir(get_data_home().parent().unwrap())?;

    // run get-nethsm-credentials example for each user
    let payload = "get-nethsm-credentials";
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            println!("Running {payload} as user {system_user_id}");
            let get_creds_bin = match which(payload) {
                Ok(bin) => bin.to_string_lossy().to_string(),
                Err(_) => payload.to_string(),
            };
            // TODO: this doesn't fail the test?!
            if run_command_as_user(&[&get_creds_bin], system_user_id.as_ref()).is_err() {
                println!("user call failed!")
            }
        } else {
            eprintln!("Mapping without system user!\n{:?}", mapping);
        }
    }

    // kill created socket to not leak the subprocess
    credentials_socket.kill()?;

    Ok(())
}
