use std::fs::{create_dir_all, write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::fs::chown;
use std::process::Command;
use std::{fs::read_to_string, path::PathBuf};

use nethsm_config::{
    ConfigInteractivity,
    ConfigSettings,
    CredsAwareUserMapping,
    HermeticParallelConfig,
    NonAdministrativeSecretHandling,
};
use nix::unistd::User;
use rstest::rstest;
use signstar_config::non_admin_credentials::get_persistent_passphrase_path_for_user;
use signstar_config::utils::delete_tmp_file;
use signstar_core::config::get_default_config_file;
use testresult::TestResult;

use super::utils::write_machine_id;
use crate::utils::{create_users, run_command_as_user};

#[rstest]
fn load_systemd_creds(
    #[files("config.toml")]
    #[base_dir = "tests/non_admin_credentials_single/fixtures/"]
    config_file_fixture: PathBuf,
) -> TestResult {
    write_machine_id()?;

    let system_config = HermeticParallelConfig::new_from_file(
        ConfigSettings::new(
            "my_app".to_string(),
            ConfigInteractivity::NonInteractive,
            None,
        ),
        Some(config_file_fixture.as_path()),
    )?;
    // write Signstar config to default config location
    system_config.store(Some(&PathBuf::from(get_default_config_file())))?;

    // create users and homes
    let system_users = system_config
        .iter_user_mappings()
        .filter_map(|mapping| mapping.get_system_user())
        .map(|system_user_id| system_user_id.to_string())
        .collect::<Vec<String>>();
    // BUG: maelstrom can not create multi-user container environments atm.
    create_users(system_users.as_slice())?;
    println!("/etc/passwd:\n{}", read_to_string("/etc/passwd")?);
    let machine_id = PathBuf::from("/etc/machine-id");
    println!(
        "/etc/machine-id permissions\n{:#?}\nuid: {}\ngid: {}",
        machine_id.metadata()?.permissions(),
        machine_id.metadata()?.st_uid(),
        machine_id.metadata()?.st_gid()
    );

    // Create dummy passphrase files for each system user and their respective NetHSM
    // credentials.
    let creds_mapping: Vec<CredsAwareUserMapping> = system_config.into();
    for mapping in &creds_mapping {
        if let Some(system_user) = mapping.get_user_mapping().get_system_user() {
            let secret_handling = mapping.get_non_admin_secret_handling();
            for user_id in mapping.get_user_mapping().get_nethsm_users() {
                println!("Setting up passphrase file for user {}", user_id);
                let passphrase_str =
                    get_persistent_passphrase_path_for_user(system_user, &user_id, secret_handling);
                let passphrase_path = PathBuf::from(&passphrase_str);

                // create parent dir
                if let Some(parent_dir) = passphrase_path.parent() {
                    create_dir_all(parent_dir)?;
                    let user = User::from_name(system_user.as_ref())?
                        .expect("all users have been created already");
                    println!("System user info: {:?}", user);
                    println!("dir {:?} exists: {}", parent_dir, parent_dir.exists());
                    println!(
                        "{:#?}\n{}\n{}",
                        parent_dir.metadata()?,
                        machine_id.metadata()?.st_uid(),
                        machine_id.metadata()?.st_gid()
                    );

                    println!(
                        "chowning with uid: {}, gid: {}",
                        user.uid.as_raw(),
                        user.gid.as_raw()
                    );
                    let chown_output = Command::new("chown")
                        .args([
                            &format!("{}:{}", user.uid.as_raw(), user.gid.as_raw()),
                            parent_dir.to_str().unwrap(),
                        ])
                        .output()?;
                    println!(
                        "chown\nstdout:\n{}\nstderr\n{}",
                        String::from_utf8(chown_output.stdout)?,
                        String::from_utf8(chown_output.stderr)?
                    );

                    let df_output = Command::new("df").arg("-H").output()?;
                    println!(
                        "df\nstdout:\n{}\nstderr\n{}",
                        String::from_utf8(df_output.stdout)?,
                        String::from_utf8(df_output.stderr)?
                    );

                    let mount_output = Command::new("mount").output()?;
                    println!(
                        "mount\nstdout:\n{}\nstderr\n{}",
                        String::from_utf8(mount_output.stdout)?,
                        String::from_utf8(mount_output.stderr)?
                    );
                    let ls_output = Command::new("ls")
                        .args(["-lahR", "/var/lib/signstar"])
                        .output()?;
                    println!(
                        "ls\nstdout:\n{}\nstderr\n{}",
                        String::from_utf8(ls_output.stdout)?,
                        String::from_utf8(ls_output.stderr)?
                    );

                    chown(parent_dir, Some(user.uid.as_raw()), Some(user.gid.as_raw()))?;

                    // Create credentials files depending on secret handling
                    match secret_handling {
                        NonAdministrativeSecretHandling::Plaintext => {
                            write(
                                &passphrase_path,
                                format!(
                                    "passphrase for system user {system_user} -> netHSM user {user_id}"
                                ),
                            )?;
                            chown(
                                &passphrase_path,
                                Some(user.uid.as_raw()),
                                Some(user.gid.as_raw()),
                            )?;
                        }
                        NonAdministrativeSecretHandling::SystemdCreds => {
                            let ephemeral_passphrase_str = get_persistent_passphrase_path_for_user(
                                system_user,
                                &user_id,
                                secret_handling,
                            );
                            Command::new("systemd-creds")
                                .args([
                                    "--user",
                                    "encrypt",
                                    &ephemeral_passphrase_str,
                                    &passphrase_str,
                                ])
                                .output()?;
                            chown(
                                &passphrase_path,
                                Some(user.uid.as_raw()),
                                Some(user.gid.as_raw()),
                            )?;
                            delete_tmp_file(PathBuf::from(ephemeral_passphrase_str).as_path());
                        }
                    }
                } else {
                    eprintln!("No parent in passphrase path: {:?}", passphrase_path);
                }
            }
        } else {
            eprintln!("Mapping without system user!\n{:?}", mapping);
        }
    }

    // TODO: run get-nethsm-credentials example for each user
    for mapping in &creds_mapping {
        if let Some(system_user_id) = mapping.get_user_mapping().get_system_user() {
            run_command_as_user(&["get-nethsm-credentials"], system_user_id.as_ref())?;
        } else {
            eprintln!("Mapping without system user!\n{:?}", mapping);
        }
    }

    println!("/etc/passwd:\n{}", read_to_string("/etc/passwd")?);
    let machine_id = PathBuf::from("/etc/machine-id");
    println!(
        "/etc/machine-id permissions\n{:#?}\nuid: {}\ngid: {}",
        machine_id.metadata()?.permissions(),
        machine_id.metadata()?.st_uid(),
        machine_id.metadata()?.st_gid()
    );
    println!("/etc/machine-id\n{}", read_to_string("/etc/machine-id")?);
    let passwd = PathBuf::from("/etc/passwd");
    println!(
        "/etc/passwd permissions\n{:#?}\nuid: {}\ngid: {}",
        passwd.metadata()?.permissions(),
        passwd.metadata()?.st_uid(),
        passwd.metadata()?.st_gid()
    );
    // BUG: when running as user, maelstrom mounts all of / as that user...

    assert!(false);
    Ok(())
}
