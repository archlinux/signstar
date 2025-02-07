use std::{
    fs::read_dir,
    os::{linux::fs::MetadataExt, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm_config::SystemUserId;
use nix::unistd::{User, geteuid};
use signstar_core::system_user::get_home_base_dir_path;

extern crate nethsm_config;
extern crate signstar_config;
extern crate signstar_core;
extern crate thiserror;

#[derive(Debug, thiserror::Error)]
enum Error {
    /// An error with an NetHSM configuration occurred.
    #[error("NetHSM configuration error: {0}")]
    SignstarConfig(#[from] signstar_config::non_admin_credentials::Error),

    /// Issues with one or more UserIds occurred.
    #[error("UserId errors for system user {system_user}:\n{errors}")]
    UserIdErrors {
        system_user: SystemUserId,
        errors: String,
    },
}

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

/// Loads the Signstar credentials associated with the current system user.
///
/// The system must have a valid Signstar configuration file available in one of the understood
/// configuration file locations, which provides an entry for the current system user.
///
/// # Errors
///
/// Returns an error if
/// - no credentials could be found that are associated with the current user,
/// - or one or more [`UserId`]s associated with the current system user triggered an error while
///   trying to retrieve their credentials.
fn load_user_credentials() -> Result<(), Error> {
    println!("EUID: {}", geteuid());
    let user = User::from_uid(geteuid()).unwrap().unwrap();
    list_files_in_dir(get_home_base_dir_path().join(PathBuf::from(user.name))).unwrap();

    let (user_mapping, credentials_loading) =
        signstar_config::non_admin_credentials::get_nethsm_credentials_for_system_user()?;

    println!("foo");
    if credentials_loading.has_userid_errors() {
        let mut errors = String::new();
        for error in credentials_loading.get_userid_errors() {
            errors.push_str(&format!("Backend user {} triggered: {}", error.0, error.1));
        }
        return Err(Error::UserIdErrors {
            system_user: credentials_loading.get_system_user().clone(),
            errors,
        });
    }

    println!("user mapping:\n{:?}", user_mapping);
    println!("credentials:\n{:?}", credentials_loading);
    Ok(())
}

/// Retrieves all [`NetHsm`] credentials for the current system user.
fn main() -> ExitCode {
    if let Err(error) = load_user_credentials() {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
