use std::process::ExitCode;

#[cfg(doc)]
use nethsm::NetHsm;
use nethsm_config::SystemUserId;

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
    let (user_mapping, credentials_loading) =
        signstar_config::non_admin_credentials::get_nethsm_credentials_for_system_user()?;

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
