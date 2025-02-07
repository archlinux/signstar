use core::panic;
use std::process::ExitCode;

#[cfg(doc)]
use nethsm::NetHsm;

extern crate nethsm_config;
extern crate signstar_common;
extern crate signstar_config;
extern crate thiserror;

#[derive(Debug, thiserror::Error)]
enum Error {
    /// An error with a Signstar configuration occurred.
    #[error("Signstar configuration error: {0}")]
    SignstarConfig(#[from] signstar_config::Error),
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
    let credentials_loading =
        signstar_config::non_admin_credentials::CredentialsLoading::from_system_user()?;

    // fail if errors were raised when getting credentials
    if credentials_loading.has_userid_errors() {
        return Err(Error::SignstarConfig(
            signstar_config::Error::NonAdminSecretHandling(
                signstar_config::non_admin_credentials::Error::CredentialsLoading {
                    system_user: credentials_loading.get_system_user_id()?.clone(),
                    errors: credentials_loading.get_userid_errors().to_string(),
                },
            ),
        ));
    }

    eprintln!("{credentials_loading:#?}");

    // get credentials for a signing user in the backend if the current system user is associated
    // with one
    if credentials_loading.has_signing_user() {
        eprintln!("Credentials for signing user in the backend:");
        let credentials = credentials_loading.credentials_for_signing_user()?;
        let Some(ref passphrase) = credentials.passphrase else {
            panic!("There should be a passphrase");
        };
        eprintln!(
            "user: {}\npassphrase: {}",
            credentials.user_id,
            passphrase.expose_owned()
        )
    }

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
