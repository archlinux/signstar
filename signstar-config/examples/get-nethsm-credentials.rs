//! Example for reading all backend user credentials associated with the current system user.
use std::process::ExitCode;

#[cfg(doc)]
use nethsm::NetHsm;
use signstar_config::{CredentialsLoading, Error, ErrorExitCode};

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
    let credentials_loading = CredentialsLoading::from_system_user()?;

    // Generally fail if errors occurred while getting credentials (for whichever type of user)
    if credentials_loading.has_userid_errors() {
        return Err(Error::NonAdminSecretHandling(
            signstar_config::non_admin_credentials::Error::CredentialsLoading {
                system_user: credentials_loading.get_system_user_id()?.clone(),
                errors: credentials_loading.get_userid_errors(),
            },
        ));
    }

    eprintln!("{credentials_loading:#?}");

    // Get credentials for a signing user in the backend if the current system user is associated
    // with one
    if credentials_loading.has_signing_user() {
        eprintln!("Credentials for signing user in the backend:");
        let credentials = credentials_loading.credentials_for_signing_user()?;
        eprintln!(
            "user: {}\npassphrase: {}",
            credentials.user(),
            credentials.passphrase().expose_borrowed()
        )
    }

    Ok(())
}

/// Retrieves all [`NetHsm`] credentials for the current system user.
fn main() -> ExitCode {
    if let Err(error) = load_user_credentials() {
        eprintln!("{error}");
        ExitCode::from(ErrorExitCode::from(error))
    } else {
        ExitCode::SUCCESS
    }
}
