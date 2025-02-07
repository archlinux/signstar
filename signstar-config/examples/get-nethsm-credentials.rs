#[cfg(doc)]
use nethsm::NetHsm;

extern crate nethsm_config;
extern crate signstar_config;
extern crate signstar_core;
extern crate thiserror;

#[derive(Debug, thiserror::Error)]
enum Error {
    /// An error with an NetHSM configuration occurred.
    #[error("NetHSM configuration error: {0}")]
    SignstarConfig(#[from] signstar_config::non_admin_credentials::Error),
}

/// Retrieves all [`NetHsm`] credentials for a system user.
fn main() -> Result<(), Error> {
    let (user_mapping, credentials_loading) =
        signstar_config::non_admin_credentials::get_nethsm_credentials_for_system_user()?;

    println!("user mapping:\n{:?}", user_mapping);
    println!("credentials:\n{:?}", credentials_loading);

    Ok(())
}
