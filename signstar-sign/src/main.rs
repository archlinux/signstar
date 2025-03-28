use std::collections::HashMap;

use nethsm::{KeyId, NetHsm};
use nethsm_config::UserMapping;
use signstar_config::{CredentialsLoading, Error as ConfigError};
use signstar_request_signature::{Error, Request, Sha512};

fn load_user_credentials() -> Result<(NetHsm, KeyId), Box<dyn std::error::Error>> {
    let credentials_loading: CredentialsLoading = CredentialsLoading::from_system_user()?;

    // Generally fail if errors occurred while getting credentials (for whichever type of user)
    if credentials_loading.has_userid_errors() {
        return Err(Box::new(ConfigError::NonAdminSecretHandling(
            signstar_config::non_admin_credentials::Error::CredentialsLoading {
                system_user: credentials_loading.get_system_user_id()?.clone(),
                errors: credentials_loading.get_userid_errors(),
            },
        )));
    }

    // Get credentials for a signing user in the backend if the current system user is associated
    // with one
    if credentials_loading.has_signing_user() {
        let key_id = if let UserMapping::SystemNetHsmOperatorSigning {
            nethsm_key_setup, ..
        } = credentials_loading.get_mapping().get_user_mapping()
        {
            nethsm_key_setup.get_key_id().clone()
        } else {
            panic!("bad");
        };

        let connection = credentials_loading
            .get_mapping()
            .get_connections()
            .iter()
            .next()
            .unwrap()
            .clone();

        let credentials = credentials_loading.credentials_for_signing_user()?;
        let Some(ref _passphrase) = credentials.passphrase else {
            panic!("There should be a passphrase");
        };

        return Ok((
            NetHsm::new(
                connection.url,
                connection.tls_security,
                Some(credentials),
                None,
                None,
            )?,
            key_id,
        ));
    }

    panic!("test")
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (nethsm, key_id) = load_user_credentials()?;

    let req = Request::from_reader(std::io::stdin())?;

    if !req.required.output.is_openpgp_v4() {
        Err(Error::InvalidContentSize)?; // FIXME: fix error variant
    }

    if req.version.major != 1 {
        Err(Error::InvalidContentSize)?; // FIXME: fix error variant
    }

    let hasher: Sha512 = req.required.input.try_into()?;

    let signature = nethsm.openpgp_sign_state(&key_id, hasher)?;

    // FIXME: use Response from !148 when it's merged
    let response = [
        ("version".into(), "0.0.0".into()),
        ("signature".into(), signature),
    ]
    .iter()
    .cloned()
    .collect::<HashMap<String, String>>();

    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}
