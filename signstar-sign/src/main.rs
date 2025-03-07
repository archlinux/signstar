use std::{io::Write, path::PathBuf};

use nethsm::UserRole;
use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
use signstar_request_signature::{Error, Request, Sha512};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::new(
        ConfigSettings::new("nethsm".to_string(), ConfigInteractivity::Interactive, None),
        Some(PathBuf::from("/tmp/cli-config").as_ref()),
    )?;

    let nethsm = config
        .get_device(Some("label"))?
        .nethsm_with_matching_creds(
            &[UserRole::Operator],
            &["cli.user".parse()?],
            &["auth_passphrases".parse()?],
        )?;

    let req = Request::from_reader(std::io::stdin())?;

    if !req.required.output.is_openpgp_v4() {
        Err(Error::InvalidContentSize)?; // FIXME: fix error variant
    }

    if req.version.major != 1 {
        Err(Error::InvalidContentSize)?; // FIXME: fix error variant
    }

    let hasher: Sha512 = req.required.input.try_into()?;

    std::io::stdout().write_all(
        nethsm
            .openpgp_sign_state(&"command.key_id".parse()?, hasher)?
            .as_slice(),
    )?;

    Ok(())
}
