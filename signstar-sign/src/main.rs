use std::{
    fs::read_to_string,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::Parser;
use nethsm::{KeyId, Passphrase, UserId, UserRole};
use nethsm_config::{Config, ConfigInteractivity, ConfigSettings};
use signstar_request_signature::{Error, Request, Sha512};

#[derive(Debug, Parser)]
struct Cli {
    #[arg(
        env = "NETHSM_AUTH_PASSPHRASE_FILE",
        global = true,
        help = "The path to a file containing a passphrase for authentication",
        long_help = "The path to a file containing a passphrase for authentication

The passphrase provided in the file must be the one for the user chosen for the command.

This option can be provided multiple times, which is needed for commands that require multiple roles at once.
With multiple passphrase files ordering matters, as the files are assigned to the respective user provided by the \"--user\" option.",
        long,
        short
    )]
    pub auth_passphrase_file: Vec<PassphraseFile>,

    #[arg(
        env = "NETHSM_CONFIG",
        global = true,
        help = "The path to a custom configuration file",
        long_help = "The path to a custom configuration file

If specified, the custom configuration file is used instead of the default configuration file location.",
        long,
        short
    )]
    pub config: Option<PathBuf>,

    #[arg(
        env = "NETHSM_USER",
        global = true,
        help = "A user name which is used for the command",
        long_help = "A user name which is used for a command

Can be provided, if no user name is setup in the configuration file for a device.
Must be provided, if several user names of the same target role are setup in the configuration file for a device.

This option can be provided multiple times, which is needed for commands that require multiple roles at once.
",
        long,
        short
    )]
    pub user: Vec<UserId>,

    #[arg(
        env = "NETHSM_LABEL",
        global = true,
        help = "A label uniquely identifying a device in the configuration file",
        long_help = "A label uniquely identifying a device in the configuration file

Must be provided if more than one device is setup in the configuration file.",
        long,
        short
    )]
    pub label: Option<String>,

    #[arg(env = "NETHSM_KEY_ID", help = "The ID of the key to use")]
    pub key_id: KeyId,
}

#[derive(Clone, Debug)]
pub struct PassphraseFile {
    pub passphrase: Passphrase,
}

impl PassphraseFile {
    pub fn new(path: &Path) -> Result<Self, Error> {
        Ok(Self {
            passphrase: Passphrase::new(read_to_string(path).unwrap()),
        })
    }
}

impl FromStr for PassphraseFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PassphraseFile::new(&PathBuf::from_str(s).unwrap())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config::new(
        ConfigSettings::new(
            "nethsm".to_string(),
            ConfigInteractivity::NonInteractive,
            None,
        ),
        cli.config.as_deref(),
    )?;

    let auth_passphrases: Vec<Passphrase> = cli
        .auth_passphrase_file
        .iter()
        .map(|x| x.passphrase.clone())
        .collect();

    let nethsm = config
        .get_device(cli.label.as_deref())?
        .nethsm_with_matching_creds(&[UserRole::Operator], &cli.user, &auth_passphrases)?;

    let req = Request::from_reader(std::io::stdin())?;

    if !req.required.output.is_openpgp_v4() {
        Err(Error::InvalidContentSize)?; // FIXME: fix error variant
    }

    if req.version.major != 1 {
        Err(Error::InvalidContentSize)?; // FIXME: fix error variant
    }

    let hasher: Sha512 = req.required.input.try_into()?;

    std::io::stdout().write_all(nethsm.openpgp_sign_state(&cli.key_id, hasher)?.as_slice())?;

    Ok(())
}
