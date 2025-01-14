use clap::{Parser, crate_name};
use signstar_core::config::{
    CONFIG_FILE,
    DEFAULT_CONFIG_DIR,
    ETC_OVERRIDE_CONFIG_DIR,
    RUN_OVERRIDE_CONFIG_DIR,
    USR_LOCAL_OVERRIDE_CONFIG_DIR,
};
use strum::VariantNames;

use crate::{
    ConfigPath,
    HOME_BASE_DIR,
    SSH_AUTHORIZED_KEY_BASE_DIR,
    SSHD_DROPIN_CONFIG_DIR,
    SshForceCommand,
};

pub const BIN_NAME: &str = crate_name!();
const SSH_FORCE_COMMAND_VARIANTS: &[&str] = SshForceCommand::VARIANTS;

#[derive(Debug, Parser)]
#[command(
    about = "A command-line interface for Signstar image build configuration",
    name = BIN_NAME,
    long_about = format!("A command-line interface for Signstar image build configuration

NOTE: This command must be run as root!

This executable is meant to be used to configure relevant system users of a Signstar system during build.

It creates system users and their integration based on a central configuration file.

By default, one of the following configuration files is used if it exists, in the following order:

- \"{USR_LOCAL_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}\"

- \"{RUN_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}\"

- \"{ETC_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}\"

If none of the above are found, the default location \"{DEFAULT_CONFIG_DIR}{CONFIG_FILE}\" is used.
Alternatively a custom configuration file location can be specified using the \"--config\"/ \"-c\" option.

System users, if they don't exist already, are created with the help of `useradd`.
The users are created without a passphrase and setup with a home below \"{HOME_BASE_DIR}\".
However, their home directory is not created automatically.
The system user accounts are then unlocked with the help of `usermod`.
For each system user a tmpfiles.d integration is provided below \"/usr/lib/tmpfiles.d\", to allow automatic creation of their home directory.

If the used configuration file associates the system user with SSH public keys, a dedicated \"authorized_keys\" file containing the SSH public keys for the user is created below \"{SSH_AUTHORIZED_KEY_BASE_DIR}\".
Additionally, an \"sshd_config\" drop-in configuration is created below \"{SSHD_DROPIN_CONFIG_DIR}\".
This \"sshd_config\" drop-in configuration enforces the use of the user's \"authorized_keys\" and the use of a specific command (i.e. one of {SSH_FORCE_COMMAND_VARIANTS:?}) depending on the user's role.",
    ),
)]
pub struct Cli {
    #[arg(
        env = "SIGNSTAR_CONFIG",
        global = true,
        help = "The path to a custom configuration file",
        long_help = format!("The path to a custom configuration file

If specified, the custom configuration file is used instead of the default configuration file location.

If unspecified, one of the following configuration files is used if it exists, in the following order:

- \"{USR_LOCAL_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}\"

- \"{RUN_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}\"

- \"{ETC_OVERRIDE_CONFIG_DIR}{CONFIG_FILE}\"

If none of the above are found, the default location \"{DEFAULT_CONFIG_DIR}{CONFIG_FILE}\" is used.
"),
        long,
        short
    )]
    pub config: Option<ConfigPath>,

    #[arg(
        global = true,
        help = "Return the name and version of the application",
        long,
        short
    )]
    pub version: bool,
}
