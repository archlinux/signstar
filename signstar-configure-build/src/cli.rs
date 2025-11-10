//! Command line interface handling for the "signstar-configure-build" executable.

use clap::{Parser, crate_name};
use signstar_common::{
    config::{
        get_default_config_file_path,
        get_etc_override_config_file_path,
        get_run_override_config_file_path,
        get_usr_local_override_config_file_path,
    },
    ssh::{get_ssh_authorized_key_base_dir, get_sshd_config_dropin_dir},
    system_user::get_home_base_dir_path,
};
use strum::VariantNames;

use crate::{ConfigPath, SshForceCommand};

/// The name of the executable.
pub const BIN_NAME: &str = crate_name!();
/// The list of commands enforced by SSH's "ForceCommand".
const SSH_FORCE_COMMAND_VARIANTS: &[&str] = SshForceCommand::VARIANTS;

/// The "signstar-configure-build" command.
#[derive(Debug, Parser)]
#[command(
    about = "A command-line interface for Signstar image build configuration",
    name = BIN_NAME,
    long_about = format!("A command-line interface for Signstar image build configuration

NOTE: This command must be run as root!

This executable is meant to be used to configure relevant system users of a Signstar system during build.

It creates system users and their integration based on a central configuration file.

By default, one of the following configuration files is used if it exists, in the following order:

- {:?}

- {:?}

- {:?}

If none of the above are found, the default location {:?} is used.
Alternatively a custom configuration file location can be specified using the \"--config\"/ \"-c\" option.

System users, if they don't exist already, are created with the help of `useradd`.
The users are created without a passphrase and setup with a home below {:?}.
However, their home directory is not created automatically.
The system user accounts are then unlocked with the help of `usermod`.
For each system user a tmpfiles.d integration is provided below \"/usr/lib/tmpfiles.d\", to allow automatic creation of their home directory.

If the used configuration file associates the system user with SSH public keys, a dedicated \"authorized_keys\" file containing the SSH public keys for the user is created below {:?}.
Additionally, an \"sshd_config\" drop-in configuration is created below {:?}.
This \"sshd_config\" drop-in configuration enforces the use of the user's \"authorized_keys\" and the use of a specific command (i.e. one of {SSH_FORCE_COMMAND_VARIANTS:?}) depending on the user's role.",
    get_usr_local_override_config_file_path(),
    get_run_override_config_file_path(),
    get_etc_override_config_file_path(),
    get_default_config_file_path(),
    get_home_base_dir_path(),
    get_ssh_authorized_key_base_dir(),
    get_sshd_config_dropin_dir(),
    )
)]
pub struct Cli {
    /// An optional path to a configuration file to use.
    #[arg(
        env = "SIGNSTAR_CONFIG",
        global = true,
        help = "The path to a custom configuration file",
        long_help = format!("The path to a custom configuration file

If specified, the custom configuration file is used instead of the default configuration file location.

If unspecified, one of the following configuration files is used if it exists, in the following order:

- {:?}

- {:?}

- {:?}

If none of the above are found, the default location {:?} is used.",
    get_usr_local_override_config_file_path(),
    get_run_override_config_file_path(),
    get_etc_override_config_file_path(),
    get_default_config_file_path(),
),
        long,
        short
    )]
    pub config: Option<ConfigPath>,

    /// Whether to return name and version of the executable.
    #[arg(
        global = true,
        help = "Return the name and version of the application",
        long,
        short
    )]
    pub version: bool,
}
