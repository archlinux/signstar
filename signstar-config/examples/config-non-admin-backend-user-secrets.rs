//! Example for loading and creating of secrets for non-administrative backend users based on a
//! Signstar config.
//!
//! Loads a Signstar [`Config`] from default system file locations.
//! Uses the specific [`Config::user_backend_connection`] and
//! [`UserBackendConnection::create_non_admin_backend_user_secrets`]
//! [`UserBackendConnection::load_non_admin_backend_user_secrets`] implementations for loading and
//! creating of secrets.
//!
//! # Note
//!
//! This example is used in integration tests and is probably not very useful on its own.
//! Furthermore, it requires loading of Signstar configuration files from predefined system
//! locations and calling this executable as root or a specifically configured system user
//! (depending on the subcommand and the configuration file).

use std::process::ExitCode;

use clap::Parser;
use log::LevelFilter;
use signstar_config::config::SystemUserId;
use simplelog::{ColorChoice, TermLogger, TerminalMode};

/// When any of the backends is compiled in.
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
mod impl_any {
    use signstar_config::config::{
        Config,
        NonAdminBackendUserIdFilter,
        NonAdminBackendUserIdKind,
        UserBackendConnectionFilter,
    };
    use signstar_crypto::traits::UserWithPassphrase;

    use super::*;

    /// Prints the user name and passphrase of each user in a list to stdout.
    fn print_creds_list(creds_list: Vec<Box<dyn UserWithPassphrase>>) {
        for creds in creds_list {
            println!(
                "backend user: {}\npassphrase: {}",
                creds.user(),
                creds.passphrase().expose_borrowed()
            );
        }
    }

    /// Runs the command.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - reading a Signstar config from a supported location fails
    /// - creation of the secret for a non-administrative backend user fails
    /// - loading of the secret for a non-administrative backend user fails
    pub fn run_command(cli: Cli) -> Result<(), Error> {
        let config = Config::from_system_path()?;

        match cli.command {
            Command::Create => {
                let creds_list = {
                    let user_backend_connections =
                        config.user_backend_connections(UserBackendConnectionFilter::NonAdmin);

                    let mut creds_list = Vec::new();
                    for user_backend_connection in user_backend_connections {
                        if let Some(creds) =
                            user_backend_connection.create_non_admin_backend_user_secrets()?
                        {
                            creds_list.extend(creds);
                        }
                    }
                    creds_list
                };

                print_creds_list(creds_list);
            }
            Command::Load(command) => {
                if let Some(user_backend_connection) =
                    config.user_backend_connection(&command.system_user_id)
                {
                    if let Some(creds_list) = user_backend_connection
                        .load_non_admin_backend_user_secrets(NonAdminBackendUserIdFilter {
                            backend_user_id_kind: NonAdminBackendUserIdKind::Any,
                        })?
                    {
                        print_creds_list(creds_list);
                    }
                } else {
                    println!(
                        "The Unix user {} is not connected to a non-administrative backend user",
                        &command.system_user_id
                    );
                };
            }
        }

        Ok(())
    }
}

/// When no backends are compiled in, this executable can't really do anything.
#[cfg(all(not(feature = "nethsm"), not(feature = "yubihsm2")))]
mod impl_none {
    use super::*;

    /// Runs the command.
    ///
    /// # Note
    ///
    /// Does nothing as there is no backend.
    pub fn run_command(_cli: Cli) -> Result<(), Error> {
        panic!("Without a backend, this example does not work!")
    }
}

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use impl_any::run_command;
#[cfg(all(not(feature = "nethsm"), not(feature = "yubihsm2")))]
use impl_none::run_command;

/// An error that may occur when using config-non-admin-backend-user-secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Expected a system user.
    #[error("The Unix user {system_user_id} has no mapping.")]
    NoMappingForUnixUser {
        /// The name of the Unix user without a mapping.
        system_user_id: SystemUserId,
    },

    /// A `signstar_config::Error`.
    #[error(transparent)]
    SignstarConfig(#[from] signstar_config::Error),
}

#[derive(Debug, Parser)]
#[command(about, author, version)]
struct LoadCommand {
    /// The name of the Unix user for which to load non-administrative backend credentials.
    #[arg(
        help = "The name of the Unix user for which to load non-administrative backend credentials."
    )]
    pub system_user_id: SystemUserId,
}

#[derive(Debug, Parser)]
#[command(about, author, version)]
enum Command {
    /// Create secrets for all non-administrative backend users.
    #[command(about = "Create secrets for all non-administrative backend users.")]
    Create,

    /// Load a secret for a non-administrative user.
    #[command(about = "Load a secret for a non-administrative user.")]
    Load(LoadCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Load and write non-administrative user secrets based on user mapping data",
    version
)]
struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// Initializes a logger.
fn init_logger() {
    if TermLogger::init(
        LevelFilter::Debug,
        simplelog::Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .is_err()
    {
        eprintln!("Not initializing another logger, as one is initialized already.");
    }
}

/// Runs the selected task against a created user mapping implementation.
fn main() -> ExitCode {
    init_logger();

    if let Err(error) = run_command(Cli::parse()) {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
