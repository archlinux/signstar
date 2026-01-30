//! Reads a single non-administrative secret for the current system user and a backend user.
//!
//! Derives the system user from the effective user ID of the calling process.
//! Based on passing in a [`NonAdministrativeSecretHandling`] allows to either use plaintext or
//! systemd-creds encrypted secrets files.

use std::process::ExitCode;

use clap::Parser;
use clap_verbosity_flag::Verbosity;
use log::LevelFilter;
use nix::unistd::{User, geteuid};
use signstar_common::logging::setup_logging;
use signstar_crypto::{
    NonAdministrativeSecretHandling,
    passphrase::Passphrase,
    secret_file::load_passphrase_from_secrets_file,
};

/// An error that may occur when using load-non-admin-secret.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The currently calling user cannot be determined.
    #[error("The currently calling user cannot be determined")]
    InvalidCallingUser,

    /// A [`nix::Error`] occurred.
    #[error("Unix user error: {0}")]
    Nix(#[from] nix::Error),

    /// A [`signstar_crypto::Error`] occurred.
    #[error(transparent)]
    SignstarCrypto(#[from] signstar_crypto::Error),

    /// A [`signstar_common::logging::Error`] occurred.
    #[error(transparent)]
    SignstarCommonLogging(#[from] signstar_common::logging::Error),
}

#[derive(Debug, Parser)]
#[command(
    about = "Load a passphrase from a secrets file for the current user",
    version
)]
struct Cli {
    #[command(flatten)]
    pub verbosity: Verbosity,

    /// How secrets are handled.
    #[arg()]
    pub secret_handling: NonAdministrativeSecretHandling,

    /// The name of the backend user.
    #[arg()]
    pub backend_user: String,
}

/// Reads a passphrase from a secrets file for a backend user.
///
/// # Errors
///
/// Returns an error if
///
/// - logging cannot be setup
/// - the currently calling system user cannot be determined or is not valid
/// - a passphrase cannot be read from the secrets file
fn load_passphrase(
    secret_handling: NonAdministrativeSecretHandling,
    backend_user: &str,
    log_level: impl Into<LevelFilter>,
) -> Result<Passphrase, Error> {
    setup_logging(log_level)?;

    let Some(system_user) = User::from_uid(geteuid())? else {
        return Err(Error::InvalidCallingUser);
    };

    Ok(load_passphrase_from_secrets_file(
        secret_handling,
        &system_user,
        backend_user,
    )?)
}

/// Reads a passphrase from a secrets file as a non-administrative user.
fn main() -> ExitCode {
    let cli = Cli::parse();

    match load_passphrase(cli.secret_handling, &cli.backend_user, cli.verbosity) {
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
        Ok(passphrase) => {
            print!("{}", passphrase.expose_borrowed());
            ExitCode::SUCCESS
        }
    }
}
