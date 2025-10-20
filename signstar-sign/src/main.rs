//! Application for the creation of signatures from signing requests.

use std::process::ExitCode;

use clap::Parser;
use nethsm::{KeyId, NetHsm};
use signstar_config::{
    CredentialsLoading,
    Error as ConfigError,
    UserMapping,
    config::base::BackendConnection,
};
use signstar_request_signature::{Request, Response, Sha512};
use signstar_sign::cli::Cli;

/// Signstar signing error.
#[derive(Debug, thiserror::Error)]
enum Error {
    /// Configuration does not contain key ID for the operator user.
    #[error("No key ID set for the operator user")]
    NoKeyId,

    /// Loading configuration encountered errors.
    #[error("Loading credentials encountered errors")]
    HasUserIdErrors,

    /// No credentials found for current system user.
    #[error("No credentials for the system user")]
    NoCredentials,

    /// Parameters of the signing request are unsupported.
    #[error("Unsupported signing request parameters")]
    UnsupportedParameters,

    /// Configuration error.
    #[error("Config error")]
    Config(#[from] ConfigError),

    /// NetHSM error.
    #[error("NetHsm error")]
    NetHsm(#[from] nethsm::Error),

    /// Signing request processing error.
    #[error("Signing request error: {0}")]
    SigningRequest(#[from] signstar_request_signature::Error),

    /// A signstar-common logging error.
    #[error(transparent)]
    SignstarCommonLogging(#[from] signstar_common::logging::Error),
}

/// Creates a new [`NetHsm`] object with correct connection and user settings and returns it
/// alongside with the [`KeyId`] that should be used for signing.
///
/// # Errors
///
/// Returns an error if configuration:
/// - loading encounters errors
/// - does not contain any key ID settings
/// - does not contain NetHSM connections
/// - does not contain credentials with a passphrase
fn load_nethsm_keyid() -> Result<(NetHsm, KeyId), Error> {
    let credentials_loading = CredentialsLoading::from_system_user()?;

    if credentials_loading.has_userid_errors() {
        return Err(Error::HasUserIdErrors);
    }

    if !credentials_loading.has_signing_user() {
        return Err(Error::NoCredentials);
    }

    let key_id = if let UserMapping::SystemNetHsmOperatorSigning { key_id, .. } =
        credentials_loading.get_mapping().get_user_mapping()
    {
        key_id.clone()
    } else {
        return Err(Error::NoKeyId);
    };

    // Currently, this picks the first connection found.
    // The Signstar setup assumes, that multiple backends are used in a round-robin fashion, but
    // this is not yet implemented.
    let connection = if let Some(connection) = credentials_loading
        .get_mapping()
        .get_connections()
        .iter()
        .next()
    {
        match connection {
            BackendConnection::NetHsm(connection) => connection.clone(),
            #[cfg(feature = "yubihsm2")]
            BackendConnection::YubiHsm2(_) => {
                unimplemented!("The use of the YubiHSM2 backend is not yet implemented.")
            }
        }
    } else {
        return Err(Error::NoCredentials);
    };

    let credentials = credentials_loading.credentials_for_signing_user()?;

    Ok((
        NetHsm::new(connection, Some(credentials.try_into()?), None, None)?,
        key_id,
    ))
}

/// Signs the signing request in `reader` and write the response to the `writer`.
///
/// # Errors
///
/// Returns an error if:
///
/// - logging cannot be set up,
/// - a [`Request`] cannot be created from `reader`,
/// - the [`Request`] does not use OpenPGP v4,
/// - the [`Request`] is not version 1,
/// - a [`Sha512`] hasher state can not be created from the [`Request`],
/// - no [`NetHsm`] and [`KeyId`] can be retrieved for the calling user,
/// - a signature can not be created over the hasher state,
/// - or the [`Response`] can not be written to the `writer`.
fn sign_request(reader: impl std::io::Read, writer: impl std::io::Write) -> Result<(), Error> {
    let req = Request::from_reader(reader)?;

    if !req.required.output.is_openpgp_v4() {
        Err(Error::UnsupportedParameters)?;
    }

    if req.version.major != 1 {
        Err(Error::UnsupportedParameters)?;
    }

    let hasher: Sha512 = req.required.input.try_into()?;

    let (nethsm, key_id) = load_nethsm_keyid()?;

    let signature = nethsm.openpgp_sign_state(&key_id, hasher)?;

    Response::v1(signature).to_writer(writer)?;

    Ok(())
}

/// Signs the signing request on standard input and returns a signing response on standard output.
fn main() -> ExitCode {
    let args = Cli::parse();

    if let Err(error) = signstar_common::logging::setup_logging(args.verbosity) {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    let result = sign_request(std::io::stdin(), std::io::stdout());

    if let Err(error) = result {
        log::error!(error:err; "Processing signing request failed: {error:#?}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
