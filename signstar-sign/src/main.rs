//! Application for the creation of signatures from signing requests.

use std::process::ExitCode;

use clap::Parser;
use signstar_crypto::signer::{openpgp::sign_hasher_state, traits::RawSigningKey};
use signstar_request_signature::{Request, Response, Sha512};
use signstar_sign::cli::Cli;

/// Signstar signing error.
#[derive(Debug, thiserror::Error)]
enum Error {
    #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
    /// No HSM backend support is compiled in.
    #[error("No HSM backend support compiled in")]
    NoBackend,

    /// The configuration offers no connection for a backend.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No connection set for the backend")]
    NoConnection,

    /// No credentials found for current system user.
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    #[error("No credentials for the system user")]
    NoCredentials,

    /// Parameters of the signing request are unsupported.
    #[error("Unsupported signing request parameters")]
    UnsupportedParameters,

    /// Configuration error.
    #[error("Config error")]
    Config(#[from] signstar_config::Error),

    /// NetHSM error.
    #[cfg(feature = "nethsm")]
    #[error("NetHsm error")]
    NetHsm(#[from] nethsm::Error),

    /// Signing request processing error.
    #[error("Signing request error: {0}")]
    SigningRequest(#[from] signstar_request_signature::Error),

    /// A signstar-common logging error.
    #[error(transparent)]
    SignstarCommonLogging(#[from] signstar_common::logging::Error),

    /// A signstar-crypto signer error.
    #[error(transparent)]
    SignstarCryptoSigner(#[from] signstar_crypto::signer::error::Error),

    /// A signstar-crypto OpenPGP error.
    #[error(transparent)]
    SignstarCryptoOpenPgp(#[from] signstar_crypto::openpgp::Error),

    /// YubiHSM error.
    #[cfg(feature = "yubihsm2")]
    #[error(transparent)]
    YubiHsm(#[from] signstar_yubihsm2::Error),
}

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
mod impl_any {
    #[cfg(feature = "nethsm")]
    use nethsm::{NetHsm, signer::OwnedNetHsmKey};
    use signstar_config::config::NonAdminBackendUserIdFilter;
    #[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
    use signstar_config::config::UserBackendConnection;
    #[cfg(feature = "nethsm")]
    use signstar_config::nethsm::NetHsmUserMapping;
    #[cfg(feature = "yubihsm2")]
    use signstar_config::yubihsm2::YubiHsm2UserMapping;
    use signstar_config::{
        SystemUserId,
        config::{Config, NonAdminBackendUserIdKind},
    };
    #[cfg(feature = "yubihsm2")]
    use signstar_yubihsm2::{Connection, Credentials, YubiHsm2SigningKey};

    use super::*;

    /// Creates a new [`RawSigningKey`] implementation from the system's Signstar config and current
    /// user.
    ///
    /// # Errors
    ///
    /// Returns an error if configuration:
    /// - loading encounters errors
    /// - does not contain any key settings
    /// - does not contain valid connections
    /// - does not contain credentials with a passphrase
    pub fn load_signer() -> Result<Box<dyn RawSigningKey>, Error> {
        let current_system_user = SystemUserId::from_current_unix_user()?;
        let config = Config::from_system_path()?;
        let Some(user_backend_connection) = config.user_backend_connection(&current_system_user)
        else {
            return Err(Error::NoCredentials);
        };

        // Load credentials for a signing user of the backend.
        // Here, we _know_ that there always is at least one connection, and we take the first one.
        let creds = user_backend_connection
            .load_non_admin_backend_user_secrets(NonAdminBackendUserIdFilter {
                backend_user_id_kind: NonAdminBackendUserIdKind::Signing,
            })?
            .ok_or(Error::NoCredentials)?
            .remove(0);

        match user_backend_connection {
            #[cfg(feature = "nethsm")]
            UserBackendConnection::NetHsm {
                admin_secret_handling: _,
                non_admin_secret_handling: _,
                connections,
                mapping,
            } => match mapping {
                NetHsmUserMapping::Signing {
                    backend_user,
                    signing_key_id,
                    key_setup: _,
                    ssh_authorized_key: _,
                    system_user: _,
                    tag: _,
                } => {
                    let connection = connections.first().cloned().ok_or(Error::NoConnection)?;

                    Ok(Box::new(OwnedNetHsmKey::new(
                        NetHsm::new(
                            connection,
                            Some(nethsm::Credentials::new(
                                backend_user,
                                Some(creds.passphrase().clone()),
                            )),
                            None,
                            None,
                        )?,
                        signing_key_id,
                    )?))
                }
                NetHsmUserMapping::Admin(_)
                | NetHsmUserMapping::Backup { .. }
                | NetHsmUserMapping::HermeticMetrics { .. }
                | NetHsmUserMapping::Metrics { .. } => Err(Error::NoCredentials),
            },
            #[cfg(feature = "yubihsm2")]
            UserBackendConnection::YubiHsm2 {
                admin_secret_handling: _,
                non_admin_secret_handling: _,
                connections,
                mapping,
            } => match mapping {
                YubiHsm2UserMapping::Signing {
                    authentication_key_id,
                    key_setup: _,
                    domain: _,
                    signing_key_id,
                    ssh_authorized_key: _,
                    system_user: _,
                } => {
                    let connection = connections.first().cloned().ok_or(Error::NoConnection)?;
                    match connection {
                        #[cfg(feature = "_yubihsm2-mockhsm")]
                        Connection::Mock => Ok(Box::new(YubiHsm2SigningKey::mock(
                            signing_key_id,
                            &Credentials::new(authentication_key_id, creds.passphrase().clone()),
                        )?)),
                        Connection::Usb { serial_number } => {
                            Ok(Box::new(YubiHsm2SigningKey::new_with_serial_number(
                                serial_number,
                                signing_key_id,
                                &Credentials::new(
                                    authentication_key_id,
                                    creds.passphrase().clone(),
                                ),
                            )?))
                        }
                    }
                }
                YubiHsm2UserMapping::Admin { .. }
                | YubiHsm2UserMapping::Backup { .. }
                | YubiHsm2UserMapping::AuditLog { .. }
                | YubiHsm2UserMapping::HermeticAuditLog { .. } => Err(Error::NoCredentials),
            },
        }
    }
}

#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
mod impl_none {
    use super::*;

    /// Creates a new [`RawSigningKey`] implementation from the system's Signstar config and current
    /// user.
    ///
    /// # Errors
    ///
    /// Always returns an error, because no HSM backend support is compiled in.
    pub fn load_signer() -> Result<Box<dyn RawSigningKey>, Error> {
        Err(Error::NoBackend)
    }
}

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use impl_any::load_signer;
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
use impl_none::load_signer;

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
/// - no HSM and key data can be retrieved for the calling user,
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

    let signer = load_signer()?;

    let signature = sign_hasher_state(&*signer, hasher)?;

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
