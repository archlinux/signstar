//! The handling of support HSM backends.

use std::fmt::Display;
#[cfg(feature = "nethsm")]
use std::str::FromStr;

use log::warn;
#[cfg(feature = "nethsm")]
use nethsm::{FullCredentials, NetHsm, signer::OwnedNetHsmKey};
use signstar_common::{
    backend::BackendType,
    request_api::{Certificate, CertificateType},
};
use signstar_config::config::{
    Config,
    NonAdminBackendUserIdFilter,
    NonAdminBackendUserIdKind,
    SystemUserId,
    UserBackendConnection,
    UserBackendConnectionFilter,
};
#[cfg(feature = "nethsm")]
use signstar_config::nethsm::{NetHsmUserMapping, nethsm_export::UserId};
#[cfg(feature = "yubihsm2")]
use signstar_config::yubihsm2::YubiHsm2UserMapping;
use signstar_crypto::{
    key::{CryptographicKeyContext, SigningKeySetup},
    signer::traits::RawSigningKey,
};
#[cfg(feature = "yubihsm2")]
use signstar_yubihsm2::{Connection, Credentials, YubiHsm2SigningKey};

use crate::error::Error;

/// Retrieves the certificate of a single signing key from a backend.
///
/// # Errors
///
/// Returns an error if the certificate retrieval from the backend fails.
fn get_backend_certificates(
    key_setup: SigningKeySetup,
    signing_key_id: impl Display,
    signers: &[impl RawSigningKey],
    backend_id: BackendType,
) -> Result<Vec<Certificate>, Error> {
    let certificate_type = if let CryptographicKeyContext::OpenPgp { .. } = key_setup.key_context()
    {
        CertificateType::OpenPgp
    } else {
        warn!("Unsupported key context for signing key {signing_key_id}");

        return Ok(Vec::new());
    };

    let mut certificates = Vec::new();
    for signer in signers.iter() {
        if let Some(cert) = signer.certificate()? {
            certificates.push(Certificate {
                certificate: certificate_type.with_framing(&cert),
                r#type: certificate_type,
                backend_id,
                signing_key_id: signing_key_id.to_string(),
            });
        }
    }

    Ok(certificates)
}

/// Loads a [`Certificate`] from the backend, for each signing key configured in the Signstar
/// configuration.
///
/// # Note
///
/// Access to each signing key's certificate is established using backend users that lack permission
/// to use the signing key for signing.
///
/// # Errors
///
/// Returns an error if
/// - loading the Signstar configuration fails
/// - getting the Unix user of the current process fails
/// - no backend user(s) are mapped to the currently calling system user
/// - no backend credentials can be loaded for the currently calling system user
/// - loading encounters errors
/// - certificate retrieval of a signing key fails
pub fn load_certificates() -> Result<Vec<Certificate>, Error> {
    let config = Config::from_system_path()?;

    let current_system_user = SystemUserId::from_current_unix_user()?;

    let Some(user_backend_connection) = config.user_backend_connection(&current_system_user) else {
        return Err(Error::NoCredentials {
            user: current_system_user.to_string(),
        });
    };

    let Some(creds) = user_backend_connection.load_non_admin_backend_user_secrets(
        NonAdminBackendUserIdFilter {
            backend_user_id_kind: NonAdminBackendUserIdKind::Observer,
        },
    )?
    else {
        return Err(Error::NoCredentials {
            user: current_system_user.to_string(),
        });
    };
    if creds.is_empty() {
        return Err(Error::NoCredentials {
            user: current_system_user.to_string(),
        });
    }

    let backend_type = match user_backend_connection {
        #[cfg(feature = "nethsm")]
        UserBackendConnection::NetHsm { .. } => BackendType::NetHsm,
        #[cfg(feature = "yubihsm2")]
        UserBackendConnection::YubiHsm2 { .. } => BackendType::YubiHsm2,
    };

    let mut certificates = Vec::new();

    for user_backend_connection in config.user_backend_connections(&[
        UserBackendConnectionFilter::Backend(backend_type),
        UserBackendConnectionFilter::NonAdmin,
    ]) {
        match user_backend_connection {
            #[cfg(feature = "nethsm")]
            UserBackendConnection::NetHsm {
                admin_secret_handling: _,
                non_admin_secret_handling: _,
                connections,
                mapping:
                    NetHsmUserMapping::Signing {
                        backend_user,
                        signing_key_id,
                        key_setup,
                        ..
                    },
            } => {
                // NOTE: Currently we are only selecting the first connection found, but in the
                // future we could select them randomly.
                let connection = connections.first().cloned().ok_or(Error::NoConnection)?;

                let signers = creds
                    .iter()
                    .map(|creds| {
                        Ok(FullCredentials::new(
                            UserId::from_str(&creds.user())?,
                            creds.passphrase().clone(),
                        ))
                    })
                    .collect::<Result<Vec<_>, <UserId as FromStr>::Err>>()
                    .map_err(|e| Error::NetHsm(e.into()))?
                    .into_iter()
                    .filter(|cred| cred.name.namespace() == backend_user.namespace())
                    .map(|creds| {
                        OwnedNetHsmKey::new(
                            NetHsm::new(connection.clone(), Some(creds.into()), None, None)?,
                            signing_key_id.clone(),
                        )
                    })
                    .collect::<Result<Vec<_>, nethsm::Error>>()?;

                certificates.extend(get_backend_certificates(
                    key_setup,
                    signing_key_id,
                    &signers,
                    BackendType::NetHsm,
                )?)
            }

            #[cfg(feature = "yubihsm2")]
            UserBackendConnection::YubiHsm2 {
                admin_secret_handling: _,
                non_admin_secret_handling: _,
                connections,
                mapping:
                    YubiHsm2UserMapping::Signing {
                        key_setup,
                        signing_key_id,
                        ..
                    },
            } => {
                // NOTE: Currently we are only selecting the first connection found, but in the
                // future we could select them randomly.
                let connection = connections.first().cloned().ok_or(Error::NoConnection)?;

                let signers = creds
                    .iter()
                    .map(|creds| {
                        let creds = Credentials::new(
                            creds
                                .user()
                                .parse()
                                .map_err(|_| Error::InvalidUser { user: creds.user() })?,
                            creds.passphrase().clone(),
                        );

                        let signer = match connection {
                            #[cfg(feature = "_yubihsm2-mockhsm")]
                            Connection::Mock => YubiHsm2SigningKey::mock(signing_key_id, &creds)?,
                            Connection::Usb { serial_number } => {
                                YubiHsm2SigningKey::new_with_serial_number(
                                    serial_number,
                                    signing_key_id,
                                    &creds,
                                )?
                            }
                        };

                        Ok(signer)
                    })
                    .collect::<Result<Vec<_>, Error>>()?;

                certificates.extend(get_backend_certificates(
                    key_setup,
                    signing_key_id,
                    &signers,
                    BackendType::YubiHsm2,
                )?)
            }
            _ => (),
        }
    }
    Ok(certificates)
}
