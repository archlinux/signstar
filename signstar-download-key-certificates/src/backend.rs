use std::collections::BTreeSet;

#[cfg(feature = "nethsm")]
use nethsm::{Connection as NetHsmConnection, NetHsm, signer::OwnedNetHsmKey};
use signstar_common::backend::BackendType;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_config::config::UserBackendConnection;
use signstar_config::config::{
    Config,
    NonAdminBackendUserIdFilter,
    NonAdminBackendUserIdKind,
    SystemUserId,
    UserBackendConnectionFilter,
};
#[cfg(feature = "nethsm")]
use signstar_config::nethsm::NetHsmUserMapping;
#[cfg(feature = "yubihsm2")]
use signstar_config::yubihsm2::YubiHsm2UserMapping;
use signstar_crypto::signer::traits::RawSigningKey;
use signstar_crypto::{key::CryptographicKeyContext, traits::UserWithPassphrase};
#[cfg(feature = "yubihsm2")]
use signstar_yubihsm2::{Connection, Credentials, YubiHsm2SigningKey};

use super::*;

/// Returns certificates from NetHSM backends.
///
/// # Errors
///
/// Returns an error if configuration:
/// - does not contain valid connections
/// - does not contain valid credentials with a passphrase
/// - certificate retrieval fails
#[cfg(feature = "nethsm")]
fn get_nethsm_certificates(
    connections: BTreeSet<NetHsmConnection>,
    mapping: NetHsmUserMapping,
    creds: &[Box<dyn UserWithPassphrase>],
) -> Result<Vec<Certificate>, Error> {
    if let NetHsmUserMapping::Signing {
        signing_key_id,
        key_setup,
        ..
    } = mapping
    {
        let certificate_type =
            if let CryptographicKeyContext::OpenPgp { .. } = key_setup.key_context() {
                CertificateType::OpenPgp
            } else {
                return Ok(Vec::new());
            };

        let mut certificates = Vec::new();

        for connection in connections {
            for creds in creds.iter() {
                let signer = OwnedNetHsmKey::new(
                    NetHsm::new(
                        connection.clone(),
                        Some(nethsm::Credentials::new(
                            creds.user().parse().unwrap(),
                            Some(creds.passphrase().clone()),
                        )),
                        None,
                        None,
                    )?,
                    signing_key_id.clone(),
                )?;
                if let Some(cert) = signer.certificate()? {
                    certificates.push(Certificate {
                        certificate: certificate_type.with_framing(&cert),
                        r#type: certificate_type,
                        backend_id: BackendType::NetHsm,
                        signing_key_id: signing_key_id.to_string(),
                    });
                }
            }
        }
        Ok(certificates)
    } else {
        Ok(Vec::new())
    }
}

/// Returns certificates from YubiHSM2 backends.
///
/// # Errors
///
/// Returns an error if configuration:
/// - does not contain valid connections
/// - does not contain valid credentials with a passphrase
/// - certificate retrieval fails
#[cfg(feature = "yubihsm2")]
fn get_yubihsm2_certificates(
    connections: BTreeSet<Connection>,
    mapping: YubiHsm2UserMapping,
    creds: &[Box<dyn UserWithPassphrase>],
) -> Result<Vec<Certificate>, Error> {
    if let YubiHsm2UserMapping::Signing {
        key_setup,
        signing_key_id,
        ..
    } = mapping
    {
        let certificate_type =
            if let CryptographicKeyContext::OpenPgp { .. } = key_setup.key_context() {
                CertificateType::OpenPgp
            } else {
                return Ok(Vec::new());
            };

        let mut certificates = Vec::new();
        for connection in connections {
            for creds in creds.iter() {
                let signer = match connection {
                    #[cfg(feature = "_yubihsm2-mockhsm")]
                    Connection::Mock => YubiHsm2SigningKey::mock(
                        signing_key_id,
                        &Credentials::new(
                            creds.user().parse().unwrap(),
                            creds.passphrase().clone(),
                        ),
                    )?,
                    Connection::Usb { serial_number } => {
                        YubiHsm2SigningKey::new_with_serial_number(
                            serial_number,
                            signing_key_id,
                            &Credentials::new(
                                creds.user().parse().unwrap(),
                                creds.passphrase().clone(),
                            ),
                        )?
                    }
                };
                if let Some(cert) = signer.certificate()? {
                    certificates.push(Certificate {
                        certificate: certificate_type.with_framing(&cert),
                        r#type: certificate_type,
                        backend_id: BackendType::YubiHsm2,
                        signing_key_id: signing_key_id.to_string(),
                    });
                }
            }
        }
        Ok(certificates)
    } else {
        Ok(Vec::new())
    }
}

/// Loads [`Certificate`]s from signing keys used in Signstar configuration.
///
/// Note that the signing keys are not used here for any actual signing but just to fetch the
/// certificate associated with them. As such, a reduced set of permissions will
/// be sufficient to use this function.
///
/// # Errors
///
/// Returns an error if configuration:
/// - loading encounters errors
/// - does not contain any key settings
/// - does not contain valid connections
/// - does not contain credentials with a passphrase
pub fn load_certificates() -> Result<Vec<Certificate>, Error> {
    let config = Config::from_system_path()?;

    let current_system_user = SystemUserId::from_current_unix_user()?;

    let Some(user_backend_connection) = config.user_backend_connection(&current_system_user) else {
        return Err(Error::NoCredentials {
            user: current_system_user.to_string(),
        });
    };

    let creds = if let Some(creds) = user_backend_connection.load_non_admin_backend_user_secrets(
        NonAdminBackendUserIdFilter {
            backend_user_id_kind: NonAdminBackendUserIdKind::Observer,
        },
    )? {
        if creds.is_empty() {
            return Err(Error::NoCredentials {
                user: current_system_user.to_string(),
            });
        } else {
            creds
        }
    } else {
        return Err(Error::NoCredentials {
            user: current_system_user.to_string(),
        });
    };

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
                mapping,
            } => certificates.extend(get_nethsm_certificates(connections, mapping, &creds)?),

            #[cfg(feature = "yubihsm2")]
            UserBackendConnection::YubiHsm2 {
                admin_secret_handling: _,
                non_admin_secret_handling: _,
                connections,
                mapping,
            } => certificates.extend(get_yubihsm2_certificates(connections, mapping, &creds)?),
        }
    }
    Ok(certificates)
}
