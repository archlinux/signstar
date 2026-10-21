//! Utilities related to mocking.

use signstar_crypto::{
    openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId, OpenPgpVersion},
    signer::openpgp::{Timestamp, generate_certificate},
    traits::UserWithPassphrase as _,
};
use yubihsm::{
    Capability,
    Connector,
    Credentials as YubiCredentials,
    Domain,
    asymmetric::Algorithm as AsymmetricAlgorithm,
    authentication::{Algorithm as AuthenticationAlgorithm, Key},
    client::Client,
    object::Id,
    opaque::Algorithm as OpaqueAlgorithm,
};

use crate::{Credentials, Error, YubiHsm2SigningKey};

/// Sets up a single signing key for use with OpenPGP signing in a MockHSM.
///
/// The `credentials` are used to setup authentication for a signing key with `key_id`.
/// Both signing and authentication key are located in domain one.
///
/// # Warning
///
/// The signing key created by this function should be used only for tests as the signing
/// material is exposed in memory!
///
/// # Errors
///
/// When automatic provisioning of the connector fails this function can return [`Error`].
pub fn setup_single_key_in_mockhsm(
    key_id: Id,
    credentials: &Credentials,
) -> Result<Connector, Error> {
    let connector = Connector::mockhsm();
    let client =
        Client::open(connector, Default::default(), true).map_err(|source| Error::Client {
            context: "connecting to mockhsm",
            source,
        })?;
    let auth_key = Key::derive_from_password(credentials.passphrase().expose_borrowed().as_bytes());
    let domain = Domain::DOM1;
    client
        .put_authentication_key(
            credentials.id(),
            Default::default(),
            domain,
            Capability::empty(),
            Capability::SIGN_EDDSA,
            AuthenticationAlgorithm::YubicoAes,
            auth_key.clone(),
        )
        .map_err(|source| Error::Client {
            context: "putting authentication key",
            source,
        })?;

    let client = Client::open(
        client.connector().clone(),
        YubiCredentials::new(credentials.id(), auth_key),
        true,
    )
    .map_err(|source| Error::Client {
        context: "connecting to mockhsm",
        source,
    })?;

    client
        .generate_asymmetric_key(
            key_id,
            Default::default(),
            domain,
            Capability::SIGN_EDDSA,
            AsymmetricAlgorithm::Ed25519,
        )
        .map_err(|source| Error::Client {
            context: "generating asymmetric key",
            source,
        })?;

    let flags = {
        let mut flags = OpenPgpKeyUsageFlags::default();
        flags.set_sign();
        flags
    };

    let signer = YubiHsm2SigningKey::new(client, key_id);

    let cert = generate_certificate(
        &signer,
        flags,
        &[OpenPgpUserId::new("Test".to_owned()).expect("static user ID to be valid")],
        Default::default(),
        Timestamp::now(),
        OpenPgpVersion::V4,
    )
    .map_err(|source| Error::CertificateGeneration {
        context: "generating OpenPGP certificate",
        source,
    })?;

    signer
        .client()
        .put_opaque(
            key_id,
            Default::default(),
            domain,
            Capability::empty(),
            OpaqueAlgorithm::Data,
            cert,
        )
        .map_err(|source| Error::Client {
            context: "putting generated certificate on the device",
            source,
        })?;

    Ok(signer.client().connector().clone())
}
