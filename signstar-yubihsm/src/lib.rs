//! YubiHSM signer interface.

use std::time::SystemTime;

use signstar_crypto::{
    openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId},
    passphrase::Passphrase,
    signer::{RawPublicKey, RawSigningKey},
};
use yubihsm::{
    Capability,
    Credentials as YubiCredentials,
    Domain,
    asymmetric::Algorithm,
    authentication,
};

/// YubiHSM error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Client error.
    #[error(transparent)]
    Client(#[from] yubihsm::client::Error),

    /// Device error.
    #[error(transparent)]
    Device(#[from] yubihsm::device::Error),
}

/// YubiHSM credentials.
#[derive(Debug)]
pub struct Credentials {
    /// The identifier of the authentication key.
    pub auth_key_id: u16,

    /// The passphrase associated with the authentication key.
    pub passphrase: Passphrase,
}

impl From<&Credentials> for YubiCredentials {
    fn from(value: &Credentials) -> Self {
        YubiCredentials::from_password(
            value.auth_key_id,
            value.passphrase.expose_borrowed().as_bytes(),
        )
    }
}

/// A signing key stored in the YubiHSM.
pub struct YubiHsmSigner {
    yubihsm: yubihsm::client::Client,
    key_id: yubihsm::object::Id,
}

impl YubiHsmSigner {
    /// Return a signing key emulated in software.
    ///
    /// # Warning
    ///
    /// The signing key created by this function should be used only for tests as the signing
    /// material is exposed in memory!
    ///
    /// # Errors
    ///
    /// When automatic provisioning of the emulator fails this function can return [`Error`].
    pub fn mock(key_id: u16, credentials: &Credentials) -> Result<Self, Error> {
        let connector = yubihsm::Connector::mockhsm();
        let client = yubihsm::client::Client::open(connector, Default::default(), true)?;
        let auth_key = authentication::Key::derive_from_password(
            credentials.passphrase.expose_borrowed().as_bytes(),
        );
        let domain = Domain::DOM1;
        client.put_authentication_key(
            credentials.auth_key_id,
            Default::default(),
            domain,
            Capability::empty(),
            Capability::SIGN_EDDSA,
            yubihsm::authentication::Algorithm::YubicoAes,
            auth_key.clone(),
        )?;

        let client = yubihsm::client::Client::open(
            client.connector().clone(),
            YubiCredentials::new(credentials.auth_key_id, auth_key),
            true,
        )?;

        client.generate_asymmetric_key(
            key_id,
            Default::default(),
            domain,
            yubihsm::Capability::SIGN_EDDSA,
            yubihsm::asymmetric::Algorithm::Ed25519,
        )?;

        let mut flags = OpenPgpKeyUsageFlags::default();
        flags.set_sign();

        let signer = Self {
            yubihsm: client,
            key_id,
        };

        let cert = signstar_crypto::signer::add_certificate(
            &signer,
            flags,
            OpenPgpUserId::new("Test".to_owned()).expect("static user ID to be valid"),
            SystemTime::now().into(),
            signstar_crypto::openpgp::OpenPgpVersion::V4,
        )
        .expect("certificate generation to succeed");

        signer.yubihsm.put_opaque(
            key_id,
            Default::default(),
            domain,
            yubihsm::capability::Capability::empty(),
            yubihsm::opaque::Algorithm::Data,
            cert,
        )?;

        Ok(signer)
    }

    /// Return a signing key backed by hardware YubiHSM with given serial number and key identifier.
    ///
    /// # Errors
    ///
    /// If the communication with the device fails or the authentication data is incorrect this
    /// function will return an [`Error`].
    pub fn new_with_serial_number(
        sn: &str,
        key_id: u16,
        credentials: &Credentials,
    ) -> Result<Self, Error> {
        let connector = yubihsm::Connector::usb(&yubihsm::UsbConfig {
            serial: Some(sn.parse()?),
            timeout_ms: yubihsm::UsbConfig::DEFAULT_TIMEOUT_MILLIS,
        });
        let client = yubihsm::client::Client::open(connector, credentials.into(), true)?;
        Ok(Self {
            yubihsm: client,
            key_id,
        })
    }
}

impl std::fmt::Debug for YubiHsmSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YubiHsmSigner")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl RawSigningKey for YubiHsmSigner {
    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, signstar_crypto::signer::Error> {
        let sig = self
            .yubihsm
            .sign_ed25519(self.key_id, digest)
            .map_err(|e| signstar_crypto::signer::Error::Hsm {
                context: "calling yubihsm::sign_ed25519",
                source: Box::new(e),
            })?;

        Ok(vec![sig.r_bytes().into(), sig.s_bytes().into()])
    }

    fn certificate(&self) -> Result<Option<Vec<u8>>, signstar_crypto::signer::Error> {
        Ok(Some(self.yubihsm.get_opaque(self.key_id).map_err(|e| {
            signstar_crypto::signer::Error::Hsm {
                context: "calling yubihsm::get_opaque",
                source: Box::new(e),
            }
        })?))
    }

    fn public(&self) -> Result<RawPublicKey, signstar_crypto::signer::Error> {
        let pk = self.yubihsm.get_public_key(self.key_id).map_err(|e| {
            signstar_crypto::signer::Error::Hsm {
                context: "calling yubihsm::get_public_key",
                source: Box::new(e),
            }
        })?;
        assert_eq!(pk.algorithm, Algorithm::Ed25519);
        Ok(signstar_crypto::signer::RawPublicKey::Ed25519(pk.bytes))
    }
}
