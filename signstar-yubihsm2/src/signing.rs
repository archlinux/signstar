//! Signing data with YubiHSM.

use std::time::SystemTime;

use signstar_crypto::{
    openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId},
    signer::error::Error as SignerError,
    signer::traits::{RawPublicKey, RawSigningKey},
    traits::UserWithPassphrase as _,
};
use yubihsm::{
    Capability,
    Credentials as YubiCredentials,
    Domain,
    asymmetric::Algorithm,
    authentication,
};

use crate::{Credentials, Error};

/// A signing key stored in the YubiHSM.
pub struct YubiHsmSigner {
    yubihsm: yubihsm::client::Client,
    key_id: yubihsm::object::Id,
}

impl YubiHsmSigner {
    /// Returns a signing key emulated in software.
    ///
    /// # Warning
    ///
    /// The signing key created by this function should be used only for tests as the signing
    /// material is exposed in memory!
    ///
    /// # Errors
    ///
    /// When automatic provisioning of the emulator fails this function can return [`Error`].
    ///
    /// # Panics
    ///
    /// This function panics if certificate generation fails.
    pub fn mock(key_id: u16, credentials: &Credentials) -> Result<Self, Error> {
        let connector = yubihsm::Connector::mockhsm();
        let client = yubihsm::client::Client::open(connector, Default::default(), true).map_err(
            |source| Error::Client {
                context: "connecting to mockhsm",
                source,
            },
        )?;
        let auth_key = authentication::Key::derive_from_password(
            credentials.passphrase().expose_borrowed().as_bytes(),
        );
        let domain = Domain::DOM1;
        client
            .put_authentication_key(
                credentials.id,
                Default::default(),
                domain,
                Capability::empty(),
                Capability::SIGN_EDDSA,
                yubihsm::authentication::Algorithm::YubicoAes,
                auth_key.clone(),
            )
            .map_err(|source| Error::Client {
                context: "putting authentication key",
                source,
            })?;

        let client = yubihsm::client::Client::open(
            client.connector().clone(),
            YubiCredentials::new(credentials.id, auth_key),
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
                yubihsm::Capability::SIGN_EDDSA,
                yubihsm::asymmetric::Algorithm::Ed25519,
            )
            .map_err(|source| Error::Client {
                context: "generating asymmetric key",
                source,
            })?;

        let mut flags = OpenPgpKeyUsageFlags::default();
        flags.set_sign();

        let signer = Self {
            yubihsm: client,
            key_id,
        };

        let cert = signstar_crypto::signer::openpgp::add_certificate(
            &signer,
            flags,
            OpenPgpUserId::new("Test".to_owned()).expect("static user ID to be valid"),
            SystemTime::now().into(),
            signstar_crypto::openpgp::OpenPgpVersion::V4,
        )
        .expect("certificate generation to succeed");

        signer
            .yubihsm
            .put_opaque(
                key_id,
                Default::default(),
                domain,
                yubihsm::capability::Capability::empty(),
                yubihsm::opaque::Algorithm::Data,
                cert,
            )
            .map_err(|source| Error::Client {
                context: "putting generated certificate on the device",
                source,
            })?;

        Ok(signer)
    }

    /// Returns a new [`YubiHsmSigner`] backed by specific YubiHSM2 hardware.
    ///
    /// The hardware is identified using its `serial_number` and the key is addressed by its
    /// `key_id`.
    ///
    /// # Errors
    ///
    /// If the communication with the device fails or the authentication data is incorrect this
    /// function will return an [`Error`].
    pub fn new_with_serial_number(
        serial_number: &str,
        key_id: u16,
        credentials: &Credentials,
    ) -> Result<Self, Error> {
        let connector = yubihsm::Connector::usb(&yubihsm::UsbConfig {
            serial: Some(serial_number.parse().map_err(|source| Error::Device {
                context: "parsing serial number",
                source,
            })?),
            timeout_ms: yubihsm::UsbConfig::DEFAULT_TIMEOUT_MILLIS,
        });
        let client = yubihsm::client::Client::open(connector, credentials.into(), true).map_err(
            |source| Error::Client {
                context: "connecting to a hardware device",
                source,
            },
        )?;
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
    /// Signs a raw digest.
    ///
    /// The digest is without any framing and the result will be a vector of raw signature parts.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation returns a
    /// [`signstar_crypto::signer::error::Error::Hsm`], which wraps the client-specific HSM error
    /// in its `source` field.
    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, SignerError> {
        let sig = self
            .yubihsm
            .sign_ed25519(self.key_id, digest)
            .map_err(|e| SignerError::Hsm {
                context: "calling yubihsm::sign_ed25519",
                source: Box::new(e),
            })?;

        Ok(vec![sig.r_bytes().into(), sig.s_bytes().into()])
    }

    /// Returns certificate bytes associated with this signing key, if any.
    ///
    /// This interface does not interpret the certificate in any way but has a notion of certificate
    /// being set or unset.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation returns a
    /// [`SignerError::Hsm`], which wraps the client-specific HSM error
    /// in its `source` field.
    fn certificate(&self) -> Result<Option<Vec<u8>>, SignerError> {
        Ok(Some(self.yubihsm.get_opaque(self.key_id).map_err(|e| {
            SignerError::Hsm {
                context: "calling yubihsm::get_opaque",
                source: Box::new(e),
            }
        })?))
    }

    /// Returns raw public parts of this signing key.
    ///
    /// Implementation of this trait implies that the signing key exists and as such always has
    /// public parts. The public key is used for generating application-specific certificates.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation returns a
    /// [`SignerError::Hsm`], which wraps the client-specific HSM error
    /// in its `source` field.
    fn public(&self) -> Result<RawPublicKey, SignerError> {
        let pk = self
            .yubihsm
            .get_public_key(self.key_id)
            .map_err(|e| SignerError::Hsm {
                context: "calling yubihsm::get_public_key",
                source: Box::new(e),
            })?;
        if pk.algorithm != Algorithm::Ed25519 {
            return Err(SignerError::KeyData(format!(
                "Unsupported algorithm of the HSM key: {:?}",
                pk.algorithm
            )));
        }
        Ok(RawPublicKey::Ed25519(pk.bytes))
    }
}
