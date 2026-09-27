//! Types related to Signstar requests and responses.

use std::fmt::Display;

use base64ct::{Base64, Encoding as _};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::backend::BackendType;

/// The type of the certificate that has been generated for the signing key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub enum CertificateType {
    /// OpenPGP certificate.
    OpenPgp,
}

impl CertificateType {
    /// Print raw certificate bytes with correct framing.
    ///
    /// For OpenPGP, for example, this is the same as using armor.
    pub fn with_framing(&self, raw_bytes: &[u8]) -> CertificateData {
        let bytes = Base64::encode_string(raw_bytes);
        match self {
            CertificateType::OpenPgp => CertificateData(format!(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n{bytes}\n-----END PGP PUBLIC KEY BLOCK-----"
            )),
        }
    }
}

/// Certificate data, as presented to the user.
///
/// This representation already contains protocol framing and is base64-encoded.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct CertificateData(String);

impl AsRef<str> for CertificateData {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Display for CertificateData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Data and metadata of a certificate residing in a Signstar backend.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Certificate {
    /// Base64-encoded certificate with protocol framing.
    pub certificate: CertificateData,

    /// The type of the certificate.
    pub r#type: CertificateType,

    /// The name of the backend, e.g. `NetHSM` or `YubiHSM2`.
    pub backend_id: BackendType,

    /// The signing key ID on that particular backend.
    pub signing_key_id: String,
}

/// List of certificates stored on the Signstar host.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Certificates {
    /// Array of base64-encoded certificates.
    pub certs: Vec<Certificate>,
}
