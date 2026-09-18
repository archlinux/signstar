//! Library for the retrieval of key certificates.

use std::fmt::Display;

use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use signstar_common::backend::BackendType;

use crate::error::Error;

#[cfg(feature = "cli")]
pub mod cli;
pub mod error;

/// The type of the certificate that has been generated for the signing key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
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
#[derive(Debug, Deserialize, Serialize)]
pub struct Certificates {
    /// Array of base64-encoded certificates.
    pub certs: Vec<Certificate>,
}

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
mod backend;

#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
pub use backend::load_certificates;

/// Loads [`Certificate`]s from signing keys used in Signstar configuration.
///
/// # Errors
///
/// Always returns an error, because no HSM backend support is compiled in.
#[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
pub fn load_certificates() -> Result<Vec<Certificate>, Error> {
    Err(Error::NoBackend)
}
