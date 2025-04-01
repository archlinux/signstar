use std::str::FromStr;
use std::sync::Arc;
use std::thread::available_parallelism;
use std::time::Duration;

use log::{debug, error, info, trace};
use nethsm_sdk_rs::ureq::{Agent, AgentBuilder};
use rustls::client::{
    ClientConfig,
    danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use rustls::crypto::{CryptoProvider, ring as tls_provider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Error;
#[cfg(doc)]
use crate::NetHsm;

/// The fingerprint of a TLS certificate (as hex)
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct CertFingerprint(
    #[serde(
        deserialize_with = "hex::serde::deserialize",
        serialize_with = "hex::serde::serialize"
    )]
    Vec<u8>,
);

impl FromStr for CertFingerprint {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.as_bytes().to_vec()))
    }
}

impl From<Vec<u8>> for CertFingerprint {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// Certificate fingerprints to use for matching against a host's TLS
/// certificate
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct HostCertificateFingerprints {
    /// An optional list of SHA-256 checksums
    sha256: Option<Vec<CertFingerprint>>,
}

/// The security model chosen for a [`crate::NetHsm`]'s TLS connection
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ConnectionSecurity {
    /// Always trust the TLS certificate associated with a host
    Unsafe,
    /// Use the native trust store to evaluate the trust of a host
    Native,
    /// Use a list of checksums (fingerprints) to verify a host's TLS certificate
    Fingerprints(HostCertificateFingerprints),
}

impl FromStr for ConnectionSecurity {
    type Err = Error;

    /// Create a ConnectionSecurity from string
    ///
    /// Valid inputs are either "Unsafe" (or "unsafe"), "Native" (or "native") or "sha256:checksum"
    /// where "checksum" denotes 64 ASCII hexadecimal chars.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if the input is neither "Unsafe" nor "Native" and also no valid
    /// certificate fingerprint can be derived from the input.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use nethsm::ConnectionSecurity;
    ///
    /// assert!(ConnectionSecurity::from_str("unsafe").is_ok());
    /// assert!(ConnectionSecurity::from_str("native").is_ok());
    /// assert!(
    ///     ConnectionSecurity::from_str(
    ///         "sha256:324f7bd1530c55cf6812ca6865445de21dfc74cf7a3bb5fae7585e849e3553b7"
    ///     )
    ///     .is_ok()
    /// );
    /// assert!(ConnectionSecurity::from_str("something").is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unsafe" | "Unsafe" => Ok(Self::Unsafe),
            "native" | "Native" => Ok(Self::Native),
            _ => {
                let sha256_fingerprints: Vec<Vec<u8>> = s
                    .split(',')
                    .filter_map(|checksum| {
                        checksum
                            .strip_prefix("sha256:")
                            .filter(|x| x.len() == 64 && x.chars().all(|x| x.is_ascii_hexdigit()))
                            .map(|checksum| checksum.as_bytes().to_vec())
                    })
                    .collect();
                if sha256_fingerprints.is_empty() {
                    Err(Error::Default(
                        "No valid TLS certificate fingerprints detected.".to_string(),
                    ))
                } else {
                    Ok(Self::Fingerprints(HostCertificateFingerprints {
                        sha256: Some(
                            sha256_fingerprints
                                .iter()
                                .map(|checksum| checksum.clone().into())
                                .collect(),
                        ),
                    }))
                }
            }
        }
    }
}

/// A verifier for server certificates that always accepts them
///
/// This verifier is used when choosing [`ConnectionSecurity::Unsafe`]. It is **unsafe** and should
/// not be used unless for initial setup scenarios of a NetHSM! Instead use [`FingerprintVerifier`]
/// (selected by [`ConnectionSecurity::Fingerprints`]) or better yet rely on
/// [`ConnectionSecurity::Native`].
#[derive(Debug)]
pub struct DangerIgnoreVerifier(pub CryptoProvider);

impl ServerCertVerifier for DangerIgnoreVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // always accept the certificate
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// A verifier for server certificates that verifies them based on fingerprints
///
/// This verifier is selected when using [`ConnectionSecurity::Fingerprints`] and relies on
/// [`HostCertificateFingerprints`] to be able to match a host certificate fingerprint against a
/// predefined list of fingerprints. It should be preferred over the use of [`DangerIgnoreVerifier`]
/// (selected by [`ConnectionSecurity::Unsafe`]), but ideally a setup should make use of
/// [`ConnectionSecurity::Native`] instead!
#[derive(Debug)]
pub struct FingerprintVerifier {
    pub fingerprints: HostCertificateFingerprints,
    pub provider: CryptoProvider,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Some(sha256_fingerprints) = self.fingerprints.sha256.as_ref() {
            let mut hasher = Sha256::new();
            hasher.update(end_entity.as_ref());
            let result = hasher.finalize();
            for fingerprint in sha256_fingerprints.iter() {
                if fingerprint.0 == result[..] {
                    trace!("Certificate fingerprint matches");
                    return Ok(ServerCertVerified::assertion());
                }
            }
        } else {
            return Err(rustls::Error::General(
                "Could not verify certificate fingerprint as no fingerprints were provided to match against".to_string(),
            ));
        }
        Err(rustls::Error::General(
            "Could not verify certificate fingerprint".to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Creates an [`Agent`] for the use in a [`NetHsm`] connection.
///
/// Takes a [`ConnectionSecurity`] to define the TLS security model for the connection.
/// Allows setting the maximum idle connections per host using the optional
/// `max_idle_connections` (defaults to [`available_parallelism`] and falls back to `100` if
/// unavailable).
/// Also allows setting the timeout in seconds for a successful socket connection
/// using the optional `timeout_seconds` (defaults to `10`).
///
/// # Errors
///
/// Returns an error if
///
/// - the TLS client configuration can not be created,
/// - [`ConnectionSecurity::Native`] is provided as `tls_security`, but no certification authority
///   certificates are available on the system.
pub(crate) fn create_agent(
    tls_security: ConnectionSecurity,
    max_idle_connections: Option<usize>,
    timeout_seconds: Option<u64>,
) -> Result<Agent, Error> {
    let tls_conf = {
        let tls_conf = ClientConfig::builder_with_provider(Arc::new(CryptoProvider {
            cipher_suites: tls_provider::ALL_CIPHER_SUITES.into(),
            ..tls_provider::default_provider()
        }))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)?;

        match tls_security {
            ConnectionSecurity::Unsafe => {
                let dangerous = tls_conf.dangerous();
                dangerous
                    .with_custom_certificate_verifier(Arc::new(DangerIgnoreVerifier(
                        tls_provider::default_provider(),
                    )))
                    .with_no_client_auth()
            }
            ConnectionSecurity::Native => {
                let native_certs = rustls_native_certs::load_native_certs();
                if !native_certs.errors.is_empty() {
                    return Err(Error::CertLoading(native_certs.errors));
                }
                let native_certs = native_certs.certs;

                let roots = {
                    let mut roots = rustls::RootCertStore::empty();
                    let (added, failed) = roots.add_parsable_certificates(native_certs);
                    debug!("Added {added} certificates and failed to parse {failed} certificates");
                    if added == 0 {
                        error!("Added no native certificates");
                        return Err(Error::NoSystemCertsAdded { failed });
                    }
                    roots
                };

                tls_conf.with_root_certificates(roots).with_no_client_auth()
            }
            ConnectionSecurity::Fingerprints(fingerprints) => {
                let dangerous = tls_conf.dangerous();
                dangerous
                    .with_custom_certificate_verifier(Arc::new(FingerprintVerifier {
                        fingerprints,
                        provider: tls_provider::default_provider(),
                    }))
                    .with_no_client_auth()
            }
        }
    };

    let max_idle_connections = max_idle_connections
        .or_else(|| available_parallelism().ok().map(Into::into))
        .unwrap_or(100);
    let timeout_seconds = timeout_seconds.unwrap_or(10);
    info!(
        "NetHSM connection configured with \"max_idle_connection\" {} and \"timeout_seconds\" {}.",
        max_idle_connections, timeout_seconds
    );

    Ok(AgentBuilder::new()
        .tls_config(Arc::new(tls_conf))
        .max_idle_connections(max_idle_connections)
        .max_idle_connections_per_host(max_idle_connections)
        .timeout_connect(Duration::from_secs(timeout_seconds))
        .build())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[rstest]
    #[case("native", Some(ConnectionSecurity::Native))]
    #[case("unsafe", Some(ConnectionSecurity::Unsafe))]
    #[case("sha256:324f7bd1530c55cf6812ca6865445de21dfc74cf7a3bb5fae7585e849e3553b7", Some(ConnectionSecurity::Fingerprints(HostCertificateFingerprints { sha256: Some(vec![CertFingerprint::from_str("324f7bd1530c55cf6812ca6865445de21dfc74cf7a3bb5fae7585e849e3553b7")?]) })))]
    #[case(
        "324f7bd1530c55cf6812ca6865445de21dfc74cf7a3bb5fae7585e849e3553b7",
        None
    )]
    #[case(
        "sha256:324f7bd1530c55cf6812ca6865445de21dfc74cf7a3bb5fae7585e849e",
        None
    )]
    #[case(
        "sha256:324f7bd1530c55cf6812ca6865445de21dfc74cf7a3bb5fae7585e849e3553b73553b7",
        None
    )]
    fn connection_security_fromstr(
        #[case] input: &str,
        #[case] expected: Option<ConnectionSecurity>,
    ) -> TestResult {
        if let Some(expected) = expected {
            assert_eq!(ConnectionSecurity::from_str(input)?, expected);
        } else {
            assert!(ConnectionSecurity::from_str(input).is_err());
        }
        Ok(())
    }
}
