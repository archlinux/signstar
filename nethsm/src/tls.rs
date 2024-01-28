// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use log::trace;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

/// Certificate fingerprints to use for matching against a host's TLS
/// certificate
#[derive(Debug)]
pub struct HostCertificateFingerprints {
    /// An optional list of SHA-256 checksums
    sha256: Option<Vec<Vec<u8>>>,
}

/// The security model chosen for a [`crate::NetHsm`]'s TLS connection
#[derive(Debug)]
pub enum ConnectionSecurity {
    /// Always trust the TLS certificate associated with a host
    Unsafe,
    /// Use the native trust store to evaluate the trust of a host
    Native,
    /// Use a list of checksums (fingerprints) to verify a host's TLS certificate
    Fingerprints(HostCertificateFingerprints),
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
                if fingerprint == &result[..] {
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
