//! OpenPGP signer interface.

use std::backtrace::Backtrace;

use chrono::{DateTime, Utc};
use digest::DynDigest;
use ed25519_dalek::VerifyingKey;
use log::{error, warn};
use pgp::{
    composed::{
        ArmorOptions,
        Deserializable as _,
        DetachedSignature,
        SignedPublicKey,
        SignedSecretKey,
    },
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{
        Notation,
        PacketTrait,
        PubKeyInner,
        PublicKey,
        Signature,
        SignatureConfig,
        SignatureType,
        Subpacket,
        SubpacketData,
        UserId,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm,
        EcdsaPublicParams,
        KeyDetails as _,
        KeyId,
        KeyVersion,
        Mpi,
        Password,
        PlainSecretParams,
        PublicKeyTrait as _,
        PublicParams,
        RsaPublicParams,
        SecretKeyTrait,
        SecretParams,
        SignatureBytes,
    },
};
use rsa::BigUint;
use rsa::traits::PublicKeyParts as _;
use sha2::digest::Digest as _;

use crate::{
    key::{KeyMechanism, KeyType, PrivateKeyImport, key_type_matches_length},
    openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId, OpenPgpVersion},
};

/// An error that may occur when working with OpenPGP data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Certificate for the key has not been initialized
    #[error("Certificate for the key has not been initialized")]
    CertificateMissing,

    /// Elliptic curve error
    #[error("Elliptic curve error: {0}")]
    EllipticCurve(#[from] p256::elliptic_curve::Error),

    /// Provided key data is invalid
    #[error("Key data invalid: {0}")]
    KeyData(String),

    /// OpenPGP error
    #[error("rPGP error: {0}")]
    Pgp(#[from] pgp::errors::Error),

    /// The Transferable Secret Key is passphrase protected
    #[error("Transferable Secret Key is passphrase protected")]
    PrivateKeyPassphraseProtected,

    /// Multiple component keys are unsupported
    #[error("Unsupported multiple component keys")]
    UnsupportedMultipleComponentKeys,

    /// Invalid signature returned from the HSM
    #[error("Invalid signature returned from the HSM")]
    InvalidSignature,

    /// Unsupported hash requested
    #[error("Unsupported hash requested: {actual}. Supported hash must be {expected}")]
    UnsupportedHashAlgorithm {
        /// The hash algorithm that has been used.
        actual: HashAlgorithm,

        /// The hash algorithm that is supported.
        expected: HashAlgorithm,
    },

    /// The key format used is unsupported
    #[error("Unsupported key format: {public_params:?}")]
    UnsupportedKeyFormat {
        /// The unsupported public key parameters.
        public_params: Box<PublicParams>,
    },

    /// A signstar_crypto key  error.
    #[error("A signstar_crypto key error:\n{0}")]
    SignstarCryptoKey(#[from] crate::key::Error),

    /// An HSM operation error.
    #[error("HSM operation failed while {context}:\n{source}")]
    Hsm {
        /// The context in which a HSM error occurred.
        ///
        /// This is meant to complete the sentence "HSM operation failed
        /// while ".
        context: &'static str,
        /// The source error.
        source: Box<dyn std::error::Error + 'static + Send + Sync>,
    },
}

/// Represents a public key associated with the [signing key][RawSigningKey].
#[derive(Debug)]
pub enum RawPublicKey {
    /// Ed25519 public key.
    Ed25519(Vec<u8>),
    /// RSA public key.
    Rsa {
        /// Modulus of the RSA key.
        modulus: Vec<u8>,
        /// Exponent of the RSA key.
        exponent: Vec<u8>,
    },
    /// NIST P-256 public key.
    P256(Vec<u8>),
    /// NIST P-348 public key.
    P384(Vec<u8>),
    /// NIST P-521 public key.
    P521(Vec<u8>),
}

/// Represents a signing key for low-level operations.
pub trait RawSigningKey {
    /// Signs a raw digest.
    ///
    /// The digest is without any framing and the result should be a vector of raw signature parts.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation should return appropriate error.
    /// [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error>;

    /// Returns certificate bytes associated with this signing key, if any.
    ///
    /// This interface does not interpret the certificate in any way but has a notion of certificate
    /// being set or unset.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation should return appropriate error.
    /// [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn certificate(&self) -> Result<Option<Vec<u8>>, Error>;

    /// Returns raw public parts of this signing key.
    ///
    /// Implementation of this trait implies that the signing key exists and as such always have
    /// public parts. The public key is used for generating application-specific certificates.
    ///
    /// # Errors
    ///
    /// If the operation fails the implementation should return appropriate error.
    /// [`Error::Hsm`] variant is appropriate for forwarding client-specific HSM errors.
    fn public(&self) -> Result<RawPublicKey, Error>;
}

/// PGP-adapter for a [raw HSM key][RawSigningKey].
///
/// All PGP-related operations executed on objects of this type will be forwarded to
/// the HSM instance.
struct OpenPgpHsmKey<'a> {
    public_key: PublicKey,
    raw_signer: &'a dyn RawSigningKey,
}

impl std::fmt::Debug for OpenPgpHsmKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmKey")
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Wraps an [`Error`] in a [`std::io::Error`] and returns it as a [`pgp::errors::Error`].
///
/// Since it is currently not possible to wrap the arbitrary [`Error`] of an external function
/// cleanly in a [`pgp::errors::Error`], this function first wraps it in a [`std::io::Error`].
/// This behavior has been suggested upstream in <https://github.com/rpgp/rpgp/issues/517#issuecomment-2778245199>
#[inline]
fn to_rpgp_error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> pgp::errors::Error {
    pgp::errors::Error::IO {
        source: std::io::Error::other(e),
        backtrace: Some(Backtrace::capture()),
    }
}

impl<'a> OpenPgpHsmKey<'a> {
    /// Creates a new remote signing key which will use `key_id` key for signing.
    fn new(raw_signer: &'a dyn RawSigningKey, public_key: PublicKey) -> Self {
        Self {
            raw_signer,
            public_key,
        }
    }

    /// Create a new remote signing key with a certificate already stored in the HSM.
    fn new_provisioned(raw_signer: &'a dyn RawSigningKey) -> Result<Self, Error> {
        let public_key = if let Some(cert) = raw_signer.certificate()?.as_ref() {
            SignedPublicKey::from_bytes(std::io::Cursor::new(cert))?.primary_key
        } else {
            return Err(Error::CertificateMissing);
        };
        Ok(Self::new(raw_signer, public_key))
    }
}

impl pgp::types::KeyDetails for OpenPgpHsmKey<'_> {
    fn version(&self) -> KeyVersion {
        self.public_key.version()
    }

    fn fingerprint(&self) -> pgp::types::Fingerprint {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }
}

impl SecretKeyTrait for OpenPgpHsmKey<'_> {
    /// Creates a data signature.
    ///
    /// # Note
    ///
    /// The HSM in use is expected to be unlocked and configured with access to the signing key.
    ///
    /// Using a [`Password`] is not necessary as the operation deals with unencrypted cryptographic
    /// key material.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the key uses unsupported parameters (e.g. brainpool curves),
    /// - digest serialization fails (e.g. ASN1 encoding of digest for RSA signatures),
    /// - [`RawSigningKey::sign`] call fails,
    /// - parsing of signature returned from the HSM fails.
    fn create_signature(
        &self,
        _key_pw: &Password,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes> {
        if hash != self.hash_alg() {
            error!(
                "Requested signing hash is different from the default supported, got {hash} expected {expected}",
                expected = self.hash_alg()
            );
            return Err(to_rpgp_error(Error::UnsupportedHashAlgorithm {
                actual: hash,
                expected: self.hash_alg(),
            }));
        }
        let sig = self.raw_signer.sign(data).map_err(|e| {
            error!("RawSigner::sign failed: {e:?}");
            to_rpgp_error(e)
        })?;

        Ok(SignatureBytes::Mpis(
            sig.into_iter().map(|b| Mpi::from_slice(&b)).collect(),
        ))
    }

    /// Returns the preferred hash algorithm for data digests.
    ///
    /// # Note
    /// We always return SHA-512 since this it is faster than SHA-256 on modern hardware and of
    /// sufficient size to accommodate all elliptic-curve algorithms.
    fn hash_alg(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

/// Generates an OpenPGP certificate for the given signer.
pub fn add_certificate(
    raw_signer: &dyn RawSigningKey,
    flags: OpenPgpKeyUsageFlags,
    user_id: OpenPgpUserId,
    created_at: DateTime<Utc>,
    version: OpenPgpVersion,
) -> Result<Vec<u8>, Error> {
    if version != OpenPgpVersion::V4 {
        unimplemented!(
            "Support for creating OpenPGP {version} certificates is not yet implemented!"
        );
    }
    let public_key = hsm_pk_to_pgp_pk(raw_signer.public()?, created_at)?;
    let signer = OpenPgpHsmKey::new(raw_signer, public_key.clone());

    let composed_pk = pgp::composed::PublicKey::new(
        public_key.clone(),
        pgp::composed::KeyDetails::new(
            Some(UserId::from_str(Default::default(), user_id.as_ref())?),
            vec![],
            vec![],
            flags.into(),
            Default::default(),
            Default::default(),
            Default::default(),
            vec![CompressionAlgorithm::Uncompressed].into(),
            vec![].into(),
        ),
        vec![],
    );

    let signed_pk =
        composed_pk.sign(rand::thread_rng(), &signer, &public_key, &Password::empty())?;

    let mut buffer = vec![];
    signed_pk.to_writer(&mut buffer)?;
    Ok(buffer)
}

/// Converts an OpenPGP Transferable Secret Key into [`PrivateKeyImport`] object.
///
/// # Errors
///
/// Returns an [`Error`] if creating a [`PrivateKeyImport`] from `key_data` is not
/// possible.
///
/// Returns an [`crate::key::Error::InvalidKeyLengthRsa`] if `key_data` is an RSA public key and is
/// shorter than [`crate::key::base::MIN_RSA_BIT_LENGTH`].
pub fn tsk_to_private_key_import(
    key_data: &[u8],
) -> Result<(PrivateKeyImport, KeyMechanism), Error> {
    let key = SignedSecretKey::from_bytes(key_data)?;
    if !key.secret_subkeys.is_empty() {
        return Err(Error::UnsupportedMultipleComponentKeys);
    }
    let SecretParams::Plain(secret) = key.primary_key.secret_params() else {
        return Err(Error::PrivateKeyPassphraseProtected);
    };
    Ok(match (secret, key.public_key().public_params()) {
        (PlainSecretParams::RSA(secret), PublicParams::RSA(public)) => {
            // ensure, that we have sufficient bit length
            key_type_matches_length(
                KeyType::Rsa,
                Some(public.key.n().to_bytes_be().len() as u32 * 8),
            )?;

            let (_d, p, q, _u) = secret.to_bytes();

            (
                PrivateKeyImport::from_rsa(p, q, public.key.e().to_bytes_be().to_vec()),
                KeyMechanism::RsaSignaturePkcs1,
            )
        }
        (PlainSecretParams::ECDSA(secret_key), _) => {
            let ec = if let PublicParams::ECDSA(pp) = key.primary_key.public_key().public_params() {
                match pp {
                    EcdsaPublicParams::P256 { .. } => KeyType::EcP256,
                    EcdsaPublicParams::P384 { .. } => KeyType::EcP384,
                    EcdsaPublicParams::P521 { .. } => KeyType::EcP521,
                    pp => {
                        warn!("Unsupported ECDSA parameters: {pp:?}");
                        return Err(Error::UnsupportedKeyFormat {
                            public_params: Box::new(key.public_key().public_params().clone()),
                        })?;
                    }
                }
            } else {
                return Err(Error::UnsupportedKeyFormat {
                    public_params: Box::new(key.public_key().public_params().clone()),
                });
            };

            let bytes = match secret_key {
                pgp::crypto::ecdsa::SecretKey::P256(secret_key) => secret_key.to_bytes().to_vec(),
                pgp::crypto::ecdsa::SecretKey::P384(secret_key) => secret_key.to_bytes().to_vec(),
                pgp::crypto::ecdsa::SecretKey::P521(secret_key) => secret_key.to_bytes().to_vec(),

                pgp::crypto::ecdsa::SecretKey::Secp256k1(secret_key) => {
                    secret_key.to_bytes().to_vec()
                }
                secret_key => {
                    warn!("Unsupported secret key parameters: {secret_key:?}");
                    return Err(Error::UnsupportedKeyFormat {
                        public_params: Box::new(key.public_key().public_params().clone()),
                    })?;
                }
            };

            (
                PrivateKeyImport::from_raw_bytes(ec, bytes).map_err(to_rpgp_error)?,
                KeyMechanism::EcdsaSignature,
            )
        }
        (PlainSecretParams::Ed25519Legacy(bytes), _) => (
            PrivateKeyImport::from_raw_bytes(KeyType::Curve25519, bytes.as_bytes())
                .map_err(to_rpgp_error)?,
            KeyMechanism::EdDsaSignature,
        ),
        (_, public_params) => {
            return Err(Error::UnsupportedKeyFormat {
                public_params: Box::new(public_params.clone()),
            });
        }
    })
}

/// Generates an OpenPGP signature using a given HSM key for the message.
///
/// Signs the message `message` using the [`RawSigningKey`] and returns a binary [OpenPGP data
/// signature].
///
/// # Errors
///
/// Returns an [`Error`] if creating an [OpenPGP signature] for the hasher state fails:
/// * the certificate for a given key has not been generated or is invalid
/// * subpacket lengths exceed maximum values
/// * hashing signed data fails
/// * signature creation using the HSM fails
/// * constructing OpenPGP signature from parts fails
/// * writing the signature to vector fails
///
/// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
/// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
pub fn sign(raw_signer: &dyn RawSigningKey, message: &[u8]) -> Result<Vec<u8>, Error> {
    let signer = OpenPgpHsmKey::new_provisioned(raw_signer)?;

    let mut sig_config =
        SignatureConfig::v4(SignatureType::Binary, signer.algorithm(), signer.hash_alg());
    sig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            std::time::SystemTime::now().into(),
        ))?,
        Subpacket::regular(SubpacketData::Issuer(signer.key_id()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
    ];

    let mut hasher = sig_config.hash_alg.new_hasher().map_err(to_rpgp_error)?;
    sig_config.hash_data_to_sign(&mut hasher, message)?;

    let len = sig_config.hash_signature_data(&mut hasher)?;

    hasher.update(&sig_config.trailer(len)?);

    let hash = &hasher.finalize()[..];

    let signed_hash_value = [hash[0], hash[1]];
    let raw_sig = signer.create_signature(&Password::empty(), sig_config.hash_alg, hash)?;

    let signature = Signature::from_config(sig_config, signed_hash_value, raw_sig)?;

    let mut out = vec![];
    signature.to_writer_with_header(&mut out)?;

    Ok(out)
}

/// Provides an adapter bridging two versions of the `digest` crate.
///
/// # Note
///
/// rPGP uses a different version of the `digest` crate than the latest (as used by e.g.
/// `signstar-request-signature`). This adapter exposes the old `digest` 0.10 interface for
/// the [sha2::Sha512] object which uses digest 0.11.
///
/// When rPGP updates to digest 0.11 this entire struct can be removed.
#[derive(Clone, Default)]
struct Hasher(sha2::Sha512);

impl DynDigest for Hasher {
    /// Updates the digest with input data.
    ///
    /// This method can be called repeatedly for use with streaming messages.
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Writes digest into provided buffer `buf` and consumes `self`.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of `buf` is too small for `self`.
    fn finalize_into(self, buf: &mut [u8]) -> Result<(), digest::InvalidBufferSize> {
        sha2::digest::DynDigest::finalize_into(self.0, buf)
            .map_err(|_| digest::InvalidBufferSize)?;
        Ok(())
    }

    /// Writes digest into provided buffer `buf` and resets `self` to an empty hasher.
    ///
    /// # Errors
    ///
    /// Returns an error if the length of `buf` is too small for `self`.
    fn finalize_into_reset(&mut self, out: &mut [u8]) -> Result<(), digest::InvalidBufferSize> {
        sha2::digest::DynDigest::finalize_into_reset(&mut self.0, out)
            .map_err(|_| digest::InvalidBufferSize)?;
        Ok(())
    }

    /// Reset hasher instance to its initial state.
    fn reset(&mut self) {
        sha2::digest::DynDigest::reset(&mut self.0)
    }

    /// Get output size of the hasher
    fn output_size(&self) -> usize {
        sha2::digest::DynDigest::output_size(&self.0)
    }

    /// Clone hasher state into a boxed trait object
    fn box_clone(&self) -> Box<dyn DynDigest> {
        Box::new(self.clone())
    }
}

/// Generates an armored OpenPGP signature based on provided hasher state.
///
/// Signs the hasher `state` using the [`RawSigningKey`] and returns a binary [OpenPGP data
/// signature].
///
/// # Errors
///
/// Returns an [`Error`] if creating an [OpenPGP signature] for the hasher state fails:
/// * the certificate for a given key has not been generated or is invalid
/// * subpacket lengths exceed maximum values
/// * hashing signed data fails
/// * signature creation using the HSM fails
/// * constructing OpenPGP signature from parts fails
/// * writing the signature to vector fails
///
/// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
/// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
pub fn sign_hasher_state(
    raw_signer: &dyn RawSigningKey,
    state: sha2::Sha512,
) -> Result<String, Error> {
    let signer = OpenPgpHsmKey::new_provisioned(raw_signer)?;
    let hasher = state.clone();

    let file_hash = Box::new(hasher).finalize().to_vec();

    let sig_config = {
        let mut sig_config =
            SignatureConfig::v4(SignatureType::Binary, signer.algorithm(), signer.hash_alg());
        sig_config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            ))?,
            Subpacket::regular(SubpacketData::Issuer(signer.key_id()))?,
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
            Subpacket::regular(SubpacketData::Notation(Notation {
                readable: false,
                name: "data-digest@archlinux.org".into(),
                value: file_hash.into(),
            }))?,
        ];
        sig_config
    };

    let mut hasher = Box::new(Hasher(state.clone())) as Box<dyn DynDigest + Send>;

    let len = sig_config.hash_signature_data(&mut hasher)?;

    hasher.update(&sig_config.trailer(len)?);

    let hash = &hasher.finalize()[..];

    let signed_hash_value = [hash[0], hash[1]];

    let raw_sig = signer.create_signature(&Password::empty(), sig_config.hash_alg, hash)?;

    let signature = pgp::packet::Signature::from_config(sig_config, signed_hash_value, raw_sig)?;

    let signature = DetachedSignature { signature };
    Ok(signature.to_armored_string(ArmorOptions::default())?)
}

/// Creates a [`PublicKey`] object from ECDSA parameters.
///
/// Takes a `created_at` date and ECDSA `key` parameters.
///
/// # Errors
///
/// Returns an error if
///
/// - the ECDSA algorithm is unsupported by rPGP,
/// - or the calculated packet length is invalid.
fn ecdsa_to_public_key(
    created_at: DateTime<Utc>,
    key: EcdsaPublicParams,
) -> Result<PublicKey, Error> {
    Ok(PublicKey::from_inner(PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::ECDSA,
        created_at,
        None,
        PublicParams::ECDSA(key),
    )?)?)
}

/// Converts [raw public key][RawPublicKey] to OpenPGP public key packet.
///
/// Since OpenPGP public keys have a date of creation (which is used
/// for fingerprint calculation) this is an additional, explicit
/// parameter.
fn hsm_pk_to_pgp_pk(pk: RawPublicKey, created_at: DateTime<Utc>) -> Result<PublicKey, Error> {
    Ok(match pk {
        RawPublicKey::Rsa { modulus, exponent } => PublicKey::from_inner(PubKeyInner::new(
            KeyVersion::V4,
            PublicKeyAlgorithm::RSA,
            created_at,
            None,
            PublicParams::RSA(RsaPublicParams {
                key: rsa::RsaPublicKey::new(
                    BigUint::from_bytes_be(&modulus),
                    BigUint::from_bytes_be(&exponent),
                )
                .map_err(to_rpgp_error)?,
            }),
        )?)?,

        RawPublicKey::Ed25519(pubkey) => PublicKey::from_inner(PubKeyInner::new(
            KeyVersion::V4,
            PublicKeyAlgorithm::EdDSALegacy,
            created_at,
            None,
            PublicParams::EdDSALegacy(pgp::types::EddsaLegacyPublicParams::Ed25519 {
                key: VerifyingKey::from_bytes(&pubkey[..].try_into().map_err(to_rpgp_error)?)
                    .map_err(to_rpgp_error)?,
            }),
        )?)?,

        RawPublicKey::P256(pubkey) => ecdsa_to_public_key(
            created_at,
            EcdsaPublicParams::P256 {
                key: p256::PublicKey::from_sec1_bytes(&pubkey)?,
            },
        )?,

        RawPublicKey::P384(pubkey) => ecdsa_to_public_key(
            created_at,
            EcdsaPublicParams::P384 {
                key: p384::PublicKey::from_sec1_bytes(&pubkey)?,
            },
        )?,

        RawPublicKey::P521(pubkey) => ecdsa_to_public_key(
            created_at,
            EcdsaPublicParams::P521 {
                key: p521::PublicKey::from_sec1_bytes(&pubkey)?,
            },
        )?,
    })
}

/// Extracts certificate (public key) from an OpenPGP TSK.
///
/// # Errors
///
/// Returns an error if
///
/// - a secret key cannot be decoded from `key_data`,
/// - or writing a serialized certificate into a vector fails.
pub fn extract_certificate(key_data: &[u8]) -> Result<Vec<u8>, Error> {
    let key = SignedSecretKey::from_bytes(key_data)?;
    let public: SignedPublicKey = key.into();
    let mut buffer = vec![];
    public.to_writer(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64, Encoding as _};
    use pgp::types::{EcdsaPublicParams, PublicParams};
    use testresult::TestResult;

    use super::*;

    #[test]
    fn convert_ed25519_to_pgp() -> TestResult {
        let hsm_key = RawPublicKey::Ed25519(vec![
            252, 224, 232, 104, 60, 215, 247, 16, 227, 167, 29, 139, 125, 29, 3, 8, 136, 29, 198,
            163, 167, 117, 143, 109, 186, 65, 5, 45, 80, 142, 109, 10,
        ]);

        let pgp_key = hsm_pk_to_pgp_pk(hsm_key, DateTime::UNIX_EPOCH)?;
        let PublicParams::EdDSALegacy(pgp::types::EddsaLegacyPublicParams::Ed25519 { key }) =
            pgp_key.public_params()
        else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            key.to_bytes(),
            [
                252, 224, 232, 104, 60, 215, 247, 16, 227, 167, 29, 139, 125, 29, 3, 8, 136, 29,
                198, 163, 167, 117, 143, 109, 186, 65, 5, 45, 80, 142, 109, 10
            ]
        );

        Ok(())
    }

    #[test]
    fn convert_p256_to_pgp() -> TestResult {
        let hsm_key = RawPublicKey::P256(vec![
            4, 222, 106, 236, 96, 145, 243, 13, 81, 181, 119, 76, 5, 29, 72, 112, 134, 130, 169,
            182, 231, 247, 107, 204, 228, 178, 45, 77, 196, 91, 117, 122, 57, 69, 240, 240, 134,
            114, 138, 232, 63, 45, 141, 102, 164, 169, 118, 214, 99, 215, 138, 122, 89, 2, 180, 2,
            237, 15, 248, 104, 83, 142, 22, 185, 133,
        ]);
        let pgp_key = hsm_pk_to_pgp_pk(hsm_key, DateTime::UNIX_EPOCH)?;
        let PublicParams::ECDSA(EcdsaPublicParams::P256 { key, .. }) = pgp_key.public_params()
        else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            key.to_sec1_bytes().to_vec(),
            [
                4, 222, 106, 236, 96, 145, 243, 13, 81, 181, 119, 76, 5, 29, 72, 112, 134, 130,
                169, 182, 231, 247, 107, 204, 228, 178, 45, 77, 196, 91, 117, 122, 57, 69, 240,
                240, 134, 114, 138, 232, 63, 45, 141, 102, 164, 169, 118, 214, 99, 215, 138, 122,
                89, 2, 180, 2, 237, 15, 248, 104, 83, 142, 22, 185, 133
            ]
        );

        Ok(())
    }

    #[test]
    fn convert_p384_to_pgp() -> TestResult {
        let hsm_key = RawPublicKey::P384(vec![
            4, 127, 136, 147, 111, 187, 191, 131, 84, 166, 118, 67, 76, 107, 52, 142, 175, 72, 250,
            64, 197, 76, 154, 162, 48, 211, 135, 63, 153, 60, 213, 168, 40, 41, 111, 8, 8, 66, 117,
            221, 162, 244, 233, 210, 205, 206, 70, 64, 116, 30, 98, 186, 88, 17, 8, 75, 151, 252,
            123, 98, 182, 40, 183, 6, 28, 110, 29, 53, 15, 90, 227, 116, 185, 82, 134, 134, 6, 17,
            117, 218, 83, 181, 230, 154, 106, 235, 244, 112, 227, 231, 139, 217, 90, 220, 239, 191,
            148,
        ]);
        let pgp_key = hsm_pk_to_pgp_pk(hsm_key, DateTime::UNIX_EPOCH)?;
        let PublicParams::ECDSA(EcdsaPublicParams::P384 { key, .. }) = pgp_key.public_params()
        else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            key.to_sec1_bytes().to_vec(),
            [
                4, 127, 136, 147, 111, 187, 191, 131, 84, 166, 118, 67, 76, 107, 52, 142, 175, 72,
                250, 64, 197, 76, 154, 162, 48, 211, 135, 63, 153, 60, 213, 168, 40, 41, 111, 8, 8,
                66, 117, 221, 162, 244, 233, 210, 205, 206, 70, 64, 116, 30, 98, 186, 88, 17, 8,
                75, 151, 252, 123, 98, 182, 40, 183, 6, 28, 110, 29, 53, 15, 90, 227, 116, 185, 82,
                134, 134, 6, 17, 117, 218, 83, 181, 230, 154, 106, 235, 244, 112, 227, 231, 139,
                217, 90, 220, 239, 191, 148
            ]
        );

        Ok(())
    }

    #[test]
    fn convert_p521_to_pgp() -> TestResult {
        let hsm_key = RawPublicKey::P521(vec![
            4, 1, 33, 39, 193, 238, 201, 51, 127, 12, 24, 192, 161, 112, 247, 31, 184, 211, 118,
            95, 147, 192, 236, 9, 222, 214, 138, 194, 173, 170, 248, 123, 1, 138, 201, 96, 102, 55,
            160, 212, 150, 101, 58, 235, 53, 50, 30, 47, 136, 171, 244, 138, 236, 26, 190, 40, 157,
            208, 63, 92, 170, 195, 182, 80, 114, 205, 253, 1, 211, 88, 102, 243, 67, 14, 159, 46,
            35, 89, 188, 38, 134, 184, 208, 223, 213, 206, 126, 106, 33, 76, 198, 240, 32, 108, 48,
            124, 170, 158, 30, 4, 11, 37, 233, 254, 171, 163, 153, 10, 65, 118, 233, 79, 179, 90,
            185, 21, 71, 99, 21, 47, 223, 100, 224, 196, 110, 102, 113, 26, 103, 127, 234, 47, 81,
        ]);
        let pgp_key = hsm_pk_to_pgp_pk(hsm_key, DateTime::UNIX_EPOCH)?;
        let PublicParams::ECDSA(EcdsaPublicParams::P521 { key, .. }) = pgp_key.public_params()
        else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            key.to_sec1_bytes().to_vec(),
            [
                4, 1, 33, 39, 193, 238, 201, 51, 127, 12, 24, 192, 161, 112, 247, 31, 184, 211,
                118, 95, 147, 192, 236, 9, 222, 214, 138, 194, 173, 170, 248, 123, 1, 138, 201, 96,
                102, 55, 160, 212, 150, 101, 58, 235, 53, 50, 30, 47, 136, 171, 244, 138, 236, 26,
                190, 40, 157, 208, 63, 92, 170, 195, 182, 80, 114, 205, 253, 1, 211, 88, 102, 243,
                67, 14, 159, 46, 35, 89, 188, 38, 134, 184, 208, 223, 213, 206, 126, 106, 33, 76,
                198, 240, 32, 108, 48, 124, 170, 158, 30, 4, 11, 37, 233, 254, 171, 163, 153, 10,
                65, 118, 233, 79, 179, 90, 185, 21, 71, 99, 21, 47, 223, 100, 224, 196, 110, 102,
                113, 26, 103, 127, 234, 47, 81
            ]
        );

        Ok(())
    }

    #[test]
    fn convert_rsa_to_pgp() -> TestResult {
        let hsm_key = RawPublicKey::Rsa {
            modulus: vec![
                227, 127, 58, 151, 86, 130, 213, 238, 13, 247, 122, 241, 51, 227, 105, 143, 231,
                114, 208, 33, 152, 209, 109, 207, 53, 179, 147, 4, 100, 99, 238, 212, 196, 126, 89,
                4, 151, 106, 177, 219, 21, 187, 147, 41, 158, 242, 194, 208, 67, 252, 177, 135, 34,
                120, 154, 170, 63, 130, 4, 125, 56, 55, 239, 99, 43, 115, 198, 196, 191, 159, 243,
                13, 103, 7, 64, 76, 96, 184, 64, 48, 99, 62, 254, 248, 179, 254, 117, 156, 47, 224,
                100, 122, 189, 87, 59, 216, 171, 118, 230, 23, 71, 180, 88, 216, 151, 69, 61, 233,
                231, 118, 104, 126, 107, 245, 8, 16, 207, 4, 64, 235, 172, 154, 183, 50, 175, 142,
                223, 228, 199, 243, 251, 171, 220, 227, 140, 130, 243, 113, 216, 32, 224, 195, 4,
                53, 88, 100, 150, 221, 114, 19, 55, 215, 164, 102, 154, 35, 254, 31, 28, 195, 17,
                100, 207, 153, 99, 155, 40, 2, 45, 27, 87, 116, 213, 171, 205, 82, 70, 91, 113,
                185, 47, 242, 115, 246, 199, 82, 124, 77, 173, 201, 191, 62, 223, 93, 136, 84, 82,
                121, 239, 55, 47, 71, 40, 42, 2, 73, 18, 215, 91, 152, 32, 252, 110, 161, 166, 211,
                232, 130, 124, 74, 148, 156, 126, 169, 109, 26, 197, 55, 142, 32, 11, 43, 33, 81,
                87, 159, 8, 247, 82, 148, 149, 119, 160, 141, 69, 81, 223, 81, 49, 21, 205, 30, 0,
                59, 161, 187,
            ],
            exponent: vec![1, 0, 1],
        };
        let pgp_key = hsm_pk_to_pgp_pk(hsm_key, DateTime::UNIX_EPOCH)?;
        let PublicParams::RSA(public) = pgp_key.public_params() else {
            panic!("Wrong type of public params");
        };
        assert_eq!(public.key.e().to_bytes_be(), [1, 0, 1]);
        assert_eq!(
            public.key.n().to_bytes_be(),
            [
                227, 127, 58, 151, 86, 130, 213, 238, 13, 247, 122, 241, 51, 227, 105, 143, 231,
                114, 208, 33, 152, 209, 109, 207, 53, 179, 147, 4, 100, 99, 238, 212, 196, 126, 89,
                4, 151, 106, 177, 219, 21, 187, 147, 41, 158, 242, 194, 208, 67, 252, 177, 135, 34,
                120, 154, 170, 63, 130, 4, 125, 56, 55, 239, 99, 43, 115, 198, 196, 191, 159, 243,
                13, 103, 7, 64, 76, 96, 184, 64, 48, 99, 62, 254, 248, 179, 254, 117, 156, 47, 224,
                100, 122, 189, 87, 59, 216, 171, 118, 230, 23, 71, 180, 88, 216, 151, 69, 61, 233,
                231, 118, 104, 126, 107, 245, 8, 16, 207, 4, 64, 235, 172, 154, 183, 50, 175, 142,
                223, 228, 199, 243, 251, 171, 220, 227, 140, 130, 243, 113, 216, 32, 224, 195, 4,
                53, 88, 100, 150, 221, 114, 19, 55, 215, 164, 102, 154, 35, 254, 31, 28, 195, 17,
                100, 207, 153, 99, 155, 40, 2, 45, 27, 87, 116, 213, 171, 205, 82, 70, 91, 113,
                185, 47, 242, 115, 246, 199, 82, 124, 77, 173, 201, 191, 62, 223, 93, 136, 84, 82,
                121, 239, 55, 47, 71, 40, 42, 2, 73, 18, 215, 91, 152, 32, 252, 110, 161, 166, 211,
                232, 130, 124, 74, 148, 156, 126, 169, 109, 26, 197, 55, 142, 32, 11, 43, 33, 81,
                87, 159, 8, 247, 82, 148, 149, 119, 160, 141, 69, 81, 223, 81, 49, 21, 205, 30, 0,
                59, 161, 187
            ]
        );

        Ok(())
    }

    #[test]
    fn private_key_import_ed25199_is_correctly_zero_padded() -> TestResult {
        let mut key_data = vec![];
        SignedSecretKey::from_armor_single(std::fs::File::open(
            "tests/fixtures/ed25519-key-with-31-byte-private-key-scalar.asc",
        )?)?
        .0
        .to_writer(&mut key_data)?;

        let import: nethsm_sdk_rs::models::KeyPrivateData =
            tsk_to_private_key_import(&key_data)?.0.into();

        let data = Base64::decode_vec(&import.data.unwrap())?;

        // data needs to be zero-padded for NetHSM import even if the
        // input is *not* zero-padded
        assert_eq!(data.len(), 32);
        assert_eq!(data[0], 0x00);

        Ok(())
    }

    #[test]
    fn private_key_import_rsa_key_with_nonstandard_moduli_is_read_correctly() -> TestResult {
        let mut key_data = vec![];
        SignedSecretKey::from_armor_single(std::fs::File::open(
            "tests/fixtures/rsa-key-with-modulus-e-257.asc",
        )?)?
        .0
        .to_writer(&mut key_data)?;

        let import: nethsm_sdk_rs::models::KeyPrivateData =
            tsk_to_private_key_import(&key_data)?.0.into();

        let data = Base64::decode_vec(&import.public_exponent.unwrap())?;

        // this key used a non-standard modulus (e) of 257
        assert_eq!(data, vec![0x01, 0x01]); // 257 in hex

        Ok(())
    }
}
