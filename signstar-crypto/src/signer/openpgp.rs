//! OpenPGP signer interface.

use std::{backtrace::Backtrace, io::Cursor};

use digest::DynDigest;
use ed25519_dalek::VerifyingKey;
use log::{error, warn};
// Publicly re-export `pgp` facilities, used in the API of `signstar_crypto::signer::openpgp`.
pub use pgp::composed::{Deserializable, SignedSecretKey};
pub use pgp::types::Timestamp;
use pgp::{
    composed::{ArmorOptions, DetachedSignature, SignedPublicKey},
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
        PublicParams,
        RsaPublicParams,
        SecretParams,
        SignatureBytes,
        SigningKey as RpgpSigningKey,
    },
};
use rsa::BigUint;
use rsa::traits::PublicKeyParts as _;
use sha2::digest::Digest as _;

use crate::{
    key::{KeyMechanism, KeyType, PrivateKeyImport, key_type_matches_length},
    openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId, OpenPgpVersion},
    signer::{
        error::Error,
        traits::{RawPublicKey, RawSigningKey},
    },
};

/// PGP-adapter for a [raw HSM key][RawSigningKey].
///
/// All PGP-related operations executed on objects of this type will be forwarded to
/// the HSM instance.
struct SigningKey<'a> {
    public_key: PublicKey,
    raw_signer: &'a dyn RawSigningKey,
}

impl std::fmt::Debug for SigningKey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
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

impl<'a> SigningKey<'a> {
    /// Creates a new [`SigningKey`] from a [`RawSigningKey`] implementation and a [`PublicKey`].
    fn new(raw_signer: &'a dyn RawSigningKey, public_key: PublicKey) -> Self {
        Self {
            raw_signer,
            public_key,
        }
    }

    /// Creates a new [`SigningKey`] from a [`RawSigningKey`] implementation.
    ///
    /// The [`RawSigningKey`] implementation is expected to already have a certificate setup for
    /// itself.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - retrieval of the certificate from `raw_signer` fails
    /// - parsing of the certificate retrieved fails
    /// - the certificate is missing  ([`Error::OpenPpgCertificateMissing`])
    fn new_provisioned(raw_signer: &'a dyn RawSigningKey) -> Result<Self, Error> {
        let public_key = if let Some(cert) = raw_signer.certificate()?.as_ref() {
            SignedPublicKey::from_bytes(Cursor::new(cert))?.primary_key
        } else {
            return Err(Error::OpenPpgCertificateMissing);
        };
        Ok(Self::new(raw_signer, public_key))
    }
}

impl pgp::types::KeyDetails for SigningKey<'_> {
    fn version(&self) -> KeyVersion {
        self.public_key.version()
    }

    fn fingerprint(&self) -> pgp::types::Fingerprint {
        self.public_key.fingerprint()
    }

    fn legacy_key_id(&self) -> KeyId {
        self.public_key.legacy_key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }

    fn created_at(&self) -> Timestamp {
        self.public_key.created_at()
    }

    fn legacy_v3_expiration_days(&self) -> Option<u16> {
        self.public_key.legacy_v3_expiration_days()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

impl RpgpSigningKey for SigningKey<'_> {
    /// Creates a data signature.
    ///
    /// # Note
    ///
    /// If `self` targets an HSM, it is expected to be unlocked and configured with access to the
    /// signing key.
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
    fn sign(
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
    /// We always return SHA-512 as it is faster than SHA-256 on modern hardware and of
    /// sufficient size to accommodate all elliptic-curve algorithms.
    fn hash_alg(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

/// Generates an OpenPGP certificate for a [`RawSigningKey`] implementation.
///
/// # Errors
///
/// Returns an error if
///
/// - conversion of the HSM public key to OpenPGP public key fails
/// - signing the certificate with the HSM key fails
/// - writing the resulting certificate to buffer fails
pub fn add_certificate(
    raw_signer: &dyn RawSigningKey,
    flags: OpenPgpKeyUsageFlags,
    user_id: OpenPgpUserId,
    created_at: Timestamp,
    version: OpenPgpVersion,
) -> Result<Vec<u8>, Error> {
    if version != OpenPgpVersion::V4 {
        return Err(crate::openpgp::Error::InvalidOpenPgpVersion(version.to_string()).into());
    }
    let public_key = raw_signer.public()?.to_openpgp_public_key(created_at)?;
    let signer = SigningKey::new(raw_signer, public_key.clone());

    let signed_pk = SignedPublicKey {
        details: pgp::composed::KeyDetails::new(
            Some(UserId::from_str(Default::default(), user_id.as_ref())?),
            vec![],
            vec![],
            flags.into(),
            Default::default(),
            Default::default(),
            Default::default(),
            vec![CompressionAlgorithm::Uncompressed].into(),
            vec![].into(),
        )
        .sign(rand::thread_rng(), &signer, &public_key, &Password::empty())?,
        primary_key: public_key,
        public_subkeys: vec![],
    };

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
    key: &SignedSecretKey,
) -> Result<(PrivateKeyImport, KeyMechanism), Error> {
    if !key.secret_subkeys.is_empty() {
        return Err(Error::OpenPgpTskContainsMultipleComponentKeys {
            fingerprint: key.fingerprint(),
        });
    }
    let SecretParams::Plain(secret) = key.primary_key.secret_params() else {
        return Err(Error::OpenPgpTskIsPassphraseProtected {
            fingerprint: key.fingerprint(),
        });
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
                            context: "converting ECDSA key to private key import",
                            public_params: Box::new(key.public_key().public_params().clone()),
                        })?;
                    }
                }
            } else {
                return Err(Error::UnsupportedKeyFormat {
                    context: "converting non-ECDSA key to private key import",
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
                        context: "converting unsupported ECDSA key to private key import",
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
                context: "converting unknown key format to private key import",
                public_params: Box::new(public_params.clone()),
            });
        }
    })
}

/// Generates an OpenPGP signature using a [`RawSigningKey`] implementation.
///
/// Signs the message `message` using the [`RawSigningKey`] and returns a binary [OpenPGP data
/// signature].
///
/// # Errors
///
/// Returns an [`Error`] if creating an [OpenPGP signature] for the hasher state fails:
///
/// - the certificate for a given key has not been generated or is invalid
/// - subpacket lengths exceed maximum values
/// - hashing signed data fails
/// - signature creation using a [`RawSigningKey`] implementation fails
/// - constructing OpenPGP signature from parts fails
/// - writing the signature to vector fails
///
/// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
/// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
pub fn sign(raw_signer: &dyn RawSigningKey, message: &[u8]) -> Result<Vec<u8>, Error> {
    let signer = SigningKey::new_provisioned(raw_signer)?;

    let mut sig_config =
        SignatureConfig::v4(SignatureType::Binary, signer.algorithm(), signer.hash_alg());
    sig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
        Subpacket::regular(SubpacketData::IssuerKeyId(signer.legacy_key_id()))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint()))?,
    ];

    let mut hasher = sig_config.hash_alg.new_hasher().map_err(to_rpgp_error)?;
    sig_config.hash_data_to_sign(&mut hasher, message)?;

    let len = sig_config.hash_signature_data(&mut hasher)?;

    hasher.update(&sig_config.trailer(len)?);

    let hash = &hasher.finalize()[..];

    let signed_hash_value = [hash[0], hash[1]];
    let raw_sig = signer.sign(&Password::empty(), sig_config.hash_alg, hash)?;

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
///
/// - the certificate for a given key has not been generated or is invalid
/// - subpacket lengths exceed maximum values
/// - hashing signed data fails
/// - signature creation using the HSM fails
/// - constructing OpenPGP signature from parts fails
/// - writing the signature to vector fails
///
/// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
/// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
pub fn sign_hasher_state(
    raw_signer: &dyn RawSigningKey,
    state: sha2::Sha512,
) -> Result<String, Error> {
    let signer = SigningKey::new_provisioned(raw_signer)?;
    let hasher = state.clone();

    let file_hash = Box::new(hasher).finalize().to_vec();

    let sig_config = {
        let mut sig_config =
            SignatureConfig::v4(SignatureType::Binary, signer.algorithm(), signer.hash_alg());
        sig_config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now()))?,
            Subpacket::regular(SubpacketData::IssuerKeyId(signer.legacy_key_id()))?,
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

    let raw_sig = signer.sign(&Password::empty(), sig_config.hash_alg, hash)?;

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
fn ecdsa_to_public_key(created_at: Timestamp, key: EcdsaPublicParams) -> Result<PublicKey, Error> {
    Ok(PublicKey::from_inner(PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::ECDSA,
        created_at,
        None,
        PublicParams::ECDSA(key),
    )?)?)
}

impl RawPublicKey {
    /// Converts [raw public key][RawPublicKey] to OpenPGP public key packet.
    ///
    /// OpenPGP public keys have a date of creation, which is e.g. used
    /// for fingerprint calculation.
    /// This date of creation needs to be passed in specifically using
    /// the `created_at` parameter.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - creation of modulus or exponent fails (in case of RSA keys)
    /// - public key is of wrong size (in case of ed25519 keys)
    /// - decoding ECDSA public key fails (in case of NIST curves)
    /// - rpgp fails when encoding raw packet lengths
    fn to_openpgp_public_key(&self, created_at: Timestamp) -> Result<PublicKey, Error> {
        Ok(match self {
            RawPublicKey::Rsa { modulus, exponent } => PublicKey::from_inner(PubKeyInner::new(
                KeyVersion::V4,
                PublicKeyAlgorithm::RSA,
                created_at,
                None,
                PublicParams::RSA(RsaPublicParams {
                    key: rsa::RsaPublicKey::new(
                        BigUint::from_bytes_be(modulus),
                        BigUint::from_bytes_be(exponent),
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
                    key: p256::PublicKey::from_sec1_bytes(pubkey)?,
                },
            )?,

            RawPublicKey::P384(pubkey) => ecdsa_to_public_key(
                created_at,
                EcdsaPublicParams::P384 {
                    key: p384::PublicKey::from_sec1_bytes(pubkey)?,
                },
            )?,

            RawPublicKey::P521(pubkey) => ecdsa_to_public_key(
                created_at,
                EcdsaPublicParams::P521 {
                    key: p521::PublicKey::from_sec1_bytes(pubkey)?,
                },
            )?,
        })
    }
}

/// Extracts an OpenPGP certificate from an OpenPGP private key.
///
/// The bytes in `key_data` are expected to contain valid OpenPGP private key data.
/// From this a [`SignedSecretKey`] is created and a [`SignedPublicKey`] exported, which is returned
/// as bytes vector.
///
/// # Errors
///
/// Returns an error if
///
/// - a secret key cannot be decoded from `key_data`,
/// - or writing a serialized certificate into a vector fails.
pub fn extract_certificate(key: SignedSecretKey) -> Result<Vec<u8>, Error> {
    let public: SignedPublicKey = key.into();
    let mut buffer = vec![];
    public.to_writer(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use pgp::{
        composed::SecretKeyParamsBuilder,
        crypto::ecc_curve::ECCCurve,
        types::{EcdsaPublicParams, PublicParams},
    };
    use rand::RngCore;
    use rsa::rand_core::OsRng;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn convert_ed25519_to_pgp() -> TestResult {
        let hsm_key = RawPublicKey::Ed25519(vec![
            252, 224, 232, 104, 60, 215, 247, 16, 227, 167, 29, 139, 125, 29, 3, 8, 136, 29, 198,
            163, 167, 117, 143, 109, 186, 65, 5, 45, 80, 142, 109, 10,
        ]);

        let pgp_key = hsm_key.to_openpgp_public_key(Timestamp::now())?;
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
        let pgp_key = hsm_key.to_openpgp_public_key(Timestamp::now())?;
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
        let pgp_key = hsm_key.to_openpgp_public_key(Timestamp::now())?;
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
        let pgp_key = hsm_key.to_openpgp_public_key(Timestamp::now())?;
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
        let pgp_key = hsm_key.to_openpgp_public_key(Timestamp::now())?;
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

    /// Tests specific to the NetHSM backend.
    #[cfg(feature = "nethsm")]
    mod nethsm {
        use std::fs::File;

        use base64ct::{Base64, Encoding as _};
        use nethsm_sdk_rs::models::KeyPrivateData;

        use super::*;

        #[test]
        fn private_key_import_ed25199_is_correctly_zero_padded() -> TestResult {
            let key = SignedSecretKey::from_armor_single(File::open(
                "tests/fixtures/ed25519-key-with-31-byte-private-key-scalar.asc",
            )?)?
            .0;

            let import: KeyPrivateData = tsk_to_private_key_import(&key)?.0.into();

            let data = Base64::decode_vec(&import.data.unwrap())?;

            // data needs to be zero-padded for NetHSM import even if the
            // input is *not* zero-padded
            assert_eq!(data.len(), 32);
            assert_eq!(data[0], 0x00);

            Ok(())
        }

        #[test]
        #[cfg(feature = "nethsm")]
        fn private_key_import_rsa_key_with_nonstandard_moduli_is_read_correctly() -> TestResult {
            let key = SignedSecretKey::from_armor_single(File::open(
                "tests/fixtures/rsa-key-with-modulus-e-257.asc",
            )?)?
            .0;

            let import: KeyPrivateData = tsk_to_private_key_import(&key)?.0.into();

            let data = Base64::decode_vec(&import.public_exponent.unwrap())?;

            // this key used a non-standard modulus (e) of 257
            assert_eq!(data, vec![0x01, 0x01]); // 257 in hex

            Ok(())
        }
    }

    /// Software ed25519 key.
    struct Ed25519SoftKey {
        /// Backing software key.
        signing_key: SigningKey,

        /// OpenPGP certificate associated with the software key, if present.
        certificate: Option<Vec<u8>>,
    }

    impl Ed25519SoftKey {
        /// Generates a new software ed25519 key for signing.
        ///
        /// The `certificate` is unset ([`None`]).
        fn new() -> Self {
            Self {
                // ed25519-dalek does not re-export rand_core so reusing rsa one
                // which is maintained by the same Rust Crypto team
                signing_key: SigningKey::generate(&mut OsRng),
                certificate: None,
            }
        }
    }

    impl RawSigningKey for Ed25519SoftKey {
        /// Returns a static string "Software key".
        fn key_id(&self) -> String {
            "Software key".into()
        }

        /// Sign a `digest` and return signature parts `R` and `s` (in this order).
        ///
        /// # Errors
        ///
        /// This implementation never fails.
        fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
            let signature = self.signing_key.sign(digest);
            Ok(vec![signature.r_bytes().into(), signature.s_bytes().into()])
        }

        /// Return certificate associated with this software key.
        ///
        /// # Errors
        ///
        /// This implementation never fails.
        fn certificate(&self) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.certificate.clone())
        }

        /// Return [raw public key][RawPublicKey] associated with this signing key.
        ///
        /// # Errors
        ///
        /// This implementation never fails.
        fn public(&self) -> Result<RawPublicKey, Error> {
            Ok(RawPublicKey::Ed25519(
                self.signing_key.verifying_key().to_bytes().into(),
            ))
        }
    }

    #[test]
    fn sign_dummy() -> TestResult {
        let mut raw_signer = Ed25519SoftKey::new();

        let cert = add_certificate(
            &raw_signer,
            Default::default(),
            OpenPgpUserId::new("test".into())?,
            Timestamp::now(),
            Default::default(),
        )?;

        raw_signer.certificate = Some(cert);

        let mut data_to_sign = [0; 32];
        OsRng::fill_bytes(&mut OsRng, &mut data_to_sign);

        let signature = sign(&raw_signer, &data_to_sign)?;
        assert!(!signature.is_empty());

        Ok(())
    }

    #[rstest::rstest]
    #[case::p256(ECCCurve::P256, KeyType::EcP256)]
    #[case::p384(ECCCurve::P384, KeyType::EcP384)]
    #[case::p521(ECCCurve::P521, KeyType::EcP521)]
    fn import_ecdsa(#[case] pgp_curve: ECCCurve, #[case] expected_type: KeyType) -> TestResult {
        let params = SecretKeyParamsBuilder::default()
            .key_type(pgp::composed::KeyType::ECDSA(pgp_curve))
            .can_sign(true)
            .build()?;

        let rng = rsa::rand_core::OsRng;

        let key = params.generate(rng)?;
        let actual_type = tsk_to_private_key_import(&key)?.0.key_type();
        assert_eq!(actual_type, expected_type);

        Ok(())
    }

    #[test]
    fn test_unsupported_ecdsa_curve() -> TestResult {
        let key = SecretKeyParamsBuilder::default()
            .key_type(pgp::composed::KeyType::ECDSA(ECCCurve::Secp256k1))
            .can_sign(true)
            .build()?
            .generate(rsa::rand_core::OsRng)?;

        assert!(tsk_to_private_key_import(&key).is_err());

        Ok(())
    }
}
