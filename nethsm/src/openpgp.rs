//! OpenPGP-related functions.

use std::{backtrace::Backtrace, fmt::Debug};

use base64ct::{Base64, Encoding as _};
use chrono::{DateTime, Utc};
use digest::DynDigest;
use ed25519_dalek::VerifyingKey;
use log::{error, warn};
use pgp::{
    composed::{
        ArmorOptions,
        Deserializable as _,
        SignedPublicKey,
        SignedSecretKey,
        StandaloneSignature,
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
use picky_asn1_der::Asn1DerError;
use rsa::BigUint;
use rsa::traits::PublicKeyParts as _;
use sha2::digest::Digest as _;
use signstar_crypto::openpgp::{OpenPgpKeyUsageFlags, OpenPgpUserId, OpenPgpVersion};

use crate::{
    KeyMechanism,
    KeyType,
    NetHsm,
    PrivateKeyImport,
    key_type_matches_length,
    openpgp_nethsm::{NetHsmKey, signing_mode},
};

/// An error that may occur when working with OpenPGP data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Base64 encoded string can not be decode
    #[error("Decoding Base64 string failed: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// Certificate for the key has not been initialized
    #[error("Certificate for the key \"{0}\" has not been initialized")]
    CertificateMissing(crate::KeyId),

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

    /// The key format used is unsupported
    #[error("Unsupported key format: {public_params:?}")]
    UnsupportedKeyFormat {
        /// The unsupported public key parameters.
        public_params: Box<PublicParams>,
    },

    /// A signstar_crypto key  error.
    #[error("A signstar_crypto key error:\n{0}")]
    SignstarCryptoKey(#[from] signstar_crypto::key::Error),

    /// An ASN.1 serialization error.
    #[error("ASN.1 serialization failed while {context}:\n{source}")]
    Asn1Der {
        /// The context in which a ASN.1 error occurred.
        ///
        /// This is meant to complete the sentence "ASN.1 serialization failed
        /// while ".
        context: &'static str,
        /// The source error.
        source: Asn1DerError,
    },

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

/// Low-level signer interface
pub trait RawSigner {
    /// Sign a digest.
    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error>;
}

/// PGP-adapter for a NetHSM key.
///
/// All PGP-related operations executed on objects of this type will be forwarded to
/// the NetHSM instance.
struct HsmKey<'a, 'b> {
    public_key: PublicKey,
    raw_signer: &'a dyn RawSigner,
    key_id: &'b crate::KeyId,
}

impl Debug for HsmKey<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmKey")
            .field("public_key", &self.public_key)
            .field("key_id", &self.key_id)
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

impl<'a, 'b> HsmKey<'a, 'b> {
    /// Creates a new remote signing key which will use `key_id` key for signing.
    fn new(raw_signer: &'a dyn RawSigner, public_key: PublicKey, key_id: &'b crate::KeyId) -> Self {
        Self {
            raw_signer,
            public_key,
            key_id,
        }
    }
}

impl pgp::types::KeyDetails for HsmKey<'_, '_> {
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

impl SecretKeyTrait for HsmKey<'_, '_> {
    /// Creates a data signature.
    ///
    /// # Note
    ///
    /// The [`NetHsm`] in use is expected to be unlocked and configured to use a user in the
    /// [`Operator`][`crate::UserRole::Operator`] role with access to the signing key.
    /// Using a [`Password`] is not necessary as the operation deals with unencrypted cryptographic
    /// key material.
    ///
    /// # Errors
    ///
    /// Returns an error if
    /// - the key uses unsupported parameters (e.g. brainpool curves),
    /// - digest serialization fails (e.g. ASN1 encoding of digest for RSA signatures),
    /// - NetHSM `sign_digest` call fails,
    /// - parsing of signature returned from the NetHSM fails.
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
            return Err(to_rpgp_error(Error::UnsupportedMultipleComponentKeys)); // FIXME: unsupported hash
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

/// Generates an OpenPGP certificate for the given NetHSM key.
pub fn add_certificate(
    nethsm: &NetHsm,
    flags: OpenPgpKeyUsageFlags,
    key_id: &crate::KeyId,
    user_id: OpenPgpUserId,
    created_at: DateTime<Utc>,
    version: OpenPgpVersion,
) -> Result<Vec<u8>, Error> {
    let public_key = nethsm.get_key(key_id).map_err(to_rpgp_error)?;
    let signing_mode = signing_mode(public_key.r#type);
    let public_key = hsm_pk_to_pgp_pk(public_key, created_at)?;
    let raw_signer = NetHsmKey::new(nethsm, signing_mode, key_id);
    let signer = HsmKey::new(&raw_signer, public_key.clone(), key_id);
    add_certificate_with_signer(public_key, flags, user_id, version, signer)
}

/// Generates an OpenPGP certificate for the given signer.
pub fn add_certificate_with_signer(
    public_key: PublicKey,
    flags: OpenPgpKeyUsageFlags,
    user_id: OpenPgpUserId,
    version: OpenPgpVersion,
    signer: impl SecretKeyTrait,
) -> Result<Vec<u8>, Error> {
    if version != OpenPgpVersion::V4 {
        unimplemented!(
            "Support for creating OpenPGP {version} certificates is not yet implemented!"
        );
    }

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
/// Returns an [`Error::Pgp`] if creating a [`PrivateKeyImport`] from `key_data` is not
/// possible.
///
/// Returns an [`crate::Error::Key`] if `key_data` is an RSA public key and is shorter than
/// [`signstar_crypto::key::MIN_RSA_BIT_LENGTH`].
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
            )
            .map_err(to_rpgp_error)?;

            let (_d, p, q, _u) = secret.to_bytes();

            (
                PrivateKeyImport::from_rsa(p, q, public.key.e().to_bytes_be().to_vec()),
                KeyMechanism::RsaSignaturePkcs1,
            )
        }
        (PlainSecretParams::ECDSA(secret_key), _) => {
            let ec = if let PublicParams::ECDSA(pp) = key.primary_key.public_key().public_params() {
                match pp {
                    EcdsaPublicParams::P256 { .. } => crate::KeyType::EcP256,
                    EcdsaPublicParams::P384 { .. } => crate::KeyType::EcP384,
                    EcdsaPublicParams::P521 { .. } => crate::KeyType::EcP521,
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
            PrivateKeyImport::from_raw_bytes(crate::KeyType::Curve25519, bytes.as_bytes())
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

/// Generates an OpenPGP signature using a given NetHSM key for the message.
///
/// Signs the message `message` using the key identified by `key_id`
/// and returns a binary [OpenPGP data signature].
///
/// This call requires using a user in the [`Operator`][`crate::UserRole::Operator`] [role], which
/// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
/// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
///
/// ## Namespaces
///
/// * [`Operator`][`crate::UserRole::Operator`] users in a [namespace] only have access to keys in
///   their own [namespace].
/// * System-wide [`Operator`][`crate::UserRole::Operator`] users only have access to system-wide
///   keys.
///
/// # Errors
///
/// Returns an [`crate::Error::Api`] if creating an [OpenPGP signature] for the hasher state fails:
/// * the NetHSM is not in [`Operational`][`crate::SystemState::Operational`] [state]
/// * no key identified by `key_id` exists on the NetHSM
/// * the [`Operator`][`crate::UserRole::Operator`] user does not have access to the key (e.g.
///   different [namespace])
/// * the [`Operator`][`crate::UserRole::Operator`] user does not carry a tag matching one of the
///   key tags
/// * the used [`Credentials`][`crate::Credentials`] are not correct
/// * the used [`Credentials`][`crate::Credentials`] are not those of a user in the
///   [`Operator`][`crate::UserRole::Operator`] [role]
/// * the certificate for a given key has not been generated or is invalid
/// * subpacket lengths exceed maximum values
/// * hashing signed data fails
/// * signature creation using the NetHSM fails
/// * constructing OpenPGP signature from parts fails
/// * writing the signature to vector fails
///
/// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
/// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
/// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
/// [role]: https://docs.nitrokey.com/nethsm/administration#roles
/// [state]: https://docs.nitrokey.com/nethsm/administration#state
pub fn sign(nethsm: &NetHsm, key_id: &crate::KeyId, message: &[u8]) -> Result<Vec<u8>, Error> {
    let Some(public_key) = nethsm.get_key_certificate(key_id).map_err(to_rpgp_error)? else {
        return Err(Error::CertificateMissing(key_id.clone()));
    };

    let pk = nethsm.get_key(key_id).map_err(to_rpgp_error)?;
    let signing_mode = signing_mode(pk.r#type);

    let public_key = SignedPublicKey::from_bytes(&*public_key)?.primary_key;
    let raw_signer = NetHsmKey::new(nethsm, signing_mode, key_id);
    let signer = HsmKey::new(&raw_signer, public_key, key_id);

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
/// Signs the hasher `state` using the key identified by `key_id`
/// and returns a binary [OpenPGP data signature].
///
/// This call requires using a user in the [`Operator`][`crate::UserRole::Operator`] [role], which
/// carries a tag (see [`add_user_tag`][`NetHsm::add_user_tag`]) matching one of the tags of
/// the targeted key (see [`add_key_tag`][`NetHsm::add_key_tag`]).
///
/// ## Namespaces
///
/// * [`Operator`][`crate::UserRole::Operator`] users in a [namespace] only have access to keys in
///   their own [namespace].
/// * System-wide [`Operator`][`crate::UserRole::Operator`] users only have access to system-wide
///   keys.
///
/// # Errors
///
/// Returns an [`crate::Error::Api`] if creating an [OpenPGP signature] for the hasher state fails:
/// * the NetHSM is not in [`Operational`][`crate::SystemState::Operational`] [state]
/// * no key identified by `key_id` exists on the NetHSM
/// * the [`Operator`][`crate::UserRole::Operator`] user does not have access to the key (e.g.
///   different [namespace])
/// * the [`Operator`][`crate::UserRole::Operator`] user does not carry a tag matching one of the
///   key tags
/// * the used [`Credentials`][`crate::Credentials`] are not correct
/// * the used [`Credentials`][`crate::Credentials`] are not those of a user in the
///   [`Operator`][`crate::UserRole::Operator`] [role]
///
/// [OpenPGP signature]: https://openpgp.dev/book/signing_data.html
/// [OpenPGP data signature]: https://openpgp.dev/book/signing_data.html
/// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
/// [role]: https://docs.nitrokey.com/nethsm/administration#roles
/// [state]: https://docs.nitrokey.com/nethsm/administration#state
pub fn sign_hasher_state(
    nethsm: &NetHsm,
    key_id: &crate::KeyId,
    state: sha2::Sha512,
) -> Result<String, Error> {
    let Some(public_key) = nethsm.get_key_certificate(key_id).map_err(to_rpgp_error)? else {
        return Err(Error::CertificateMissing(key_id.clone()));
    };

    let pk = nethsm.get_key(key_id).map_err(to_rpgp_error)?;
    let signing_mode = signing_mode(pk.r#type);
    let public_key = SignedPublicKey::from_bytes(public_key.as_slice())?.primary_key;
    let raw_signer = NetHsmKey::new(nethsm, signing_mode, key_id);
    let signer = HsmKey::new(&raw_signer, public_key, key_id);

    sign_hasher_state_with_signer(state, &signer)
}

/// XXX
pub fn sign_hasher_state_with_signer(
    state: sha2::Sha512,
    signer: &dyn SecretKeyTrait,
) -> Result<String, Error> {
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

    let signature = StandaloneSignature { signature };
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

/// Converts base64-encoded data into a vector of bytes.
///
/// # Errors
///
/// Returns an error if
///
/// - `data` is [`None`],
/// - or `data` provides invalid base64 encoding.
fn data_to_bytes(data: Option<&str>) -> Result<Vec<u8>, Error> {
    Ok(Base64::decode_vec(data.ok_or(Error::KeyData(
        "missing EC public key data".into(),
    ))?)?)
}

/// Converts NetHSM public key to OpenPGP public key.
///
/// Since OpenPGP public keys have a date of creation (which is used
/// for fingerprint calculation) this is an additional, explicit
/// parameter.
fn hsm_pk_to_pgp_pk(
    pk: nethsm_sdk_rs::models::PublicKey,
    created_at: DateTime<Utc>,
) -> Result<PublicKey, Error> {
    let public = &pk
        .public
        .ok_or(Error::KeyData("missing public key data".into()))?;

    let key_type: KeyType = pk.r#type.try_into()?;
    Ok(match key_type {
        KeyType::Rsa => PublicKey::from_inner(PubKeyInner::new(
            KeyVersion::V4,
            PublicKeyAlgorithm::RSA,
            created_at,
            None,
            PublicParams::RSA(RsaPublicParams {
                key: rsa::RsaPublicKey::new(
                    BigUint::from_bytes_be(&Base64::decode_vec(
                        public
                            .modulus
                            .as_ref()
                            .ok_or(Error::KeyData("missing RSA modulus".into()))?,
                    )?),
                    BigUint::from_bytes_be(&Base64::decode_vec(
                        public
                            .public_exponent
                            .as_ref()
                            .ok_or(Error::KeyData("missing RSA exponent".into()))?,
                    )?),
                )
                .map_err(to_rpgp_error)?,
            }),
        )?)?,

        KeyType::Curve25519 => {
            let pubkey: &[u8] = &data_to_bytes(public.data.as_deref())?;

            PublicKey::from_inner(PubKeyInner::new(
                KeyVersion::V4,
                PublicKeyAlgorithm::EdDSALegacy,
                created_at,
                None,
                PublicParams::EdDSALegacy(pgp::types::EddsaLegacyPublicParams::Ed25519 {
                    key: VerifyingKey::from_bytes(pubkey.try_into().map_err(to_rpgp_error)?)
                        .map_err(to_rpgp_error)?,
                }),
            )?)?
        }

        KeyType::EcP256 => ecdsa_to_public_key(
            created_at,
            EcdsaPublicParams::P256 {
                key: p256::PublicKey::from_sec1_bytes(&data_to_bytes(public.data.as_deref())?)?,
            },
        )?,
        KeyType::EcP384 => ecdsa_to_public_key(
            created_at,
            EcdsaPublicParams::P384 {
                key: p384::PublicKey::from_sec1_bytes(&data_to_bytes(public.data.as_deref())?)?,
            },
        )?,
        KeyType::EcP521 => ecdsa_to_public_key(
            created_at,
            EcdsaPublicParams::P521 {
                key: p521::PublicKey::from_sec1_bytes(&data_to_bytes(public.data.as_deref())?)?,
            },
        )?,

        _ => {
            warn!("Unsupported key type: {key_type}");
            return Err(pgp::errors::Error::InvalidInput {
                backtrace: Some(Backtrace::capture()),
            })?;
        }
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
    use nethsm_sdk_rs::models::{KeyMechanism, KeyPublicData, KeyRestrictions, KeyType};
    use pgp::types::{EcdsaPublicParams, PublicParams};
    use testresult::TestResult;

    use super::*;

    #[test]
    fn convert_ed25519_to_pgp() -> TestResult {
        let hsm_key = nethsm_sdk_rs::models::PublicKey {
            mechanisms: vec![KeyMechanism::EdDsaSignature],
            r#type: KeyType::Curve25519,
            restrictions: Box::new(KeyRestrictions {
                tags: Some(vec!["signing1".into()]),
            }),
            public: Some(Box::new(KeyPublicData {
                modulus: None,
                public_exponent: None,
                data: Some("/ODoaDzX9xDjpx2LfR0DCIgdxqOndY9tukEFLVCObQo=".into()),
            })),
            operations: 1,
        };

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
        let hsm_key = nethsm_sdk_rs::models::PublicKey {
            mechanisms: vec![KeyMechanism::EcdsaSignature],
            r#type: KeyType::EcP256,
            restrictions: Box::new(KeyRestrictions {
                tags: Some(vec!["signing2".into()]),
            }),
            public: Some(Box::new(KeyPublicData {
                modulus: None,
                public_exponent: None,
                data: Some(
                    "BN5q7GCR8w1RtXdMBR1IcIaCqbbn92vM5LItTcRbdXo5RfDwhnKK6D8tjWakqXbWY9eKelkCtALtD/hoU44WuYU="
                        .into(),
                ),
            })),
            operations: 1,
        };
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
        let hsm_key = nethsm_sdk_rs::models::PublicKey {
            mechanisms: vec![KeyMechanism::EcdsaSignature],
            r#type: KeyType::EcP384,
            restrictions: Box::new(KeyRestrictions {
                tags: Some(vec!["signing2".into()]),
            }),
            public: Some(Box::new(KeyPublicData {
                modulus: None,
                public_exponent: None,
                data: Some(
                    "BH+Ik2+7v4NUpnZDTGs0jq9I+kDFTJqiMNOHP5k81agoKW8ICEJ13aL06dLNzkZAdB5iulgRCEuX/Htitii3BhxuHTUPWuN0uVKGhgYRddpTteaaauv0cOPni9la3O+/lA=="
                        .into(),
                ),
            })),
            operations: 3,
        };
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
        let hsm_key = nethsm_sdk_rs::models::PublicKey {
            mechanisms: vec![KeyMechanism::EcdsaSignature],
            r#type: KeyType::EcP521,
            restrictions: Box::new(KeyRestrictions {
                tags: Some(vec!["signing2".into()]),
            }),
            public: Some(Box::new(KeyPublicData {
                modulus: None,
                public_exponent: None,
                data: Some(
                    "BAEhJ8HuyTN/DBjAoXD3H7jTdl+TwOwJ3taKwq2q+HsBislgZjeg1JZlOus1Mh4viKv0iuwaviid0D9cqsO2UHLN/QHTWGbzQw6fLiNZvCaGuNDf1c5+aiFMxvAgbDB8qp4eBAsl6f6ro5kKQXbpT7NauRVHYxUv32TgxG5mcRpnf+ovUQ=="
                        .into(),
                ),
            })),
            operations: 2,
        };
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
        let hsm_key = nethsm_sdk_rs::models::PublicKey {
            mechanisms: vec![KeyMechanism::RsaSignaturePkcs1],
            r#type: KeyType::Rsa,
            restrictions: Box::new(KeyRestrictions {
                tags: Some(vec!["signing8".into()]) }),
                public: Some(Box::new(KeyPublicData {
                    modulus: Some("4386l1aC1e4N93rxM+Npj+dy0CGY0W3PNbOTBGRj7tTEflkEl2qx2xW7kyme8sLQQ/yxhyJ4mqo/ggR9ODfvYytzxsS/n/MNZwdATGC4QDBjPv74s/51nC/gZHq9VzvYq3bmF0e0WNiXRT3p53Zofmv1CBDPBEDrrJq3Mq+O3+TH8/ur3OOMgvNx2CDgwwQ1WGSW3XITN9ekZpoj/h8cwxFkz5ljmygCLRtXdNWrzVJGW3G5L/Jz9sdSfE2tyb8+312IVFJ57zcvRygqAkkS11uYIPxuoabT6IJ8SpScfqltGsU3jiALKyFRV58I91KUlXegjUVR31ExFc0eADuhuw==".into()),
                    public_exponent: Some("AQAB".into()),
                    data: None })),
            operations: 2 };
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
