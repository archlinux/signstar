//! OpenPGP-related functions.

use std::{
    borrow::{Borrow, Cow},
    collections::HashSet,
    fmt::{Debug, Display},
    str::FromStr,
};

use base64ct::{Base64, Encoding as _};
use chrono::{DateTime, Utc};
use email_address::{EmailAddress, Options};
use pgp::{
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{
        KeyFlags,
        Notation,
        PublicKey,
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
        EskType,
        KeyId,
        KeyVersion,
        Mpi,
        PkeskBytes,
        PlainSecretParams,
        PublicKeyTrait,
        PublicParams,
        SecretKeyTrait,
        SecretParams,
        SignatureBytes,
        Version,
    },
    Deserializable,
    KeyDetails,
    SignedPublicKey,
    SignedSecretKey,
};
use picky_asn1_x509::{
    signature::EcdsaSignatureValue,
    AlgorithmIdentifier,
    DigestInfo,
    ShaVariant,
};
use rand::prelude::{CryptoRng, Rng};

use crate::{key_type_matches_length, KeyMechanism, KeyType, NetHsm, PrivateKeyImport};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Base64 encoded string can not be decode
    #[error("Decoding Base64 string failed: {0}")]
    Base64Decode(#[from] base64ct::Error),

    /// Elliptic curve error
    #[error("Elliptic curve error: {0}")]
    EllipticCurve(#[from] p256::elliptic_curve::Error),

    /// Duplicate OpenPGP User ID
    #[error("The OpenPGP User ID {user_id} is used more than once!")]
    DuplicateUserId { user_id: OpenPgpUserId },

    /// Provided OpenPGP version is invalid
    #[error("Invalid OpenPGP version: {0}")]
    InvalidOpenPgpVersion(String),

    /// Provided key data is invalid
    #[error("Key data invalid: {0}")]
    KeyData(String),

    /// NetHsm error
    #[error("NetHSM error: {0}")]
    NetHsm(String),

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
    UnsupportedKeyFormat { public_params: Box<PublicParams> },

    /// The User ID is too large
    #[error("The OpenPGP User ID is too large: {user_id}")]
    UserIdTooLarge { user_id: String },
}

/// The OpenPGP version
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    serde::Deserialize,
    strum::Display,
    strum::EnumIter,
    Hash,
    strum::IntoStaticStr,
    Eq,
    PartialEq,
    serde::Serialize,
)]
#[serde(into = "String", try_from = "String")]
pub enum OpenPgpVersion {
    /// OpenPGP version 4 as defined in [RFC 4880]
    ///
    /// [RFC 4880]: https://www.rfc-editor.org/rfc/rfc4880.html
    #[default]
    #[strum(to_string = "4")]
    V4,

    /// OpenPGP version 6 as defined in [RFC 9580]
    ///
    /// [RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
    #[strum(to_string = "6")]
    V6,
}

impl AsRef<str> for OpenPgpVersion {
    fn as_ref(&self) -> &str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
}

impl FromStr for OpenPgpVersion {
    type Err = Error;

    /// Creates an [`OpenPgpVersion`] from a string slice
    ///
    /// Only valid OpenPGP versions are considered:
    /// * [RFC 4880] aka "v4"
    /// * [RFC 9580] aka "v6"
    ///
    /// # Errors
    ///
    /// Returns an error if the provided string slice does not represent a valid OpenPGP version.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use nethsm::OpenPgpVersion;
    ///
    /// # fn main() -> testresult::TestResult {
    /// assert_eq!(OpenPgpVersion::from_str("4")?, OpenPgpVersion::V4);
    /// assert_eq!(OpenPgpVersion::from_str("6")?, OpenPgpVersion::V6);
    ///
    /// assert!(OpenPgpVersion::from_str("5").is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [RFC 4880]: https://www.rfc-editor.org/rfc/rfc4880.html
    /// [RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "4" | "v4" | "V4" | "OpenPGPv4" => Ok(Self::V4),
            "5" | "v5" | "V5" | "OpenPGPv5" => Err(Error::InvalidOpenPgpVersion(format!(
                "{s} (\"we don't do these things around here\")"
            ))),
            "6" | "v6" | "V6" | "OpenPGPv6" => Ok(Self::V6),
            _ => Err(Error::InvalidOpenPgpVersion(s.to_string())),
        }
    }
}

impl From<OpenPgpVersion> for String {
    fn from(value: OpenPgpVersion) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for OpenPgpVersion {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

/// A distinction between types of OpenPGP User IDs
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
enum OpenPgpUserIdType {
    /// An OpenPGP User ID that contains a valid e-mail address (e.g. "John Doe
    /// <john@example.org>")
    ///
    /// The e-mail address must use a top-level domain (TLD) and no domain literal (e.g. an IP
    /// address) is allowed.
    Email(EmailAddress),

    /// A plain OpenPGP User ID
    ///
    /// The User ID may contain any UTF-8 character, but does not represent a valid e-mail address.
    Plain(String),
}

/// A basic representation of a User ID for OpenPGP
///
/// While [OpenPGP User IDs] are loosely defined to be UTF-8 strings, they do not enforce
/// particular rules around the use of e-mail addresses or their general length.
/// This type allows to distinguish between plain UTF-8 strings and valid e-mail addresses.
/// Valid e-mail addresses must provide a display part, use a top-level domain (TLD) and not rely on
/// domain literals (e.g. IP address).
/// The length of a User ID is implicitly limited by the maximum length of an OpenPGP packet (8192
/// bytes).
/// As such, this type only allows a maximum length of 4096 bytes as middle ground.
///
/// [OpenPGP User IDs]: https://www.rfc-editor.org/rfc/rfc9580.html#name-user-id-packet-type-id-13
#[derive(Clone, Debug, serde::Deserialize, Hash, Eq, PartialEq, serde::Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct OpenPgpUserId(OpenPgpUserIdType);

impl OpenPgpUserId {
    /// Creates a new [`OpenPgpUserId`] from a String
    ///
    /// # Errors
    ///
    /// Returns an [`Error::Key`][`crate::Error::Key`] if the chars of the provided String exceed
    /// 4096 bytes. This ensures to stay below the valid upper limit defined by the maximum OpenPGP
    /// packet size of 8192 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use nethsm::OpenPgpUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// assert!(!OpenPgpUserId::new("🤡".to_string())?.is_email());
    ///
    /// assert!(OpenPgpUserId::new("🤡 <foo@xn--rl8h.org>".to_string())?.is_email());
    ///
    /// // an e-mail without a display name is not considered a valid e-mail
    /// assert!(!OpenPgpUserId::new("<foo@xn--rl8h.org>".to_string())?.is_email());
    ///
    /// // this fails because the provided String is too long
    /// assert!(OpenPgpUserId::new("U".repeat(4097)).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_id: String) -> Result<Self, Error> {
        if user_id.len() > 4096 {
            return Err(Error::UserIdTooLarge { user_id });
        }
        if let Ok(email) = EmailAddress::parse_with_options(
            &user_id,
            Options::default()
                .with_required_tld()
                .without_domain_literal(),
        ) {
            Ok(Self(OpenPgpUserIdType::Email(email)))
        } else {
            Ok(Self(OpenPgpUserIdType::Plain(user_id)))
        }
    }

    /// Returns whether the [`OpenPgpUserId`] is a valid e-mail address
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::OpenPgpUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// assert!(!OpenPgpUserId::new("🤡".to_string())?.is_email());
    ///
    /// assert!(OpenPgpUserId::new("🤡 <foo@xn--rl8h.org>".to_string())?.is_email());
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_email(&self) -> bool {
        matches!(self.0, OpenPgpUserIdType::Email(..))
    }
}

impl AsRef<str> for OpenPgpUserId {
    fn as_ref(&self) -> &str {
        match self.0.borrow() {
            OpenPgpUserIdType::Email(user_id) => user_id.as_str(),
            OpenPgpUserIdType::Plain(user_id) => user_id.as_str(),
        }
    }
}

impl Display for OpenPgpUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl FromStr for OpenPgpUserId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl From<OpenPgpUserId> for String {
    fn from(value: OpenPgpUserId) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for OpenPgpUserId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A list of [`OpenPgpUserId`]
///
/// The items of the list are guaranteed to be unique.
#[derive(Clone, Debug, serde::Deserialize, Hash, Eq, PartialEq, serde::Serialize)]
#[serde(into = "Vec<String>", try_from = "Vec<String>")]
pub struct OpenPgpUserIdList(Vec<OpenPgpUserId>);

impl OpenPgpUserIdList {
    /// Creates a new [`OpenPgpUserIdList`]
    ///
    /// # Errors
    ///
    /// Returns an error, if one of the provided [`OpenPgpUserId`]s is a duplicate.
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::OpenPgpUserIdList;
    ///
    /// # fn main() -> testresult::TestResult {
    /// OpenPgpUserIdList::new(vec![
    ///     "🤡 <foo@xn--rl8h.org>".parse()?,
    ///     "🤡 <bar@xn--rl8h.org>".parse()?,
    /// ])?;
    ///
    /// // this fails because the two OpenPgpUserIds are the same
    /// assert!(OpenPgpUserIdList::new(vec![
    ///     "🤡 <foo@xn--rl8h.org>".parse()?,
    ///     "🤡 <foo@xn--rl8h.org>".parse()?,
    /// ])
    /// .is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_ids: Vec<OpenPgpUserId>) -> Result<Self, Error> {
        let mut set = HashSet::new();
        for user_id in user_ids.iter() {
            if !set.insert(user_id) {
                return Err(Error::DuplicateUserId {
                    user_id: user_id.to_owned(),
                });
            }
        }
        Ok(Self(user_ids))
    }

    pub fn iter(&self) -> impl Iterator<Item = &OpenPgpUserId> {
        self.0.iter()
    }
}

impl AsRef<[OpenPgpUserId]> for OpenPgpUserIdList {
    fn as_ref(&self) -> &[OpenPgpUserId] {
        &self.0
    }
}

impl From<OpenPgpUserIdList> for Vec<String> {
    fn from(value: OpenPgpUserIdList) -> Self {
        value
            .iter()
            .map(|user_id| user_id.to_string())
            .collect::<Vec<String>>()
    }
}

impl TryFrom<Vec<String>> for OpenPgpUserIdList {
    type Error = Error;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let user_ids = {
            let mut user_ids: Vec<OpenPgpUserId> = vec![];
            for user_id in value {
                user_ids.push(OpenPgpUserId::new(user_id)?)
            }
            user_ids
        };
        OpenPgpUserIdList::new(user_ids)
    }
}

/// PGP-adapter for a NetHSM key.
///
/// All PGP-related operations executed on objects of this type will be forwarded to
/// the NetHSM instance.
struct HsmKey<'a, 'b> {
    public_key: PublicKey,
    nethsm: &'a NetHsm,
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

/// Parse signature bytes into algorithm-specific vector of MPIs.
fn parse_signature(sig_type: crate::SignatureType, sig: &[u8]) -> pgp::errors::Result<Vec<Mpi>> {
    use crate::SignatureType::*;
    Ok(match sig_type {
        EcdsaP256 | EcdsaP384 | EcdsaP521 => {
            let sig: EcdsaSignatureValue =
                picky_asn1_der::from_bytes(sig).map_err(|_| pgp::errors::Error::InvalidInput)?;
            vec![
                Mpi::from_slice(sig.r.as_unsigned_bytes_be()),
                Mpi::from_slice(sig.s.as_unsigned_bytes_be()),
            ]
        }
        EdDsa => {
            if sig.len() != 64 {
                return Err(pgp::errors::Error::InvalidKeyLength);
            }

            vec![Mpi::from_slice(&sig[..32]), Mpi::from_slice(&sig[32..])]
        }
        Pkcs1 => {
            // RSA
            vec![Mpi::from_slice(sig)]
        }
        param => {
            return Err(pgp::errors::Error::Unsupported(format!(
                "Unsupoprted key type: {param:?}"
            )))
        }
    })
}

impl<'a, 'b> HsmKey<'a, 'b> {
    /// Creates a new remote signing key which will use `key_id` key for signing.
    fn new(nethsm: &'a NetHsm, public_key: PublicKey, key_id: &'b crate::KeyId) -> Self {
        Self {
            nethsm,
            public_key,
            key_id,
        }
    }

    /// Returns correct mode to use for signatures which depend on the public key.
    fn sign_mode(&self) -> pgp::errors::Result<crate::SignatureType> {
        Ok(match self.public_key.public_params() {
            PublicParams::ECDSA(ecdsa) => match ecdsa {
                EcdsaPublicParams::P256 { .. } => crate::SignatureType::EcdsaP256,
                EcdsaPublicParams::P384 { .. } => crate::SignatureType::EcdsaP384,
                EcdsaPublicParams::P521 { .. } => crate::SignatureType::EcdsaP521,
                param => {
                    return Err(pgp::errors::Error::Unsupported(format!(
                        "Unsupported EC key type: {param:?}"
                    )))
                }
            },
            PublicParams::EdDSALegacy { .. } => crate::SignatureType::EdDsa,
            PublicParams::RSA { .. } => crate::SignatureType::Pkcs1,
            param => {
                return Err(pgp::errors::Error::Unsupported(format!(
                    "Unsupported key type: {param:?}"
                )))
            }
        })
    }
}

impl PublicKeyTrait for HsmKey<'_, '_> {
    fn verify_signature(
        &self,
        hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        esk_type: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        self.public_key.encrypt(rng, plain, esk_type)
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        self.public_key.serialize_for_hashing(writer)
    }

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

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.public_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.public_key.expiration()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

/// Transforms the raw digest data for cryptographic signing.
///
/// Raw cryptographic signing primitives have special provisions that
/// need to be taken care of when using certain combinations of
/// signing schemes and hashing algorithms.
///
/// This function transforms the digest into bytes that are ready to
/// be passed to raw cryptographic functions. The exact specifics of
/// the transformations are documented inside the function.
fn prepare_digest_data(
    signature_type: crate::SignatureType,
    hash: HashAlgorithm,
    digest: &[u8],
) -> pgp::errors::Result<Cow<'_, [u8]>> {
    Ok(match signature_type {
        // RSA-PKCS#1 signing scheme needs to wrap the digest value
        // in an DER-encoded ASN.1 DigestInfo structure which captures
        // the hash used.
        // See: https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4
        crate::SignatureType::Pkcs1 => picky_asn1_der::to_vec(&DigestInfo {
            oid: hash_to_oid(hash)?,
            digest: digest.to_vec().into(),
        })
        .map_err(|_| pgp::errors::Error::InvalidInput)?
        .into(),

        // ECDSA may need to truncate the digest if it's too long
        // See: https://www.rfc-editor.org/rfc/rfc9580#section-5.2.3.2
        crate::SignatureType::EcdsaP224 => digest[..usize::min(28, digest.len())].into(),
        crate::SignatureType::EcdsaP256 => digest[..usize::min(32, digest.len())].into(),
        crate::SignatureType::EcdsaP384 => digest[..usize::min(48, digest.len())].into(),

        // All other schemes that we use will not need any kind of
        // digest transformations.
        _ => digest.into(),
    })
}

impl SecretKeyTrait for HsmKey<'_, '_> {
    type PublicKey = PublicKey;

    type Unlocked = Self;

    fn unlock<F, G, T>(&self, _pw: F, work: G) -> pgp::errors::Result<T>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> pgp::errors::Result<T>,
    {
        work(self)
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        hash: HashAlgorithm,
        data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        let signature_type = self.sign_mode()?;
        let request_data = prepare_digest_data(signature_type, hash, data)?;

        let sig = self
            .nethsm
            .sign_digest(self.key_id, signature_type, &request_data)
            .map_err(|_| pgp::errors::Error::InvalidInput)?;

        Ok(parse_signature(signature_type, &sig)?.into())
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn hash_alg(&self) -> HashAlgorithm {
        HashAlgorithm::SHA2_512
    }
}

/// Generates an OpenPGP certificate for the given NetHSM key.
pub fn add_certificate(
    nethsm: &NetHsm,
    flags: KeyUsageFlags,
    key_id: &crate::KeyId,
    user_id: OpenPgpUserId,
    created_at: DateTime<Utc>,
    version: OpenPgpVersion,
) -> Result<Vec<u8>, crate::Error> {
    if version != OpenPgpVersion::V4 {
        unimplemented!(
            "Support for creating OpenPGP {version} certificates is not yet implemented!"
        );
    }

    let public_key = nethsm.get_key(key_id)?;
    let signer = HsmKey::new(nethsm, hsm_pk_to_pgp_pk(public_key, created_at)?, key_id);
    let mut keyflags: KeyFlags = flags.into();
    // the primary key always need to be certifying
    keyflags.set_certify(true);

    let composed_pk = pgp::PublicKey::new(
        signer.public_key(),
        KeyDetails::new(
            UserId::from_str(Default::default(), user_id.as_ref()),
            vec![],
            vec![],
            keyflags,
            Default::default(),
            Default::default(),
            vec![CompressionAlgorithm::Uncompressed].into(),
            vec![].into(),
            None,
        ),
        vec![],
    );
    let signed_pk = composed_pk
        .sign(rand::thread_rng(), &signer, String::new)
        .map_err(Error::Pgp)?;
    let mut buffer = vec![];
    signed_pk.to_writer(&mut buffer).map_err(Error::Pgp)?;
    Ok(buffer)
}

/// Converts OpenPGP hash algorithm into an OID form for PKCS#1 signing.
fn hash_to_oid(hash: HashAlgorithm) -> pgp::errors::Result<AlgorithmIdentifier> {
    Ok(AlgorithmIdentifier::new_sha(match hash {
        HashAlgorithm::SHA1 => ShaVariant::SHA1,
        HashAlgorithm::SHA2_256 => ShaVariant::SHA2_256,
        HashAlgorithm::SHA2_384 => ShaVariant::SHA2_384,
        HashAlgorithm::SHA2_512 => ShaVariant::SHA2_512,
        HashAlgorithm::SHA2_224 => ShaVariant::SHA2_224,
        HashAlgorithm::SHA3_256 => ShaVariant::SHA3_256,
        HashAlgorithm::SHA3_512 => ShaVariant::SHA3_512,
        hash => {
            return Err(pgp::errors::Error::Unsupported(format!(
                "Unsupported hash: {hash:?}"
            )))
        }
    }))
}

/// Converts an OpenPGP Transferable Secret Key into [`PrivateKeyImport`] object.
///
/// # Errors
///
/// Returns an [`crate::Error::OpenPgp`] if creating a [`PrivateKeyImport`] from `key_data` is not
/// possible.
///
/// Returns an [`crate::Error::Key`] if an RSA public key is shorter than
/// [`crate::MIN_RSA_BIT_LENGTH`].
pub fn tsk_to_private_key_import(
    key_data: &[u8],
) -> Result<(PrivateKeyImport, KeyMechanism), crate::Error> {
    let key = SignedSecretKey::from_bytes(key_data).map_err(Error::Pgp)?;
    if !key.secret_subkeys.is_empty() {
        return Err(crate::Error::OpenPgp(
            Error::UnsupportedMultipleComponentKeys,
        ));
    }
    let SecretParams::Plain(secret) = key.primary_key.secret_params() else {
        return Err(crate::Error::OpenPgp(Error::PrivateKeyPassphraseProtected));
    };
    Ok(match (secret, key.public_params()) {
        (PlainSecretParams::RSA { p, q, .. }, PublicParams::RSA { n, e }) => {
            // ensure, that we have sufficient bit length
            key_type_matches_length(KeyType::Rsa, Some(n.as_bytes().len() as u32 * 8))?;

            (
                PrivateKeyImport::from_rsa(
                    p.as_bytes().to_vec(),
                    q.as_bytes().to_vec(),
                    e.as_bytes().to_vec(),
                ),
                KeyMechanism::RsaSignaturePkcs1,
            )
        }
        (PlainSecretParams::ECDSA(bytes), _) => {
            let ec = if let PublicParams::ECDSA(pp) = key.primary_key.public_params() {
                match pp {
                    EcdsaPublicParams::P256 { .. } => crate::KeyType::EcP256,
                    EcdsaPublicParams::P384 { .. } => crate::KeyType::EcP384,
                    EcdsaPublicParams::P521 { .. } => crate::KeyType::EcP521,
                    _ => {
                        return Err(crate::Error::OpenPgp(Error::UnsupportedKeyFormat {
                            public_params: Box::new(key.public_params().clone()),
                        }))
                    }
                }
            } else {
                return Err(crate::Error::OpenPgp(Error::UnsupportedKeyFormat {
                    public_params: Box::new(key.public_params().clone()),
                }));
            };

            (
                PrivateKeyImport::from_raw_bytes(ec, bytes)?,
                KeyMechanism::EcdsaSignature,
            )
        }
        (PlainSecretParams::EdDSALegacy(bytes), _) => (
            PrivateKeyImport::from_raw_bytes(crate::KeyType::Curve25519, bytes)?,
            KeyMechanism::EdDsaSignature,
        ),
        (_, public_params) => {
            return Err(crate::Error::OpenPgp(Error::UnsupportedKeyFormat {
                public_params: Box::new(public_params.clone()),
            }))
        }
    })
}

/// Generates an OpenPGP signature using a given NetHSM key for the message.
pub fn sign(
    nethsm: &NetHsm,
    key_id: &crate::KeyId,
    message: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    let public_key = nethsm.get_key_certificate(key_id)?;

    let signer = HsmKey::new(
        nethsm,
        SignedPublicKey::from_bytes(&*public_key)
            .map_err(Error::Pgp)?
            .primary_key,
        key_id,
    );

    let mut sig_config =
        SignatureConfig::v4(SignatureType::Binary, signer.algorithm(), signer.hash_alg());
    sig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            std::time::SystemTime::now().into(),
        )),
        Subpacket::regular(SubpacketData::Issuer(signer.key_id())),
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint())),
    ];

    let mut hasher = sig_config.hash_alg.new_hasher().map_err(Error::Pgp)?;
    sig_config
        .hash_data_to_sign(&mut *hasher, message)
        .map_err(Error::Pgp)?;

    let len = sig_config
        .hash_signature_data(&mut hasher)
        .map_err(Error::Pgp)?;

    hasher.update(&sig_config.trailer(len).map_err(Error::Pgp)?);

    let hash = &hasher.finish()[..];

    let signed_hash_value = [hash[0], hash[1]];
    let raw_sig = signer
        .create_signature(String::new, sig_config.hash_alg, hash)
        .map_err(Error::Pgp)?;

    let signature = pgp::Signature::from_config(sig_config, signed_hash_value, raw_sig);

    let mut out = vec![];
    pgp::packet::write_packet(&mut out, &signature).map_err(Error::Pgp)?;

    Ok(out)
}

/// Generates an OpenPGP signature based on provided hasher state.
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
    state: impl sha2::Digest + Clone + std::io::Write,
) -> Result<Vec<u8>, crate::Error> {
    let public_key = nethsm.get_key_certificate(key_id)?;

    let signer = HsmKey::new(
        nethsm,
        SignedPublicKey::from_bytes(public_key.as_slice())
            .map_err(Error::Pgp)?
            .primary_key,
        key_id,
    );

    let hasher = state.clone();
    let file_hash = hasher.finalize();

    let sig_config = {
        let mut sig_config =
            SignatureConfig::v4(SignatureType::Binary, signer.algorithm(), signer.hash_alg());
        sig_config.hashed_subpackets = vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            Subpacket::regular(SubpacketData::Issuer(signer.key_id())),
            Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint())),
            Subpacket::regular(SubpacketData::Notation(Notation {
                readable: false,
                name: "data-digest@archlinux.org".into(),
                value: file_hash[..].into(),
            })),
        ];
        sig_config
    };

    let hasher = {
        let mut hasher = state.clone();
        let write: &mut dyn std::io::Write = &mut hasher;

        let len = sig_config.hash_signature_data(write).map_err(Error::Pgp)?;

        hasher.update(&sig_config.trailer(len).map_err(Error::Pgp)?);
        hasher
    };

    let hash = &hasher.finalize()[..];

    let signed_hash_value = [hash[0], hash[1]];

    let raw_sig = signer
        .create_signature(String::new, sig_config.hash_alg, hash)
        .map_err(Error::Pgp)?;

    let signature = pgp::Signature::from_config(sig_config, signed_hash_value, raw_sig);

    let out = {
        let mut out = vec![];
        pgp::packet::write_packet(&mut out, &signature).map_err(Error::Pgp)?;
        out
    };

    Ok(out)
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
    let public = pk
        .public
        .ok_or(Error::KeyData("missing public key data".into()))?;
    let key_type: KeyType = pk.r#type.into();
    Ok(match key_type {
        KeyType::Rsa => PublicKey::new(
            Version::New,
            KeyVersion::V4,
            PublicKeyAlgorithm::RSA,
            created_at,
            None,
            PublicParams::RSA {
                n: Mpi::from_raw(Base64::decode_vec(
                    &public
                        .modulus
                        .ok_or(Error::KeyData("missing RSA modulus".into()))?,
                )?),
                e: Mpi::from_raw(Base64::decode_vec(
                    &public
                        .public_exponent
                        .ok_or(Error::KeyData("missing RSA exponent".into()))?,
                )?),
            },
        )?,
        KeyType::Curve25519 => {
            let pubkey = Base64::decode_vec(
                &public
                    .data
                    .ok_or(Error::KeyData("missing ed25519 public key data".into()))?,
            )?;
            let mut bytes = vec![0x40];
            bytes.extend(pubkey);

            PublicKey::new(
                Version::New,
                KeyVersion::V4,
                PublicKeyAlgorithm::EdDSALegacy,
                created_at,
                None,
                PublicParams::EdDSALegacy {
                    curve: ECCCurve::Ed25519,
                    q: Mpi::from_raw(bytes),
                },
            )?
        }
        curve @ (KeyType::EcP256 | KeyType::EcP384 | KeyType::EcP521) => {
            let pubkey = Base64::decode_vec(
                &public
                    .data
                    .ok_or(Error::KeyData("missing EC public key data".into()))?,
            )?;
            let key = match curve {
                KeyType::EcP256 => EcdsaPublicParams::P256 {
                    key: p256::PublicKey::from_sec1_bytes(&pubkey)?,
                    p: Mpi::from_raw(pubkey),
                },
                KeyType::EcP384 => EcdsaPublicParams::P384 {
                    key: p384::PublicKey::from_sec1_bytes(&pubkey)?,
                    p: Mpi::from_raw(pubkey),
                },
                KeyType::EcP521 => EcdsaPublicParams::P521 {
                    key: p521::PublicKey::from_sec1_bytes(&pubkey)?,
                    p: Mpi::from_raw(pubkey),
                },
                _ => unreachable!(),
            };

            PublicKey::new(
                Version::New,
                KeyVersion::V4,
                PublicKeyAlgorithm::ECDSA,
                created_at,
                None,
                PublicParams::ECDSA(key),
            )?
        }

        _ => {
            return Err(pgp::errors::Error::Unsupported(
                "unsupported key type".into(),
            ))?
        }
    })
}

/// Extracts certificate (public key) from an OpenPGP TSK.
pub fn extract_certificate(key_data: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let key = SignedSecretKey::from_bytes(key_data).map_err(Error::Pgp)?;
    let public: SignedPublicKey = key.into();
    let mut buffer = vec![];
    public.to_writer(&mut buffer).map_err(Error::Pgp)?;
    Ok(buffer)
}

/// Key usage flags that can be set on the generated certificate.
#[derive(Default)]
pub struct KeyUsageFlags(KeyFlags);

impl KeyUsageFlags {
    /// Makes it possible for this key to issue data signatures.
    pub fn set_sign(&mut self) {
        self.0.set_sign(true);
    }

    /// Makes it impossible for this key to issue data signatures.
    pub fn clear_sign(&mut self) {
        self.0.set_sign(false);
    }
}

impl From<KeyUsageFlags> for KeyFlags {
    fn from(value: KeyUsageFlags) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use nethsm_sdk_rs::models::{KeyMechanism, KeyPublicData, KeyRestrictions, KeyType};
    use pgp::{
        crypto::ecc_curve::ECCCurve,
        types::{EcdsaPublicParams, PublicParams},
    };
    use rstest::rstest;
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
        let PublicParams::EdDSALegacy { curve, q } = pgp_key.public_params() else {
            panic!("Wrong type of public params");
        };
        assert_eq!(curve, &ECCCurve::Ed25519);
        assert_eq!(
            q.to_vec(),
            [
                64, 252, 224, 232, 104, 60, 215, 247, 16, 227, 167, 29, 139, 125, 29, 3, 8, 136,
                29, 198, 163, 167, 117, 143, 109, 186, 65, 5, 45, 80, 142, 109, 10
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
        let PublicParams::ECDSA(EcdsaPublicParams::P256 { p, .. }) = pgp_key.public_params() else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            p.to_vec(),
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
        let PublicParams::ECDSA(EcdsaPublicParams::P384 { p, .. }) = pgp_key.public_params() else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            p.to_vec(),
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
        let PublicParams::ECDSA(EcdsaPublicParams::P521 { p, .. }) = pgp_key.public_params() else {
            panic!("Wrong type of public params");
        };
        assert_eq!(
            p.to_vec(),
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
        let PublicParams::RSA { e, n } = pgp_key.public_params() else {
            panic!("Wrong type of public params");
        };
        assert_eq!(e.to_vec(), [1, 0, 1]);
        assert_eq!(
            n.to_vec(),
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
    fn parse_rsa_signature_produces_valid_data() -> TestResult {
        let sig = parse_signature(crate::SignatureType::Pkcs1, &[0, 1, 2])?;
        assert_eq!(sig.len(), 1);
        assert_eq!(&sig[0][..], &[1, 2]);

        Ok(())
    }

    #[test]
    fn parse_ed25519_signature_produces_valid_data() -> TestResult {
        let sig = parse_signature(
            crate::SignatureType::EdDsa,
            &[
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
            ],
        )?;
        assert_eq!(sig.len(), 2);
        assert_eq!(sig[0].as_bytes(), vec![2; 32]);
        assert_eq!(sig[1].as_bytes(), vec![1; 32]);

        Ok(())
    }

    #[test]
    fn parse_p256_signature_produces_valid_data() -> TestResult {
        let sig = parse_signature(
            crate::SignatureType::EcdsaP256,
            &[
                48, 70, 2, 33, 0, 193, 176, 219, 0, 133, 254, 212, 239, 236, 122, 85, 239, 73, 161,
                179, 53, 100, 172, 103, 45, 123, 21, 169, 28, 59, 150, 72, 92, 242, 9, 53, 143, 2,
                33, 0, 165, 1, 144, 97, 102, 109, 66, 50, 185, 234, 211, 150, 253, 228, 210, 126,
                26, 0, 189, 184, 230, 163, 36, 203, 232, 161, 12, 75, 121, 171, 45, 107,
            ],
        )?;
        assert_eq!(sig.len(), 2);
        assert_eq!(
            sig[0].as_bytes(),
            [
                193, 176, 219, 0, 133, 254, 212, 239, 236, 122, 85, 239, 73, 161, 179, 53, 100,
                172, 103, 45, 123, 21, 169, 28, 59, 150, 72, 92, 242, 9, 53, 143
            ]
        );
        assert_eq!(
            sig[1].as_bytes(),
            [
                165, 1, 144, 97, 102, 109, 66, 50, 185, 234, 211, 150, 253, 228, 210, 126, 26, 0,
                189, 184, 230, 163, 36, 203, 232, 161, 12, 75, 121, 171, 45, 107
            ]
        );

        Ok(())
    }

    #[test]
    fn parse_p384_signature_produces_valid_data() -> TestResult {
        let sig = parse_signature(
            crate::SignatureType::EcdsaP384,
            &[
                48, 101, 2, 49, 0, 134, 13, 108, 74, 135, 234, 174, 105, 208, 46, 109, 18, 77, 21,
                177, 59, 73, 150, 228, 26, 244, 134, 187, 217, 172, 34, 2, 1, 229, 123, 105, 202,
                132, 233, 72, 41, 243, 138, 127, 107, 135, 95, 139, 19, 121, 179, 170, 27, 2, 48,
                44, 80, 117, 90, 18, 137, 36, 190, 8, 60, 201, 235, 242, 168, 164, 245, 119, 136,
                207, 178, 237, 64, 117, 69, 218, 189, 209, 110, 2, 9, 191, 194, 70, 50, 227, 47, 6,
                34, 8, 135, 43, 188, 236, 192, 184, 227, 59, 40,
            ],
        )?;
        assert_eq!(sig.len(), 2);
        assert_eq!(
            sig[0].as_bytes(),
            [
                134, 13, 108, 74, 135, 234, 174, 105, 208, 46, 109, 18, 77, 21, 177, 59, 73, 150,
                228, 26, 244, 134, 187, 217, 172, 34, 2, 1, 229, 123, 105, 202, 132, 233, 72, 41,
                243, 138, 127, 107, 135, 95, 139, 19, 121, 179, 170, 27
            ]
        );
        assert_eq!(
            sig[1].as_bytes(),
            [
                44, 80, 117, 90, 18, 137, 36, 190, 8, 60, 201, 235, 242, 168, 164, 245, 119, 136,
                207, 178, 237, 64, 117, 69, 218, 189, 209, 110, 2, 9, 191, 194, 70, 50, 227, 47, 6,
                34, 8, 135, 43, 188, 236, 192, 184, 227, 59, 40
            ]
        );

        Ok(())
    }

    #[test]
    fn parse_p521_signature_produces_valid_data() -> TestResult {
        let sig = parse_signature(
            crate::SignatureType::EcdsaP521,
            &[
                48, 129, 136, 2, 66, 0, 203, 246, 21, 57, 217, 6, 101, 73, 103, 113, 98, 39, 223,
                246, 199, 136, 238, 213, 134, 163, 153, 151, 116, 237, 207, 181, 107, 183, 204,
                110, 97, 160, 95, 160, 193, 3, 219, 46, 105, 191, 0, 139, 124, 234, 90, 125, 114,
                115, 205, 109, 15, 193, 166, 100, 224, 108, 87, 143, 240, 65, 41, 93, 164, 166, 2,
                2, 66, 1, 203, 115, 121, 219, 49, 18, 3, 101, 130, 153, 95, 80, 27, 148, 249, 221,
                198, 251, 149, 118, 119, 32, 44, 160, 24, 125, 72, 161, 168, 71, 48, 138, 223, 200,
                37, 124, 234, 17, 237, 246, 13, 123, 102, 151, 83, 95, 186, 161, 112, 41, 158, 138,
                144, 55, 23, 110, 100, 185, 237, 13, 174, 83, 4, 153, 34,
            ],
        )?;
        assert_eq!(sig.len(), 2);
        assert_eq!(
            sig[0].as_bytes(),
            [
                203, 246, 21, 57, 217, 6, 101, 73, 103, 113, 98, 39, 223, 246, 199, 136, 238, 213,
                134, 163, 153, 151, 116, 237, 207, 181, 107, 183, 204, 110, 97, 160, 95, 160, 193,
                3, 219, 46, 105, 191, 0, 139, 124, 234, 90, 125, 114, 115, 205, 109, 15, 193, 166,
                100, 224, 108, 87, 143, 240, 65, 41, 93, 164, 166, 2
            ]
        );
        assert_eq!(
            sig[1].as_bytes(),
            [
                1, 203, 115, 121, 219, 49, 18, 3, 101, 130, 153, 95, 80, 27, 148, 249, 221, 198,
                251, 149, 118, 119, 32, 44, 160, 24, 125, 72, 161, 168, 71, 48, 138, 223, 200, 37,
                124, 234, 17, 237, 246, 13, 123, 102, 151, 83, 95, 186, 161, 112, 41, 158, 138,
                144, 55, 23, 110, 100, 185, 237, 13, 174, 83, 4, 153, 34
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

    #[test]
    fn rsa_digest_info_is_wrapped() -> TestResult {
        let data = prepare_digest_data(crate::SignatureType::Pkcs1, HashAlgorithm::SHA1, &[0; 20])?;

        assert_eq!(
            data,
            vec![
                48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );

        Ok(())
    }

    #[rstest]
    #[case(crate::SignatureType::EcdsaP224, 28)]
    #[case(crate::SignatureType::EcdsaP256, 32)]
    #[case(crate::SignatureType::EcdsaP384, 48)]
    #[case(crate::SignatureType::EcdsaP521, 64)]
    fn ecdsa_wrapped_up_to_max_len(
        #[case] sig_type: crate::SignatureType,
        #[case] max_len: usize,
        #[values(HashAlgorithm::SHA1, HashAlgorithm::SHA2_256, HashAlgorithm::SHA2_512)] hash_algo: HashAlgorithm,
    ) -> TestResult {
        // the digest value is irrelevant - just the size of the digest
        let digest = hash_algo.new_hasher()?.finish();
        let data = prepare_digest_data(sig_type, hash_algo, &digest)?;

        // The data to be signed size needs to be truncated to the value specific the the curve
        // being used. If the digest is short enough to be smaller than the curve specific field
        // size the digest is used as a whole.
        assert_eq!(
            data.len(), usize::min(max_len, digest.len()),
            "the data to be signed's length ({}) cannot exceed maximum length imposed by the curve ({})", data.len(), max_len
        );

        Ok(())
    }

    #[rstest]
    fn eddsa_is_not_wrapped(
        #[values(HashAlgorithm::SHA1, HashAlgorithm::SHA2_256, HashAlgorithm::SHA2_512)] hash_algo: HashAlgorithm,
    ) -> TestResult {
        // the digest value is irrelevant - just the size of the digest
        let digest = hash_algo.new_hasher()?.finish();

        let data = prepare_digest_data(crate::SignatureType::EdDsa, hash_algo, &digest)?;

        assert_eq!(data, digest);

        Ok(())
    }
}
