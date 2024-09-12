//! OpenPGP-related functions.

use std::fmt::Debug;

use base64ct::{Base64, Encoding as _};
use chrono::{DateTime, Utc};
use pgp::{
    crypto::{ecc_curve::ECCCurve, hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    packet::{
        KeyFlags,
        PublicKey,
        SignatureConfig,
        SignatureType,
        SignatureVersion,
        Subpacket,
        SubpacketData,
        UserId,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm,
        EcdsaPublicParams,
        KeyId,
        KeyTrait,
        KeyVersion,
        Mpi,
        PlainSecretParams,
        PublicKeyTrait,
        PublicParams,
        SecretKeyTrait,
        SecretParams,
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

/// Safely construct an MPI from a slice of bytes.
#[inline]
fn mpi(bytes: &[u8]) -> Mpi {
    // construct an MPI using a safe function which will correctly truncate
    // any leading zeros, see also: https://github.com/rpgp/rpgp/issues/401
    Mpi::from_raw_slice(bytes)
}

/// Parse signature bytes into algorithm-specific vector of MPIs.
fn parse_signature(sig_type: crate::SignatureType, sig: &[u8]) -> pgp::errors::Result<Vec<Mpi>> {
    use crate::SignatureType::*;
    Ok(match sig_type {
        EcdsaP256 | EcdsaP384 | EcdsaP521 => {
            let sig: EcdsaSignatureValue =
                picky_asn1_der::from_bytes(sig).map_err(|_| pgp::errors::Error::InvalidInput)?;
            vec![
                mpi(sig.r.as_unsigned_bytes_be()),
                mpi(sig.s.as_unsigned_bytes_be()),
            ]
        }
        EdDsa => {
            if sig.len() != 64 {
                return Err(pgp::errors::Error::InvalidKeyLength);
            }

            vec![mpi(&sig[..32]), mpi(&sig[32..])]
        }
        Pkcs1 => {
            // RSA
            vec![mpi(sig)]
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
            PublicParams::EdDSA { .. } => crate::SignatureType::EdDsa,
            PublicParams::RSA { .. } => crate::SignatureType::Pkcs1,
            param => {
                return Err(pgp::errors::Error::Unsupported(format!(
                    "Unsupported key type: {param:?}"
                )))
            }
        })
    }
}

impl KeyTrait for HsmKey<'_, '_> {
    fn fingerprint(&self) -> Vec<u8> {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }
}

impl PublicKeyTrait for HsmKey<'_, '_> {
    fn verify_signature(
        &self,
        hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
        sig: &[Mpi],
    ) -> pgp::errors::Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: &mut R,
        plain: &[u8],
    ) -> pgp::errors::Result<Vec<Mpi>> {
        self.public_key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        self.public_key.to_writer_old(writer)
    }
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
    ) -> pgp::errors::Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        let signature_type = self.sign_mode()?;
        // https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4
        let request_data = if signature_type == crate::SignatureType::Pkcs1 {
            let pdata = &picky_asn1_der::to_vec(&DigestInfo {
                oid: hash_to_oid(hash)?,
                digest: data.to_vec().into(),
            })
            .map_err(|_| pgp::errors::Error::InvalidInput)?;
            pdata.to_vec()
        } else {
            data.to_vec()
        };

        let sig = self
            .nethsm
            .sign_digest(self.key_id, signature_type, &request_data)
            .map_err(|_| pgp::errors::Error::InvalidInput)?;

        parse_signature(signature_type, &sig)
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }
}

/// Generates an OpenPGP certificate for the given NetHSM key.
pub fn add_certificate(
    nethsm: &NetHsm,
    flags: KeyUsageFlags,
    key_id: &crate::KeyId,
    user_id: &str,
    created_at: DateTime<Utc>,
) -> Result<Vec<u8>, crate::Error> {
    let public_key = nethsm.get_key(key_id)?;
    let signer = HsmKey::new(nethsm, hsm_pk_to_pgp_pk(public_key, created_at)?, key_id);
    let mut keyflags: KeyFlags = flags.into();
    // the primary key always need to be certifying
    keyflags.set_certify(true);

    let composed_pk = pgp::PublicKey::new(
        signer.public_key(),
        KeyDetails::new(
            UserId::from_str(Default::default(), user_id),
            vec![],
            vec![],
            keyflags,
            Default::default(),
            Default::default(),
            vec![CompressionAlgorithm::Uncompressed].into(),
            None,
        ),
        vec![],
    );
    let signed_pk = composed_pk.sign(&signer, String::new).map_err(Error::Pgp)?;
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
        (PlainSecretParams::EdDSA(bytes), _) => (
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

    let sig_config = SignatureConfig::new_v4(
        SignatureVersion::V4,
        SignatureType::Binary,
        signer.algorithm(),
        signer.hash_alg(),
        vec![
            Subpacket::regular(SubpacketData::SignatureCreationTime(
                std::time::SystemTime::now().into(),
            )),
            Subpacket::regular(SubpacketData::Issuer(signer.key_id())),
            Subpacket::regular(SubpacketData::IssuerFingerprint(
                KeyVersion::V4,
                signer.fingerprint().into(),
            )),
        ],
        vec![],
    );

    let mut hasher = sig_config.hash_alg.new_hasher().map_err(Error::Pgp)?;

    sig_config
        .hash_data_to_sign(&mut *hasher, message)
        .map_err(Error::Pgp)?;
    let len = sig_config
        .hash_signature_data(&mut *hasher)
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
                n: Base64::decode_vec(
                    &public
                        .modulus
                        .ok_or(Error::KeyData("missing RSA modulus".into()))?,
                )?
                .into(),
                e: Base64::decode_vec(
                    &public
                        .public_exponent
                        .ok_or(Error::KeyData("missing RSA exponent".into()))?,
                )?
                .into(),
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
                PublicKeyAlgorithm::EdDSA,
                created_at,
                None,
                PublicParams::EdDSA {
                    curve: ECCCurve::Ed25519,
                    q: bytes.into(),
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
                    p: pubkey.into(),
                },
                KeyType::EcP384 => EcdsaPublicParams::P384 {
                    key: p384::PublicKey::from_sec1_bytes(&pubkey)?,
                    p: pubkey.into(),
                },
                KeyType::EcP521 => EcdsaPublicParams::P521 {
                    key: p521::PublicKey::from_sec1_bytes(&pubkey)?,
                    p: pubkey.into(),
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
        let PublicParams::EdDSA { curve, q } = pgp_key.public_params() else {
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
}
