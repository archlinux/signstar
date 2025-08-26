//! OpenPGP related signing facilities for NetHSM.

use std::borrow::Cow;

use base64ct::{Base64, Encoding as _};
use log::{error, warn};
use nethsm_sdk_rs::models::KeyType;
use picky_asn1_x509::{
    AlgorithmIdentifier,
    DigestInfo,
    ShaVariant,
    signature::EcdsaSignatureValue,
};
use signstar_crypto::signer::{
    error::Error,
    traits::{RawPublicKey, RawSigningKey},
};

use crate::{KeyId, NetHsm, SignatureType};

/// Access to signature creation with a specific key in a [`NetHsm`].
///
/// Tracks a [`SignatureType`], which defines the type of signature that is created when using a key
/// identified by [`KeyId`] on a [`NetHsm`].
///
/// For owned access see [`OwnedNetHsmKey`].
#[derive(Debug)]
pub struct NetHsmKey<'a, 'b> {
    signature_type: SignatureType,
    nethsm: &'a NetHsm,
    key_id: &'b KeyId,
}

/// Returns a [`SignatureType`] for a [`KeyType`].
///
/// Reflects the specific capabilities of a NetHSM backend and only returns a [`SignatureType`] for
/// a supported `key_type`.
///
/// # Errors
///
/// Returns an error if the key type is unsupported. This includes [`KeyType::EcP224`] and
/// [`KeyType::Generic`].
pub(crate) fn nethsm_signature_type(key_type: KeyType) -> Result<SignatureType, crate::Error> {
    Ok(match key_type {
        KeyType::Rsa => SignatureType::Pkcs1,
        KeyType::Curve25519 => SignatureType::EdDsa,
        KeyType::EcP224 => {
            return Err(crate::Error::Default(
                "P-224 keys are unsupported by the NetHSM".into(),
            ));
        }
        KeyType::EcP256 => SignatureType::EcdsaP256,
        KeyType::EcP384 => SignatureType::EcdsaP384,
        KeyType::EcP521 => SignatureType::EcdsaP521,
        KeyType::Generic => {
            return Err(crate::Error::Default(
                "Generic keys cannot be used to sign OpenPGP data".into(),
            ));
        }
    })
}

impl<'a, 'b> NetHsmKey<'a, 'b> {
    /// Creates a new remote signing key which will use `key_id` key for signing.
    ///
    /// # Errors
    ///
    /// Returns an error if no key can be retrieved from `nethsm` using `key_id`.
    pub fn new(nethsm: &'a NetHsm, key_id: &'b KeyId) -> Result<Self, crate::Error> {
        let pk = nethsm.get_key(key_id)?;
        let signature_type = nethsm_signature_type(pk.r#type)?;

        Ok(Self {
            nethsm,
            signature_type,
            key_id,
        })
    }
}

/// Converts base64-encoded EC public key data into a vector of bytes.
///
/// # Errors
///
/// Returns an error if
///
/// - `data` is [`None`],
/// - or `data` provides invalid base64 encoding.
fn ec_public_key_data_to_bytes(data: Option<&str>) -> Result<Vec<u8>, Error> {
    Base64::decode_vec(data.ok_or(Error::InvalidPublicKeyData {
        context: "EC public key data is missing".into(),
    })?)
    .map_err(|e| Error::Hsm {
        context: "deserializing EC data",
        source: Box::new(e),
    })
}

impl RawSigningKey for NetHsmKey<'_, '_> {
    fn key_id(&self) -> String {
        self.key_id.to_string()
    }

    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        let hash = AlgorithmIdentifier::new_sha(ShaVariant::SHA2_512);
        let request_data = prepare_digest_data_for_openpgp(self.signature_type, hash, digest)?;

        let sig = self
            .nethsm
            .sign_digest(self.key_id, self.signature_type, &request_data)
            .map_err(|e| {
                error!("NetHsm::sign_digest failed: {e:?}");
                Error::Hsm {
                    context: "executing NetHsm::sign_digest",
                    source: e.into(),
                }
            })?;

        raw_signature_to_mpis(self.signature_type, &sig)
    }

    fn certificate(&self) -> Result<Option<Vec<u8>>, Error> {
        self.nethsm
            .get_key_certificate(self.key_id)
            .map_err(|e| Error::Hsm {
                context: "executing NetHsm::get_key_certificate",
                source: e.into(),
            })
    }

    fn public(&self) -> Result<RawPublicKey, Error> {
        let pk = self.nethsm.get_key(self.key_id).map_err(|e| Error::Hsm {
            context: "executing NetHsm::get_key",
            source: e.into(),
        })?;

        let public = &pk.public.ok_or(Error::InvalidPublicKeyData {
            context: "public key data is missing".into(),
        })?;

        let key_type: KeyType = pk.r#type;
        Ok(match key_type {
            KeyType::Rsa => RawPublicKey::Rsa {
                modulus: Base64::decode_vec(public.modulus.as_ref().ok_or(
                    Error::InvalidPublicKeyData {
                        context: "RSA modulus is missing".into(),
                    },
                )?)
                .map_err(|e| Error::Hsm {
                    context: "deserializing modulus",
                    source: Box::new(e),
                })?,
                exponent: Base64::decode_vec(public.public_exponent.as_ref().ok_or(
                    Error::InvalidPublicKeyData {
                        context: "RSA exponent is missing".into(),
                    },
                )?)
                .map_err(|e| Error::Hsm {
                    context: "deserializing exponent",
                    source: Box::new(e),
                })?,
            },
            KeyType::Curve25519 => {
                RawPublicKey::Ed25519(ec_public_key_data_to_bytes(public.data.as_deref())?)
            }
            KeyType::EcP256 => {
                RawPublicKey::P256(ec_public_key_data_to_bytes(public.data.as_deref())?)
            }
            KeyType::EcP384 => {
                RawPublicKey::P384(ec_public_key_data_to_bytes(public.data.as_deref())?)
            }
            KeyType::EcP521 => {
                RawPublicKey::P521(ec_public_key_data_to_bytes(public.data.as_deref())?)
            }
            KeyType::EcP224 | KeyType::Generic => {
                warn!("Unsupported key type: {key_type}");
                return Err(Error::InvalidPublicKeyData {
                    context: format!("Unsupported key type: {key_type}"),
                });
            }
        })
    }
}

/// Owned access to signature creation with a specific key in a [`NetHsm`].
///
/// Tracks a [`SignatureType`], which defines the type of signature that is created when using a key
/// identified by [`KeyId`] on a [`NetHsm`].
///
/// For reference access see [`NetHsmKey`].
#[derive(Debug)]
pub struct OwnedNetHsmKey {
    signature_type: SignatureType,
    nethsm: NetHsm,
    key_id: KeyId,
}

impl OwnedNetHsmKey {
    /// Creates a new [`OwnedNetHsmKey`].
    ///
    /// This remote signing key relies on a backend key accessible via `key_id` for signing.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - retrieving raw signing key from NetHSM fails
    /// - signing mode of the key is unsupported
    pub fn new(nethsm: NetHsm, key_id: KeyId) -> Result<Self, crate::Error> {
        let pk = nethsm.get_key(&key_id)?;
        let signature_type = nethsm_signature_type(pk.r#type)?;

        Ok(Self {
            nethsm,
            signature_type,
            key_id,
        })
    }

    /// Returns a reference view of `self` (a [`NetHsmKey`]).
    pub(crate) fn as_nethsm_key<'a>(&'a self) -> NetHsmKey<'a, 'a> {
        NetHsmKey {
            signature_type: self.signature_type,
            nethsm: &self.nethsm,
            key_id: &self.key_id,
        }
    }
}

impl RawSigningKey for OwnedNetHsmKey {
    fn key_id(&self) -> String {
        self.as_nethsm_key().key_id()
    }

    fn sign(&self, digest: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        self.as_nethsm_key().sign(digest)
    }

    fn certificate(&self) -> Result<Option<Vec<u8>>, Error> {
        self.as_nethsm_key().certificate()
    }

    fn public(&self) -> Result<RawPublicKey, Error> {
        self.as_nethsm_key().public()
    }
}

/// Transforms the raw digest data for cryptographic signing with OpenPGP.
///
/// Raw cryptographic signing primitives have special provisions that
/// need to be taken care of when using certain combinations of
/// signing schemes and hashing algorithms.
///
/// This function transforms the digest into bytes that are ready to
/// be passed to raw cryptographic functions. The exact specifics of
/// the transformations are documented inside the function.
///
/// # Errors
///
/// Returns a PKCS#1 encoding error wrapped in [`Error::Hsm`] in case the RSA-PKCS#1 signing scheme
/// is used but the encoding of digest to the `DigestInfo` structure fails.
fn prepare_digest_data_for_openpgp(
    signature_type: SignatureType,
    oid: AlgorithmIdentifier,
    digest: &[u8],
) -> Result<Cow<'_, [u8]>, Error> {
    Ok(match signature_type {
        // RSA-PKCS#1 signing scheme needs to wrap the digest value
        // in an DER-encoded ASN.1 DigestInfo structure which captures
        // the hash used.
        // See: https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.4
        SignatureType::Pkcs1 => picky_asn1_der::to_vec(&DigestInfo {
            oid,
            digest: digest.to_vec().into(),
        })
        .map_err(|e| {
            error!("Encoding signature to PKCS#1 format failed: {e:?}");
            Error::Hsm {
                context: "preparing digest data",
                source: Box::new(e),
            }
        })?
        .into(),

        // ECDSA may need to truncate the digest if it's too long
        // See: https://www.rfc-editor.org/rfc/rfc9580#section-5.2.3.2
        SignatureType::EcdsaP256 => digest[..usize::min(32, digest.len())].into(),
        SignatureType::EcdsaP384 => digest[..usize::min(48, digest.len())].into(),

        // All other schemes that we use will not need any kind of
        // digest transformations.
        SignatureType::EdDsa | SignatureType::EcdsaP521 => digest.into(),

        SignatureType::PssMd5
        | SignatureType::PssSha1
        | SignatureType::PssSha224
        | SignatureType::PssSha256
        | SignatureType::PssSha384
        | SignatureType::PssSha512 => {
            return Err(Error::UnsupportedSignatureAlgorithm(signature_type));
        }
    })
}

/// Parses raw signature bytes as vector of algorithm-specific multiple precision integers (MPIs).
///
/// MPIs (see [arbitrary-precision arithmetic]) are handled in an algorithm specific way.
/// This function prepares raw signature bytes for technology specific use.
///
/// # Errors
///
/// Returns an error if
///
/// - parsing DER-encoded ECDSA signature fails
/// - EdDSA signature is of wrong length
/// - the signature type is not supported
///
/// [arbitrary-precision arithmetic]: https://en.wikipedia.org/wiki/Arbitrary-precision_arithmetic
fn raw_signature_to_mpis(sig_type: SignatureType, sig: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    use SignatureType;
    Ok(match sig_type {
        SignatureType::EcdsaP256 | SignatureType::EcdsaP384 | SignatureType::EcdsaP521 => {
            let sig: EcdsaSignatureValue = picky_asn1_der::from_bytes(sig).map_err(|e| {
                error!("DER decoding error when parsing ECDSA signature: {e:?}");
                Error::Hsm {
                    context: "DER decoding ECDSA signature",
                    source: Box::new(e),
                }
            })?;
            vec![
                sig.r.as_unsigned_bytes_be().into(),
                sig.s.as_unsigned_bytes_be().into(),
            ]
        }
        SignatureType::EdDsa => {
            if sig.len() != 64 {
                error!(
                    "Signature length should be exactly 64 bytes but is: {}",
                    sig.len()
                );
                return Err(Error::InvalidSignature {
                    context: "decoding EdDSA signature",
                    signature_type: sig_type,
                });
            }

            vec![sig[..32].into(), sig[32..].into()]
        }
        SignatureType::Pkcs1 => {
            // RSA
            vec![sig.into()]
        }
        SignatureType::PssMd5
        | SignatureType::PssSha1
        | SignatureType::PssSha224
        | SignatureType::PssSha256
        | SignatureType::PssSha384
        | SignatureType::PssSha512 => {
            error!("Unsupported signature type: {sig_type}");
            return Err(Error::InvalidSignature {
                context: "parsing signature",
                signature_type: sig_type,
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn parse_rsa_signature_produces_valid_data() -> TestResult {
        let sig = raw_signature_to_mpis(SignatureType::Pkcs1, &[0, 1, 2])?;
        assert_eq!(sig.len(), 1);
        assert_eq!(&sig[0].as_ref(), &[0, 1, 2]);

        Ok(())
    }

    #[test]
    fn parse_ed25519_signature_produces_valid_data() -> TestResult {
        let sig = raw_signature_to_mpis(
            SignatureType::EdDsa,
            &[
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1, 1, 1, 1, 1,
            ],
        )?;
        assert_eq!(sig.len(), 2);
        assert_eq!(sig[0].as_ref(), vec![2; 32]);
        assert_eq!(sig[1].as_ref(), vec![1; 32]);

        Ok(())
    }

    #[test]
    fn parse_p256_signature_produces_valid_data() -> TestResult {
        let sig = raw_signature_to_mpis(
            SignatureType::EcdsaP256,
            &[
                48, 70, 2, 33, 0, 193, 176, 219, 0, 133, 254, 212, 239, 236, 122, 85, 239, 73, 161,
                179, 53, 100, 172, 103, 45, 123, 21, 169, 28, 59, 150, 72, 92, 242, 9, 53, 143, 2,
                33, 0, 165, 1, 144, 97, 102, 109, 66, 50, 185, 234, 211, 150, 253, 228, 210, 126,
                26, 0, 189, 184, 230, 163, 36, 203, 232, 161, 12, 75, 121, 171, 45, 107,
            ],
        )?;
        assert_eq!(sig.len(), 2);
        assert_eq!(
            sig[0].as_ref(),
            [
                193, 176, 219, 0, 133, 254, 212, 239, 236, 122, 85, 239, 73, 161, 179, 53, 100,
                172, 103, 45, 123, 21, 169, 28, 59, 150, 72, 92, 242, 9, 53, 143
            ]
        );
        assert_eq!(
            sig[1].as_ref(),
            [
                165, 1, 144, 97, 102, 109, 66, 50, 185, 234, 211, 150, 253, 228, 210, 126, 26, 0,
                189, 184, 230, 163, 36, 203, 232, 161, 12, 75, 121, 171, 45, 107
            ]
        );

        Ok(())
    }

    #[test]
    fn parse_p384_signature_produces_valid_data() -> TestResult {
        let sig = raw_signature_to_mpis(
            SignatureType::EcdsaP384,
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
            sig[0].as_ref(),
            [
                134, 13, 108, 74, 135, 234, 174, 105, 208, 46, 109, 18, 77, 21, 177, 59, 73, 150,
                228, 26, 244, 134, 187, 217, 172, 34, 2, 1, 229, 123, 105, 202, 132, 233, 72, 41,
                243, 138, 127, 107, 135, 95, 139, 19, 121, 179, 170, 27
            ]
        );
        assert_eq!(
            sig[1].as_ref(),
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
        let sig = raw_signature_to_mpis(
            SignatureType::EcdsaP521,
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
            sig[0].as_ref(),
            [
                203, 246, 21, 57, 217, 6, 101, 73, 103, 113, 98, 39, 223, 246, 199, 136, 238, 213,
                134, 163, 153, 151, 116, 237, 207, 181, 107, 183, 204, 110, 97, 160, 95, 160, 193,
                3, 219, 46, 105, 191, 0, 139, 124, 234, 90, 125, 114, 115, 205, 109, 15, 193, 166,
                100, 224, 108, 87, 143, 240, 65, 41, 93, 164, 166, 2
            ]
        );
        assert_eq!(
            sig[1].as_ref(),
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
    fn rsa_digest_info_is_wrapped_sha1() -> TestResult {
        let hash = AlgorithmIdentifier::new_sha(ShaVariant::SHA1);
        let data = prepare_digest_data_for_openpgp(SignatureType::Pkcs1, hash, &[0; 20])?;

        assert_eq!(
            data,
            &[
                48, 33, 48, 9, 6, 5, 43, 14, 3, 2, 26, 5, 0, 4, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ][..]
        );

        Ok(())
    }

    #[test]
    fn rsa_digest_info_is_wrapped_sha512() -> TestResult {
        let hash = AlgorithmIdentifier::new_sha(ShaVariant::SHA2_512);
        let data = prepare_digest_data_for_openpgp(SignatureType::Pkcs1, hash, &[0; 64])?;

        assert_eq!(
            data,
            &[
                48, 81, 48, 13, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3, 5, 0, 4, 64, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0
            ][..]
        );

        Ok(())
    }

    #[rstest]
    #[case(SignatureType::EcdsaP256, 32)]
    #[case(SignatureType::EcdsaP384, 48)]
    #[case(SignatureType::EcdsaP521, 64)]
    fn ecdsa_wrapped_up_to_max_len(
        #[case] sig_type: SignatureType,
        #[case] max_len: usize,
    ) -> TestResult {
        // the digest value is irrelevant - just the size of the digest
        let digest = [0; 512 / 8];
        let hash = AlgorithmIdentifier::new_sha(ShaVariant::SHA2_512);
        let data = prepare_digest_data_for_openpgp(sig_type, hash, &digest)?;

        // The data to be signed size needs to be truncated to the value specific the the curve
        // being used. If the digest is short enough to be smaller than the curve specific field
        // size the digest is used as a whole.
        assert_eq!(
            data.len(),
            usize::min(max_len, digest.len()),
            "the data to be signed's length ({}) cannot exceed maximum length imposed by the curve ({})",
            data.len(),
            max_len
        );

        Ok(())
    }

    #[rstest]
    fn eddsa_is_not_wrapped() -> TestResult {
        // the digest value is irrelevant - just the size of the digest
        let digest = &[0; 512 / 8][..];

        let hash = AlgorithmIdentifier::new_sha(ShaVariant::SHA2_512);
        let data = prepare_digest_data_for_openpgp(SignatureType::EdDsa, hash, digest)?;

        assert_eq!(data, digest);

        Ok(())
    }
}
