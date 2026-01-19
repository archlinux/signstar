//! Setup for signing keys.

use serde::{Deserialize, Serialize};

use crate::key::Error;
use crate::key::{
    CryptographicKeyContext,
    KeyMechanism,
    KeyType,
    SignatureType,
    key_type_and_mechanisms_match_signature_type,
    key_type_matches_length,
    key_type_matches_mechanisms,
};

/// The setup of a cryptographic signing key.
///
/// This covers the type of key, its supported mechanisms, its optional length, its signature type
/// and the context in which it is used.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SigningKeySetup {
    key_type: KeyType,
    key_mechanisms: Vec<KeyMechanism>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_length: Option<u32>,
    signature_type: SignatureType,
    key_context: CryptographicKeyContext,
}

impl SigningKeySetup {
    /// Creates a new [`SigningKeySetup`].
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::{
    ///     key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
    ///     openpgp::OpenPgpUserIdList,
    /// };
    ///
    /// # fn main() -> testresult::TestResult {
    /// SigningKeySetup::new(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     SignatureType::EdDsa,
    ///     CryptographicKeyContext::Raw,
    /// )?;
    ///
    /// SigningKeySetup::new(
    ///     KeyType::Curve25519,
    ///     vec![KeyMechanism::EdDsaSignature],
    ///     None,
    ///     SignatureType::EdDsa,
    ///     CryptographicKeyContext::OpenPgp {
    ///         user_ids: OpenPgpUserIdList::new(vec![
    ///             "Foobar McFooface <foobar@mcfooface.org>".parse()?,
    ///         ])?,
    ///         version: "v4".parse()?,
    ///     },
    /// )?;
    ///
    /// // this fails because Curve25519 does not support the ECDSA key mechanism
    /// assert!(
    ///     SigningKeySetup::new(
    ///         KeyType::Curve25519,
    ///         vec![KeyMechanism::EcdsaSignature],
    ///         None,
    ///         SignatureType::EdDsa,
    ///         CryptographicKeyContext::OpenPgp {
    ///             user_ids: OpenPgpUserIdList::new(vec![
    ///                 "Foobar McFooface <foobar@mcfooface.org>".parse()?
    ///             ])?,
    ///             version: "v4".parse()?,
    ///         },
    ///     )
    ///     .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the `key_type` and `key_mechanisms` are incompatible,
    /// - the `key_type` and `key_length` are incompatible,
    /// - the `key_type`, `key_mechanisms` and `signature_type` are incompatible,
    /// - or the `cryptographic_key_context` is not valid.
    pub fn new(
        key_type: KeyType,
        key_mechanisms: Vec<KeyMechanism>,
        key_length: Option<u32>,
        signature_type: SignatureType,
        cryptographic_key_context: CryptographicKeyContext,
    ) -> Result<Self, Error> {
        key_type_matches_mechanisms(key_type, &key_mechanisms)?;
        key_type_matches_length(key_type, key_length)?;
        key_type_and_mechanisms_match_signature_type(key_type, &key_mechanisms, signature_type)?;
        cryptographic_key_context.validate_signing_key_setup(
            key_type,
            &key_mechanisms,
            signature_type,
        )?;

        Ok(Self {
            key_type,
            key_mechanisms,
            key_length,
            signature_type,
            key_context: cryptographic_key_context,
        })
    }

    /// Returns the [`KeyType`].
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }

    /// Returns a reference to the list of [`KeyMechanism`]s.
    pub fn key_mechanisms(&self) -> &[KeyMechanism] {
        &self.key_mechanisms
    }

    /// Returns the optional key length.
    pub fn key_length(&self) -> Option<u32> {
        self.key_length
    }

    /// Returns the [`SignatureType`].
    pub fn signature_type(&self) -> SignatureType {
        self.signature_type
    }

    /// Returns a reference to the [`CryptographicKeyContext`].
    pub fn key_context(&self) -> &CryptographicKeyContext {
        &self.key_context
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn signing_key_setup_new_succeeds() -> TestResult {
        let setup = SigningKeySetup::new(
            KeyType::Curve25519,
            vec![KeyMechanism::EdDsaSignature],
            None,
            SignatureType::EdDsa,
            CryptographicKeyContext::Raw,
        )?;

        assert_eq!(setup.key_type(), KeyType::Curve25519);
        assert_eq!(setup.key_mechanisms(), [KeyMechanism::EdDsaSignature]);
        assert_eq!(setup.key_length(), None);
        assert_eq!(setup.signature_type(), SignatureType::EdDsa);
        assert_eq!(setup.key_context(), &CryptographicKeyContext::Raw);

        Ok(())
    }

    #[rstest]
    #[case::curve25519_ecdsa(KeyType::Curve25519, vec![KeyMechanism::EcdsaSignature])]
    #[case::rsa_ecdsa(KeyType::Rsa, vec![KeyMechanism::EcdsaSignature])]
    fn signing_key_setup_new_fails_on_key_type_mechanism_mismatch(
        #[case] key_type: KeyType,
        #[case] key_mechanisms: Vec<KeyMechanism>,
    ) -> TestResult {
        let result = SigningKeySetup::new(
            key_type,
            key_mechanisms,
            None,
            SignatureType::EdDsa,
            CryptographicKeyContext::Raw,
        );

        match result {
            Err(Error::InvalidKeyMechanism { .. }) => {}
            Err(error) => {
                panic!("Expected an Error::InvalidKeyMechanism, but got {error}");
            }
            Ok(setup) => {
                panic!(
                    "Should have failed, but succeeded in creating a SigningKeySetup: {setup:?}"
                );
            }
        }

        Ok(())
    }

    #[rstest]
    #[case::curve25519_with_length(KeyType::Curve25519, vec![KeyMechanism::EdDsaSignature], Some(1024))]
    #[case::ecp521_with_length(KeyType::EcP521, vec![KeyMechanism::EcdsaSignature], Some(1024))]
    fn signing_key_setup_new_fails_on_key_length_unsupported(
        #[case] key_type: KeyType,
        #[case] key_mechanisms: Vec<KeyMechanism>,
        #[case] key_length: Option<u32>,
    ) -> TestResult {
        let result = SigningKeySetup::new(
            key_type,
            key_mechanisms,
            key_length,
            SignatureType::EdDsa,
            CryptographicKeyContext::Raw,
        );

        match result {
            Err(Error::KeyLengthUnsupported { .. }) => {}
            Err(error) => {
                panic!("Expected an Error::KeyLengthUnsupported, but got {error}");
            }
            Ok(setup) => {
                panic!(
                    "Should have failed, but succeeded in creating a SigningKeySetup: {setup:?}"
                );
            }
        }

        Ok(())
    }

    #[rstest]
    #[case::rsa_too_short(KeyType::Rsa, vec![KeyMechanism::RsaSignaturePkcs1], Some(1024))]
    #[case::rsa_no_length(KeyType::Rsa, vec![KeyMechanism::RsaSignaturePkcs1], None)]
    fn signing_key_setup_new_fails_on_key_length_required_or_too_short(
        #[case] key_type: KeyType,
        #[case] key_mechanisms: Vec<KeyMechanism>,
        #[case] key_length: Option<u32>,
    ) -> TestResult {
        let result = SigningKeySetup::new(
            key_type,
            key_mechanisms,
            key_length,
            SignatureType::EdDsa,
            CryptographicKeyContext::Raw,
        );

        match result {
            Err(Error::KeyLengthRequired { .. }) | Err(Error::InvalidKeyLengthRsa { .. }) => {}
            Err(error) => {
                panic!(
                    "Expected an Error::KeyLengthRequired or Error::InvalidKeyLengthRsa, but got {error}"
                );
            }
            Ok(setup) => {
                panic!(
                    "Should have failed, but succeeded in creating a SigningKeySetup: {setup:?}"
                );
            }
        }

        Ok(())
    }

    #[rstest]
    #[case::curve25519_ecdsap521(KeyType::Curve25519, vec![KeyMechanism::EdDsaSignature], SignatureType::EcdsaP521)]
    #[case::ecdsap521_eddsa(KeyType::EcP521, vec![KeyMechanism::EcdsaSignature], SignatureType::EdDsa)]
    fn signing_key_setup_new_fails_signature_type_mismatch(
        #[case] key_type: KeyType,
        #[case] key_mechanisms: Vec<KeyMechanism>,
        #[case] signature_type: SignatureType,
    ) -> TestResult {
        let result = SigningKeySetup::new(
            key_type,
            key_mechanisms,
            None,
            signature_type,
            CryptographicKeyContext::Raw,
        );

        match result {
            Err(Error::InvalidKeyTypeForSignatureType { .. })
            | Err(Error::InvalidKeyMechanismsForSignatureType { .. }) => {}
            Err(error) => {
                panic!(
                    "Expected an Error::InvalidKeyTypeForSignatureType or Error::InvalidKeyMechanismsForSignatureType, but got {error}"
                )
            }
            Ok(setup) => {
                panic!("Should have failed, but succeeded in creating a SigningKeySetup: {setup:?}")
            }
        }

        Ok(())
    }
}
