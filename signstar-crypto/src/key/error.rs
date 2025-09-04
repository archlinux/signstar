//! Error handling

use crate::key::base::{KeyMechanism, KeyType, MIN_RSA_BIT_LENGTH, SignatureType};

/// An error that can occur when dealing with keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The key mechanisms provided for a key type are not valid
    #[error(
        "The key type {key_type} does not support the following key mechanisms: {invalid_mechanisms:?}"
    )]
    InvalidKeyMechanism {
        /// The key type not supporting specific mechanisms.
        key_type: KeyType,
        /// The list of invalid key mechanisms.
        invalid_mechanisms: Vec<KeyMechanism>,
    },

    /// Elliptic curve keys do not support providing a length
    #[error("Elliptic curve key ({key_type}) does not support setting length")]
    KeyLengthUnsupported {
        /// The key type that does not support setting length.
        key_type: KeyType,
    },

    /// Key type requires setting a length
    #[error("Generating a key of type {key_type} requires setting a length")]
    KeyLengthRequired {
        /// The key type that requires a length.
        key_type: KeyType,
    },

    /// AES key is generated with unsupported key length (not 128, 192 or 256)
    #[error(
        "AES only defines key lengths of 128, 192 and 256. A key length of {key_length} is unsupported!"
    )]
    InvalidKeyLengthAes {
        /// The invalid key length.
        key_length: u32,
    },

    /// RSA key is generated with unsafe key length (smaller than 2048)
    #[error(
        "RSA keys shorter than {MIN_RSA_BIT_LENGTH} are not supported. A key length of {key_length} is unsafe!"
    )]
    InvalidKeyLengthRsa {
        /// The invalid key length.
        key_length: u32,
    },

    /// The signature type provided for a key type is not valid
    #[error("The key type {key_type} is not compatible with signature type: {signature_type}")]
    InvalidKeyTypeForSignatureType {
        /// The key type.
        key_type: KeyType,
        /// The signature type that is invalid for the use with `key_type`.
        signature_type: SignatureType,
    },

    /// The key mechanisms provided for a signature type are not valid
    #[error(
        "The key mechanism {required_key_mechanism} must be used with signature type {signature_type}"
    )]
    InvalidKeyMechanismsForSignatureType {
        /// The invalid key mechanism.
        required_key_mechanism: KeyMechanism,
        /// The signature type matching the key mechanism.
        signature_type: SignatureType,
    },

    /// A signing key setup is not compatible with raw cryptographic signing
    #[error(
        "The key type {key_type}, key mechanisms {key_mechanisms:?} and signature type {signature_type} are incompatible with raw cryptographic signing"
    )]
    InvalidRawSigningKeySetup {
        /// The key type incompatible with raw cryptographic signing.
        key_type: KeyType,
        /// The list of key mechanisms incompatible with raw cryptographic signing.
        key_mechanisms: Vec<KeyMechanism>,
        /// The signature type incompatible with raw cryptographic signing.
        signature_type: SignatureType,
    },

    /// A signing key setup is not compatible with OpenPGP signing
    #[error(
        "The key type {key_type}, key mechanisms {key_mechanisms:?} and signature type {signature_type} are incompatible with OpenPGP signing"
    )]
    InvalidOpenPgpSigningKeySetup {
        /// The key type incompatible with OpenPGP signing.
        key_type: KeyType,
        /// The list of key mechanisms incompatible with OpenPGP signing.
        key_mechanisms: Vec<KeyMechanism>,
        /// The signature type incompatible with OpenPGP signing.
        signature_type: SignatureType,
    },
}
