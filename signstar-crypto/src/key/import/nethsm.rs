//! Implementations specific to a NetHSM backend.

use base64ct::{Base64, Encoding};
use nethsm_sdk_rs::models::KeyPrivateData;

use crate::key::import::{PrivateKeyData, PrivateKeyImport};

impl From<PrivateKeyImport> for KeyPrivateData {
    fn from(value: PrivateKeyImport) -> Self {
        match value.key_data {
            PrivateKeyData::Rsa {
                prime_p,
                prime_q,
                public_exponent,
            } => KeyPrivateData {
                prime_p: Some(Base64::encode_string(&prime_p)),
                prime_q: Some(Base64::encode_string(&prime_q)),
                public_exponent: Some(Base64::encode_string(&public_exponent)),
                data: None,
            },
            PrivateKeyData::EcP256(data)
            | PrivateKeyData::EcP384(data)
            | PrivateKeyData::EcP521(data)
            | PrivateKeyData::Curve25519(data) => KeyPrivateData {
                prime_p: None,
                prime_q: None,
                public_exponent: None,
                data: Some(Base64::encode_string(&data)),
            },
        }
    }
}
