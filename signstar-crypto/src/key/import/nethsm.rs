//! Implementations specific to a NetHSM backend.

use base64ct::{Base64, Encoding};
use nethsm_sdk_rs::models::KeyPrivateData;

use crate::key::{
    Error,
    KeyType,
    import::{PrivateKeyData, PrivateKeyImport},
};

impl TryFrom<PrivateKeyImport> for KeyPrivateData {
    type Error = crate::Error;

    fn try_from(value: PrivateKeyImport) -> Result<Self, Self::Error> {
        Ok(match value.key_data {
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
            PrivateKeyData::EcP224(data)
            | PrivateKeyData::EcP256(data)
            | PrivateKeyData::EcP384(data)
            | PrivateKeyData::EcP521(data)
            | PrivateKeyData::Curve25519(data) => KeyPrivateData {
                prime_p: None,
                prime_q: None,
                public_exponent: None,
                data: Some(Base64::encode_string(&data)),
            },
            PrivateKeyData::EcK256(_) => {
                return Err(Error::UnsupportedPrivateKeyData {
                    key_type: KeyType::EcK256,
                    context: "the NetHSM backend does not support it",
                }
                .into());
            }
        })
    }
}
