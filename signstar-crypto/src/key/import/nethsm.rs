//! Implementations specific to a NetHSM backend.

use base64ct::{Base64, Encoding};
use nethsm_sdk_rs::models::KeyPrivateData;

use crate::key::import::{PrivateKeyData, PrivateKeyImport};

impl TryFrom<PrivateKeyImport> for KeyPrivateData {
    type Error = crate::Error;

    fn try_from(value: PrivateKeyImport) -> Result<Self, Self::Error> {
        Ok(match value.key_data {
            PrivateKeyData::Rsa {
                prime_p,
                prime_q,
                public_exponent,
            } =>
            // WARNING: Upstream has decided to set all models non-exhaustive.
            //
            // On each update to nethsm-sdk-rs, check whether KeyPrivateData has gained further
            // fields.
            {
                let mut key_private_data = KeyPrivateData::default();
                key_private_data.prime_p = Some(Base64::encode_string(&prime_p));
                key_private_data.prime_q = Some(Base64::encode_string(&prime_q));
                key_private_data.public_exponent = Some(Base64::encode_string(&public_exponent));
                key_private_data.data = None;
                key_private_data
            }
            PrivateKeyData::Curve25519(data)
            | PrivateKeyData::EcBp256(data)
            | PrivateKeyData::EcBp384(data)
            | PrivateKeyData::EcK256(data)
            | PrivateKeyData::EcP224(data)
            | PrivateKeyData::EcP256(data)
            | PrivateKeyData::EcP384(data)
            | PrivateKeyData::EcP521(data) =>
            // WARNING: Upstream has decided to set all models non-exhaustive.
            //
            // On each update to nethsm-sdk-rs, check whether KeyPrivateData has gained further
            // fields.
            {
                let mut key_private_data = KeyPrivateData::default();
                key_private_data.prime_q = None;
                key_private_data.prime_q = None;
                key_private_data.public_exponent = None;
                key_private_data.data = Some(Base64::encode_string(&data));
                key_private_data
            }
        })
    }
}
