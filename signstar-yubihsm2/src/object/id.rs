//! YubiHSM2 objects.

use serde::{Deserialize, Serialize};
use yubihsm::object::{Handle, Type};

/// Identifier for an object stored on a YubiHSM2.
///
/// The YubiHSM2 provides several different types of objects.
/// Each object type serves as a namespace, which means that an object of a specific type is
/// isolated from objects of a different type.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "object_type", content = "object_id", rename_all = "kebab-case")]
pub enum ObjectId {
    /// Asymmetric key used for data signing.
    AsymmetricKey(u16),

    /// Authentication key used for authentication.
    AuthenticationKey(u16),

    /// Wrapping key used for exporting other objects under wrap.
    WrappingKey(u16),

    /// Opaque byte arrays which hold implementation-defined data, e.g. an OpenPGP certificate.
    Opaque(u16),

    /// HMAC-signing key.
    Hmac(u16),

    /// SSH certificate template.
    Template(u16),

    /// One-Time-Password AEAD key.
    Otp(u16),
}

impl ObjectId {
    /// Returns the raw identifier of the YubiHSM2 object.
    pub fn id(&self) -> u16 {
        match self {
            ObjectId::AsymmetricKey(id) => *id,
            ObjectId::AuthenticationKey(id) => *id,
            ObjectId::WrappingKey(id) => *id,
            ObjectId::Opaque(id) => *id,
            ObjectId::Hmac(id) => *id,
            ObjectId::Template(id) => *id,
            ObjectId::Otp(id) => *id,
        }
    }

    /// Returns the type of the YubiHSM2 object.
    pub fn object_type(&self) -> Type {
        match self {
            ObjectId::AsymmetricKey(_) => Type::AsymmetricKey,
            ObjectId::AuthenticationKey(_) => Type::AuthenticationKey,
            ObjectId::WrappingKey(_) => Type::WrapKey,
            ObjectId::Opaque(_) => Type::Opaque,
            ObjectId::Hmac(_) => Type::HmacKey,
            ObjectId::Template(_) => Type::Template,
            ObjectId::Otp(_) => Type::OtpAeadKey,
        }
    }
}

impl From<Handle> for ObjectId {
    fn from(value: Handle) -> Self {
        match value.object_type {
            Type::Opaque => ObjectId::Opaque(value.object_id),
            Type::AuthenticationKey => ObjectId::AuthenticationKey(value.object_id),
            Type::AsymmetricKey => ObjectId::AsymmetricKey(value.object_id),
            Type::WrapKey => ObjectId::WrappingKey(value.object_id),
            Type::HmacKey => ObjectId::Hmac(value.object_id),
            Type::Template => ObjectId::Template(value.object_id),
            Type::OtpAeadKey => ObjectId::Otp(value.object_id),
        }
    }
}
