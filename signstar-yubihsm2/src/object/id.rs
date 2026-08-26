//! YubiHSM2 objects.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use yubihsm::object::{Handle, Id, Type};

use crate::automation::ObjectType;

/// Identifier for an object stored on a YubiHSM2.
///
/// The YubiHSM2 provides several different types of objects.
/// Each object type serves as a namespace, which means that an object of a specific type is
/// isolated from objects of a different type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "object_type", content = "object_id", rename_all = "kebab-case")
)]
pub enum ObjectId {
    /// Asymmetric key used for data signing.
    AsymmetricKey(Id),

    /// Authentication key used for authentication.
    AuthenticationKey(Id),

    /// Wrapping key used for exporting other objects under wrap.
    WrappingKey(Id),

    /// Opaque byte arrays which hold implementation-defined data, e.g. an OpenPGP certificate.
    Opaque(Id),

    /// HMAC-signing key.
    Hmac(Id),

    /// SSH certificate template.
    Template(Id),

    /// One-Time-Password AEAD key.
    Otp(Id),

    /// Symmetric key used for encryption and decryption.
    SymmetricKey(Id),
}

impl ObjectId {
    /// Returns the raw identifier of the YubiHSM2 object.
    pub fn id(&self) -> Id {
        match self {
            ObjectId::AsymmetricKey(id) => *id,
            ObjectId::AuthenticationKey(id) => *id,
            ObjectId::WrappingKey(id) => *id,
            ObjectId::Opaque(id) => *id,
            ObjectId::Hmac(id) => *id,
            ObjectId::Template(id) => *id,
            ObjectId::Otp(id) => *id,
            ObjectId::SymmetricKey(id) => *id,
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
            ObjectId::SymmetricKey(_) => Type::SymmetricKey,
        }
    }
}

impl From<(ObjectType, Id)> for ObjectId {
    fn from(value: (ObjectType, Id)) -> Self {
        match value.0 {
            ObjectType::AsymmetricKey => Self::AsymmetricKey(value.1),
            ObjectType::AuthenticationKey => Self::AuthenticationKey(value.1),
            ObjectType::HmacKey => Self::Hmac(value.1),
            ObjectType::Opaque => Self::Opaque(value.1),
            ObjectType::OtpAeakey => Self::Otp(value.1),
            ObjectType::Template => Self::Template(value.1),
            ObjectType::WrapKey => Self::WrappingKey(value.1),
            ObjectType::SymmetricKey => Self::SymmetricKey(value.1),
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
            Type::SymmetricKey => ObjectId::SymmetricKey(value.object_id),
        }
    }
}
