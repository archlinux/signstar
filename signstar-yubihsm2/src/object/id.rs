//! YubiHSM2 objects.

use std::{
    fmt::Display,
    num::{NonZeroU16, NonZeroUsize},
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use yubihsm::object::{Handle, Type};

/// The fundamental representation of an object identifier.
///
/// Wraps [`NonZeroU16`] to reflect on the limitations imposed by a YubiHSM2 [Object ID].
///
/// # Note
///
/// Limits the allowed values to a maximum of `256`.
///
/// [object-id]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#object-id
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(into = "u16", try_from = "NonZeroU16")]
pub struct Id(NonZeroU16);

impl Id {
    /// Creates a new [`Id`] from a [`NonZeroU16`].
    pub fn new(num: NonZeroU16) -> Result<Self, crate::Error> {
        if num.get() > 256 {
            return Err(crate::object::Error::InvalidId {
                reason: "an ID must be a number between 1-256".to_string(),
                id: num.to_string(),
            }
            .into());
        }

        Ok(Self(num))
    }

    /// Returns the inner [`NonZeroU16`].
    pub fn get(&self) -> NonZeroU16 {
        self.0
    }
}

impl AsRef<NonZeroU16> for Id {
    fn as_ref(&self) -> &NonZeroU16 {
        &self.0
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

impl TryFrom<u16> for Id {
    type Error = crate::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(
            NonZeroU16::new(value).ok_or(crate::object::Error::InvalidId {
                reason: "it must not be 0".to_string(),
                id: value.to_string(),
            })?,
        )
    }
}

impl TryFrom<NonZeroU16> for Id {
    type Error = crate::Error;

    fn try_from(value: NonZeroU16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<NonZeroUsize> for Id {
    type Error = crate::Error;

    fn try_from(value: NonZeroUsize) -> Result<Self, Self::Error> {
        Self::try_from(NonZeroU16::try_from(value).map_err(|source| {
            crate::object::Error::InvalidId {
                reason: source.to_string(),
                id: value.to_string(),
            }
        })?)
    }
}

impl TryFrom<usize> for Id {
    type Error = crate::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Self::try_from(NonZeroUsize::try_from(value).map_err(|source| {
            crate::object::Error::InvalidId {
                reason: source.to_string(),
                id: value.to_string(),
            }
        })?)
    }
}

impl FromStr for Id {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(
            NonZeroU16::from_str(s).map_err(|source| crate::object::Error::InvalidId {
                reason: source.to_string(),
                id: s.to_string(),
            })?,
        )
    }
}

impl From<&Id> for u16 {
    fn from(value: &Id) -> Self {
        value.get().get()
    }
}

impl From<Id> for u16 {
    fn from(value: Id) -> Self {
        value.get().get()
    }
}

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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[test]
    fn id_new_too_large() {
        assert!(Id::new(NonZeroU16::new(257u16).unwrap()).is_err());
    }

    #[test]
    fn id_from_str_too_large() {
        assert!(Id::from_str("257").is_err());
    }

    #[test]
    fn id_try_from_str_invalid_nonzero_u16() {
        assert!(Id::from_str("foo").is_err());
    }

    #[test]
    fn id_try_from_non_zero_usize_too_large() {
        assert!(Id::try_from(NonZeroUsize::new(257).unwrap()).is_err());
    }

    #[test]
    fn id_try_from_non_zero_usize_invalid_non_zero_u16() {
        assert!(Id::try_from(NonZeroUsize::new(65536).unwrap()).is_err());
    }

    #[rstest]
    #[case::zero(0usize)]
    #[case::too_large(257usize)]
    fn id_from_usize_fails(#[case] input: usize) {
        assert!(Id::try_from(input).is_err());
    }
}
