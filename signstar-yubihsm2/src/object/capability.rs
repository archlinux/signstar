//! YubiHSM2 object capabilities.

use std::{collections::HashSet, hash::Hash, str::FromStr};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;

/// A capability of an object stored on a YubiHSM2.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    strum::Display,
    strum::EnumString,
    strum::EnumIter,
    strum::IntoStaticStr,
)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
pub enum Capability {
    /// The key can sign data.
    Sign,

    /// The object can be exported under wrap (encrypted).
    Exportable,

    /// The key can be used to export other objects under wrap.
    ///
    /// Note that both the authentication key used for export *and* the wrapping key need to be
    /// capable of export.
    Export,

    /// The key can be used to import other objects under wrap.
    ///
    /// Note that both the authentication key used for import *and* the wrapping key need to be
    /// capable of import.
    Import,
}

impl From<&Capability> for yubihsm::Capability {
    fn from(value: &Capability) -> Self {
        match *value {
            Capability::Sign => yubihsm::Capability::SIGN_EDDSA,
            Capability::Exportable => yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            Capability::Export => yubihsm::Capability::EXPORT_WRAPPED,
            Capability::Import => yubihsm::Capability::IMPORT_WRAPPED,
        }
    }
}

/// A set of capabilities of an object on a YubiHSM2.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Capabilities(HashSet<Capability>);

impl From<[u8; 8]> for Capabilities {
    fn from(bytes: [u8; 8]) -> Self {
        let numeric = u64::from_be_bytes(bytes);
        let value = yubihsm::Capability::from_bits_retain(numeric);
        Self(
            Capability::iter()
                .filter(|capability| value.contains(capability.into()))
                .collect(),
        )
    }
}

impl From<&Capabilities> for [u8; 8] {
    fn from(value: &Capabilities) -> Self {
        yubihsm::Capability::from(value).bits().to_be_bytes()
    }
}

impl From<&Capabilities> for yubihsm::Capability {
    fn from(value: &Capabilities) -> Self {
        value
            .0
            .iter()
            .map(yubihsm::Capability::from)
            .fold(yubihsm::Capability::empty(), |acc, c| acc | c)
    }
}

impl FromStr for Capabilities {
    type Err = ::strum::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            s.split(',')
                .map(Capability::from_str)
                .collect::<Result<HashSet<_>, _>>()?,
        ))
    }
}
