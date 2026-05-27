//! YubiHSM2 object capabilities.

use std::{collections::BTreeSet, hash::Hash};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use strum::{AsRefStr, Display, EnumIter, EnumString, IntoEnumIterator, IntoStaticStr};

/// A capability of an object stored on a YubiHSM2.
#[derive(
    AsRefStr,
    Clone,
    Copy,
    Debug,
    Display,
    EnumIter,
    EnumString,
    Eq,
    Hash,
    IntoStaticStr,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[strum(serialize_all = "kebab-case")]
pub enum Capability {
    /// The object can be exported under wrap (encrypted).
    ExportableUnderWrap,

    /// The key can be used to export other objects under wrap.
    ///
    /// Note that both the authentication key used for export *and* the wrapping key need to be
    /// capable of export.
    ExportWrapped,

    /// The key can be used to import other objects under wrap.
    ///
    /// Note that both the authentication key used for import *and* the wrapping key need to be
    /// capable of import.
    ImportWrapped,

    /// The key can create [EdDSA] data signatures.
    ///
    /// [EdDSA]: https://en.wikipedia.org/wiki/EdDSA
    SignEddsa,
}

impl From<&Capability> for yubihsm::Capability {
    fn from(value: &Capability) -> Self {
        match *value {
            Capability::ExportableUnderWrap => yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            Capability::ExportWrapped => yubihsm::Capability::EXPORT_WRAPPED,
            Capability::ImportWrapped => yubihsm::Capability::IMPORT_WRAPPED,
            Capability::SignEddsa => yubihsm::Capability::SIGN_EDDSA,
        }
    }
}

/// A set of capabilities of an object on a YubiHSM2.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Capabilities(BTreeSet<Capability>);

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

impl From<&[Capability]> for Capabilities {
    fn from(value: &[Capability]) -> Self {
        Self(value.iter().copied().collect())
    }
}
