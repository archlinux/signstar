//! YubiHSM2 object capabilities.

use std::{collections::HashSet, hash::Hash};

use serde::{Deserialize, Serialize};

/// A capability of an object stored on a YubiHSM2.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
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

impl From<Capability> for yubihsm::Capability {
    fn from(value: Capability) -> Self {
        match value {
            Capability::Sign => yubihsm::Capability::SIGN_EDDSA,
            Capability::Exportable => yubihsm::Capability::EXPORTABLE_UNDER_WRAP,
            Capability::Export => yubihsm::Capability::EXPORT_WRAPPED,
            Capability::Import => yubihsm::Capability::IMPORT_WRAPPED,
        }
    }
}

/// A set of capabilities of an object on a YubiHSM2.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Capabilities(HashSet<Capability>);

impl From<&Capabilities> for yubihsm::Capability {
    fn from(value: &Capabilities) -> Self {
        value
            .0
            .iter()
            .map(|cap| yubihsm::Capability::from(*cap))
            .fold(yubihsm::Capability::empty(), |acc, c| acc | c)
    }
}
