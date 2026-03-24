//! YubiHSM2 key metadata.

use std::{collections::HashSet, fmt::Display, hash::Hash};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::object::{Capabilities, Id};

/// YubiHSM2 object domain.
///
/// Objects can belong to one or many domains on the YubiHSM2.
/// See [Core Concepts - Domains](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains) for more details.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize_repr, Serialize_repr))]
#[repr(u8)]
pub enum Domain {
    /// First domain.
    One = 1,
    /// Second domain.
    Two = 2,
    /// Third domain.
    Three = 3,
    /// Fourth domain.
    Four = 4,
    /// Fifth domain.
    Five = 5,
    /// Sixth domain.
    Six = 6,
    /// Seventh domain.
    Seven = 7,
    /// Eighth domain.
    Eight = 8,
    /// Ninth domain.
    Nine = 9,
    /// Tenth domain.
    Ten = 10,
    /// Eleventh domain.
    Eleven = 11,
    /// Twelfth domain.
    Twelve = 12,
    /// Thirteenth domain.
    Thirteen = 13,
    /// Fourteenth domain.
    Fourteen = 14,
    /// Fifteenth domain.
    Fifteen = 15,
    /// Sixteenth domain.
    Sixteen = 16,
}

impl Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::One => "1",
                Self::Two => "2",
                Self::Three => "3",
                Self::Four => "4",
                Self::Five => "5",
                Self::Six => "6",
                Self::Seven => "7",
                Self::Eight => "8",
                Self::Nine => "9",
                Self::Ten => "10",
                Self::Eleven => "11",
                Self::Twelve => "12",
                Self::Thirteen => "13",
                Self::Fourteen => "14",
                Self::Fifteen => "15",
                Self::Sixteen => "16",
            }
        )
    }
}

impl From<Domain> for yubihsm::Domain {
    fn from(value: Domain) -> Self {
        match value {
            Domain::One => Self::DOM1,
            Domain::Two => Self::DOM2,
            Domain::Three => Self::DOM3,
            Domain::Four => Self::DOM4,
            Domain::Five => Self::DOM5,
            Domain::Six => Self::DOM6,
            Domain::Seven => Self::DOM7,
            Domain::Eight => Self::DOM8,
            Domain::Nine => Self::DOM9,
            Domain::Ten => Self::DOM10,
            Domain::Eleven => Self::DOM11,
            Domain::Twelve => Self::DOM12,
            Domain::Thirteen => Self::DOM13,
            Domain::Fourteen => Self::DOM14,
            Domain::Fifteen => Self::DOM15,
            Domain::Sixteen => Self::DOM16,
        }
    }
}

/// A set of domains of an object on a YubiHSM2.
///
/// Each object is assigned to at least one [`Domain`].
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "HashSet<Domain>")
)]
pub struct Domains(HashSet<Domain>);

impl TryFrom<HashSet<Domain>> for Domains {
    type Error = crate::object::Error;

    fn try_from(domains: HashSet<Domain>) -> Result<Self, Self::Error> {
        if domains.is_empty() {
            return Err(Self::Error::EmptySetOfDomains);
        }
        Ok(Self(domains))
    }
}

impl Domains {
    /// Converts this object into raw big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 2] {
        yubihsm::Domain::from(self).bits().to_be_bytes()
    }

    /// Returns set of domains containing all available domains.
    pub fn all() -> Self {
        yubihsm::Domain::all().bits().into()
    }
}

impl From<&Domains> for yubihsm::Domain {
    fn from(value: &Domains) -> Self {
        value
            .0
            .iter()
            .map(|cap| yubihsm::Domain::from(*cap))
            .fold(yubihsm::Domain::empty(), |acc, c| acc | c)
    }
}

impl From<Domain> for Domains {
    fn from(value: Domain) -> Self {
        let mut domains = HashSet::new();
        domains.insert(value);
        Self(domains)
    }
}

impl From<u16> for Domains {
    fn from(value: u16) -> Self {
        let mut domains = HashSet::new();
        let yubi_domain = yubihsm::Domain::from_bits_retain(value);
        for (yubi_dom, dom) in [
            (yubihsm::Domain::DOM1, Domain::One),
            (yubihsm::Domain::DOM2, Domain::Two),
            (yubihsm::Domain::DOM3, Domain::Three),
            (yubihsm::Domain::DOM4, Domain::Four),
            (yubihsm::Domain::DOM5, Domain::Five),
            (yubihsm::Domain::DOM6, Domain::Six),
            (yubihsm::Domain::DOM7, Domain::Seven),
            (yubihsm::Domain::DOM8, Domain::Eight),
            (yubihsm::Domain::DOM9, Domain::Nine),
            (yubihsm::Domain::DOM10, Domain::Ten),
            (yubihsm::Domain::DOM11, Domain::Eleven),
            (yubihsm::Domain::DOM12, Domain::Twelve),
            (yubihsm::Domain::DOM13, Domain::Thirteen),
            (yubihsm::Domain::DOM14, Domain::Fourteen),
            (yubihsm::Domain::DOM15, Domain::Fifteen),
            (yubihsm::Domain::DOM16, Domain::Sixteen),
        ] {
            if yubi_domain.contains(yubi_dom) {
                domains.insert(dom);
            }
        }

        Domains(domains)
    }
}

/// Metadata about a key stored on a YubiHSM2.
///
/// This struct stores common parameters of keys regardless of their usage may describe
/// authentication, wrapping and signing keys.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct KeyInfo {
    /// Inner identifier used to track the key on the YubiHSM2.
    pub key_id: Id,

    /// Key domain.
    ///
    /// Must be in range `1..16`.
    /// See [Core Concepts - Domains](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains).
    pub domains: Domains,

    /// Capabilities of this key.
    pub caps: Capabilities,
}
