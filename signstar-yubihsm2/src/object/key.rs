//! YubiHSM2 key metadata.

use std::{collections::BTreeSet, hash::Hash};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_repr::{Deserialize_repr, Serialize_repr};
use strum::{AsRefStr, IntoStaticStr};

use crate::object::{Capabilities, Id};

/// YubiHSM2 object domain.
///
/// Objects can belong to one or many domains on the YubiHSM2.
/// See [Core Concepts - Domains](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains) for more details.
#[derive(
    AsRefStr,
    Clone,
    Copy,
    Debug,
    strum::Display,
    Eq,
    Hash,
    IntoStaticStr,
    Ord,
    PartialEq,
    PartialOrd,
)]
#[cfg_attr(feature = "serde", derive(Deserialize_repr, Serialize_repr))]
#[repr(u8)]
pub enum Domain {
    /// First domain.
    #[strum(serialize = "1")]
    One = 1,
    /// Second domain.
    #[strum(serialize = "2")]
    Two = 2,
    /// Third domain.
    #[strum(serialize = "3")]
    Three = 3,
    /// Fourth domain.
    #[strum(serialize = "4")]
    Four = 4,
    /// Fifth domain.
    #[strum(serialize = "5")]
    Five = 5,
    /// Sixth domain.
    #[strum(serialize = "6")]
    Six = 6,
    /// Seventh domain.
    #[strum(serialize = "7")]
    Seven = 7,
    /// Eighth domain.
    #[strum(serialize = "8")]
    Eight = 8,
    /// Ninth domain.
    #[strum(serialize = "9")]
    Nine = 9,
    /// Tenth domain.
    #[strum(serialize = "10")]
    Ten = 10,
    /// Eleventh domain.
    #[strum(serialize = "11")]
    Eleven = 11,
    /// Twelfth domain.
    #[strum(serialize = "12")]
    Twelve = 12,
    /// Thirteenth domain.
    #[strum(serialize = "13")]
    Thirteen = 13,
    /// Fourteenth domain.
    #[strum(serialize = "14")]
    Fourteen = 14,
    /// Fifteenth domain.
    #[strum(serialize = "15")]
    Fifteen = 15,
    /// Sixteenth domain.
    #[strum(serialize = "16")]
    Sixteen = 16,
}

#[cfg(feature = "cli")]
impl clap::ValueEnum for Domain {
    fn value_variants<'a>() -> &'a [Self] {
        static VARIANTS: &[Domain] = &[
            Domain::One,
            Domain::Two,
            Domain::Three,
            Domain::Four,
            Domain::Five,
            Domain::Six,
            Domain::Seven,
            Domain::Eight,
            Domain::Nine,
            Domain::Ten,
            Domain::Eleven,
            Domain::Twelve,
            Domain::Thirteen,
            Domain::Fourteen,
            Domain::Fifteen,
            Domain::Sixteen,
        ];
        VARIANTS
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        let str: &'static str = self.into();
        Some(clap::builder::PossibleValue::new(str))
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
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "BTreeSet<Domain>")
)]
pub struct Domains(BTreeSet<Domain>);

impl Domains {
    /// Converts this object into raw big-endian bytes.
    pub fn to_be_bytes(&self) -> [u8; 2] {
        self.bits().to_be_bytes()
    }

    /// Returns set of domains containing all available domains.
    pub fn all() -> Self {
        yubihsm::Domain::all().bits().into()
    }

    /// Returns the underlying bits value.
    pub fn bits(&self) -> u16 {
        yubihsm::Domain::from(self).bits()
    }
}

impl From<Domain> for Domains {
    fn from(value: Domain) -> Self {
        Self(BTreeSet::from_iter([value]))
    }
}

impl From<yubihsm::Domain> for Domains {
    fn from(value: yubihsm::Domain) -> Self {
        let lookup = [
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
        ];

        Domains(BTreeSet::from_iter(lookup.iter().filter_map(
            |(yubi_dom, dom)| {
                if value.contains(*yubi_dom) {
                    Some(*dom)
                } else {
                    None
                }
            },
        )))
    }
}

impl From<u16> for Domains {
    fn from(value: u16) -> Self {
        yubihsm::Domain::from_bits_retain(value).into()
    }
}

impl From<&[Domain]> for Domains {
    fn from(value: &[Domain]) -> Self {
        Self(value.iter().copied().collect())
    }
}

impl TryFrom<BTreeSet<Domain>> for Domains {
    type Error = crate::object::Error;

    fn try_from(domains: BTreeSet<Domain>) -> Result<Self, Self::Error> {
        if domains.is_empty() {
            return Err(Self::Error::EmptySetOfDomains);
        }
        Ok(Self(domains))
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
