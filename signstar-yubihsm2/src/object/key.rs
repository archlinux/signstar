//! YubiHSM2 key metadata.

use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::object::Capabilities;

/// YubiHSM2 object domain.
///
/// Objects can belong to one or many domains on the YubiHSM2.
/// See [Core Concepts - Domains](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains) for more details.
#[derive(Clone, Copy, Debug, Deserialize_repr, PartialEq, Serialize_repr)]
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

/// Metadata about a key stored on a YubiHSM2.
///
/// This struct stores common parameters of keys regardless of their usage may describe
/// authentication, wrapping and signing keys.
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyInfo {
    /// Inner identifier used to track the key on the YubiHSM2.
    pub key_id: u16,

    /// Key domain.
    ///
    /// Must be in range `1..16`.
    /// See [Core Concepts - Domains](https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html#domains).
    pub domain: Domain,

    /// Capabilities of this key.
    pub caps: Capabilities,
}
