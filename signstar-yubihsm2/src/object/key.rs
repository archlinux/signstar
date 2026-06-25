//! YubiHSM2 key metadata.

use std::{
    collections::BTreeSet,
    fmt::{Debug, Display},
    fs::read_to_string,
    hash::Hash,
    path::Path,
};

use getrandom::fill;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_repr::{Deserialize_repr, Serialize_repr};
use signstar_crypto::passphrase::{Passphrase, PassphrasePolicy};
use strum::{AsRefStr, IntoStaticStr};
use yubihsm::{
    authentication::Key as YubiHsmAuthenticationKey,
    wrap::Algorithm as YubiHsmWrapAlgorithm,
};
use zeroize::{Zeroize, Zeroizing};

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

impl Display for Domains {
    /// Formats a [`Domains`] as a string.
    ///
    /// Here, the domains in `self` are represented as a comma-separated list (e.g. `1, 2, 3` or
    /// `1`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            self.0
                .iter()
                .map(|domain| domain.as_ref())
                .collect::<Vec<_>>()
                .join(", ")
        )
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

/// An authentication key.
#[derive(Debug)]
pub struct AuthenticationKey(YubiHsmAuthenticationKey);

impl AuthenticationKey {
    /// The default [`PassphrasePolicy`] for an [`AuthenticationKey`].
    pub const PASSPHRASE_POLICY: PassphrasePolicy = PassphrasePolicy { minimum_length: 30 };
}

impl AsRef<YubiHsmAuthenticationKey> for AuthenticationKey {
    fn as_ref(&self) -> &YubiHsmAuthenticationKey {
        &self.0
    }
}

impl From<AuthenticationKey> for YubiHsmAuthenticationKey {
    fn from(value: AuthenticationKey) -> Self {
        value.0
    }
}

impl From<&AuthenticationKey> for YubiHsmAuthenticationKey {
    fn from(value: &AuthenticationKey) -> Self {
        value.0.clone()
    }
}

impl TryFrom<&Path> for AuthenticationKey {
    type Error = crate::Error;

    /// Creates a new [`AuthenticationKey`] from the contents of `file`.
    ///
    /// The contents of `file` must be a valid UTF-8 string that satisfies the default
    /// [`PassphrasePolicy`].
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the contents of `file` cannot be read to a valid UTF-8 encoded string
    /// - the contents of `file` do not satisfy the requirements of [`Self::PASSPHRASE_POLICY`]
    fn try_from(file: &Path) -> Result<Self, Self::Error> {
        let passphrase = Passphrase::new_with_policy(
            read_to_string(file).map_err(|source| crate::Error::IoPath {
                path: file.into(),
                context: "reading the passphrase for an authentication key derivation from file",
                source,
            })?,
            &Self::PASSPHRASE_POLICY,
        )?;

        Ok(Self(YubiHsmAuthenticationKey::derive_from_password(
            passphrase.expose_borrowed().as_bytes(),
        )))
    }
}

impl TryFrom<&Passphrase> for AuthenticationKey {
    type Error = crate::Error;

    /// Creates a new [`AuthenticationKey`] from a [`Passphrase`].
    ///
    /// # Errors
    ///
    /// Returns an error, if
    ///
    /// - the `passphrase` does not satisfy the requirements of [`Self::PASSPHRASE_POLICY`]
    fn try_from(passphrase: &Passphrase) -> Result<Self, Self::Error> {
        passphrase.check_against_policy(&Self::PASSPHRASE_POLICY)?;

        Ok(Self(YubiHsmAuthenticationKey::derive_from_password(
            passphrase.expose_borrowed().as_bytes(),
        )))
    }
}

/// The kind of a wrap key as used by the YubiHSM2.
#[derive(Clone, Copy, Debug, Default, Eq, IntoStaticStr, PartialEq)]
pub enum WrapKeyKind {
    /// AES-128 in Counter with CBC-MAC (CCM) mode.
    Aes128,

    /// AES-192 in Counter with CBC-MAC (CCM) mode.
    Aes192,

    /// AES-256 in Counter with CBC-MAC (CCM) mode.
    #[default]
    Aes256,
}

impl WrapKeyKind {
    /// Returns the size of the wrap key kind in bytes.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes192 => 24,
            Self::Aes256 => 32,
        }
    }
}

impl From<&WrapKeyKind> for YubiHsmWrapAlgorithm {
    fn from(value: &WrapKeyKind) -> Self {
        match value {
            WrapKeyKind::Aes128 => Self::Aes128Ccm,
            WrapKeyKind::Aes192 => Self::Aes192Ccm,
            WrapKeyKind::Aes256 => Self::Aes256Ccm,
        }
    }
}

/// A wrap key.
///
/// Wrap keys are used to wrap (encrypt) objects (e.g. other keys or data) in a YubiHSM2.
pub struct WrapKey {
    kind: WrapKeyKind,
    data: Zeroizing<Vec<u8>>,
}

impl WrapKey {
    /// The default [`PassphrasePolicy`] for a [`WrapKey`].
    pub const PASSPHRASE_POLICY: PassphrasePolicy = PassphrasePolicy {
        minimum_length: 100,
    };

    /// Creates a new [`WrapKey`] of a specific kind.
    ///
    /// # Errors
    ///
    /// Returns an error if generating random bytes for the new wrap key fails
    pub fn generate_random(kind: WrapKeyKind) -> Result<Self, crate::Error> {
        let data = {
            let mut bytes = Zeroizing::new(vec![0u8; kind.key_len()]);
            fill(&mut bytes).map_err(|source| crate::object::Error::GetRandom {
                context: "generating a random wrapping key",
                source,
            })?;
            bytes
        };

        Ok(Self { kind, data })
    }
}

impl Debug for WrapKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrapKey")
            .field("kind", &self.kind)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl Drop for WrapKey {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl From<&WrapKey> for Vec<u8> {
    fn from(value: &WrapKey) -> Self {
        value.data.to_vec()
    }
}

/// Metadata about a key stored on a YubiHSM2.
///
/// This struct stores common parameters of keys regardless of their usage may describe
/// authentication, wrapping and signing keys.
#[derive(Clone, Debug)]
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use rand::{
        distributions::{Alphanumeric, DistString},
        thread_rng,
    };
    use rstest::rstest;
    use tempfile::{NamedTempFile, TempDir};
    use testresult::TestResult;

    use super::*;

    /// Ensures that [`Domains::to_string`] works as expected.
    #[test]
    fn domains_to_string() {
        let domain_list = vec![Domain::One];
        let domains = Domains::from(domain_list.as_slice());
        assert_eq!("1", domains.to_string());

        let domain_list = vec![Domain::One, Domain::Two];
        let domains = Domains::from(domain_list.as_slice());
        assert_eq!("1, 2", domains.to_string());
    }

    #[test]
    fn authentication_key_try_from_path_succeeds() -> TestResult {
        let file = {
            let mut file = NamedTempFile::new()?;
            let passphrase = Alphanumeric.sample_string(&mut thread_rng(), 30);
            file.write_all(passphrase.as_bytes())?;
            file
        };

        match AuthenticationKey::try_from(file.path()) {
            Ok(_) => {}
            Err(error) => panic!(
                "Expected to create an authentication key from the contents of a file, but got an error instead: {error}"
            ),
        }

        Ok(())
    }

    #[test]
    fn authentication_key_try_from_path_fails_on_short_passphrase() -> TestResult {
        let file = {
            let mut file = NamedTempFile::new()?;
            let passphrase = Alphanumeric.sample_string(&mut thread_rng(), 10);
            file.write_all(passphrase.as_bytes())?;
            file
        };

        match AuthenticationKey::try_from(file.path()) {
            Ok(_) => panic!(
                "Expected to fail with Error::Length, but succeeded in creating an authentication key from a passphrase file instead."
            ),
            Err(crate::Error::SignstarCrypto(signstar_crypto::Error::Passphrase(_))) => {}
            Err(error) => panic!(
                "Expected to fail with Error::Length, but failed with a different error instead: {error}"
            ),
        }

        Ok(())
    }

    #[test]
    fn authentication_key_try_from_path_fails_on_file_is_dir() -> TestResult {
        let file = TempDir::new()?;

        match AuthenticationKey::try_from(file.path()) {
            Ok(_) => panic!(
                "Expected to fail with Error::IoPath, but succeeded in creating an authentication key from a passphrase file instead."
            ),
            Err(crate::Error::IoPath { .. }) => {}
            Err(error) => panic!(
                "Expected to fail with Error::IoPath, but failed with a different error instead: {error}"
            ),
        }

        Ok(())
    }

    #[test]
    fn authentication_key_try_from_passphrase_succeeds() -> TestResult {
        let passphrase = Passphrase::generate(Some(30));

        match AuthenticationKey::try_from(&passphrase) {
            Ok(_) => {}
            Err(error) => panic!(
                "Expected to create an authentication key from a passphrase, but got an error instead: {error}"
            ),
        }

        Ok(())
    }

    #[test]
    fn authentication_key_try_from_passphrase_fails_on_passphrase_too_short() -> TestResult {
        let passphrase = Passphrase::new("passphrase".to_string());

        match AuthenticationKey::try_from(&passphrase) {
            Ok(_) => panic!("Expected to fail with Error::Length, but succeeded instead."),
            Err(crate::Error::SignstarCrypto(signstar_crypto::Error::Passphrase(_))) => {}
            Err(error) => panic!(
                "Expected to fail with Error::Length, but failed with a different error instead: {error}"
            ),
        }

        Ok(())
    }

    /// Ensures that [`WrapKeyKind::key_len`] returns the correct number for each variant.
    #[rstest]
    #[case(WrapKeyKind::Aes128, 16)]
    #[case(WrapKeyKind::Aes192, 24)]
    #[case(WrapKeyKind::Aes256, 32)]
    fn wrap_key_kind_key_len(#[case] wrap_key_kind: WrapKeyKind, #[case] len: usize) {
        assert_eq!(wrap_key_kind.key_len(), len);
    }

    /// Ensures that variants of [`YubiHsmWrapAlgorithm`] can be created from [`WrapKeyKind`]
    /// variants.
    #[rstest]
    #[case(WrapKeyKind::Aes128, YubiHsmWrapAlgorithm::Aes128Ccm)]
    #[case(WrapKeyKind::Aes192, YubiHsmWrapAlgorithm::Aes192Ccm)]
    #[case(WrapKeyKind::Aes256, YubiHsmWrapAlgorithm::Aes256Ccm)]
    fn yubihsm_wrap_algorithm_from_wrap_key_kind(
        #[case] wrap_key_kind: WrapKeyKind,
        #[case] algorithm: YubiHsmWrapAlgorithm,
    ) {
        assert_eq!(YubiHsmWrapAlgorithm::from(&wrap_key_kind), algorithm);
    }

    /// Ensures that [`WrapKey::generate_random`] creates a [`WrapKey`] based on a [`WrapKeyKind`].
    #[rstest]
    #[case(WrapKeyKind::Aes128)]
    #[case(WrapKeyKind::Aes192)]
    #[case(WrapKeyKind::Aes256)]
    fn wrap_key_generate_random_succeeds(#[case] wrap_key_kind: WrapKeyKind) -> TestResult {
        let wrap_key = WrapKey::generate_random(wrap_key_kind)?;
        let data: Vec<u8> = From::from(&wrap_key);

        assert_eq!(data.len(), wrap_key_kind.key_len());

        Ok(())
    }

    /// Ensures that the [`Debug`] representation of [`WrapKey`] contains the correct data.
    #[rstest]
    #[case(WrapKeyKind::Aes128)]
    #[case(WrapKeyKind::Aes192)]
    #[case(WrapKeyKind::Aes256)]
    fn wrap_key_debug(#[case] wrap_key_kind: WrapKeyKind) -> TestResult {
        let wrap_key = WrapKey::generate_random(wrap_key_kind)?;
        let wrap_key_debug = format!("{wrap_key:?}");
        let wrap_key_kind_debug = format!("{wrap_key_kind:?}");

        assert!(wrap_key_debug.contains(&wrap_key_kind_debug));
        assert!(wrap_key_debug.contains("[REDACTED]"));

        Ok(())
    }
}
