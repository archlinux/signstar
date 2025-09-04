//! OpenPGP functionality for Signstar.

use std::{
    borrow::Borrow,
    collections::HashSet,
    fmt::{Debug, Display},
    str::FromStr,
    string::FromUtf8Error,
};

use email_address::{EmailAddress, Options};
use log::error;
use pgp::{
    packet::KeyFlags,
    types::{KeyVersion, SignedUser},
};
use serde::Deserialize;
use strum::{EnumIter, IntoStaticStr};

/// An error that may occur when working with OpenPGP data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Duplicate OpenPGP User ID
    #[error("The OpenPGP User ID {user_id} is used more than once!")]
    DuplicateUserId {
        /// The duplicate OpenPGP User ID.
        user_id: OpenPgpUserId,
    },

    /// Provided OpenPGP version is invalid
    #[error("Invalid OpenPGP version: {0}")]
    InvalidOpenPgpVersion(String),

    /// The User ID is too large
    #[error("The OpenPGP User ID is too large: {user_id}")]
    UserIdTooLarge {
        /// The string that is too long to be used as an OpenPGP User ID.
        user_id: String,
    },

    /// A UTF-8 error when trying to create a string from bytes.
    #[error("Creating a valid UTF-8 string from bytes failed while {context}:\n{source}")]
    FromUtf8 {
        /// The context in which a UTF-8 error occurred.
        ///
        /// This is meant to complete the sentence "Creating a valid UTF-8 string from bytes failed
        /// while ".
        context: &'static str,
        /// The source error.
        source: FromUtf8Error,
    },
}

/// The OpenPGP version
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Deserialize,
    strum::Display,
    EnumIter,
    Hash,
    IntoStaticStr,
    Eq,
    PartialEq,
    serde::Serialize,
)]
#[serde(into = "String", try_from = "String")]
pub enum OpenPgpVersion {
    /// OpenPGP version 4 as defined in [RFC 4880]
    ///
    /// [RFC 4880]: https://www.rfc-editor.org/rfc/rfc4880.html
    #[default]
    #[strum(to_string = "4")]
    V4,

    /// OpenPGP version 6 as defined in [RFC 9580]
    ///
    /// [RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
    #[strum(to_string = "6")]
    V6,
}

impl AsRef<str> for OpenPgpVersion {
    fn as_ref(&self) -> &str {
        match self {
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
}

impl FromStr for OpenPgpVersion {
    type Err = Error;

    /// Creates an [`OpenPgpVersion`] from a string slice
    ///
    /// Only valid OpenPGP versions are considered:
    /// * [RFC 4880] aka "v4"
    /// * [RFC 9580] aka "v6"
    ///
    /// # Errors
    ///
    /// Returns an error if the provided string slice does not represent a valid OpenPGP version.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use signstar_crypto::openpgp::OpenPgpVersion;
    ///
    /// # fn main() -> testresult::TestResult {
    /// assert_eq!(OpenPgpVersion::from_str("4")?, OpenPgpVersion::V4);
    /// assert_eq!(OpenPgpVersion::from_str("6")?, OpenPgpVersion::V6);
    ///
    /// assert!(OpenPgpVersion::from_str("5").is_err());
    /// # Ok(())
    /// # }
    /// ```
    /// [RFC 4880]: https://www.rfc-editor.org/rfc/rfc4880.html
    /// [RFC 9580]: https://www.rfc-editor.org/rfc/rfc9580.html
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "4" | "v4" | "V4" | "OpenPGPv4" => Ok(Self::V4),
            "5" | "v5" | "V5" | "OpenPGPv5" => Err(Error::InvalidOpenPgpVersion(format!(
                "{s} (\"we don't do these things around here\")"
            ))),
            "6" | "v6" | "V6" | "OpenPGPv6" => Ok(Self::V6),
            _ => Err(Error::InvalidOpenPgpVersion(s.to_string())),
        }
    }
}

impl From<OpenPgpVersion> for String {
    fn from(value: OpenPgpVersion) -> Self {
        value.to_string()
    }
}

impl TryFrom<KeyVersion> for OpenPgpVersion {
    type Error = Error;

    /// Creates an [`OpenPgpVersion`] from a [`KeyVersion`].
    ///
    /// # Errors
    ///
    /// Returns an error if an invalid OpenPGP version is encountered.
    fn try_from(value: KeyVersion) -> Result<Self, Self::Error> {
        Ok(match value {
            KeyVersion::V4 => Self::V4,
            KeyVersion::V6 => Self::V6,
            _ => {
                return Err(Error::InvalidOpenPgpVersion(
                    Into::<u8>::into(value).to_string(),
                ));
            }
        })
    }
}

impl TryFrom<String> for OpenPgpVersion {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_str(&value)
    }
}

/// A distinction between types of OpenPGP User IDs
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum OpenPgpUserIdType {
    /// An OpenPGP User ID that contains a valid e-mail address (e.g. "John Doe
    /// <john@example.org>")
    ///
    /// The e-mail address must use a top-level domain (TLD) and no domain literal (e.g. an IP
    /// address) is allowed.
    Email(EmailAddress),

    /// A plain OpenPGP User ID
    ///
    /// The User ID may contain any UTF-8 character, but does not represent a valid e-mail address.
    Plain(String),
}

/// A basic representation of a User ID for OpenPGP
///
/// While [OpenPGP User IDs] are loosely defined to be UTF-8 strings, they do not enforce
/// particular rules around the use of e-mail addresses or their general length.
/// This type allows to distinguish between plain UTF-8 strings and valid e-mail addresses.
/// Valid e-mail addresses must provide a display part, use a top-level domain (TLD) and not rely on
/// domain literals (e.g. IP address).
/// The length of a User ID is implicitly limited by the maximum length of an OpenPGP packet (8192
/// bytes).
/// As such, this type only allows a maximum length of 4096 bytes as middle ground.
///
/// [OpenPGP User IDs]: https://www.rfc-editor.org/rfc/rfc9580.html#name-user-id-packet-type-id-13
#[derive(Clone, Debug, serde::Deserialize, Eq, Hash, PartialEq, serde::Serialize)]
#[serde(into = "String", try_from = "String")]
pub struct OpenPgpUserId(OpenPgpUserIdType);

impl OpenPgpUserId {
    /// Creates a new [`OpenPgpUserId`] from a String
    ///
    /// # Errors
    ///
    /// Returns an [`Error::UserIdTooLarge`] if the chars of the provided String exceed
    /// 4096 bytes. This ensures to stay below the valid upper limit defined by the maximum OpenPGP
    /// packet size of 8192 bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::str::FromStr;
    ///
    /// use signstar_crypto::openpgp::OpenPgpUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// assert!(!OpenPgpUserId::new("🤡".to_string())?.is_email());
    ///
    /// assert!(OpenPgpUserId::new("🤡 <foo@xn--rl8h.org>".to_string())?.is_email());
    ///
    /// // an e-mail without a display name is not considered a valid e-mail
    /// assert!(!OpenPgpUserId::new("<foo@xn--rl8h.org>".to_string())?.is_email());
    ///
    /// // this fails because the provided String is too long
    /// assert!(OpenPgpUserId::new("U".repeat(4097)).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_id: String) -> Result<Self, Error> {
        if user_id.len() > 4096 {
            return Err(Error::UserIdTooLarge { user_id });
        }
        if let Ok(email) = EmailAddress::parse_with_options(
            &user_id,
            Options::default()
                .with_required_tld()
                .without_domain_literal(),
        ) {
            Ok(Self(OpenPgpUserIdType::Email(email)))
        } else {
            Ok(Self(OpenPgpUserIdType::Plain(user_id)))
        }
    }

    /// Returns whether the [`OpenPgpUserId`] is a valid e-mail address
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::openpgp::OpenPgpUserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// assert!(!OpenPgpUserId::new("🤡".to_string())?.is_email());
    ///
    /// assert!(OpenPgpUserId::new("🤡 <foo@xn--rl8h.org>".to_string())?.is_email());
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_email(&self) -> bool {
        matches!(self.0, OpenPgpUserIdType::Email(..))
    }
}

impl AsRef<str> for OpenPgpUserId {
    fn as_ref(&self) -> &str {
        match self.0.borrow() {
            OpenPgpUserIdType::Email(user_id) => user_id.as_str(),
            OpenPgpUserIdType::Plain(user_id) => user_id.as_str(),
        }
    }
}

impl Display for OpenPgpUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl FromStr for OpenPgpUserId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl From<OpenPgpUserId> for String {
    fn from(value: OpenPgpUserId) -> Self {
        value.to_string()
    }
}

impl TryFrom<&SignedUser> for OpenPgpUserId {
    type Error = Error;

    /// Creates an [`OpenPgpUserId`] from [`SignedUser`].
    ///
    /// # Errors
    ///
    /// Returns an error if the [`SignedUser`]'s User ID can not be converted to a valid UTF-8
    /// string.
    fn try_from(value: &SignedUser) -> Result<Self, Self::Error> {
        Self::new(
            String::from_utf8(value.id.id().to_vec()).map_err(|source| Error::FromUtf8 {
                context: "converting an OpenPGP UserID",
                source,
            })?,
        )
    }
}

impl TryFrom<String> for OpenPgpUserId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A list of [`OpenPgpUserId`]
///
/// The items of the list are guaranteed to be unique.
#[derive(Clone, Debug, serde::Deserialize, Eq, Hash, PartialEq, serde::Serialize)]
#[serde(into = "Vec<String>", try_from = "Vec<String>")]
pub struct OpenPgpUserIdList(Vec<OpenPgpUserId>);

impl OpenPgpUserIdList {
    /// Creates a new [`OpenPgpUserIdList`]
    ///
    /// # Errors
    ///
    /// Returns an error, if one of the provided [`OpenPgpUserId`]s is a duplicate.
    ///
    /// # Examples
    ///
    /// ```
    /// use signstar_crypto::openpgp::OpenPgpUserIdList;
    ///
    /// # fn main() -> testresult::TestResult {
    /// OpenPgpUserIdList::new(vec![
    ///     "🤡 <foo@xn--rl8h.org>".parse()?,
    ///     "🤡 <bar@xn--rl8h.org>".parse()?,
    /// ])?;
    ///
    /// // this fails because the two OpenPgpUserIds are the same
    /// assert!(
    ///     OpenPgpUserIdList::new(vec![
    ///         "🤡 <foo@xn--rl8h.org>".parse()?,
    ///         "🤡 <foo@xn--rl8h.org>".parse()?,
    ///     ])
    ///     .is_err()
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_ids: Vec<OpenPgpUserId>) -> Result<Self, Error> {
        let mut set = HashSet::new();
        for user_id in user_ids.iter() {
            if !set.insert(user_id) {
                return Err(Error::DuplicateUserId {
                    user_id: user_id.to_owned(),
                });
            }
        }
        Ok(Self(user_ids))
    }

    /// Iterator for OpenPGP User IDs contained in this list.
    pub fn iter(&self) -> impl Iterator<Item = &OpenPgpUserId> {
        self.0.iter()
    }

    /// Returns a reference to the first [`OpenPgpUserId`] if there is one.
    pub fn first(&self) -> Option<&OpenPgpUserId> {
        self.0.first()
    }
}

impl AsRef<[OpenPgpUserId]> for OpenPgpUserIdList {
    fn as_ref(&self) -> &[OpenPgpUserId] {
        &self.0
    }
}

impl From<OpenPgpUserIdList> for Vec<String> {
    fn from(value: OpenPgpUserIdList) -> Self {
        value
            .iter()
            .map(|user_id| user_id.to_string())
            .collect::<Vec<String>>()
    }
}

impl TryFrom<Vec<String>> for OpenPgpUserIdList {
    type Error = Error;

    fn try_from(value: Vec<String>) -> Result<Self, Self::Error> {
        let user_ids = {
            let mut user_ids: Vec<OpenPgpUserId> = vec![];
            for user_id in value {
                user_ids.push(OpenPgpUserId::new(user_id)?)
            }
            user_ids
        };
        OpenPgpUserIdList::new(user_ids)
    }
}

/// Key usage flags that can be set on the generated certificate.
#[derive(Debug, Default)]
pub struct OpenPgpKeyUsageFlags(KeyFlags);

impl OpenPgpKeyUsageFlags {
    /// Makes it possible for this key to issue data signatures.
    pub fn set_sign(&mut self) {
        self.0.set_sign(true);
    }

    /// Makes it impossible for this key to issue data signatures.
    pub fn clear_sign(&mut self) {
        self.0.set_sign(false);
    }
}

impl AsRef<KeyFlags> for OpenPgpKeyUsageFlags {
    fn as_ref(&self) -> &KeyFlags {
        &self.0
    }
}

impl From<OpenPgpKeyUsageFlags> for KeyFlags {
    fn from(value: OpenPgpKeyUsageFlags) -> Self {
        value.0
    }
}
