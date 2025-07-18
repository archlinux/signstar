//! Module for credentials, user IDs and passphrases.

use std::fmt::Display;
use std::str::FromStr;

use nethsm_sdk_rs::apis::configuration::BasicAuth;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use strum::AsRefStr;

use crate::UserRole;

/// An error that may occur when operating on users.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Unable to convert string slice to Passphrase
    #[error("Unable to convert string to passphrase")]
    Passphrase,

    /// The passphrase for a [`UserId`] is missing.
    #[error("The passphrase for user {user} is missing")]
    PassphraseMissing {
        /// The [`UserId`] for which the passphrase is missing.
        user: UserId,
    },

    /// One or more [`NamespaceId`]s are invalid.
    #[error("Invalid Namespace IDs: {}", namespace_ids.join(", "))]
    InvalidNamespaceIds {
        /// The list of invalid Namespace IDs.
        namespace_ids: Vec<String>,
    },

    /// One or more [`UserId`]s are invalid.
    #[error("Invalid User IDs: {}", user_ids.join(", "))]
    InvalidUserIds {
        /// A list of strings representing invalid [`UserId`]s.
        user_ids: Vec<String>,
    },

    /// The API call does not support users in namespaces
    #[error("The calling user {0} is in a namespace, which is not supported in this context.")]
    NamespaceUnsupported(UserId),

    /// A user in one namespace targets a user in another
    #[error("User {caller} targets {target} which is in a different namespace")]
    NamespaceTargetMismatch {
        /// The [`UserId`] of a user that targets a user in another namespace.
        caller: UserId,

        /// The [`UserId`] of the targeted user.
        target: UserId,
    },

    /// A user in a namespace tries to modify a system-wide user
    #[error("User {caller} targets {target} a system-wide user")]
    NamespaceSystemWideTarget {
        /// The [`UserId`] of a user in a namespace that attempts to modify a system-wide user.
        caller: UserId,

        /// The [`UserId`] of a system-wide user that `caller` attempts to modify.
        target: UserId,
    },

    /// A user in Backup or Metrics role is about to be created in a namespace
    #[error(
        "User {caller} attempts to create user {target} in role {role} which is not supported in namespaces"
    )]
    NamespaceRoleInvalid {
        /// The [`UserId`] of the user trying to create `target` in `role`.
        caller: UserId,

        /// The [`UserId`] of the user in a namespace that is attempted to be created by `caller`.
        target: UserId,

        /// The [`UserRole`] of `target`.
        role: UserRole,
    },
}

/// Whether a resource has [namespace] support or not
///
/// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
#[derive(AsRefStr, Clone, Debug, strum::Display, Eq, PartialEq)]
#[strum(serialize_all = "lowercase")]
pub enum NamespaceSupport {
    /// The resource supports namespaces
    Supported,
    /// The resource does not support namespaces
    Unsupported,
}

/// The ID of a [`NetHsm`][`crate::NetHsm`] [namespace]
///
/// [`NamespaceId`]s are used as part of a [`UserId`] or standalone for managing a [namespace] using
/// [`add_namespace`][`crate::NetHsm::add_namespace`] or
/// [`delete_namespace`][`crate::NetHsm::delete_namespace`].
///
/// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct NamespaceId(String);

impl NamespaceId {
    /// Creates a new [`NamespaceId`] from owned [`String`]
    ///
    /// The provided string must be in the character set `[a-z0-9]`.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`][`crate::Error`] if
    /// * the provided string contains an invalid character
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::NamespaceId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// // a valid NamespaceId
    /// assert!(NamespaceId::new("namespace1".to_string()).is_ok());
    ///
    /// // an invalid NamespaceId
    /// assert!(NamespaceId::new("namespace-1".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(namespace_id: String) -> Result<Self, Error> {
        if namespace_id.is_empty()
            || !namespace_id.chars().all(|char| {
                char.is_numeric() || (char.is_ascii_lowercase() && char.is_ascii_alphabetic())
            })
        {
            return Err(Error::InvalidNamespaceIds {
                namespace_ids: vec![namespace_id],
            });
        }
        Ok(Self(namespace_id))
    }
}

impl AsRef<str> for NamespaceId {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl FromStr for NamespaceId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl Display for NamespaceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<&str> for NamespaceId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

/// The ID for a [`NetHsm`][`crate::NetHsm`] user
///
/// [`UserId`]s are an essential part of the [user management] for a NetHSM.
/// They come in two types: system-wide and in a namespace.
///
/// [`UserId`]s for system-wide users only consist of characters in the set `[a-z0-9]` (e.g.
/// `user1`) and must be at least one char long.
///
/// The [`UserId`]s of users in a namespace consist of characters in the set `[a-z0-9~]` and
/// contain the name of the namespace (see [`NamespaceId`]) they are in. These [`UserId`]s must be
/// at least three chars long. The `~` character serves as delimiter between the namespace part and
/// the user part (e.g. `namespace1~user1`).
///
/// [user management]: https://docs.nitrokey.com/nethsm/administration#user-management
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(into = "String", try_from = "String")]
pub enum UserId {
    /// A system-wide user
    SystemWide(String),
    /// A user in a namespace
    Namespace(NamespaceId, String),
}

impl UserId {
    /// Creates a new [`UserId`] from owned [`String`]
    ///
    /// The provided string must be in the character set `[a-z0-9~]` and at least one char long. The
    /// `~` character can not be used as the first character and can only occur once.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`][`crate::Error`] if
    /// * the provided string contains an invalid character
    /// * the `~` character is used as the first character
    /// * the `~` character is used more than once
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// // the UserId of a system-wide user
    /// assert!(UserId::new("user1".to_string()).is_ok());
    /// // the UserId of a namespace user
    /// assert!(UserId::new("namespace1~user1".to_string()).is_ok());
    ///
    /// // the input can not contain invalid chars
    /// assert!(UserId::new("user1X".to_string()).is_err());
    /// assert!(UserId::new("user;-".to_string()).is_err());
    ///
    /// // the '~' character must be surrounded by other characters and only occur once
    /// assert!(UserId::new("~user1".to_string()).is_err());
    /// assert!(UserId::new("namespace~user~else".to_string()).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_id: String) -> Result<Self, Error> {
        if let Some((namespace, name)) = user_id.split_once("~") {
            if namespace.is_empty()
                || !(namespace.chars().all(|char| {
                    char.is_numeric() || (char.is_ascii_lowercase() && char.is_ascii_alphabetic())
                }) && name.chars().all(|char| {
                    char.is_numeric() || (char.is_ascii_lowercase() && char.is_ascii_alphabetic())
                }))
            {
                return Err(Error::InvalidUserIds {
                    user_ids: vec![user_id],
                });
            }
            Ok(Self::Namespace(namespace.parse()?, name.to_string()))
        } else {
            if user_id.is_empty()
                || !user_id.chars().all(|char| {
                    char.is_numeric() || (char.is_ascii_lowercase() && char.is_ascii_alphabetic())
                })
            {
                return Err(Error::InvalidUserIds {
                    user_ids: vec![user_id],
                });
            }
            Ok(Self::SystemWide(user_id))
        }
    }

    /// Returns the namespace of the [`UserId`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// // the UserId of a system-wide user
    /// assert_eq!(UserId::new("user1".to_string())?.namespace(), None);
    /// // the UserId of a namespace user
    /// assert_eq!(
    ///     UserId::new("namespace1~user1".to_string())?.namespace(),
    ///     Some(&"namespace1".try_into()?)
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn namespace(&self) -> Option<&NamespaceId> {
        match self {
            Self::SystemWide(_) => None,
            Self::Namespace(namespace, _) => Some(namespace),
        }
    }

    /// Returns whether the [`UserId`] contains a namespace
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::UserId;
    ///
    /// # fn main() -> testresult::TestResult {
    /// // the UserId of a system-wide user
    /// assert_eq!(UserId::new("user1".to_string())?.is_namespaced(), false);
    /// // the UserId of a namespace user
    /// assert_eq!(
    ///     UserId::new("namespace1~user1".to_string())?.is_namespaced(),
    ///     true
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn is_namespaced(&self) -> bool {
        match self {
            Self::SystemWide(_) => false,
            Self::Namespace(_, _) => true,
        }
    }

    /// Validates whether the [`UserId`] can be used in a given context
    ///
    /// Ensures that [`UserId`] can be used in its context (e.g. calls to system-wide or
    /// [namespace] resources) by defining [namespace] `support` of the context.
    /// Additionally ensures the validity of calls to resources targeting other users (provided by
    /// `target`), which are themselves system-wide or in a [namespace].
    /// When `role` is provided, the validity of targeting the [`UserRole`] is evaluated.
    ///
    /// # Errors
    ///
    /// This call returns an
    /// * [`Error::NamespaceTargetMismatch`] if a user in one namespace tries to target a user in
    ///   another namespace
    /// * [`Error::NamespaceRoleInvalid`], if a user in a namespace targets a user in the
    ///   [`Backup`][`UserRole::Backup`] or [`Metrics`][`UserRole::Metrics`] [role], or if a user
    ///   not in a namespace targets a namespaced user in the [`Backup`][`UserRole::Backup`] or
    ///   [`Metrics`][`UserRole::Metrics`] [role].
    /// * [`Error::NamespaceSystemWideTarget`], if a user in a [namespace] targets a system-wide
    ///   user
    ///
    /// [namespace]: https://docs.nitrokey.com/nethsm/administration#namespaces
    /// [role]: https://docs.nitrokey.com/nethsm/administration#roles
    pub fn validate_namespace_access(
        &self,
        support: NamespaceSupport,
        target: Option<&UserId>,
        role: Option<&UserRole>,
    ) -> Result<(), Error> {
        // the caller is in a namespace
        if let Some(caller_namespace) = self.namespace() {
            // the caller context does not support namespaces
            if support == NamespaceSupport::Unsupported {
                return Err(Error::NamespaceUnsupported(self.to_owned()));
            }

            // there is a target user
            if let Some(target) = target {
                // the target user is in a namespace
                if let Some(target_namespace) = target.namespace() {
                    // the caller's and the target's namespaces are not the same
                    if caller_namespace != target_namespace {
                        return Err(Error::NamespaceTargetMismatch {
                            caller: self.to_owned(),
                            target: target.to_owned(),
                        });
                    }

                    // the action towards the targeted user provides a role
                    if let Some(role) = role {
                        // the targeted user's role is not supported
                        if role == &UserRole::Metrics || role == &UserRole::Backup {
                            return Err(Error::NamespaceRoleInvalid {
                                caller: self.to_owned(),
                                target: target.to_owned(),
                                role: role.to_owned(),
                            });
                        }
                    }
                } else {
                    // the caller is in a namespace and the target user is not
                    return Err(Error::NamespaceSystemWideTarget {
                        caller: self.to_owned(),
                        target: target.to_owned(),
                    });
                }
            }
        // there is a target user
        } else if let Some(target) = target {
            // there is a target role
            if let Some(role) = role {
                // the targeted user's role is not supported
                if (role == &UserRole::Metrics || role == &UserRole::Backup)
                    && target.is_namespaced()
                {
                    return Err(Error::NamespaceRoleInvalid {
                        caller: self.to_owned(),
                        target: target.to_owned(),
                        role: role.to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

impl FromStr for UserId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_string())
    }
}

impl Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserId::SystemWide(user_id) => write!(f, "{user_id}"),
            UserId::Namespace(namespace, name) => write!(f, "{namespace}~{name}"),
        }
    }
}

impl From<UserId> for String {
    fn from(value: UserId) -> Self {
        value.to_string()
    }
}

impl TryFrom<&str> for UserId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

impl TryFrom<&String> for UserId {
    type Error = Error;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

impl TryFrom<String> for UserId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// Credentials for a [`NetHsm`][`crate::NetHsm`].
///
/// Tracks a [`UserId`] and an accompanying [`Passphrase`].
/// Different from [`Credentials`], this type _requires_ a [`Passphrase`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FullCredentials {
    /// The user name.
    pub name: UserId,

    /// The passphrase for `name`.
    pub passphrase: Passphrase,
}

impl FullCredentials {
    /// Creates a new [`FullCredentials`].
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::FullCredentials;
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = FullCredentials::new("operator".parse()?, "passphrase".parse()?);
    /// # eprintln!("{creds:?}");
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(name: UserId, passphrase: Passphrase) -> Self {
        Self { name, passphrase }
    }
}

impl From<FullCredentials> for BasicAuth {
    fn from(value: FullCredentials) -> Self {
        Self::from(&value)
    }
}

impl From<&FullCredentials> for BasicAuth {
    fn from(value: &FullCredentials) -> Self {
        (
            value.name.to_string(),
            Some(value.passphrase.expose_owned()),
        )
    }
}

impl TryFrom<&Credentials> for FullCredentials {
    type Error = Error;

    fn try_from(value: &Credentials) -> Result<Self, Self::Error> {
        let creds = value.clone();
        FullCredentials::try_from(creds)
    }
}

impl TryFrom<Credentials> for FullCredentials {
    type Error = Error;

    fn try_from(value: Credentials) -> Result<Self, Self::Error> {
        let Some(passphrase) = value.passphrase else {
            return Err(Error::PassphraseMissing {
                user: value.user_id,
            });
        };

        Ok(FullCredentials {
            name: value.user_id,
            passphrase,
        })
    }
}

/// Credentials for a [`NetHsm`][`crate::NetHsm`]
///
/// Holds a user ID and an accompanying [`Passphrase`].
#[derive(Clone, Debug)]
pub struct Credentials {
    /// The user ID.
    pub user_id: UserId,

    /// The optional passphrase for `user_id`.
    pub passphrase: Option<Passphrase>,
}

impl Credentials {
    /// Creates a new [`Credentials`]
    ///
    /// # Examples
    ///
    /// ```
    /// use nethsm::{Credentials, Passphrase};
    ///
    /// # fn main() -> testresult::TestResult {
    /// let creds = Credentials::new(
    ///     "operator".parse()?,
    ///     Some(Passphrase::new("passphrase".to_string())),
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(user_id: UserId, passphrase: Option<Passphrase>) -> Self {
        Self {
            user_id,
            passphrase,
        }
    }
}

impl Display for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_id)?;
        if let Some(passphrase) = self.passphrase.as_ref() {
            write!(f, " ({passphrase})")?;
        }
        Ok(())
    }
}

impl From<Credentials> for BasicAuth {
    fn from(value: Credentials) -> Self {
        (
            value.user_id.to_string(),
            value.passphrase.map(|x| x.expose_owned()),
        )
    }
}

impl From<&Credentials> for BasicAuth {
    fn from(value: &Credentials) -> Self {
        (
            value.user_id.to_string(),
            value.passphrase.as_ref().map(|x| x.expose_owned()),
        )
    }
}

impl From<&FullCredentials> for Credentials {
    fn from(value: &FullCredentials) -> Self {
        let creds = value.clone();
        Self::from(creds)
    }
}

impl From<FullCredentials> for Credentials {
    fn from(value: FullCredentials) -> Self {
        Credentials::new(value.name, Some(value.passphrase))
    }
}

/// A secret passphrase
///
/// The passphrase is held by a [`SecretString`], which guarantees zeroing of memory on
/// destruct.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct Passphrase(SecretString);

impl Passphrase {
    /// Creates a new [`Passphrase`] from owned [`String`]
    ///
    /// # Examples
    /// ```
    /// use nethsm::Passphrase;
    ///
    /// let passphrase = Passphrase::new("passphrase".to_string());
    /// ```
    pub fn new(passphrase: String) -> Self {
        Self(SecretString::new(passphrase.into()))
    }

    /// Exposes the secret passphrase as owned [`String`]
    ///
    /// This is a convenience function, as much of [`nethsm_sdk_rs`] exclusively deals with owned
    /// strings.
    pub fn expose_owned(&self) -> String {
        self.0.expose_secret().to_owned()
    }

    /// Exposes the secret passphrase as borrowed [`str`]
    pub fn expose_borrowed(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Display for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl FromStr for Passphrase {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(SecretString::from(s.to_string())))
    }
}

impl Serialize for Passphrase {
    /// Serializes a [`Passphrase`].
    ///
    /// # Warning
    ///
    /// This may be used to write a passphrase to file!
    /// Take precautions so that passphrases can not leak to the environment.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.expose_secret().serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[test]
    fn passphrase_display() -> TestResult {
        let passphrase = Passphrase::new("a-secret-passphrase".to_string());
        assert_eq!(format!("{passphrase}"), "[REDACTED]");
        Ok(())
    }

    #[rstest]
    #[case(Credentials::new(UserId::new("user".to_string())?, Some(Passphrase::new("a-secret-passphrase".to_string()))), "user ([REDACTED])")]
    #[case(Credentials::new(UserId::new("user".to_string())?, None), "user")]
    fn credentials_display(#[case] credentials: Credentials, #[case] expected: &str) -> TestResult {
        assert_eq!(credentials.to_string(), expected);
        Ok(())
    }

    #[rstest]
    #[case("foo", Some(UserId::SystemWide("foo".to_string())))]
    #[case("f", Some(UserId::SystemWide("f".to_string())))]
    #[case("1", Some(UserId::SystemWide("1".to_string())))]
    #[case("foo;-", None)]
    #[case("foo23", Some(UserId::SystemWide("foo23".to_string())))]
    #[case("FOO", None)]
    #[case("foo~bar", Some(UserId::Namespace(NamespaceId("foo".to_string()), "bar".to_string())))]
    #[case("a~b", Some(UserId::Namespace(NamespaceId("a".to_string()), "b".to_string())))]
    #[case("1~bar", Some(UserId::Namespace(NamespaceId("1".to_string()), "bar".to_string())))]
    #[case("~bar", None)]
    #[case("", None)]
    #[case("foo;-~bar\\", None)]
    #[case("foo23~bar5", Some(UserId::Namespace(NamespaceId("foo23".to_string()), "bar5".to_string())))]
    #[case("foo~bar~baz", None)]
    #[case("FOO~bar", None)]
    #[case("foo~BAR", None)]
    fn create_user_id(#[case] input: &str, #[case] user_id: Option<UserId>) -> TestResult {
        if let Some(user_id) = user_id {
            assert_eq!(UserId::from_str(input)?.to_string(), user_id.to_string());
        } else {
            assert!(UserId::from_str(input).is_err());
        }

        Ok(())
    }

    #[rstest]
    #[case(UserId::SystemWide("user".to_string()), None)]
    #[case(UserId::Namespace(NamespaceId("namespace".to_string()), "user".to_string()), Some(NamespaceId("namespace".to_string())))]
    fn user_id_namespace(#[case] input: UserId, #[case] result: Option<NamespaceId>) -> TestResult {
        assert_eq!(input.namespace(), result.as_ref());
        Ok(())
    }

    #[rstest]
    #[case(UserId::SystemWide("user".to_string()), false)]
    #[case(UserId::Namespace(NamespaceId("namespace".to_string()), "user".to_string()), true)]
    fn user_id_in_namespace(#[case] input: UserId, #[case] result: bool) -> TestResult {
        assert_eq!(input.is_namespaced(), result);
        Ok(())
    }

    #[rstest]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("user2")?), None, Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("user2")?), Some(UserRole::Administrator), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("user2")?), Some(UserRole::Operator), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("user2")?), Some(UserRole::Metrics), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("user2")?), Some(UserRole::Backup), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns1~user2")?), None, Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Administrator), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Operator), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Metrics), None)]
    #[case(UserId::from_str("user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Backup), None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns1~user2")?), None, None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("ns2~user1")?), None, None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Unsupported, Some(UserId::from_str("user2")?), None, None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("ns2~user1")?), None, None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("user2")?), None, None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("ns1~user2")?), None, Some(()))]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Administrator), Some(()))]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Operator), Some(()))]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Metrics), None)]
    #[case(UserId::from_str("ns1~user")?, NamespaceSupport::Supported, Some(UserId::from_str("ns1~user2")?), Some(UserRole::Backup), None)]
    #[case(UserId::from_str("user")?, NamespaceSupport::Supported, Some(UserId::from_str("user2")?), None, Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Supported, Some(UserId::from_str("user2")?), Some(UserRole::Administrator), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Supported, Some(UserId::from_str("user2")?), Some(UserRole::Operator), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Supported, Some(UserId::from_str("user2")?), Some(UserRole::Metrics), Some(()))]
    #[case(UserId::from_str("user")?, NamespaceSupport::Supported, Some(UserId::from_str("user2")?), Some(UserRole::Backup), Some(()))]
    fn validate_namespace_access(
        #[case] caller: UserId,
        #[case] namespace_support: NamespaceSupport,
        #[case] target: Option<UserId>,
        #[case] role: Option<UserRole>,
        #[case] result: Option<()>,
    ) -> TestResult {
        if result.is_some() {
            assert!(
                caller
                    .validate_namespace_access(namespace_support, target.as_ref(), role.as_ref())
                    .is_ok()
            );
        } else {
            assert!(
                caller
                    .validate_namespace_access(namespace_support, target.as_ref(), role.as_ref())
                    .is_err()
            )
        }
        Ok(())
    }
}
