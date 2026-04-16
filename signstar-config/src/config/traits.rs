//! Traits for configuration use.

use std::collections::HashSet;

use nix::unistd::User;
use signstar_crypto::{
    NonAdministrativeSecretHandling,
    passphrase::Passphrase,
    secret_file::{load_passphrase_from_secrets_file, write_passphrase_to_secrets_file},
    traits::UserWithPassphrase,
};

use crate::{
    config::{AuthorizedKeyEntry, SystemUserId},
    utils::get_current_system_user,
};

/// An error that may occur when using signstar-config traits.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A backend user ID does not match.
    #[error("Expected the backend user ID {expected}, but found {actual} instead")]
    BackendUserIdMismatch {
        /// The expected backend user ID.
        expected: String,

        /// The actually found backend user ID.
        actual: String,
    },
}

/// An interface for returning an optional [`SystemUserId`] or a [`User`].
///
/// It is implemented by mapping implementations, that track system user data.
///
/// # Example
///
/// ```
/// use signstar_config::config::{MappingSystemUserId, SystemUserId};
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Debug)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
/// }
///
/// impl ExampleUserMapping {
///     pub fn backend_user_id(&self) -> u8 {
///         match self {
///             Self::Admin { backend_id }
///             | Self::Backup { backend_id, .. }
///             | Self::Metrics { backend_id, .. }
///             | Self::Signer { backend_id, .. } => *backend_id,
///         }
///     }
/// }
///
/// impl MappingSystemUserId for ExampleUserMapping {
///     fn system_user_id(&self) -> Option<&SystemUserId> {
///         match self {
///             Self::Admin { .. } => None,
///             Self::Backup { system_user, .. }
///             | Self::Metrics { system_user, .. }
///             | Self::Signer { system_user, .. } => Some(system_user),
///         }
///     }
/// }
/// ```
pub trait MappingSystemUserId {
    /// Returns a reference to the [`SystemUserId`].
    ///
    /// # Note
    ///
    /// Should return [`None`], if the user mapping implementation does not track a system user.
    fn system_user_id(&self) -> Option<&SystemUserId>;

    /// Returns the tracked system user ID as [`User`] if it exists.
    ///
    /// This is a default implementation and should require no specific implementation.
    ///
    /// # Note
    ///
    /// Returns `Ok(None)`, if [`MappingSystemUserId::system_user_id`] returns [`None`] (the user
    /// mapping implementation tracks no system user).
    ///
    /// # Errors
    ///
    /// Returns an error if no Unix user of the mapping's system user name exists.
    fn system_user_id_as_existing_unix_user(&self) -> Result<Option<User>, crate::Error> {
        let Some(system_user_id) = self.system_user_id() else {
            return Ok(None);
        };

        // NOTE: We ignore the potential `None` return value of `User::from_name` because it would
        // mean an invalid system user name (which cannot happen due to validation).
        Ok(User::from_name(system_user_id.as_ref()).map_err(|source| {
            crate::utils::Error::SystemUserLookup {
                user: crate::utils::NameOrUid::Name(system_user_id.clone()),
                source,
            }
        })?)
    }

    /// Returns the tracked system user ID as the current [`User`] if it exists.
    ///
    /// This is a default implementation and should require no specific implementation.
    ///
    /// # Note
    ///
    /// Returns `Ok(None)`, if [`MappingSystemUserId::system_user_id`] returns [`None`] (the user
    /// mapping implementation tracks no system user).
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - retrieving the effective User ID of the current Unix user fails,
    /// - the currently calling system user does not match the one returned by
    ///   [`MappingSystemUserId::system_user_id`],
    fn system_user_id_as_current_unix_user(&self) -> Result<Option<User>, crate::Error> {
        let Some(system_user_id) = self.system_user_id() else {
            return Ok(None);
        };
        let current_system_user = get_current_system_user()?;

        if current_system_user.name != system_user_id.as_ref() {
            return Err(crate::utils::Error::SystemUserMismatch {
                target_user: system_user_id.to_string(),
                current_user: current_system_user.name,
            }
            .into());
        }

        Ok(Some(current_system_user))
    }
}

/// The kind of backend user.
///
/// This distinguishes between the different access rights levels (i.e. administrative and
/// non-administrative) and roles (e.g. backup, metrics, signing) of a backend user.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BackendUserIdKind {
    /// Any user.
    #[default]
    Any,

    /// Administrative user.
    Admin,

    /// Backup user.
    Backup,

    /// Metrics user.
    Metrics,

    /// Any non-administrative user.
    NonAdmin,

    /// User used to observe keys, without access to them.
    Observer,

    /// Signing user.
    Signing,
}

/// A filter for user mapping variants.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BackendUserIdFilter {
    /// The kind of backend user.
    pub backend_user_id_kind: BackendUserIdKind,
}

/// An interface for returning a list of backend users based on a filter.
///
/// # Example
///
/// ```
/// use signstar_config::{
///     Error,
///     config::{BackendUserIdFilter, BackendUserIdKind, MappingBackendUserIds, SystemUserId},
/// };
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Debug)]
/// struct ExampleCreds {
///     pub id: u8,
///     pub passphrase: Passphrase,
/// }
///
/// impl UserWithPassphrase for ExampleCreds {
///     fn user(&self) -> String {
///         self.id.to_string()
///     }
///
///     fn passphrase(&self) -> &Passphrase {
///         &self.passphrase
///     }
/// }
///
/// #[derive(Debug)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
/// }
///
/// impl ExampleUserMapping {
///     pub fn backend_user_id(&self) -> u8 {
///         match self {
///             Self::Admin { backend_id }
///             | Self::Backup { backend_id, .. }
///             | Self::Metrics { backend_id, .. }
///             | Self::Signer { backend_id, .. } => *backend_id,
///         }
///     }
/// }
///
/// impl MappingBackendUserIds for ExampleUserMapping {
///     fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String> {
///         match self {
///             Self::Admin { backend_id, .. } => {
///                 if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
///                     .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///             Self::Backup { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Backup,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///             Self::Metrics { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Metrics,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///             Self::Signer { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Signing,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///         }
///
///         Vec::new()
///     }
///
///     fn backend_user_with_passphrase(
///         &self,
///         name: &str,
///         passphrase: Passphrase,
///     ) -> Result<Box<dyn UserWithPassphrase>, Error> {
///         let backend_user_id = self.backend_user_id();
///         if backend_user_id.to_string() != name {
///             return Err(
///                 signstar_config::config::TraitsError::BackendUserIdMismatch {
///                     expected: name.to_string(),
///                     actual: backend_user_id.to_string(),
///                 }
///                 .into(),
///             );
///         }
///
///         Ok(Box::new(ExampleCreds {
///             id: backend_user_id,
///             passphrase,
///         }))
///     }
///
///     fn backend_users_with_new_passphrase(
///         &self,
///         filter: BackendUserIdFilter,
///     ) -> Vec<Box<dyn UserWithPassphrase>> {
///         if let Some(backend_id) = match self {
///             Self::Admin { backend_id, .. } => {
///                 if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
///                     .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///             Self::Backup { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Backup,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///             Self::Metrics { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Metrics,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///             Self::Signer { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Signing,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///         } {
///             vec![Box::new(ExampleCreds {
///                 id: backend_id,
///                 passphrase: Passphrase::generate(None),
///             })]
///         } else {
///             Vec::new()
///         }
///     }
/// }
///
/// # fn main() -> testresult::TestResult {
/// let backend_id = 1;
/// let mapping = ExampleUserMapping::Backup {
///     backend_id,
///     system_user: "backup".parse()?,
/// };
///
/// // Find backend user IDs based on the kind of user.
/// assert!(
///     mapping
///         .backend_user_ids(BackendUserIdFilter {
///             backend_user_id_kind: BackendUserIdKind::Backup
///         })
///         .first()
///         .is_some_and(|id| *id == backend_id.to_string())
/// );
/// // This returns an empty list if there are no matches.
/// assert!(
///     mapping
///         .backend_user_ids(BackendUserIdFilter {
///             backend_user_id_kind: BackendUserIdKind::Admin
///         })
///         .is_empty()
/// );
///
/// // Create credentials based on a user and a passphrase.
/// let passphrase = Passphrase::generate(None);
/// let creds = mapping.backend_user_with_passphrase("1", passphrase.clone())?;
/// assert_eq!(creds.user(), backend_id.to_string());
/// assert_eq!(
///     creds.passphrase().expose_borrowed(),
///     passphrase.expose_borrowed()
/// );
/// // The user ID has to match when creating credentials!
/// assert!(
///     mapping
///         .backend_user_with_passphrase("foo", passphrase.clone())
///         .is_err()
/// );
///
/// // Create new credentials with new passphrase based on backend user ID.
/// assert!(
///     mapping
///         .backend_users_with_new_passphrase(BackendUserIdFilter {
///             backend_user_id_kind: BackendUserIdKind::Backup
///         })
///         .first()
///         .is_some_and(|creds| creds.user() == backend_id.to_string())
/// );
/// # Ok(())
/// # }
/// ```
pub trait MappingBackendUserIds {
    /// Returns a list of [`String`]s representing backend User IDs according to a `filter`.
    fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String>;

    /// Returns a specific [`UserWithPassphrase`] implementation for a backend user.
    ///
    /// # Errors
    ///
    /// Returns an error if `user` matches no backend user of the user mapping.
    /// Note, that implementations may use [`Error::BackendUserIdMismatch`] for this, if they do not
    /// wish to create their own error variant for this purpose.
    fn backend_user_with_passphrase(
        &self,
        name: &str,
        passphrase: Passphrase,
    ) -> Result<Box<dyn UserWithPassphrase>, crate::Error>;

    /// Returns a list of [`UserWithPassphrase`] implementations according to a `filter`.
    ///
    /// For each returned backend user a new [`Passphrase`] is generated using the default settings
    /// of [`Passphrase::generate`].
    ///
    /// With an implementation of [`BackendUserIdFilter`] it is possible to target specific kinds of
    /// backend users.
    fn backend_users_with_new_passphrase(
        &self,
        filter: BackendUserIdFilter,
    ) -> Vec<Box<dyn UserWithPassphrase>>;
}

/// An interface for returning an optional SSH `authorized_keys` entry.
///
/// # Example
///
/// ```
/// use signstar_config::config::{AuthorizedKeyEntry, MappingAuthorizedKeyEntry, SystemUserId};
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Debug)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         ssh_authorized_key: AuthorizedKeyEntry,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         ssh_authorized_key: AuthorizedKeyEntry,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         ssh_authorized_key: AuthorizedKeyEntry,
///         system_user: SystemUserId,
///     },
/// }
///
/// impl MappingAuthorizedKeyEntry for ExampleUserMapping {
///     fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry> {
///         match self {
///             Self::Admin { .. } => None,
///             Self::Backup {
///                 ssh_authorized_key, ..
///             }
///             | Self::Metrics {
///                 ssh_authorized_key, ..
///             }
///             | Self::Signer {
///                 ssh_authorized_key, ..
///             } => Some(ssh_authorized_key),
///         }
///     }
/// }
///
/// # fn main() -> testresult::TestResult {
/// let ssh_authorized_key: AuthorizedKeyEntry = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?;
/// let mapping = ExampleUserMapping::Backup{
///     backend_id: 1,
///     ssh_authorized_key: ssh_authorized_key.clone(),
///     system_user: "backup".parse()?,
/// };
/// assert!(mapping.authorized_key_entry().is_some_and(|key| key == &ssh_authorized_key));
/// # Ok(())
/// # }
/// ```
pub trait MappingAuthorizedKeyEntry {
    /// Returns an optional SSH `authorized_keys` entry.
    ///
    /// Implementations must return [`None`] if the specific mapping does not provide any
    /// [`AuthorizedKeyEntry`].
    fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry>;
}

/// An interface to define a generic filter when evaluating the key IDs of a backend.
pub trait BackendKeyIdFilter: Clone {}

/// An interface for returning a list of key IDs based on a filter.
///
/// The associated filter is an implementation of [`BackendKeyIdFilter`] and should target the
/// inherent details of a cryptographic key in the backend.
/// A key ID must only be returned, if the filter fully matches.
///
/// # Example
///
/// ```
/// use signstar_config::config::{BackendKeyIdFilter, MappingBackendKeyId, SystemUserId};
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Clone, Debug, PartialEq)]
/// enum KeyFeature {
///     V1,
///     V2,
/// }
///
/// #[derive(Debug)]
/// struct KeySetup {
///     pub feature: KeyFeature,
///     pub id: u8,
/// }
///
/// #[derive(Debug)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         key_setup: KeySetup,
///         system_user: SystemUserId,
///     },
/// }
///
/// #[derive(Clone, Debug)]
/// struct KeyFilter {
///     pub feature: KeyFeature,
/// }
///
/// impl BackendKeyIdFilter for KeyFilter {}
///
/// impl MappingBackendKeyId<KeyFilter> for ExampleUserMapping {
///     fn backend_key_id(&self, filter: &KeyFilter) -> Option<String> {
///         match self {
///             Self::Admin { .. } | Self::Backup { .. } | Self::Metrics { .. } => None,
///             Self::Signer { key_setup, .. } => {
///                 if key_setup.feature == filter.feature {
///                     Some(key_setup.id.to_string())
///                 } else {
///                     None
///                 }
///             }
///         }
///     }
/// }
///
/// # fn main() -> testresult::TestResult {
/// let key_id = 1;
/// let mapping = ExampleUserMapping::Signer {
///     backend_id: 1,
///     key_setup: KeySetup {
///         feature: KeyFeature::V1,
///         id: key_id,
///     },
///     system_user: "backup".parse()?,
/// };
///
/// // A key ID is only returned, if the custom filter matches.
/// assert!(
///     mapping
///         .backend_key_id(&KeyFilter {
///             feature: KeyFeature::V1
///         })
///         .is_some_and(|id| id == key_id.to_string())
/// );
/// assert!(
///     mapping
///         .backend_key_id(&KeyFilter {
///             feature: KeyFeature::V2
///         })
///         .is_none()
/// );
/// # Ok(())
/// # }
/// ```
pub trait MappingBackendKeyId<T>
where
    T: BackendKeyIdFilter,
{
    /// Returns an optional [`String`] representing a backend key ID according to a `filter`.
    fn backend_key_id(&self, filter: &T) -> Option<String>;
}

/// An interface to define a generic filter when evaluating the domains of a backend.
pub trait BackendDomainFilter {}

/// An interface for returning a backend domain based on an optional filter.
///
/// A backend domain usually describes a form of access restriction for a backend.
/// With them restrictions to the access of cryptographic key material is enforced for backend
/// users.
///
/// If a filter is provided, the domain ID must only be returned if the filter matches.
///
/// # Example
///
/// ```
/// use signstar_config::config::{BackendDomainFilter, MappingBackendDomain, SystemUserId};
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Clone, Debug, PartialEq)]
/// enum KeyFeature {
///     V1,
///     V2,
/// }
///
/// #[derive(Debug)]
/// struct KeySetup {
///     pub feature: KeyFeature,
///     pub id: u8,
/// }
///
/// #[derive(Debug)]
/// struct Domain {
///     pub id: u8,
///     pub special: bool,
/// }
///
/// #[derive(Debug)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         domain: Domain,
///         key_setup: KeySetup,
///         system_user: SystemUserId,
///     },
/// }
///
/// #[derive(Debug)]
/// struct DomainFilter {
///     pub special: bool,
/// }
///
/// impl BackendDomainFilter for DomainFilter {}
///
/// impl MappingBackendDomain<DomainFilter> for ExampleUserMapping {
///     fn backend_domain(&self, filter: Option<&DomainFilter>) -> Option<String> {
///         match self {
///             Self::Admin { .. } | Self::Backup { .. } | Self::Metrics { .. } => None,
///             Self::Signer { domain, .. } => {
///                 if let Some(filter) = filter {
///                     if domain.special == filter.special {
///                         Some(domain.id.to_string())
///                     } else {
///                         None
///                     }
///                 } else {
///                     Some(domain.id.to_string())
///                 }
///             }
///         }
///     }
/// }
///
/// # fn main() -> testresult::TestResult {
/// let domain_id = 1;
/// let mapping = ExampleUserMapping::Signer {
///     backend_id: 1,
///     domain: Domain {
///         id: domain_id,
///         special: true,
///     },
///     key_setup: KeySetup {
///         feature: KeyFeature::V1,
///         id: 1,
///     },
///     system_user: "backup".parse()?,
/// };
///
/// // A domain ID is only returned, if the custom filter matches.
/// assert!(
///     mapping
///         .backend_domain(Some(&DomainFilter { special: true }))
///         .is_some_and(|id| id == domain_id.to_string())
/// );
/// // .. or if no filter is provided and a backend user with a domain is found.
/// assert!(
///     mapping
///         .backend_domain(Some(&DomainFilter { special: true }))
///         .is_some_and(|id| id == domain_id.to_string())
/// );
/// assert!(
///     mapping
///         .backend_domain(Some(&DomainFilter { special: false }))
///         .is_none()
/// );
/// # Ok(())
/// # }
/// ```
pub trait MappingBackendDomain<T>
where
    T: BackendDomainFilter,
{
    /// Returns a [`String`] representing a backend domain according to an optional `filter`.
    fn backend_domain(&self, filter: Option<&T>) -> Option<String>;
}

/// The kind of non-administrative backend user.
///
/// This distinguishes between the different access rights levels (i.e. backup, metrics, observer,
/// signing) of a non-administrative backend user.
#[derive(Clone, Copy, Debug, Default)]
pub enum NonAdminBackendUserIdKind {
    /// Any non-administrative user.
    #[default]
    Any,

    /// Backup user.
    Backup,

    /// Metrics user.
    Metrics,

    /// User used to observe keys, without access to them.
    Observer,

    /// Signing user.
    Signing,
}

impl From<NonAdminBackendUserIdKind> for BackendUserIdKind {
    fn from(value: NonAdminBackendUserIdKind) -> Self {
        match value {
            NonAdminBackendUserIdKind::Any => Self::NonAdmin,
            NonAdminBackendUserIdKind::Backup => Self::Backup,
            NonAdminBackendUserIdKind::Metrics => Self::Metrics,
            NonAdminBackendUserIdKind::Observer => Self::Observer,
            NonAdminBackendUserIdKind::Signing => Self::Signing,
        }
    }
}

/// A filter for non-administrative user mapping variants.
#[derive(Clone, Debug, Default)]
pub struct NonAdminBackendUserIdFilter {
    /// The kind of backend user.
    pub backend_user_id_kind: NonAdminBackendUserIdKind,
}

impl From<NonAdminBackendUserIdFilter> for BackendUserIdFilter {
    fn from(value: NonAdminBackendUserIdFilter) -> Self {
        Self {
            backend_user_id_kind: value.backend_user_id_kind.into(),
        }
    }
}

/// An interface to create and load secrets for backend users in user mapping implementations.
///
/// Implementations are required to also implement [`MappingBackendUserIds`] and
/// [`MappingSystemUserId`]
///
/// # Example
///
/// ```
/// use signstar_config::{
///     Error,
///     config::{
///         BackendUserIdFilter,
///         BackendUserIdKind,
///         MappingBackendUserIds,
///         MappingBackendUserSecrets,
///         MappingSystemUserId,
///         SystemUserId,
///     },
/// };
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Debug)]
/// struct ExampleCreds {
///     pub id: u8,
///     pub passphrase: Passphrase,
/// }
///
/// impl UserWithPassphrase for ExampleCreds {
///     fn user(&self) -> String {
///         self.id.to_string()
///     }
///
///     fn passphrase(&self) -> &Passphrase {
///         &self.passphrase
///     }
/// }
///
/// #[derive(Debug)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
/// }
///
/// impl ExampleUserMapping {
///     pub fn backend_user_id(&self) -> u8 {
///         match self {
///             Self::Admin { backend_id }
///             | Self::Backup { backend_id, .. }
///             | Self::Metrics { backend_id, .. }
///             | Self::Signer { backend_id, .. } => *backend_id,
///         }
///     }
/// }
///
/// impl MappingBackendUserIds for ExampleUserMapping {
///     fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String> {
///         match self {
///             Self::Admin { backend_id, .. } => {
///                 if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
///                     .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///             Self::Backup { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Backup,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///             Self::Metrics { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Metrics,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///             Self::Signer { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Signing,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     return vec![backend_id.to_string()];
///                 }
///             }
///         }
///
///         Vec::new()
///     }
///
///     fn backend_user_with_passphrase(
///         &self,
///         name: &str,
///         passphrase: Passphrase,
///     ) -> Result<Box<dyn UserWithPassphrase>, Error> {
///         let backend_user_id = self.backend_user_id();
///         if backend_user_id.to_string() != name {
///             return Err(
///                 signstar_config::config::TraitsError::BackendUserIdMismatch {
///                     expected: name.to_string(),
///                     actual: backend_user_id.to_string(),
///                 }
///                 .into(),
///             );
///         }
///
///         Ok(Box::new(ExampleCreds {
///             id: backend_user_id,
///             passphrase,
///         }))
///     }
///
///     fn backend_users_with_new_passphrase(
///         &self,
///         filter: BackendUserIdFilter,
///     ) -> Vec<Box<dyn UserWithPassphrase>> {
///         if let Some(backend_id) = match self {
///             Self::Admin { backend_id, .. } => {
///                 if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
///                     .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///             Self::Backup { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Backup,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///             Self::Metrics { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Metrics,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///             Self::Signer { backend_id, .. } => {
///                 if [
///                     BackendUserIdKind::Any,
///                     BackendUserIdKind::Signing,
///                     BackendUserIdKind::NonAdmin,
///                 ]
///                 .contains(&filter.backend_user_id_kind)
///                 {
///                     Some(*backend_id)
///                 } else {
///                     None
///                 }
///             }
///         } {
///             vec![Box::new(ExampleCreds {
///                 id: backend_id,
///                 passphrase: Passphrase::generate(None),
///             })]
///         } else {
///             Vec::new()
///         }
///     }
/// }
///
/// impl MappingSystemUserId for ExampleUserMapping {
///     fn system_user_id(&self) -> Option<&SystemUserId> {
///         match self {
///             Self::Admin { .. } => None,
///             Self::Backup { system_user, .. }
///             | Self::Metrics { system_user, .. }
///             | Self::Signer { system_user, .. } => Some(system_user),
///         }
///     }
/// }
///
/// impl MappingBackendUserSecrets for ExampleUserMapping {}
/// ```
pub trait MappingBackendUserSecrets: MappingSystemUserId + MappingBackendUserIds {
    /// Creates on-disk secrets for non-administrative backend users of the mapping.
    ///
    /// Returns a list of the created credentials as [`UserWithPassphrase`] implementations.
    ///
    /// # Note
    ///
    /// Returns `Ok(None)`, if the mapping implementation tracks no system user.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the system user in the user mapping does not match an existing Unix user
    /// - the user calling this function is not root
    /// - [`write_passphrase_to_secrets_file`] fails for one of the newly generated passphrases
    fn create_non_admin_backend_user_secrets(
        &self,
        secret_handling: NonAdministrativeSecretHandling,
    ) -> Result<Option<Vec<Box<dyn UserWithPassphrase>>>, crate::Error> {
        let Some(user) = self.system_user_id_as_existing_unix_user()? else {
            // The mapping implementation does not track a system user.
            return Ok(None);
        };

        // Get credentials for all non-admin backend users (with newly generated passphrases).
        let credentials = self.backend_users_with_new_passphrase(BackendUserIdFilter {
            backend_user_id_kind: BackendUserIdKind::NonAdmin,
        });

        // Write the passphrase for each set of credentials to disk.
        for creds in credentials.iter() {
            write_passphrase_to_secrets_file(
                secret_handling,
                &user,
                &creds.user(),
                creds.passphrase(),
            )?
        }

        Ok(Some(credentials))
    }

    /// Loads secrets from on-disk files for each non-administrative backend user matching a
    /// `filter`.
    ///
    /// Returns a list of the loaded credentials as [`UserWithPassphrase`] implementations.
    ///
    /// # Notes
    ///
    /// Returns `Ok(None)`, if the mapping implementation tracks no system user.
    ///
    /// The system user of the user mapping implementation must match the effective user of the
    /// current process.
    ///
    /// Delegates to [`load_passphrase_from_secrets_file`] for the loading of a single
    /// [`Passphrase`] from a secrets file.
    ///
    /// # Errors
    ///
    /// Returns an error if
    ///
    /// - the system user in the user mapping does not match the currently calling Unix user
    /// - [`load_passphrase_from_secrets_file`] fails for one of the secret files of the system user
    ///   of the mapping
    fn load_non_admin_backend_user_secrets(
        &self,
        secret_handling: NonAdministrativeSecretHandling,
        filter: NonAdminBackendUserIdFilter,
    ) -> Result<Option<Vec<Box<dyn UserWithPassphrase>>>, crate::Error> {
        let Some(system_user) = self.system_user_id_as_current_unix_user()? else {
            // The mapping implementation does not track a system user.
            return Ok(None);
        };

        let mut credentials = Vec::new();

        for backend_user in self.backend_user_ids(filter.into()) {
            credentials.push(self.backend_user_with_passphrase(
                &backend_user,
                load_passphrase_from_secrets_file(secret_handling, &system_user, &backend_user)?,
            )?);
        }

        Ok(Some(credentials))
    }
}

/// An interface for returning all [`SystemUserId`]s tracked by a configuration implementation.
///
/// # Example
///
/// ```
/// use std::collections::HashSet;
///
/// use signstar_config::config::{ConfigSystemUserIds, MappingSystemUserId, SystemUserId};
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Debug, Eq, Hash, PartialEq)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         system_user: SystemUserId,
///     },
/// }
///
/// impl ExampleUserMapping {
///     pub fn backend_user_id(&self) -> u8 {
///         match self {
///             Self::Admin { backend_id }
///             | Self::Backup { backend_id, .. }
///             | Self::Metrics { backend_id, .. }
///             | Self::Signer { backend_id, .. } => *backend_id,
///         }
///     }
/// }
///
/// impl MappingSystemUserId for ExampleUserMapping {
///     fn system_user_id(&self) -> Option<&SystemUserId> {
///         match self {
///             Self::Admin { .. } => None,
///             Self::Backup { system_user, .. }
///             | Self::Metrics { system_user, .. }
///             | Self::Signer { system_user, .. } => Some(system_user),
///         }
///     }
/// }
///
/// #[derive(Debug)]
/// struct Config {
///     pub mappings: HashSet<ExampleUserMapping>,
/// }
///
/// impl ConfigSystemUserIds for Config {
///     fn system_user_ids(&self) -> HashSet<&SystemUserId> {
///         self.mappings
///             .iter()
///             .filter_map(|mapping| mapping.system_user_id())
///             .collect::<HashSet<_>>()
///     }
/// }
///
/// # fn main() -> testresult::TestResult {
/// let config = Config {
///     mappings: HashSet::from_iter([
///         ExampleUserMapping::Admin { backend_id: 1 },
///         ExampleUserMapping::Backup {
///             backend_id: 2,
///             system_user: "backup".parse()?,
///         },
///         ExampleUserMapping::Metrics {
///             backend_id: 3,
///             system_user: "metrics".parse()?,
///         },
///         ExampleUserMapping::Signer {
///             backend_id: 3,
///             system_user: "signer".parse()?,
///         },
///     ]),
/// };
/// let system_users: HashSet<SystemUserId> =
///     HashSet::from_iter(["backup".parse()?, "metrics".parse()?, "signer".parse()?]);
///
/// assert_eq!(
///     config.system_user_ids(),
///     system_users.iter().collect::<HashSet<_>>()
/// );
/// # Ok(())
/// # }
/// ```
pub trait ConfigSystemUserIds {
    /// Returns the list of all [`SystemUserId`]s.
    fn system_user_ids(&self) -> HashSet<&SystemUserId>;
}

/// An interface for returning all [`AuthorizedKeyEntry`]s tracked by a configuration
/// implementation.
///
/// # Example
///
/// ```
/// use std::collections::HashSet;
///
/// use signstar_config::config::{AuthorizedKeyEntry, ConfigAuthorizedKeyEntries, MappingAuthorizedKeyEntry, SystemUserId};
/// use signstar_crypto::{passphrase::Passphrase, traits::UserWithPassphrase};
///
/// #[derive(Debug, Eq, Hash, PartialEq)]
/// enum ExampleUserMapping {
///     Admin {
///         backend_id: u8,
///     },
///     Backup {
///         backend_id: u8,
///         ssh_authorized_key: AuthorizedKeyEntry,
///         system_user: SystemUserId,
///     },
///     Metrics {
///         backend_id: u8,
///         ssh_authorized_key: AuthorizedKeyEntry,
///         system_user: SystemUserId,
///     },
///     Signer {
///         backend_id: u8,
///         ssh_authorized_key: AuthorizedKeyEntry,
///         system_user: SystemUserId,
///     },
/// }
///
/// impl MappingAuthorizedKeyEntry for ExampleUserMapping {
///     fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry> {
///         match self {
///             Self::Admin { .. } => None,
///             Self::Backup {
///                 ssh_authorized_key, ..
///             }
///             | Self::Metrics {
///                 ssh_authorized_key, ..
///             }
///             | Self::Signer {
///                 ssh_authorized_key, ..
///             } => Some(ssh_authorized_key),
///         }
///     }
/// }
///
/// #[derive(Debug)]
/// struct Config {
///     pub mappings: HashSet<ExampleUserMapping>,
/// }
///
/// impl ConfigAuthorizedKeyEntries for Config {
///     fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry> {
///         self.mappings
///             .iter()
///             .filter_map(|mapping| mapping.authorized_key_entry())
///             .collect::<HashSet<_>>()
///     }
/// }
///
/// # fn main() -> testresult::TestResult {
/// let config = Config {
///     mappings: HashSet::from_iter([
///     ExampleUserMapping::Admin {
///         backend_id: 1,
///     },
///     ExampleUserMapping::Backup {
///         backend_id: 2,
///         ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
///         system_user: "backup".parse()?,
///     },
///     ExampleUserMapping::Signer {
///         backend_id: 3,
///         ssh_authorized_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?,
///         system_user: "signer".parse()?,
///     },
///     ])
/// };
/// let ssh_authorized_keys: HashSet<AuthorizedKeyEntry> = HashSet::from_iter([
/// "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOh96uFTnvX6P1ebbLxXFvy6sK7qFqlMHDOuJ0TmuXQQ user@host".parse()?,
/// "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkpXKiNhy39A3bZ1u19a5d4sFwYMBkWQyCbzgUfdKBm user@host".parse()?
/// ]);
///
/// assert_eq!(config.authorized_key_entries(), ssh_authorized_keys.iter().collect::<HashSet<_>>());
/// # Ok(())
/// # }
/// ```
pub trait ConfigAuthorizedKeyEntries {
    /// Returns the list of all [`AuthorizedKeyEntry`]s.
    fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry>;
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use testresult::TestResult;

    use super::*;

    #[derive(Debug)]
    struct ExampleCreds {
        pub id: u8,
        pub passphrase: Passphrase,
    }

    impl UserWithPassphrase for ExampleCreds {
        fn user(&self) -> String {
            self.id.to_string()
        }

        fn passphrase(&self) -> &Passphrase {
            &self.passphrase
        }
    }

    #[derive(Debug)]
    enum ExampleUserMapping {
        Admin { backend_id: u8 },
        Backup { backend_id: u8 },
        Metrics { backend_id: u8 },
        Observer { backend_id: u8 },
        Signer { backend_id: u8 },
    }

    impl ExampleUserMapping {
        pub fn backend_user_id(&self) -> u8 {
            match self {
                Self::Admin { backend_id }
                | Self::Backup { backend_id }
                | Self::Metrics { backend_id }
                | Self::Observer { backend_id }
                | Self::Signer { backend_id } => *backend_id,
            }
        }
    }

    impl MappingBackendUserIds for ExampleUserMapping {
        fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String> {
            match self {
                Self::Admin { backend_id } => {
                    if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
                        .contains(&filter.backend_user_id_kind)
                    {
                        return vec![backend_id.to_string()];
                    }
                }
                Self::Backup { backend_id } => {
                    if [
                        BackendUserIdKind::Backup,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        return vec![backend_id.to_string()];
                    }
                }
                Self::Metrics { backend_id } => {
                    if [
                        BackendUserIdKind::Metrics,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        return vec![backend_id.to_string()];
                    }
                }
                Self::Observer { backend_id } => {
                    if [
                        BackendUserIdKind::Observer,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        return vec![backend_id.to_string()];
                    }
                }
                Self::Signer { backend_id } => {
                    if [
                        BackendUserIdKind::Signing,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        return vec![backend_id.to_string()];
                    }
                }
            }

            Vec::new()
        }

        fn backend_user_with_passphrase(
            &self,
            name: &str,
            passphrase: Passphrase,
        ) -> Result<Box<dyn UserWithPassphrase>, crate::Error> {
            let backend_user_id = self.backend_user_id();
            if backend_user_id.to_string() != name {
                return Err(Error::BackendUserIdMismatch {
                    expected: name.to_string(),
                    actual: backend_user_id.to_string(),
                }
                .into());
            }

            Ok(Box::new(ExampleCreds {
                id: backend_user_id,
                passphrase,
            }))
        }

        fn backend_users_with_new_passphrase(
            &self,
            filter: BackendUserIdFilter,
        ) -> Vec<Box<dyn UserWithPassphrase>> {
            if let Some(backend_id) = match self {
                Self::Admin { backend_id } => {
                    if [BackendUserIdKind::Admin, BackendUserIdKind::Any]
                        .contains(&filter.backend_user_id_kind)
                    {
                        Some(*backend_id)
                    } else {
                        None
                    }
                }
                Self::Backup { backend_id } => {
                    if [
                        BackendUserIdKind::Backup,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        Some(*backend_id)
                    } else {
                        None
                    }
                }
                Self::Metrics { backend_id } => {
                    if [
                        BackendUserIdKind::Metrics,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        Some(*backend_id)
                    } else {
                        None
                    }
                }
                Self::Observer { backend_id } => {
                    if [
                        BackendUserIdKind::Observer,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        Some(*backend_id)
                    } else {
                        None
                    }
                }
                Self::Signer { backend_id } => {
                    if [
                        BackendUserIdKind::Signing,
                        BackendUserIdKind::NonAdmin,
                        BackendUserIdKind::Any,
                    ]
                    .contains(&filter.backend_user_id_kind)
                    {
                        Some(*backend_id)
                    } else {
                        None
                    }
                }
            } {
                vec![Box::new(ExampleCreds {
                    id: backend_id,
                    passphrase: Passphrase::generate(None),
                })]
            } else {
                Vec::new()
            }
        }
    }

    // NonAdminBackendUserIdFilter
    #[rstest]
    #[case(NonAdminBackendUserIdKind::Any, BackendUserIdKind::NonAdmin)]
    #[case(NonAdminBackendUserIdKind::Backup, BackendUserIdKind::Backup)]
    #[case(NonAdminBackendUserIdKind::Observer, BackendUserIdKind::Observer)]
    #[case(NonAdminBackendUserIdKind::Metrics, BackendUserIdKind::Metrics)]
    #[case(NonAdminBackendUserIdKind::Signing, BackendUserIdKind::Signing)]
    fn non_admin_backend_user_id_kind_to_backend_user_id_kind(
        #[case] input: NonAdminBackendUserIdKind,
        #[case] output: BackendUserIdKind,
    ) {
        let transform: BackendUserIdKind = input.into();

        assert_eq!(transform, output)
    }

    #[rstest]
    #[case(NonAdminBackendUserIdFilter{ backend_user_id_kind: NonAdminBackendUserIdKind::Any }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(NonAdminBackendUserIdFilter{ backend_user_id_kind: NonAdminBackendUserIdKind::Backup }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup })]
    #[case(NonAdminBackendUserIdFilter{ backend_user_id_kind: NonAdminBackendUserIdKind::Observer }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer })]
    #[case(NonAdminBackendUserIdFilter{ backend_user_id_kind: NonAdminBackendUserIdKind::Metrics }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics })]
    #[case(NonAdminBackendUserIdFilter{ backend_user_id_kind: NonAdminBackendUserIdKind::Signing }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing })]
    fn backend_user_id_filter_from_non_admin_backend_user_id_filter(
        #[case] input: NonAdminBackendUserIdFilter,
        #[case] output: BackendUserIdFilter,
    ) {
        let transform: BackendUserIdFilter = input.into();

        assert_eq!(transform, output)
    }

    #[rstest]
    #[case(ExampleUserMapping::Admin{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Backup{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Observer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Metrics{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Signer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Admin{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin })]
    #[case(ExampleUserMapping::Backup{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup })]
    #[case(ExampleUserMapping::Observer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer })]
    #[case(ExampleUserMapping::Metrics{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics })]
    #[case(ExampleUserMapping::Signer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing })]
    #[case(ExampleUserMapping::Backup{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(ExampleUserMapping::Observer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(ExampleUserMapping::Metrics{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(ExampleUserMapping::Signer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    fn backend_user_ids_matches(
        #[case] mapping: ExampleUserMapping,
        #[case] filter: BackendUserIdFilter,
    ) {
        assert_eq!(mapping.backend_user_ids(filter), ["1"])
    }

    #[test]
    fn backend_user_with_passphrase_succeeds() -> TestResult {
        let mapping = ExampleUserMapping::Admin { backend_id: 1 };
        let passphrase = Passphrase::generate(None);
        let creds = mapping.backend_user_with_passphrase("1", passphrase.clone())?;
        assert_eq!(creds.user(), "1");
        assert_eq!(
            creds.passphrase().expose_borrowed(),
            passphrase.expose_borrowed()
        );

        Ok(())
    }

    #[test]
    fn backend_user_with_passphrase_fails() {
        let mapping = ExampleUserMapping::Admin { backend_id: 1 };
        assert!(
            mapping
                .backend_user_with_passphrase("2", Passphrase::generate(None))
                .is_err()
        );
    }

    #[rstest]
    #[case(ExampleUserMapping::Admin{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Backup{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Observer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Metrics{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Signer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Any })]
    #[case(ExampleUserMapping::Admin{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Admin })]
    #[case(ExampleUserMapping::Backup{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Backup })]
    #[case(ExampleUserMapping::Observer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Observer })]
    #[case(ExampleUserMapping::Metrics{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Metrics })]
    #[case(ExampleUserMapping::Signer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::Signing })]
    #[case(ExampleUserMapping::Backup{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(ExampleUserMapping::Observer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(ExampleUserMapping::Metrics{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    #[case(ExampleUserMapping::Signer{ backend_id: 1 }, BackendUserIdFilter{ backend_user_id_kind: BackendUserIdKind::NonAdmin })]
    fn backend_users_with_new_passphrase_applies(
        #[case] mapping: ExampleUserMapping,
        #[case] filter: BackendUserIdFilter,
    ) {
        let creds = mapping.backend_users_with_new_passphrase(filter);
        assert!(creds.first().is_some_and(|creds| creds.user() == "1"))
    }
}
