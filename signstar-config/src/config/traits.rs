//! Traits for configuration use.

use std::collections::HashSet;

use crate::{AuthorizedKeyEntry, SystemUserId};

/// An interface for returning an optional [`SystemUserId`].
pub trait MappingSystemUserId {
    /// Returns a reference to the [`SystemUserId`].
    fn system_user_id(&self) -> Option<&SystemUserId>;
}

/// The kind of backend user.
///
/// This distinguishes between the different access rights levels (i.e. administrative and
/// non-administrative) of a backend user.
#[derive(Clone, Copy, Debug, Default)]
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

    /// Operator user without any other capabilities.
    Observer,

    /// Signing user.
    Signing,
}

/// A filter for user mapping variants.
#[derive(Clone, Debug, Default)]
pub struct BackendUserIdFilter {
    /// The kind of backend user.
    pub backend_user_id_kind: BackendUserIdKind,
}

/// An interface for returning a list of backend users based on a filter.
pub trait MappingBackendUserIds {
    /// Returns a list of [`String`]s representing backend User IDs according to a `filter`.
    fn backend_user_ids(&self, filter: BackendUserIdFilter) -> Vec<String>;
}

/// An interface for returning a list of backend users based on a filter.
pub trait MappingAuthorizedKeyEntry {
    /// Returns a list of [`String`]s representing backend user IDs according to a `filter`.
    fn authorized_key_entry(&self) -> Option<&AuthorizedKeyEntry>;
}

/// An interface to define a generic filter when evaluating the key IDs of a backend.
pub trait BackendKeyIdFilter: Clone {}

/// An interface for returning a list of backend users based on a filter.
pub trait MappingBackendKeyId<T>
where
    T: BackendKeyIdFilter,
{
    /// Returns a list of [`String`]s representing backend key IDs according to a `filter`.
    fn backend_key_id(&self, filter: &T) -> Option<String>;
}

/// An interface to define a generic filter when evaluating the domains of a backend.
pub trait BackendDomainFilter {}

/// An interface for returning a backend domain based on an optional filter.
pub trait MappingBackendDomain<T>
where
    T: BackendDomainFilter,
{
    /// Returns a [`String`] representing a backend domain according to an optional `filter`.
    fn backend_domain(&self, filter: Option<&T>) -> Option<String>;
}

/// An interface for returning all [`SystemUserId`]s tracked by a configuration.
pub trait ConfigSystemUserIds {
    /// Returns the list of all [`SystemUserId`]s.
    fn system_user_ids(&self) -> HashSet<&SystemUserId>;
}

/// An interface for returning all [`AuthorizedKeyEntry`]s tracked by a configuration.
pub trait ConfigAuthorizedKeyEntries {
    /// Returns the list of all [`AuthorizedKeyEntry`]s.
    fn authorized_key_entries(&self) -> HashSet<&AuthorizedKeyEntry>;
}
