//! Traits for configuration use.

use std::collections::HashSet;

use nix::unistd::User;
use signstar_crypto::{
    NonAdministrativeSecretHandling,
    passphrase::Passphrase,
    secret_file::{load_passphrase_from_secrets_file, write_passphrase_to_secrets_file},
    traits::UserWithPassphrase,
};

use crate::{AuthorizedKeyEntry, SystemUserId, utils::get_current_system_user};

/// An interface for returning an optional [`SystemUserId`].
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

    /// Any non-administrative user.
    NonAdmin,

    /// User used to observe keys, without access to them.
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

    /// Returns a specific [`UserWithPassphrase`] implementation for a backend user.
    ///
    /// # Errors
    ///
    /// Returns an error if `user` matches no backend user of the user mapping.
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

        // Get credentials for all backend users (with newly generated passphrases).
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

    /// Loads secrets from on-disk files for each backend user matching a `filter`.
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
