//! Handling of users and keys in a NetHSM backend.

use nethsm::{Connection, KeyId, NamespaceId, NetHsm, Passphrase, SystemState, UserId};
use nethsm_config::UserMapping;

use crate::AdminCredentials;

/// An error that may occur when handling a NetHSM backend.
#[derive(Debug, thiserror::Error)]
pub enum Error {}

/// The state of a NetHSM backend.
///
/// Tracks all users and keys on the backend.
pub struct NetHsmState {
    users: Vec<UserId>,
    keys: Vec<(NamespaceId, KeyId)>,
}

impl NetHsmState {
    /// Syncs the state of NetHSM backend and returns it.
    pub fn sync(
        connection: Connection,
        admin_credentials: &AdminCredentials,
        users: &[UserMapping],
    ) -> Result<(), crate::Error> {
        let nethsm = NetHsm::new(connection, None, None, None).map_err(crate::Error::NetHsm)?;

        // If the backend is locked, unlock it
        if nethsm.state()? == SystemState::Operational {
            eprintln!("Already operational, only sync");
            nethsm.unlock(Passphrase::new(
                admin_credentials.get_unlock_passphrase().into(),
            ))?
        }

        // Add all administrative credentials for the connection
        for user in admin_credentials.get_administrators() {
            nethsm.add_credentials(user.into());
        }
        for user in admin_credentials.get_namespace_administrators() {
            nethsm.add_credentials(user.into());
        }

        // Use the default administrator
        nethsm.use_credentials(&admin_credentials.get_default_administrator()?.name)?;

        // If the backend is locked, unlock it
        if nethsm.state()? == SystemState::Locked {
            nethsm.unlock(Passphrase::new(
                admin_credentials.get_unlock_passphrase().into(),
            ))?
        }

        println!("{users:?}");

        Ok(())
    }

    /// Returns a slice of the user IDs.
    pub fn get_users(&self) -> &[UserId] {
        &self.users
    }

    /// Returns a slice of the tracked keys.
    pub fn get_keys(&self) -> &[(NamespaceId, KeyId)] {
        &self.keys
    }
}
