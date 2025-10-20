//! Traits for cryptography related items.

use crate::passphrase::Passphrase;

/// An abstraction for a user with a passphrase.
pub trait UserWithPassphrase: std::fmt::Debug {
    /// Returns the name of the user as owned string.
    fn user(&self) -> String;

    /// Returns the passphrase of the user.
    fn passphrase(&self) -> &Passphrase;
}
