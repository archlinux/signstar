//! Utility functionality shared across the [`NetHsm`] implementation.

#[cfg(doc)]
use crate::NetHsm;
use crate::UserId;

/// Creates a string for when there is a user or there is no user.
///
/// Creates the string `the user <user>` if `user` is [`Some`].
/// Creates the string `no user` if `user` is [`None`].
pub(crate) fn user_or_no_user_string(user: Option<&UserId>) -> String {
    if let Some(current_credentials) = user {
        format!("the user {current_credentials}")
    } else {
        "no user".to_string()
    }
}
