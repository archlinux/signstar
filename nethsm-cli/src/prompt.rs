// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use nethsm::{Passphrase, UserRole};
use rpassword::prompt_password;
use rprompt::prompt_reply;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Getting backup passphrase failed
    #[error("Unable to get backup passphrase")]
    Backup,

    /// Getting current backup passphrase failed
    #[error("Unable to get current backup passphrase")]
    CurrentBackup,

    /// Getting current unlock passphrase failed
    #[error("Unable to get current unlock passphrase")]
    CurrentUnlock,

    /// Getting new backup passphrase failed
    #[error("Unable to get new backup passphrase")]
    NewBackup,

    /// Getting new unlock passphrase failed
    #[error("Unable to get new unlock passphrase")]
    NewUnlock,

    /// Getting new passphrase for user failed
    #[error("Unable to get new passphrase for user {0}")]
    NewUser(String),

    /// Getting unlock passphrase failed
    #[error("Unable to get unlock passphrase")]
    Unlock,

    /// Getting current passphrase for user failed
    #[error("Unable to get passphrase for user {0}")]
    User(String),

    /// Getting username failed
    #[error("Unable to get username")]
    UserName,
}

/// Passphrase prompt
pub enum PassphrasePrompt {
    /// Prompt for backup passphrase
    Backup,
    /// Prompt for current backup passphrase
    CurrentBackup,
    /// Prompt for current unlock passphrase
    CurrentUnlock,
    /// Prompt for new backup passphrase
    NewBackup,
    /// Prompt for new unlock passphrase
    NewUnlock,
    /// Prompt for new user passphrase
    NewUser(String),
    /// Prompt for unlock passphrase
    Unlock,
    /// Prompt for current user passphrase
    User(String),
}

impl PassphrasePrompt {
    /// Prompts for a passphrase
    pub fn prompt(&self) -> Result<Passphrase, Error> {
        let reason = match self {
            Self::Backup => "Backup passphrase: ".to_string(),
            Self::CurrentBackup => "Current backup passphrase: ".to_string(),
            Self::CurrentUnlock => "Current unlock passphrase: ".to_string(),
            Self::NewBackup => "New backup passphrase: ".to_string(),
            Self::NewUnlock => "New unlock passphrase: ".to_string(),
            Self::NewUser(user) => format!("New passphrase for user \"{user}\": "),
            Self::Unlock => "Unlock passphrase: ".to_string(),
            Self::User(user) => format!("Passphrase for user \"{user}\": "),
        };

        Ok(Passphrase::new(prompt_password(reason).map_err(
            |_| match self {
                Self::Backup => Error::Backup,
                Self::CurrentBackup => Error::CurrentBackup,
                Self::CurrentUnlock => Error::CurrentUnlock,
                Self::NewBackup => Error::NewBackup,
                Self::NewUnlock => Error::NewUnlock,
                Self::NewUser(user) => Error::NewUser(user.to_string()),
                Self::Unlock => Error::Unlock,
                Self::User(user) => Error::User(user.to_string()),
            },
        )?))
    }
}

/// Username prompt
pub struct UserPrompt(UserRole);

impl UserPrompt {
    /// Creates a new [`UserPrompt`] based on a [`UserRole`]
    pub fn new(role: UserRole) -> Self {
        Self(role)
    }

    /// Prompt for a username
    pub fn prompt(&self) -> Result<String, Error> {
        let reason = match self.0 {
            UserRole::Administrator => "Name of a user in the \"administrator\" role: ".to_string(),
            UserRole::Backup => "Name of a user in the \"backup\" role: ".to_string(),
            UserRole::Metrics => "Name of a user in the \"metrics\" role: ".to_string(),
            UserRole::Operator => "Name of a user in the \"operator\" role: ".to_string(),
        };

        let name = prompt_reply(reason).map_err(|_| Error::UserName)?;
        Ok(name)
    }
}
