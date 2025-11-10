use nethsm::{Passphrase, UserId, UserRole};
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
    #[error("Unable to get passphrase for user {user_id:?} ({real_name:?}) ")]
    User {
        user_id: Option<UserId>,
        real_name: Option<String>,
    },

    /// Getting username failed
    #[error("Unable to get username")]
    UserName,

    /// The user data is not correct
    #[error("User data is invalid: {0}")]
    NetHsmUser(#[from] nethsm::UserError),
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
    NewUser(UserId),
    /// Prompt for unlock passphrase
    Unlock,
    /// Prompt for current user passphrase
    User {
        /// The optional user ID to show.
        user_id: Option<UserId>,
        /// The optional real name to show.
        real_name: Option<String>,
    },
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
            Self::User { user_id, real_name } => match (user_id, real_name) {
                (Some(user_id), Some(real_name)) => {
                    format!("Passphrase for user \"{user_id}\" (\"{real_name}\"): ")
                }
                (None, Some(real_name)) => format!("Passphrase for user \"{real_name}\": "),
                (None, None) => "Passphrase for unknown user: ".to_string(),
                (Some(user_id), None) => format!("Passphrase for unknown user \"{user_id}\": "),
            },
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
                Self::User { user_id, real_name } => Error::User {
                    user_id: user_id.to_owned(),
                    real_name: real_name.to_owned(),
                },
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
    pub fn prompt(&self) -> Result<UserId, Error> {
        let reason = match self.0 {
            UserRole::Administrator => "Name of a user in the \"Administrator\" role: ".to_string(),
            UserRole::Backup => "Name of a user in the \"Backup\" role: ".to_string(),
            UserRole::Metrics => "Name of a user in the \"Metrics\" role: ".to_string(),
            UserRole::Operator => "Name of a user in the \"Operator\" role: ".to_string(),
        };

        let name = UserId::new(prompt_reply(reason).map_err(|_| Error::UserName)?)?;
        Ok(name)
    }
}
