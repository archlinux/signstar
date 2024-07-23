use clap::{Parser, Subcommand};
use nethsm::{SystemState, UserRole};
use strum::IntoEnumIterator;

use crate::passphrase_file::PassphraseFile;

#[derive(Debug, Subcommand)]
#[command(
    about = "Operate on users of a device",
    long_about = "Operate on users of a device

Allows to add and remove users, retrieve information about them, set their passphrases and set or unset tags for them."
)]
pub enum UserCommand {
    Add(UserAddCommand),
    Get(UserGetCommand),
    List(UserListCommand),
    Passphrase(UserPassphraseCommand),
    Remove(UserRemoveCommand),
    Tag(UserTagCommand),
    Untag(UserUntagCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Add a user",
    long_about = format!("Add a user

Adds a new user by providing a real name and a user role.
If no user name is provided specifically, a random one is generated automatically by the target device.
If no passphrase is provided, it is prompted for interactively.

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct UserAddCommand {
    #[arg(
        env = "NETHSM_REAL_NAME",
        help = "The real name of the user that is created",
        long_help = "The real name of the user that is created

This name is only used for further identification, but not for authentication!"
    )]
    pub real_name: String,

    #[arg(
        env = "NETHSM_USER_ROLE",
        help = "The role of the user that is created",
        long_help = format!("The role of the user that is created

One of {:?} (defaults to \"{:?}\").", UserRole::iter().map(Into::into).collect::<Vec<&'static str>>(), UserRole::default())
    )]
    pub role: Option<UserRole>,

    #[arg(
        env = "NETHSM_USER_NAME",
        help = "A unique name for the user that is created",
        long_help = "A unique name for the user that is created

This name must be unique as it is used for authentication!"
    )]
    pub name: Option<String>,

    #[arg(
        env = "NETHSM_PASSPHRASE_FILE",
        help = "The path to a file containing the new user's passphrase",
        long_help = "The path to a file containing the new user's passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short
    )]
    pub passphrase_file: Option<PassphraseFile>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get information about a user",
    long_about = format!("Get information about a user

Retrieves the real name and role of a user.
If the user is in the \"{:?}\" role, also displays tags that are assigned to the user.

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", UserRole::Operator, SystemState::Operational, UserRole::Administrator),
)]
pub struct UserGetCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The unique name of a user on the target device"
    )]
    pub name: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "List all user names",
    long_about = format!("List all user names

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct UserListCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Set the passphrase for a user",
    long_about = format!("Set the passphrase for a user

If no passphrase is provided specifically, it is prompted for interactively.

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct UserPassphraseCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user on the target device"
    )]
    pub name: String,

    #[arg(
        env = "NETHSM_PASSPHRASE_FILE",
        help = "The path to a file containing the user's new passphrase",
        long_help = "The path to a file containing the user's new passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short
    )]
    pub passphrase_file: Option<PassphraseFile>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Remove a user",
    long_about = format!("Remove a user

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct UserRemoveCommand {
    #[arg(env = "NETHSM_USER_NAME", help = "The name of the user to remove")]
    pub name: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Add a tag to a user",
    long_about = format!("Add a tag to a user

Tags provide access to keys for users.
Keys that carry identical tags to that of a user, are accessible for the user.

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct UserTagCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user for which to add a tag"
    )]
    pub name: String,

    #[arg(env = "NETHSM_USER_TAG", help = "The tag to add for a user")]
    pub tag: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Remove a tag from a user",
    long_about = format!("Remove a tag from a user

Tags provide access to keys for users.
Removing a tag from a user removes its access to keys that carry identical tags.

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct UserUntagCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user from which to remove a tag"
    )]
    pub name: String,

    #[arg(env = "NETHSM_USER_TAG", help = "The tag to remove from a user")]
    pub tag: String,
}
