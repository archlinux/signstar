use clap::{Parser, Subcommand};
use expression_format::ex_format;
use nethsm::{
    SystemState::Operational,
    UserId,
    UserRole::{self, Administrator, Operator},
};
use strum::IntoEnumIterator;

use super::BIN_NAME;
use crate::passphrase_file::PassphraseFile;

#[derive(Debug, Subcommand)]
#[command(
    about = "Operate on users of a device",
    long_about = ex_format!("Operate on users of a device

Allows to add and remove users, retrieve information about them, set their passphrases and set or unset tags for them.

Users may exist in specific scopes: system-wide or in namespaces (see \"{BIN_NAME} namespace\").
The use of a namespace is indicated by a prefix in the user name (e.g. the user name \"namespace1~user1\" indicates that the user is in \"namespace1\").
Users in a namespace can only be administrated by users in the \"{Administrator}\" role in that same namespace.
System-wide users can only be administratred by system-wide users in the \"{Administrator}\" role.")
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
    long_about = ex_format!("Add a user

Adds a new user by providing a real name and a user role.
If no user name is provided specifically, a random one is generated automatically by the target device.
If no passphrase is provided, it is prompted for interactively.

New users inherit the scope of the user that created them.
If a system-wide user in the \"{Administrator}\" role creates a new user (e.g. \"user1\"), then that new user is also a system-wide user.
As exception to this rule, a system-wide user in the \"{Administrator}\" role can create namespaced users by providing a user name specifically (e.g. \"namespace1~user1\"), but only if the targeted namespace (i.e. \"namespace1\") does not yet exist (see \"{BIN_NAME} namespace add\").
If a namespaced user in the \"{Administrator}\" role creates a new user, then that new user is also a user in that namespace.
If a namespaced user in the \"{Administrator}\" role (e.g. \"namespace1~admin1\") provides a specific user name, it must be in that same namespace (e.g. \"namespace1~user1\", not \"namespace2~user1\")!

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
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
    pub name: Option<UserId>,

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
    long_about = ex_format!("Get information about a user

Retrieves the real name and role of a user.
If the user is in the \"{Operator}\" role, also displays tags that are assigned to the user.

System-wide users in the \"{Administrator}\" role have access to information of system-wide and namespaced users.
Namespaced users in the \"{Administrator}\" role only have access to information of users in the same namespace.

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UserGetCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The unique name of a user on the target device"
    )]
    pub name: UserId,
}

#[derive(Debug, Parser)]
#[command(
    about = "List all user names",
    long_about = ex_format!("List all user names

System-wide users in the \"{Administrator}\" role can list system-wide and namespaced users.
Namespaced users in the \"{Administrator}\" role can only list users in the same namespace.

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UserListCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Set the passphrase for a user",
    long_about = ex_format!("Set the passphrase for a user

If no passphrase is provided specifically, it is prompted for interactively.

System-wide users in the \"{Administrator}\" role can only set the passphrase for system-wide users.
Namespaced users in the \"{Administrator}\" role can only set the passphrase for users in the same namespace.

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UserPassphraseCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user on the target device"
    )]
    pub name: UserId,

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
    long_about = ex_format!("Remove a user

System-wide users in the \"{Administrator}\" role can only remove system-wide users.
As an exception to this rule, system-wide users in the \"{Administrator}\" role can delete users in a namespace, if the namespace is removed first (see \"{BIN_NAME} namespace remove\").
Namespaced users in the \"{Administrator}\" role can only remove users in the same namespace.

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UserRemoveCommand {
    #[arg(env = "NETHSM_USER_NAME", help = "The name of the user to remove")]
    pub name: UserId,
}

#[derive(Debug, Parser)]
#[command(
    about = "Add a tag to a user",
    long_about = ex_format!("Add a tag to a user

Tags provide access to keys for users.
Keys that carry identical tags to that of a user, are accessible for the user.
Tags on a key must exist (see \"{BIN_NAME} key tag\") before an identical tag can be added to a user.

System-wide users in the \"{Administrator}\" role can only add tags for system-wide users in the \"{Operator}\" role.
Namespaced users in the \"{Administrator}\" role can only add tags for users in the \"{Operator}\" role in the same namespace.

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UserTagCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user for which to add a tag"
    )]
    pub name: UserId,

    #[arg(env = "NETHSM_USER_TAG", help = "The tag to add for a user")]
    pub tag: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Remove a tag from a user",
    long_about = ex_format!("Remove a tag from a user

Tags provide access to keys for users.
Removing a tag from a user removes its access to keys that carry identical tags.

System-wide users in the \"{Administrator}\" role can only remove tags for system-wide users in the \"{Operator}\" role.
Namespaced users in the \"{Administrator}\" role can only remove tags for users in the \"{Operator}\" role in the same namespace.

The device must be in state \"{:?Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct UserUntagCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user from which to remove a tag"
    )]
    pub name: UserId,

    #[arg(env = "NETHSM_USER_TAG", help = "The tag to remove from a user")]
    pub tag: String,
}
