use clap::{Parser, Subcommand};
use expression_format::ex_format;
use nethsm::{NamespaceId, SystemState::Operational, UserRole::Administrator};

use super::BIN_NAME;

/// The "nethsm namespace" command.
#[derive(Debug, Subcommand)]
#[command(
    about = "Operate on namespaces of a device",
    long_about = "Operate on namespaces of a device

Allows to add, list and remove namespaces.

Namespaces are a way to segregate users and keys.
Users in a namespace only have access to the keys in their own namespace.
"
)]
pub enum NamespaceCommand {
    /// The "nethsm namespace add" command.
    Add(NamespaceAddCommand),
    /// The "nethsm namespace list" command.
    List(NamespaceListCommand),
    /// The "nethsm namespace remove" command.
    Remove(NamespaceRemoveCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Add a namespace",
    long_about = ex_format!("Add a namespace

Adds a new namespace by providing a unique name.

**WARNING**: Make sure to *first* create a user in the \"{Administrator}\" role for a namespace using \"{BIN_NAME} user add\".
Only afterwards add the namespace, as otherwise the new namespace does not have an administrative user!

The device must be in state \"{Operational}\".

Requires authentication of a user in the \"{Administrator}\" role."),
)]
pub struct NamespaceAddCommand {
    #[arg(
        env = "NETHSM_NAMESPACE_NAME",
        help = "The name of the namespace that is created"
    )]
    pub name: NamespaceId,
}

#[derive(Debug, Parser)]
#[command(
    about = "List all namespace names",
    long_about = ex_format!("List all namespace names

The device must be in state \"{Operational}\".

Requires authentication of a system-wide user in the \"{Administrator}\" role."),
)]
pub struct NamespaceListCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Remove a namespace",
    long_about = ex_format!("Remove a namespace

**WARNING**: This command deletes **all keys** in the targeted namespace.
It is strongly advised to first create a backup using \"{BIN_NAME} system backup\" before running this command.

The device must be in state \"{Operational}\".

Requires authentication of a system-wide user in the \"{Administrator}\" role."),
)]
pub struct NamespaceRemoveCommand {
    #[arg(
        env = "NETHSM_NAMESPACE_NAME",
        help = "The name of the namespace to remove"
    )]
    pub name: NamespaceId,
}
