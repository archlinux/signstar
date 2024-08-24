use clap::{Parser, Subcommand};
use nethsm::{NamespaceId, SystemState, UserRole};

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
    Add(NamespaceAddCommand),
    List(NamespaceListCommand),
    Remove(NamespaceRemoveCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Add a namespace",
    long_about = format!("Add a namespace

Adds a new namespace by providing a unique name.

**WARNING**: Make sure to *first* create a user in the \"{}\" role for a namespace using \"nethsm user add\".
Only afterwards add the namespace, as otherwise the new namespace does not have an administrative user!

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.",
        UserRole::Administrator,
        SystemState::Operational,
        UserRole::Administrator
    ),
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
    long_about = format!("List all namespace names

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct NamespaceListCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Remove a namespace",
    long_about = format!("Remove a namespace

**WARNING**: This command deletes **all keys** in the targeted namespace.
It is strongly advised to first create a backup using \"nethsm system backup\" before running this command.

The device must be in state \"{:?}\".

Requires authentication of a user in the \"{}\" role.", SystemState::Operational, UserRole::Administrator),
)]
pub struct NamespaceRemoveCommand {
    #[arg(
        env = "NETHSM_NAMESPACE_NAME",
        help = "The name of the namespace to remove"
    )]
    pub name: NamespaceId,
}
