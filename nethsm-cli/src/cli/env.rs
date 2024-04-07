// SPDX-FileCopyrightText: 2024 David Runge <dvzrv@archlinux.org>
// SPDX-License-Identifier: Apache-2.0 OR MIT

use clap::{Parser, Subcommand};
use nethsm::{ConnectionSecurity, Url, UserRole};
use strum::IntoEnumIterator;

use crate::passphrase_file::PassphraseFile;

#[derive(Debug, Subcommand)]
#[command(about = "Manage environments in the configuration file")]
pub enum EnvCommand {
    #[command(subcommand)]
    Add(EnvAddCommand),

    #[command(subcommand)]
    Delete(EnvDeleteCommand),

    #[command(about = "List all items in the configuration file")]
    List,
}

#[derive(Debug, Subcommand)]
#[command(
    about = "Add a configuration item",
    long_about = "Add a configuration item

Add a new device, or credentials for an existing one."
)]
pub enum EnvAddCommand {
    Credentials(CredentialsAddCommand),
    Device(DeviceAddCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Add credentials for a device in the configuration",
    long_about = "Add credentials for a device in the configuration

By default credentials in the configuration file only contain user name and role.
In this scenario the passphrase of a user is prompted for interactively, once it is needed.

Optionally, it is possible to also persist a passphrase for a given user name to allow non-interactive use.
This use is discouraged as it persists the passphrase in an unencrypted configuration file."
)]
pub struct CredentialsAddCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The name of the user on the target device"
    )]
    pub name: String,

    #[arg(
        env = "NETHSM_PASSPHRASE_FILE",
        help = "The path to a file containing the passphrase",
        long,
        short
    )]
    pub passphrase_file: Option<PassphraseFile>,

    #[arg(
        env = "NETHSM_USER_ROLE",
        help = "The optional role of the user on the target device",
        long_help = format!("The optional role of the user on the target device

One of {:?} (defaults to \"{}\").", UserRole::iter().map(Into::into).collect::<Vec<&'static str>>(), UserRole::default())
    )]
    pub role: Option<UserRole>,

    #[arg(
        env = "NETHSM_WITH_PASSPHRASE",
        help = "Whether to prompt for and store a passphrase for the user",
        long_help = "Whether to prompt for and store a passphrase for the user

The passphrase is persisted in the configuration file. Use with caution!",
        long,
        short
    )]
    pub with_passphrase: bool,
}

#[derive(Debug, Parser)]
#[command(
    about = "Add a device to the configuration",
    long_about = "Add a device to the configuration

Device entries are added with a URL and settings for the TLS connection security.

For this command it is required to provide a label that identifies the device."
)]
pub struct DeviceAddCommand {
    #[arg(env = "NETHSM_URL", help = "The URL of the device API")]
    pub url: Url,

    #[arg(
        env = "NETHSM_TLS_SECURITY",
        help = "The TLS connection security for the device",
        long_help = format!("The TLS connection security for the device

One of the following:
* \"{:?}\": the TLS connection is not validated by authenticating the target host certificate
* \"{:?}\": the TLS connection is validated by authenticating the target host certificate against the caller's native system-wide certificate store
* the pinned SHA-256 checksum of the target host key (prefixed with \"sha256:\") is used to validate the target host certificate", ConnectionSecurity::Unsafe, ConnectionSecurity::Native),
    )]
    pub tls_security: ConnectionSecurity,
}

#[derive(Debug, Subcommand)]
#[command(
    about = "Delete a configuration item",
    long_about = "Delete a configuration item

Delete credentials for an existing device or a device."
)]
pub enum EnvDeleteCommand {
    Credentials(CredentialsDeleteCommand),
    Device(DeviceDeleteCommand),
}

#[derive(Debug, Parser)]
#[command(about = "Delete credentials for a device")]
pub struct CredentialsDeleteCommand {
    #[arg(
        env = "NETHSM_USER_NAME",
        help = "The user name matching the credentials to be deleted"
    )]
    pub name: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Delete a device",
    long_about = "Delete a device from the configuration

For this command it is required to provide a label that identifies the device."
)]
pub struct DeviceDeleteCommand {}
