use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use expression_format::ex_format;
use nethsm::{
    KeyId,
    UserRole::{Administrator, Operator},
};

use super::BIN_NAME;

#[derive(Debug, Subcommand)]
#[command(
    about = "OpenPGP operations",
    long_about = ex_format!("OpenPGP operations

Supports creating OpenPGP certificates for existing keys, as well as cryptographic operations using those keys.

Keys may exist in specific scopes: system-wide or in namespaces (see \"{BIN_NAME} namespace\").
While system-wide users only have access to system-wide keys, namespaced users only have access to keys in their own namespace.")
)]
pub enum OpenPgpCommand {
    Add(OpenPgpAddCommand),
    Import(OpenPgpImportCommand),
    Sign(OpenPgpSignCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Add an OpenPGP certificate for a key",
    long_about = ex_format!("Add an OpenPGP certificate for a key

Creates an OpenPGP certificate for an existing key.
The created certificate is then added as the key's certificate (see \"{BIN_NAME} key cert import\").

System-wide users in the \"{Administrator}\" and \"{Operator}\" role can only add OpenPGP certificates for system-wide keys.
Namespaced users in the \"{Administrator}\" and \"{Operator}\" role can only add OpenPGP certificates for keys in their own namespace.

Requires authentication of a user in the \"{Operator}\" role, that has access to the targeted key (see \"{BIN_NAME} key tag\" and \"{BIN_NAME} user tag\").
Additionally, authentication of a user in the \"{Administrator}\" role is needed to import the certificate.")
)]
pub struct OpenPgpAddCommand {
    #[arg(env = "NETHSM_KEY_ID", help = "The ID of the key to use")]
    pub key_id: KeyId,

    #[arg(env = "NETHSM_OPENPGP_USERID", help = "The User ID to use for the key")]
    pub user_id: String,

    #[arg(
        env = "NETHSM_OPENPGP_CREATED_AT",
        help = "The optional creation time of the certificate (defaults to now)",
        long,
        short
    )]
    pub time: Option<DateTime<Utc>>,

    #[arg(
        env = "NETHSM_OPENPGP_CERT_GENERATE_CAN_SIGN",
        help = "Sets the signing key flag (default to set)",
        long_help = "Sets the signing key flag (default to set)

If this option is used, the key is created with a component key that has the signing key flag set.",
        group = "sign-group",
        long,
        default_value_t = true
    )]
    pub can_sign: bool,

    #[arg(
        env = "NETHSM_OPENPGP_CERT_GENERATE_CANNOT_SIGN",
        help = "Clears the signing key flag",
        long_help = "Clears the signing key flag

If this option is used, the key is created without a component key that has the signing key flag set.",
        group = "sign-group",
        long
    )]
    pub cannot_sign: bool,
}

#[derive(Debug, Parser)]
#[command(
    about = "Create an OpenPGP signature for a message",
    long_about = ex_format!("Create an OpenPGP signature for a message

The signature is written to stdout, unless a specific path to a file is provided.

System-wide users in the \"{Operator}\" role can only create OpenPGP signatures for a message using system-wide keys.
Namespaced users in the \"{Operator}\" role can only create OpenPGP signatures for a message using keys in their own namespace.

Requires authentication of a user in the \"{Operator}\" role that has access to the targeted key (see \"{BIN_NAME} key tag\" and \"{BIN_NAME} user tag\").")
)]
pub struct OpenPgpSignCommand {
    #[arg(env = "NETHSM_KEY_ID", help = "The ID of the key to use")]
    pub key_id: KeyId,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_OPENPGP_SIGNATURE_MESSAGE",
        help = "The path to a message for which to create a signature"
    )]
    pub message: PathBuf,

    #[arg(
        env = "NETHSM_OPENPGP_SIGNATURE_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Import OpenPGP TSK-formatted private key",
    long_about = ex_format!("Import OpenPGP Transferable Secret Key (TSK) formatted private key

Only TSKs with a single component key are supported.

System-wide users in the \"{Administrator}\" role can only import TSKs as system-wide keys.
Namespaced users in the \"{Administrator}\" role can only import TSKs as keys in their own namespace.

Note: Although assigning tags to the new key is optional, it is highly recommended as not doing so means that all users in the same scope have access to it!

Requires authentication of a user in the \"{Administrator}\" role.")
)]
pub struct OpenPgpImportCommand {
    #[arg(
        env = "NETHSM_OPENPGP_TSK_FILE",
        help = "The path to the Transferable Secret Key file to import"
    )]
    pub tsk_file: PathBuf,

    #[arg(
        env = "NETHSM_OPENPGP_KEY_ID",
        help = "An optional unique ID that is assigned to the imported key",
        long_help = "An optional unique ID that is assigned to the imported key

If none is provided a generic one is generated for the key.",
        long,
        short
    )]
    pub key_id: Option<KeyId>,

    #[arg(
        env = "NETHSM_OPENPGP_KEY_TAGS",
        help = "An optional list of tags that are assigned to the imported key",
        long_help = "An optional list of tags that are assigned to the imported key

Tags on keys are used to grant access to those keys for users that carry the same tags.",
        long,
        short
    )]
    pub tags: Option<Vec<String>>,
}
