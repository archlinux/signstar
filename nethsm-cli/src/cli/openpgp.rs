use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use nethsm::{KeyId, UserRole};

#[derive(Debug, Subcommand)]
#[command(
    about = "OpenPGP operations",
    long_about = "OpenPGP operations

Supports creating OpenPGP certificates for existing keys, as well as cryptographic
operations using those keys."
)]
pub enum OpenPgpCommand {
    Add(OpenPgpAddCommand),
    Import(OpenPgpImportCommand),
    Sign(OpenPgpSignCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Add an OpenPGP certificate for a key",
    long_about = format!("Add an OpenPGP certificate for a key

Creates an OpenPGP certificate for an existing key.
The created certificate is then added as the key's certificate (see `nethsm key cert import`).
Requires authentication of a user in the \"{}\" role, that has access to the targeted key.
Additionally, authentication of a user in the \"{}\" role is needed to import the certificate."
    ,UserRole::Operator
    ,UserRole::Administrator
    )
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
    long_about = format!("Create an OpenPGP signature for a message

The signature is written to stdout, unless a specific path to a file is provided.

Requires authentication of a user in the \"{}\" role that has access to the targeted key.", UserRole::Operator)
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
    long_about = format!("Import OpenPGP TSK-formatted private key

Only TSKs with a single component key are supported.

Requires authentication of a user in the \"{}\" role that has access to the targeted key.", UserRole::Administrator)
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
