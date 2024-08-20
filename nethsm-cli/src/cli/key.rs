use std::path::PathBuf;

use clap::{Parser, Subcommand};
use nethsm::{DecryptMode, EncryptMode, KeyFormat, KeyMechanism, KeyType, SignatureType, UserRole};
use strum::IntoEnumIterator;

#[derive(Debug, Subcommand)]
#[command(
    about = "Operate on the keys of a device",
    long_about = "Operate on the keys of a device

Supports all relevant cryptographic operations (decrypt, encrypt, sign), certificate handling, importing, generation and ACL management."
)]
pub enum KeyCommand {
    #[command(subcommand)]
    Cert(KeyCertCommand),
    Csr(KeyCsrCommand),
    Decrypt(KeyDecryptCommand),
    Encrypt(KeyEncryptCommand),
    Generate(KeyGenerateCommand),
    Get(KeyGetCommand),
    Import(KeyImportCommand),
    List(KeyListCommand),
    PublicKey(KeyPublicKeyCommand),
    Remove(KeyRemoveCommand),
    Sign(KeySignCommand),
    Tag(KeyTagCommand),
    Untag(KeyUntagCommand),
}

#[derive(Debug, Subcommand)]
#[command(
    about = "Operate on certificates for a key",
    long_about = "Operate on certificates for a key

Supports certificate retrieval, removal and import."
)]
pub enum KeyCertCommand {
    Delete(KeyCertDeleteCommand),
    Get(KeyCertGetCommand),
    Import(KeyCertImportCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Delete the certificate for a key",
    long_about = format!("Delete the certificate for a key

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct KeyCertDeleteCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key, for which to delete the certificate"
    )]
    pub key_id: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get the certificate for a key",
    long_about = format!("Get the certificate for a key

The NetHSM backend can store binary data as the certificate and offers no guarantee for the certificate to be of any particular format.

The `nethsm openpgp add` command sets the certificate to a newly generated OpenPGP certificate.

Unless a specific output file is specified, the certificate is written to stdout.

Requires authentication of a user in the \"{}\" or \"{}\" role.", UserRole::Administrator, UserRole::Operator)
)]
pub struct KeyCertGetCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key, for which to retrieve the certificate"
    )]
    pub key_id: String,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_KEY_CERT_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Import the certificate for a key",
    long_about = format!("Import the certificate for a key

The NetHSM backend can store binary data up to 1 MiB in size as certificate.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct KeyCertImportCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key, for which to import the certificate"
    )]
    pub key_id: String,

    #[arg(
        env = "NETHSM_KEY_CERT_FILE",
        help = "The path to the certificate file to import"
    )]
    pub cert_file: PathBuf,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get a Certificate Signing Request for a key",
    long_about = format!("Get a Certificate Signing Request for a key

The PKCS#10 Certificate Signing Request (CSR) is returned in Privacy-enhanced Electronic Mail (PEM) format.
Unless a specific output file is chosen, the certificate is returned on stdout.

At a minimum, the \"Common Name\" (CN) attribute for the CSR has to be provided.

Requires authentication of a user in the \"{}\" or \"{}\" role.", UserRole::Administrator, UserRole::Operator)
)]
pub struct KeyCsrCommand {
    #[arg(env = "NETHSM_KEY_ID", help = "The key ID for which to create a CSR")]
    pub key_id: String,

    #[arg(
        env = "NETHSM_KEY_CSR_COMMON_NAME",
        help = "The mandatory \"Common Name\" (CN) attribute for the CSR",
        long_help = "The mandatory \"Common Name\" (CN) attribute for the CSR

A fully qualified domain name (FQDN) that should be secured using the CSR."
    )]
    pub common_name: String,

    #[arg(
        env = "NETHSM_KEY_CSR_ORG_NAME",
        help = "The optional \"Organization Name\" (O) attribute for the CSR",
        long_help = "The optional \"Organization Name\" (O) attribute for the CSR

Usually the legal name of a company or entity and should include any suffixes such as Ltd., Inc., or Corp."
    )]
    pub org_name: Option<String>,

    #[arg(
        env = "NETHSM_KEY_CSR_ORG_UNIT",
        help = "The optional \"Organizational Unit\" (OU) attribute for the CSR",
        long_help = "The optional \"Organizational Unit\" (OU) attribute for the CSR

Internal organization department/division name."
    )]
    pub org_unit: Option<String>,

    #[arg(
        env = "NETHSM_KEY_CSR_LOCALITY",
        help = "The optional \"Locality\" (L) attribute for the CSR",
        long_help = "The optional \"Locality\" (L) attribute for the CSR

Name of town, city, village, etc."
    )]
    pub locality: Option<String>,

    #[arg(
        env = "NETHSM_KEY_CSR_STATE",
        help = "The optional \"State\" (ST) attribute for the CSR",
        long_help = "The optional \"State\" (ST) attribute for the CSR

Province, region, county or state."
    )]
    pub state: Option<String>,

    #[arg(
        env = "NETHSM_KEY_CSR_COUNTRY",
        help = "The optional \"Country\" (C) attribute for the CSR",
        long_help = "The optional \"Country\" (C) attribute for the CSR

The two-letter ISO code for the country where the \"Organization\" (O) is located."
    )]
    pub country: Option<String>,

    #[arg(
        env = "NETHSM_KEY_CSR_EMAIL",
        help = "The optional \"Email Address\" (EMAIL) attribute for the CSR",
        long_help = "The optional \"Email Address\" (EMAIL) attribute for the CSR

The organization contact, usually of the certificate administrator or IT department."
    )]
    pub email: Option<String>,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_KEY_CSR_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Decrypt a message using a key",
    long_about = format!("Decrypt a message using a key

The chosen decryption mode must match the targeted key and the initialization vector (if applicable) must be identical to the one used for encryption.

Requires authentication of a user in the \"{}\" role that has access to the targeted key.", UserRole::Operator)
)]
pub struct KeyDecryptCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key to use for decryption"
    )]
    pub key_id: String,

    #[arg(
        env = "NETHSM_KEY_DECRYPT_MESSAGE",
        help = "The path to an encrypted message to decrypt"
    )]
    pub message: PathBuf,

    #[arg(
        env = "NETHSM_KEY_DECRYPT_MODE",
        help = "The decryption mode to use",
        long_help = format!("The decryption mode to use

One of {:?} (defaults to \"{:?}\").", DecryptMode::iter().map(Into::into).collect::<Vec<&'static str>>(), DecryptMode::default())
    )]
    pub decrypt_mode: Option<DecryptMode>,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_KEY_DECRYPT_IV",
        help = "The path to a file containing the initialization vector (IV) for symmetric decryption",
        long_help = format!("The path to a file containing the initialization vector (IV) for symmetric decryption

The IV can only be used when choosing symmetric decryption (i.e. with \"{:?}\")", DecryptMode::AesCbc),
        long,
        short
    )]
    pub initialization_vector: Option<PathBuf>,

    #[arg(
        env = "NETHSM_KEY_DECRYPT_OUTPUT",
        help = "The path to a specific file to write the decrypted message to",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Encrypt a message using a key",
    long_about = format!("Encrypt a message using a key

Only symmetric encryption is supported.

Requires authentication of a user in the \"{}\" role that has access to the targeted key.", UserRole::Operator)
)]
pub struct KeyEncryptCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key to use for encryption"
    )]
    pub key_id: String,

    #[arg(
        env = "NETHSM_KEY_ENCRYPT_MESSAGE",
        help = "The path to a message to encrypt"
    )]
    pub message: PathBuf,

    #[arg(
        env = "NETHSM_KEY_ENCRYPT_MODE",
        help = "The encryption mode to use",
        long_help = format!("The encryption mode to use

One of {:?} (defaults to \"{:?}\").", EncryptMode::iter().map(Into::into).collect::<Vec<&'static str>>(), EncryptMode::default())
    )]
    pub encrypt_mode: Option<EncryptMode>,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_KEY_ENCRYPT_IV",
        help = "The path to a file containing the initialization vector (IV) for symmetric encryption",
        long_help = format!("The path to a file containing the initialization vector (IV) for symmetric encryption

The IV can only be used when choosing symmetric encryption (i.e. with \"{:?}\")", EncryptMode::AesCbc),
        long,
        short
    )]
    pub initialization_vector: Option<PathBuf>,

    #[arg(
        env = "NETHSM_KEY_ENCRYPT_OUTPUT",
        help = "The path to a specific file to write the encrypted message to",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Generate a new key",
    long_about = format!("Generate a new key

The provided key type and list of key mechanisms have to match:
* \"{}\" requires one of {:?}
* \"{}\" requires one of {:?}
* \"{}\", \"{}\", \"{}\" and \"{}\" require one of {:?}
* \"{}\" requires at least one of {:?}

Requires authentication of a user in the \"{}\" role.",
        KeyType::Rsa,
        KeyMechanism::rsa_mechanisms(),
        KeyType::Curve25519,
        KeyMechanism::curve25519_mechanisms(),
        KeyType::EcP224,
        KeyType::EcP256,
        KeyType::EcP384,
        KeyType::EcP521,
        KeyMechanism::elliptic_curve_mechanisms(),
        KeyType::Generic,
        KeyMechanism::generic_mechanisms(),
        UserRole::Administrator
    )
)]
pub struct KeyGenerateCommand {
    #[arg(
        env = "NETHSM_KEY_TYPE",
        help = "The optional type of key to generate",
        long_help = format!("The optional type of key to generate

The key type must match the chosen key mechanisms!

One of {:?} (defaults to \"{:?}\").",
            KeyType::iter().map(Into::into).collect::<Vec<&'static str>>(),
            KeyType::default()),
    )]
    pub key_type: Option<KeyType>,

    #[arg(
        env = "NETHSM_KEY_MECHANISMS",
        help = "The mechanisms provided by the generated key",
        long_help = format!("The mechanisms provided by the generated key

The key mechanisms must match the chosen key type!

At least one of {:?} (defaults to \"{:?}\").",
            KeyMechanism::iter().map(Into::into).collect::<Vec<&'static str>>(),
            KeyMechanism::default()),
    )]
    pub key_mechanisms: Vec<KeyMechanism>,

    #[arg(
        env = "NETHSM_KEY_BIT_LENGTH",
        help = "The optional bit length of the generated key",
        long_help = "The optional bit length of the generated key

If none is provided, a default is chosen.",
        long,
        short = 'L'
    )]
    pub length: Option<i32>,

    #[arg(
        env = "NETHSM_KEY_ID",
        help = "An optional unique ID that is assigned to the generated key",
        long_help = "An optional unique ID that is assigned to the generated key

If none is provided a generic one is generated for the key.",
        long,
        short
    )]
    pub key_id: Option<String>,

    #[arg(
        env = "NETHSM_KEY_TAGS",
        help = "An optional list of tags that are assigned to the generated key",
        long_help = "An optional list of tags that are assigned to the generated key

Tags on keys are used to grant access to those keys for users that carry the same tags.",
        long,
        short
    )]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get information on a key",
    long_about = format!("Get information on a key

Displays information on supported key mechanisms, the key type, which restrictions apply (i.e. which tags are set for the key), information on the public key part and how many operations have been done with the key.

Requires authentication of a user in the \"{}\" or \"{}\" role.", UserRole::Administrator, UserRole::Operator)
)]
pub struct KeyGetCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key, for which to show information for"
    )]
    pub key_id: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Import a key",
    long_about = format!("Import a key

The provided key data must be provided as PKCS#8 private key in ASN.1 DER-encoded format.
The key data must match the provided key type.

The provided key type and list of key mechanisms have to match:
* \"{}\" requires one of {:?}
* \"{}\" requires one of {:?}
* \"{}\", \"{}\", \"{}\" and \"{}\" require one of {:?}
* \"{}\" requires at least one of {:?}

Requires authentication of a user in the \"{}\" role.",
        KeyType::Rsa,
        KeyMechanism::rsa_mechanisms(),
        KeyType::Curve25519,
        KeyMechanism::curve25519_mechanisms(),
        KeyType::EcP224,
        KeyType::EcP256,
        KeyType::EcP384,
        KeyType::EcP521,
        KeyMechanism::elliptic_curve_mechanisms(),
        KeyType::Generic,
        KeyMechanism::generic_mechanisms(),
        UserRole::Administrator
    )
)]
pub struct KeyImportCommand {
    #[arg(
        env = "NETHSM_KEY_TYPE",
        help = "The type of key to import",
        long_help = format!("The type of key to import

The key type must match the provided key data and chosen key mechanisms!

One of {:?}.",
            KeyMechanism::iter().map(Into::into).collect::<Vec<&'static str>>()),
    )]
    pub key_type: KeyType,

    #[arg(
        env = "NETHSM_KEY_FORMAT",
        help = "The format of key to import",
        default_value_t = KeyFormat::default(),
        long,
        long_help = format!("The format of key to import

The key type must match the provided key data and chosen key mechanisms!

One of {:?}.",
            KeyFormat::iter().map(Into::into).collect::<Vec<&'static str>>()),
    )]
    pub format: KeyFormat,

    #[arg(
        env = "NETHSM_KEY_DATA",
        help = "The path to a PKCS#8 private key in ASN.1 DER-encoded format",
        long_help = "The path to a PKCS#8 private key in ASN.1 DER-encoded format

The private key data must match the chosen key type."
    )]
    pub key_data: PathBuf,

    #[arg(
        env = "NETHSM_KEY_MECHANISMS",
        help = "The mechanisms provided by the imported key",
        long_help = format!("The mechanisms provided by the imported key

The key mechanisms must match the chosen key type!

At least one of {:?}.",
            KeyMechanism::iter().map(Into::into).collect::<Vec<&'static str>>()),
    )]
    pub key_mechanisms: Vec<KeyMechanism>,

    #[arg(
        env = "NETHSM_KEY_ID",
        help = "An optional unique ID that is assigned to the imported key",
        long_help = "An optional unique ID that is assigned to the imported key

If none is provided a generic one is generated for the key.",
        long,
        short
    )]
    pub key_id: Option<String>,

    #[arg(
        env = "NETHSM_KEY_TAGS",
        help = "An optional list of tags that are assigned to the imported key",
        long_help = "An optional list of tags that are assigned to the imported key

Tags on keys are used to grant access to those keys for users that carry the same tags.",
        long,
        short
    )]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Parser)]
#[command(
    about = "List all key IDs",
    long_about = format!("List all key IDs

Optionally filter the list of key IDs by a keyword.

Requires authentication of a user in the \"{}\" or \"{}\" role.", UserRole::Administrator, UserRole::Operator)
)]
pub struct KeyListCommand {
    #[arg(
        env = "NETHSM_KEY_ID_FILTER",
        help = "A filter to apply to the list of key IDs"
    )]
    pub filter: Option<String>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get the public key for a key",
    long_about = format!("Get the public key for a key

The public key is returned as X.509 public key certificate in Privacy-enhanced Electronic Mail (PEM) format.
If no specific output file is chosen, the public key is emitted on stdout.

Note: Keys of type \"{:?}\" do not have a public key and this command fails for them!

Requires authentication of a user in the \"{}\" or \"{}\" role.",
        KeyType::Generic,
        UserRole::Administrator,
        UserRole::Operator,
    )

)]
pub struct KeyPublicKeyCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key to get the public key for"
    )]
    pub key_id: String,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_KEY_PUBKEY_OUTPUT_FILE",
        help = "The optional path to a specific output file",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Remove a key",
    long_about = format!("Remove a key

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct KeyRemoveCommand {
    #[arg(env = "NETHSM_KEY_ID", help = "The ID of the key that is removed")]
    pub key_id: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Sign a message using a key",
    long_about = format!("Sign a message using a key

The targeted key must be equipped with relevant key mechanisms for signing.
The chosen signature type must match the target key type and key mechanisms.

If no specific output file is chosen, the signature is written to stdout.

Requires authentication of a user in the \"{}\" role with access to the target key.", UserRole::Operator)
)]
pub struct KeySignCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key to use for signing the message"
    )]
    pub key_id: String,

    #[arg(
        env = "NETHSM_KEY_SIGNATURE_TYPE",
        help = "The signature type to use for the signature",
        long_help = format!("The signature type to use for the signature

One of {:?}", SignatureType::iter().map(Into::into).collect::<Vec<&'static str>>()),
    )]
    pub signature_type: SignatureType,

    #[arg(
        env = "NETHSM_KEY_SIGNATURE_MESSAGE",
        help = "The path to a message for which to create a signature"
    )]
    pub message: PathBuf,

    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_KEY_SIGNATURE_OUTPUT_FILE",
        help = "The optional path to a specific file that the signature is written to",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Tag a key",
    long_about = format!("Tag a key

Tags are used to grant access to keys for users in the \"{}\" role.
If users are tagged with an identical tag, they are able to use a given key.

Tags on keys must be created before creating tags on users.

Requires authentication of a user in the \"{}\" role.",
        UserRole::Operator,
        UserRole::Administrator,
    )
)]
pub struct KeyTagCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key for which a tag is added"
    )]
    pub key_id: String,
    #[arg(env = "NETHSM_KEY_TAG", help = "The tag to add to the key")]
    pub tag: String,
}

#[derive(Debug, Parser)]
#[command(
    about = "Untag a key",
    long_about = format!("Untag a key

Removes access to the key for users in the \"{}\" role with an identical tag.

Requires authentication of a user in the \"{}\" role.", UserRole::Operator, UserRole::Administrator)
)]
pub struct KeyUntagCommand {
    #[arg(
        env = "NETHSM_KEY_ID",
        help = "The ID of the key for which a tag is removed"
    )]
    pub key_id: String,
    #[arg(env = "NETHSM_KEY_TAG", help = "The tag to remove from the key")]
    pub tag: String,
}
