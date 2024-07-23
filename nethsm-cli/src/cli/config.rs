use std::{net::Ipv4Addr, path::PathBuf};

use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use nethsm::{BootMode, LogLevel, SystemState, TlsKeyType, UserRole};
use strum::IntoEnumIterator;

use crate::passphrase_file::PassphraseFile;

#[derive(Debug, Subcommand)]
#[command(
    about = "Manage the configuration of a device",
    long_about = "Manage the configuration of a device

Allows adding, removing and listing of configuration items"
)]
pub enum ConfigCommand {
    #[command(subcommand)]
    Get(ConfigGetCommand),

    #[command(subcommand)]
    Set(ConfigSetCommand),
}

#[derive(Debug, Subcommand)]
#[command(about = "Get a configuration item for a device")]
pub enum ConfigGetCommand {
    BootMode(GetBootModeCommand),
    Logging(GetLoggingCommand),
    Network(GetNetworkCommand),
    Time(GetTimeCommand),
    TlsCertificate(GetTlsCertificateCommand),
    TlsCsr(GetTlsCsrCommand),
    TlsPublicKey(GetTlsPublicKeyCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Get the unattended boot configuration",
    long_about = format!("Get the unattended boot configuration

* \"{}\" if the device needs to be unlocked during boot
* \"{}\" if the device does not need to be unlocked during boot

Requires authentication of a user in the \"{}\" role.", BootMode::Attended, BootMode::Unattended, UserRole::Administrator)
)]
pub struct GetBootModeCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Get the logging configuration",
    long_about = format!("Get the logging configuration

Shows IP address and port number of the host the target device logs to at a given log level.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct GetLoggingCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Get the network configuration",
    long_about = format!("Get the network configuration

Shows IP address, netmask and gateway of the target device.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct GetNetworkCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Get the time",
    long_about = format!("Get the time

Returns the current time as ISO 8601 formatted timestamp.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct GetTimeCommand {}

#[derive(Debug, Parser)]
#[command(
    about = "Get the certificate for the TLS connection",
    long_about = format!("Get the certificate for the TLS connection

The X.509 certificate is returned in Privacy-enhanced Electronic Mail (PEM) format.
Unless a specific output file is chosen, the certificate is returned on stdout.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct GetTlsCertificateCommand {
    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_CONFIG_TLS_CERT_OUTPUT_FILE",
        help = "The optional path to a specific file that the certificate is written to",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get a Certificate Signing Request for the TLS certificate",
    long_about = format!("Get a Certificate Signing Request for the TLS certificate

The PKCS#10 Certificate Signing Request (CSR) is returned in Privacy-enhanced Electronic Mail (PEM) format.
Unless a specific output file is chosen, the certificate is returned on stdout.

At a minimum, the \"Common Name\" (CN) attribute for the CSR has to be provided.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct GetTlsCsrCommand {
    #[arg(
        env = "NETHSM_TLS_CSR_COMMON_NAME",
        help = "The mandatory \"Common Name\" (CN) attribute for the CSR",
        long_help = "The mandatory \"Common Name\" (CN) attribute for the CSR

A fully qualified domain name (FQDN) that should be secured using the CSR."
    )]
    pub common_name: String,

    #[arg(
        env = "NETHSM_TLS_CSR_ORG_NAME",
        help = "The optional \"Organization Name\" (O) attribute for the CSR",
        long_help = "The optional \"Organization Name\" (O) attribute for the CSR

Usually the legal name of a company or entity and should include any suffixes such as Ltd., Inc., or Corp."
    )]
    pub org_name: Option<String>,

    #[arg(
        env = "NETHSM_TLS_CSR_ORG_UNIT",
        help = "The optional \"Organizational Unit\" (OU) attribute for the CSR",
        long_help = "The optional \"Organizational Unit\" (OU) attribute for the CSR

Internal organization department/division name."
    )]
    pub org_unit: Option<String>,

    #[arg(
        env = "NETHSM_TLS_CSR_LOCALITY",
        help = "The optional \"Locality\" (L) attribute for the CSR",
        long_help = "The optional \"Locality\" (L) attribute for the CSR

Name of town, city, village, etc."
    )]
    pub locality: Option<String>,

    #[arg(
        env = "NETHSM_TLS_CSR_STATE",
        help = "The optional \"State\" (ST) attribute for the CSR",
        long_help = "The optional \"State\" (ST) attribute for the CSR

Province, region, county or state."
    )]
    pub state: Option<String>,

    #[arg(
        env = "NETHSM_TLS_CSR_COUNTRY",
        help = "The optional \"Country\" (C) attribute for the CSR",
        long_help = "The optional \"Country\" (C) attribute for the CSR

The two-letter ISO code for the country where the \"Organization\" (O) is located."
    )]
    pub country: Option<String>,

    #[arg(
        env = "NETHSM_TLS_CSR_EMAIL",
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
        env = "NETHSM_CONFIG_TLS_CSR_OUTPUT_FILE",
        help = "The optional path to a specific file that the certificate is written to",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Get the public key for the TLS connection",
    long_about = format!("Get the public key for the TLS connection

The X.509 public key certificate is returned in Privacy-enhanced Electronic Mail (PEM) format.
Unless a specific output file is chosen, the certificate is returned on stdout.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct GetTlsPublicKeyCommand {
    #[arg(
        env = "NETHSM_FORCE",
        help = "Write to output file even if it exists already",
        long,
        short
    )]
    pub force: bool,

    #[arg(
        env = "NETHSM_CONFIG_TLS_PUBKEY_OUTPUT_FILE",
        help = "The optional path to a specific file that the certificate is written to",
        long,
        short
    )]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
#[command(about = "Set a configuration item for a device")]
pub enum ConfigSetCommand {
    BackupPassphrase(SetBackupPassphraseCommand),
    BootMode(SetBootModeCommand),
    Logging(SetLoggingCommand),
    Network(SetNetworkCommand),
    Time(SetTimeCommand),
    TlsCertificate(SetTlsCertificateCommand),
    TlsGenerate(SetTlsGenerateCommand),
    UnlockPassphrase(SetUnlockPassphraseCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Set the backup passphrase",
    long_about = format!("Set the backup passphrase

The initial backup passphrase is the empty string.

The new passphrase must be >= 10 and <= 200 characters.

By default the passphrases are prompted for interactively, but they can each be provided using a dedicated passphrase file instead.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct SetBackupPassphraseCommand {
    #[arg(
        env = "NETHSM_NEW_PASSPHRASE_FILE",
        help = "The path to a file containing the new passphrase",
        long_help = "The path to a file containing the new passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short
    )]
    pub new_passphrase_file: Option<PassphraseFile>,

    #[arg(
        env = "NETHSM_OLD_PASSPHRASE_FILE",
        help = "The path to a file containing the old passphrase",
        long_help = "The path to a file containing the old passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short
    )]
    pub old_passphrase_file: Option<PassphraseFile>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Set the unattended boot mode",
    long_about = format!("Set the unattended boot mode

Sets whether the device boots into state \"{:?}\" (using boot mode \"{:?}\") or \"{:?}\" (using boot mode \"{:?}\").

Requires authentication of a user in the \"{}\" role.",
        SystemState::Locked,
        BootMode::Attended,
        SystemState::Operational,
        BootMode::Unattended,
        UserRole::Administrator
    ),
)]
pub struct SetBootModeCommand {
    #[arg(
        env = "NETHSM_BOOT_MODE",
        help = "The boot mode to use",
        long_help = format!("The boot mode to use

One of {:?} (no default).",
            BootMode::iter().map(Into::into).collect::<Vec<&'static str>>()
        )
    )]
    pub boot_mode: BootMode,
}

#[derive(Debug, Parser)]
#[command(
    about = "Set the logging configuration",
    long_about = format!("Set the logging configuration

Provide IP address and port of a host to send syslog to at a specified log level.

Requires authentication of a user in the \"{}\" role.",
        UserRole::Administrator,
    )
)]
pub struct SetLoggingCommand {
    #[arg(
        env = "NETHSM_LOGGING_IP_ADDRESS",
        help = "The IPv4 address of the host to send syslog to"
    )]
    pub ip_address: Ipv4Addr,

    #[arg(
        env = "NETHSM_LOGGING_PORT",
        help = "The port of the host to send syslog to"
    )]
    pub port: i32,

    #[arg(
        env = "NETHSM_LOGGING_LOG_LEVEL",
        help = "The log level at which to log",
        long_help = format!("The log level at which to log

One of {:?} (defaults to \"{:?}\").",
            LogLevel::iter().map(Into::into).collect::<Vec<&'static str>>(),
            LogLevel::default(),
        )
    )]
    pub log_level: Option<LogLevel>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Set the network configuration",
    long_about = format!("Set the network configuration

Provide IPv4 address, netmask and Ipv4 gateway address for the device to use.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct SetNetworkCommand {
    #[arg(
        env = "NETHSM_NETWORK_IP_ADDRESS",
        help = "The IPv4 address the device is to use"
    )]
    pub ip_address: Ipv4Addr,

    #[arg(
        env = "NETHSM_NETWORK_NETMASK",
        help = "The IPv4 netmask the device is to use"
    )]
    pub netmask: String,

    #[arg(
        env = "NETHSM_NETWORK_GATEWAY",
        help = "The IPv4 gateway the device is to use"
    )]
    pub gateway: Ipv4Addr,
}

#[derive(Debug, Parser)]
#[command(
    about = "Set the time",
    long_about = format!("Set the time

The time must be provided as ISO 8601 formatted UTC timestamp.
If no timestamp is provided, the caller's current system time is used to construct a UTC timestamp.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct SetTimeCommand {
    #[arg(
        env = "NETHSM_SYSTEM_TIME",
        help = "An optional ISO 8601 formatted UTC timestamp",
        long_help = "An optional ISO 8601 formatted UTC timestamp

If no timestamp is provided, the caller's current system time is used."
    )]
    pub system_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Set a new TLS certificate",
    long_about = format!("Set a new TLS certificate

The X.509 certificate must be provided in Privacy-enhanced Electronic Mail (PEM) format.

The certificate is only accepted if it is created using a Certificate Signing Request (CSR) generated by the target device.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct SetTlsCertificateCommand {
    #[arg(
        env = "NETHSM_TLS_CERT",
        help = "A new TLS certificate file",
        long_help = "A new TLS certificate file

The X.509 certificate must be provided in Privacy-enhanced Electronic Mail (PEM) format."
    )]
    pub tls_cert: PathBuf,
}

#[derive(Debug, Parser)]
#[command(
    about = "Generate a new TLS certificate",
    long_about = format!("Generate a new TLS certificate

The current TLS certificate is replaced by the newly generated one.
Optionally, the type of key and its length can be specified.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct SetTlsGenerateCommand {
    #[arg(
        env = "NETHSM_TLS_KEY_TYPE",
        help = "The optional key type of the TLS certificate to generate",
        long_help = format!("The optional key type of the TLS certificate to generate

One of {:?} (defaults to \"{}\").",
            TlsKeyType::iter().map(Into::into).collect::<Vec<&'static str>>(),
            TlsKeyType::default(),
        ),
    )]
    pub tls_key_type: Option<TlsKeyType>,

    #[arg(
        env = "NETHSM_TLS_KEY_LENGTH",
        help = "The bit length of the TLS key to generate",
        long_help = format!("The optional bit length of the TLS key to generate

The bit length must be compatible with the chosen key type.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
    )]
    pub tls_key_length: Option<i32>,
}

#[derive(Debug, Parser)]
#[command(
    about = "Set the unlock passphrase",
    long_about = format!("Set the unlock passphrase

The initial unlock passphrase is set during provisioning.

The new passphrase must be >= 10 and <= 200 characters.

By default the passphrases are prompted for interactively, but they can each be provided using a dedicated passphrase file instead.

Requires authentication of a user in the \"{}\" role.", UserRole::Administrator)
)]
pub struct SetUnlockPassphraseCommand {
    #[arg(
        env = "NETHSM_NEW_PASSPHRASE_FILE",
        help = "The path to a file containing the new passphrase",
        long_help = "The path to a file containing the new passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short
    )]
    pub new_passphrase_file: Option<PassphraseFile>,

    #[arg(
        env = "NETHSM_OLD_PASSPHRASE_FILE",
        help = "The path to a file containing the old passphrase",
        long_help = "The path to a file containing the old passphrase

The passphrase must be >= 10 and <= 200 characters long.",
        long,
        short
    )]
    pub old_passphrase_file: Option<PassphraseFile>,
}
