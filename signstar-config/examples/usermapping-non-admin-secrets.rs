//! Example for loading and creating of secrets for non-administrative backend users.
//!
//! Uses the [`MappingBackendUserSecrets`] interface for creating and loading secrets.
//!
//! # Note
//!
//! This example is used in integration tests and is probably not very useful on its own.

use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use log::LevelFilter;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_config::AuthorizedKeyEntry;
#[cfg(feature = "nethsm")]
use signstar_config::nethsm::{NetHsmMetricsUsers, NetHsmUserMapping};
#[cfg(feature = "yubihsm2")]
use signstar_config::yubihsm2::YubiHsm2UserMapping;
use signstar_config::{
    SystemUserId,
    config::{MappingBackendUserSecrets, NonAdminBackendUserIdFilter, NonAdminBackendUserIdKind},
};
use signstar_crypto::NonAdministrativeSecretHandling;
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
use signstar_crypto::{
    key::{CryptographicKeyContext, KeyMechanism, KeyType, SignatureType, SigningKeySetup},
    openpgp::OpenPgpUserIdList,
};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

/// An error that may occur when using usermapping-system-user-info.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Expected a system user.
    #[error("Expected a system user.")]
    MissingSystemUser,

    /// A `nethsm::user::Error`.
    #[error(transparent)]
    NetHsmKey(#[from] nethsm::KeyError),

    /// A `nethsm::user::Error`.
    #[cfg(feature = "nethsm")]
    #[error(transparent)]
    NetHsmUser(#[from] nethsm::UserError),

    /// A `signstar_config::Error`.
    #[error(transparent)]
    SignstarConfig(#[from] signstar_config::Error),

    /// A `signstar_crypto::openpgp::Error`.
    #[error(transparent)]
    SignstarCryptoOpenpgp(#[from] signstar_crypto::openpgp::Error),

    /// A `signstar_crypto::key::Error`.
    #[error(transparent)]
    SignstarCryptoKey(#[from] signstar_crypto::key::Error),

    /// A `signstar_yubihsm2::Error`.
    #[cfg(feature = "yubihsm2")]
    #[error(transparent)]
    SignstarYubiHsm2(#[from] signstar_yubihsm2::Error),

    /// Encountered an unexpected system user.
    #[error("Encountered the unexpected system user {system_user}")]
    UnexpectedSystemUser {
        /// The system user.
        system_user: SystemUserId,
    },
}

/// The kind of HSM backend to use.
#[derive(Clone, Copy, Debug, strum::Display, ValueEnum)]
#[strum(serialize_all = "lowercase")]
enum BackendKind {
    #[cfg(feature = "nethsm")]
    NetHsm,
    #[cfg(feature = "yubihsm2")]
    YubiHsm2,
}

/// The kind of user mapping to use.
#[derive(Clone, Copy, Debug, strum::Display, ValueEnum)]
#[strum(serialize_all = "lowercase")]
enum MappingKind {
    Admin,
    Backup,
    HermeticMetrics,
    Metrics,
    Signing,
}

#[derive(Clone, Copy, Debug, strum::Display, ValueEnum)]
#[strum(serialize_all = "lowercase")]
#[cfg_attr(
    any(
        all(feature = "nethsm", not(feature = "yubihsm2")),
        all(not(feature = "nethsm"), feature = "yubihsm2")
    ),
    expect(clippy::enum_variant_names)
)]
enum BackendMappingKind {
    #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
    Dummy,
    #[cfg(feature = "nethsm")]
    NethsmAdmin,
    #[cfg(feature = "nethsm")]
    NethsmBackup,
    #[cfg(feature = "nethsm")]
    NethsmHermeticMetrics,
    #[cfg(feature = "nethsm")]
    NethsmMetrics,
    #[cfg(feature = "nethsm")]
    NethsmSigning,
    #[cfg(feature = "yubihsm2")]
    Yubihsm2Admin,
    #[cfg(feature = "yubihsm2")]
    Yubihsm2AuditLog,
    #[cfg(feature = "yubihsm2")]
    Yubihsm2Backup,
    #[cfg(feature = "yubihsm2")]
    Yubihsm2HermeticAuditLog,
    #[cfg(feature = "yubihsm2")]
    Yubihsm2Signing,
}

#[derive(Debug, Parser)]
#[command(about, author, version)]
struct CreateCommand {
    /// How the non-administrative secret is handled.
    #[arg(
        help = "How the non-administrative secret is handled.",
        long,
        required = true
    )]
    pub secret_handling: NonAdministrativeSecretHandling,
}

#[derive(Debug, Parser)]
#[command(about, author, version)]
struct LoadCommand {
    /// How the non-administrative secret is handled.
    #[arg(
        help = "How the non-administrative secret is handled.",
        long,
        required = true
    )]
    pub secret_handling: NonAdministrativeSecretHandling,
}

#[derive(Debug, Parser)]
#[command(about, author, version)]
enum Command {
    /// Create a secret for a non-administrative user from a user mapping.
    #[command(about = "Create a secret for a non-administrative user from a user mapping.")]
    Create(CreateCommand),

    /// Load a secret for a non-administrative user from a user mapping.
    #[command(about = "Load a secret for a non-administrative user from a user mapping.")]
    Load(LoadCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Load and write non-administrative user secrets based on user mapping data",
    version
)]
struct Cli {
    /// The kind of backend mapping the user is tied to.
    #[arg(
        help = "The kind of backend mapping the user is tied to.",
        long,
        required = true
    )]
    pub backend_mapping_kind: BackendMappingKind,

    /// The system user name to use when constructing a mapping.
    #[arg(
        help = "The system user name to use when constructing a mapping.",
        long
    )]
    pub system_user: Option<SystemUserId>,

    #[command(subcommand)]
    pub command: Command,
}

/// Initializes a logger.
fn init_logger() {
    if TermLogger::init(
        LevelFilter::Debug,
        Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )
    .is_err()
    {
        eprintln!("Not initializing another logger, as one is initialized already.");
    }
}

/// Creates a dummy [`AuthorizedKeyEntry`].
#[cfg(any(feature = "nethsm", feature = "yubihsm2"))]
fn dummy_ssh_authorized_key() -> Result<AuthorizedKeyEntry, Error> {
    Ok("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host"
        .parse()?)
}

/// Creates the requested user mapping implementation.
///
/// Creation is based on [`BackendMappingKind`] and an optional [`SystemUserId`].
/// Remaining data is populated using static dummy data.
///
/// # Errors
///
/// Returns an error if the provided `backend_mapping_kind` is not compatible with the
/// `system_user`.
fn create_mapping(
    backend_mapping_kind: BackendMappingKind,
    system_user: Option<SystemUserId>,
) -> Result<Box<dyn MappingBackendUserSecrets>, Error> {
    match backend_mapping_kind {
        #[cfg(not(any(feature = "nethsm", feature = "yubihsm2")))]
        BackendMappingKind::Dummy => {
            let _unused = system_user;
            unimplemented!("There is no dummy backend")
        }
        #[cfg(feature = "nethsm")]
        BackendMappingKind::NethsmAdmin => {
            if let Some(system_user) = system_user {
                return Err(Error::UnexpectedSystemUser { system_user });
            }
            Ok(Box::new(NetHsmUserMapping::Admin("admin".parse()?)))
        }
        #[cfg(feature = "nethsm")]
        BackendMappingKind::NethsmBackup => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(NetHsmUserMapping::Backup {
                backend_user: "backup".parse()?,
                ssh_authorized_key: dummy_ssh_authorized_key()?,
                system_user,
            }))
        }
        #[cfg(feature = "nethsm")]
        BackendMappingKind::NethsmHermeticMetrics => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(NetHsmUserMapping::HermeticMetrics {
                backend_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["observer".parse()?],
                )?,
                system_user,
            }))
        }
        #[cfg(feature = "nethsm")]
        BackendMappingKind::NethsmMetrics => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["observer".parse()?],
                )?,
                ssh_authorized_key: dummy_ssh_authorized_key()?,
                system_user,
            }))
        }
        #[cfg(feature = "nethsm")]
        BackendMappingKind::NethsmSigning => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(NetHsmUserMapping::Signing {
                backend_user: "signing".parse()?,
                signing_key_id: "key1".parse()?,
                key_setup: SigningKeySetup::new(
                    KeyType::Curve25519,
                    vec![KeyMechanism::EdDsaSignature],
                    None,
                    SignatureType::EdDsa,
                    CryptographicKeyContext::OpenPgp {
                        user_ids: OpenPgpUserIdList::new(vec![
                            "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                        ])?,
                        version: "v4".parse()?,
                    },
                )?,
                ssh_authorized_key: dummy_ssh_authorized_key()?,
                system_user,
                tag: "tag1".to_string(),
            }))
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Admin => {
            if let Some(system_user) = system_user {
                return Err(Error::UnexpectedSystemUser { system_user });
            }
            Ok(Box::new(YubiHsm2UserMapping::Admin {
                authentication_key_id: "1".parse()?,
            }))
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2AuditLog => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "1".parse()?,
                ssh_authorized_key: dummy_ssh_authorized_key()?,
                system_user,
            }))
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Backup => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(YubiHsm2UserMapping::Backup {
                authentication_key_id: "1".parse()?,
                wrapping_key_id: "1".parse()?,
                ssh_authorized_key: dummy_ssh_authorized_key()?,
                system_user,
            }))
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2HermeticAuditLog => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(YubiHsm2UserMapping::HermeticAuditLog {
                authentication_key_id: "1".parse()?,
                system_user,
            }))
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Signing => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Ok(Box::new(YubiHsm2UserMapping::Signing {
                authentication_key_id: "1".parse()?,
                key_setup: SigningKeySetup::new(
                    KeyType::Curve25519,
                    vec![KeyMechanism::EdDsaSignature],
                    None,
                    SignatureType::EdDsa,
                    CryptographicKeyContext::OpenPgp {
                        user_ids: OpenPgpUserIdList::new(vec![
                            "Foobar McFooface <foobar@mcfooface.org>".parse()?,
                        ])?,
                        version: "v4".parse()?,
                    },
                )?,
                domain: signstar_yubihsm2::object::Domain::One,
                signing_key_id: "1".parse()?,
                ssh_authorized_key: dummy_ssh_authorized_key()?,
                system_user,
            }))
        }
    }
}

/// Runs the task for a specific user mapping implementation.
///
/// First creates a specific variant of a user mapping implementation,
/// then runs the requested command with it.
///
/// # Errors
///
/// Returns an error if
///
/// - creation of the specific user mapping implementation fails
/// - creation or loading of secrets fails
fn run_mapping_task(cli: Cli) -> Result<(), Error> {
    let mapping = create_mapping(cli.backend_mapping_kind, cli.system_user)?;

    match cli.command {
        Command::Create(command) => {
            if let Some(creds_list) =
                mapping.create_non_admin_backend_user_secrets(command.secret_handling)?
            {
                for creds in creds_list {
                    println!(
                        "backend user: {}\npassphrase: {}",
                        creds.user(),
                        creds.passphrase().expose_borrowed()
                    );
                }
            }
        }
        Command::Load(command) => {
            if let Some(creds_list) = mapping.load_non_admin_backend_user_secrets(
                command.secret_handling,
                NonAdminBackendUserIdFilter {
                    backend_user_id_kind: NonAdminBackendUserIdKind::Any,
                },
            )? {
                for creds in creds_list {
                    println!(
                        "backend user: {}\npassphrase: {}",
                        creds.user(),
                        creds.passphrase().expose_borrowed()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Runs the selected task against a created user mapping implementation.
fn main() -> ExitCode {
    init_logger();

    if let Err(error) = run_mapping_task(Cli::parse()) {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
