//! Example for checking system user data against data found in user mapping implementations.
//!
//! Allows to check whether an existing Unix user matches that of a user mapping implementation, or
//! whether the currently calling Unix user matches that of a user mapping implementation.
//!
//! Uses the [`MappingSystemUserId`] interface for querying relevant data from user mapping
//! implementations.
//!
//! # Note
//!
//! This example is used in integration tests and is probably not very useful on its own.

use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use log::{LevelFilter, debug};
use nix::unistd::User;
#[cfg(feature = "yubihsm2")]
use signstar_config::yubihsm2::YubiHsm2UserMapping;
use signstar_config::{
    NetHsmMetricsUsers,
    SystemUserId,
    config::MappingSystemUserId,
    nethsm::NetHsmUserMapping,
};
use signstar_crypto::key::{
    CryptographicKeyContext,
    KeyMechanism,
    KeyType,
    SignatureType,
    SigningKeySetup,
};
use signstar_crypto::openpgp::OpenPgpUserIdList;
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode};

/// An error that may occur when using usermapping-system-user-info.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The dummy backend is encountered.
    #[error("The dummy backend has no functionality.")]
    Dummy,

    /// Expected a system user.
    #[error("Expected a system user.")]
    MissingSystemUser,

    /// A `nethsm::user::Error`.
    #[error(transparent)]
    NetHsmKey(#[from] nethsm::KeyError),

    /// A `nethsm::user::Error`.
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

    /// Encountered an unexpected system user.
    #[error("Encountered the unexpected Unix user {}", unix_user.name)]
    UnexpectedUnixUser {
        /// The Unix user.
        unix_user: User,
    },

    /// Expected a specific system user.
    #[error("Expected the system user {system_user}")]
    ExpectedSystemUser {
        /// The system user.
        system_user: SystemUserId,
    },

    /// Expected a specific Unix user, but there was none.
    #[error("Expected the Unix user {unix_user}, but there was none.")]
    ExpectedUnixUser {
        /// The Unix user.
        unix_user: String,
    },

    /// Expected a specific Unix user, but there was none.
    #[error("Expected the Unix user {expected}, but got {actual} instead.")]
    MismatchingUnixUser {
        /// The expected Unix user.
        expected: String,

        /// The actual Unix user.
        actual: String,
    },
}

#[derive(Clone, Copy, Debug, strum::Display, ValueEnum)]
#[strum(serialize_all = "lowercase")]
enum BackendMappingKind {
    Dummy,
    NethsmAdmin,
    NethsmBackup,
    NethsmHermeticMetrics,
    NethsmMetrics,
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
#[command(
    about = "Retrieve Unix user information from user mapping implementations",
    version
)]
struct Cli {
    /// The kind of backend mapping the user is tied to.
    #[arg(help = "The kind of backend mapping the user is tied to.")]
    pub backend_mapping_kind: BackendMappingKind,

    /// The system user name to use when constructing a mapping.
    #[arg(help = "The system user name to use when constructing a mapping.")]
    pub system_user: Option<SystemUserId>,

    /// Check whether the selected system user should exist as Unix user.
    #[arg(
        help = "Check whether the selected system user should exist as Unix user.",
        long,
        short
    )]
    pub exists: bool,

    /// Check whether the selected system user should be the currently calling user.
    #[arg(
        help = "Check whether the selected system user should be the currently calling user.",
        long,
        short
    )]
    pub current_user: bool,
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
) -> Result<Box<dyn MappingSystemUserId>, Error> {
    let ssh_authorized_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDgwGfIRBAsOUuDEZw/uJQZSwOYr4sg2DAZpcc7MfOj user@host".parse()?;

    Ok(match backend_mapping_kind {
        BackendMappingKind::Dummy => return Err(Error::Dummy),
        BackendMappingKind::NethsmAdmin => {
            if let Some(system_user) = system_user {
                return Err(Error::UnexpectedSystemUser { system_user });
            }
            Box::new(NetHsmUserMapping::Admin("admin".parse()?))
        }
        BackendMappingKind::NethsmBackup => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(NetHsmUserMapping::Backup {
                backend_user: "backup".parse()?,
                ssh_authorized_key,
                system_user,
            })
        }
        BackendMappingKind::NethsmHermeticMetrics => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(NetHsmUserMapping::HermeticMetrics {
                backend_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["observer".parse()?],
                )?,
                system_user,
            })
        }
        BackendMappingKind::NethsmMetrics => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(NetHsmUserMapping::Metrics {
                backend_users: NetHsmMetricsUsers::new(
                    "metrics".parse()?,
                    vec!["observer".parse()?],
                )?,
                ssh_authorized_key,
                system_user,
            })
        }
        BackendMappingKind::NethsmSigning => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(NetHsmUserMapping::Signing {
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
                ssh_authorized_key,
                system_user,
                tag: "tag1".to_string(),
            })
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Admin => {
            if let Some(system_user) = system_user {
                return Err(Error::UnexpectedSystemUser { system_user });
            }
            Box::new(YubiHsm2UserMapping::Admin {
                authentication_key_id: "1".parse()?,
            })
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2AuditLog => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(YubiHsm2UserMapping::AuditLog {
                authentication_key_id: "1".parse()?,
                ssh_authorized_key,
                system_user,
            })
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Backup => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(YubiHsm2UserMapping::Backup {
                authentication_key_id: "1".parse()?,
                wrapping_key_id: "1".parse()?,
                ssh_authorized_key,
                system_user,
            })
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2HermeticAuditLog => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(YubiHsm2UserMapping::HermeticAuditLog {
                authentication_key_id: "1".parse()?,
                system_user,
            })
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Signing => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            Box::new(YubiHsm2UserMapping::Signing {
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
                ssh_authorized_key,
                system_user,
            })
        }
    })
}

/// Checks whether a [`SystemUserId`] and [`User`] match the requirements of a
/// [`BackendMappingKind`].
///
/// # Errors
///
/// Returns an error, if
///
/// - `unix_user` is supplied for [`BackendMappingKind`] variants that don't support it.
/// - `unix_user` and `system_user` don't match,
/// - the `backend_mapping_kind` and `system_user` combination expect a `unix_user`, but none is
///   provided
/// - `check_unix_user_requirement` fails for the selected action (e.g. check if the provided system
///   user matches an existing Unix user, or if the currently calling Unix user matches the provided
///   system user)
fn check_unix_user_requirement(
    backend_mapping_kind: &BackendMappingKind,
    system_user: Option<&SystemUserId>,
    unix_user: Option<User>,
) -> Result<(), Error> {
    debug!("Checking the Unix user requirement for {backend_mapping_kind}");

    match backend_mapping_kind {
        BackendMappingKind::Dummy => return Err(Error::Dummy),
        BackendMappingKind::NethsmAdmin => {
            if let Some(unix_user) = unix_user {
                return Err(Error::UnexpectedUnixUser { unix_user });
            }
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Admin => {
            if let Some(unix_user) = unix_user {
                return Err(Error::UnexpectedUnixUser { unix_user });
            }
        }
        BackendMappingKind::NethsmBackup
        | BackendMappingKind::NethsmHermeticMetrics
        | BackendMappingKind::NethsmMetrics
        | BackendMappingKind::NethsmSigning => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            if let Some(unix_user) = unix_user {
                if unix_user.name != system_user.to_string() {
                    return Err(Error::MismatchingUnixUser {
                        expected: system_user.to_string(),
                        actual: unix_user.name,
                    });
                }
            } else {
                return Err(Error::ExpectedUnixUser {
                    unix_user: system_user.to_string(),
                });
            }
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2AuditLog
        | BackendMappingKind::Yubihsm2Backup
        | BackendMappingKind::Yubihsm2HermeticAuditLog
        | BackendMappingKind::Yubihsm2Signing => {
            let Some(system_user) = system_user else {
                return Err(Error::MissingSystemUser);
            };
            if let Some(unix_user) = unix_user {
                if unix_user.name != system_user.to_string() {
                    return Err(Error::MismatchingUnixUser {
                        expected: system_user.to_string(),
                        actual: unix_user.name,
                    });
                }
            } else {
                return Err(Error::ExpectedUnixUser {
                    unix_user: system_user.to_string(),
                });
            }
        }
    }

    Ok(())
}

/// Runs the selected user mapping task.
fn run_mapping_task(cli: Cli) -> Result<(), Error> {
    let system_user = cli.system_user.clone();
    let mapping = create_mapping(cli.backend_mapping_kind, cli.system_user)?;

    // Ensure the mapping works correctly.
    let mapping_system_user_id = mapping.system_user_id();
    match cli.backend_mapping_kind {
        BackendMappingKind::Dummy => return Err(Error::Dummy),
        BackendMappingKind::NethsmAdmin => {
            if let Some(system_user) = mapping_system_user_id {
                return Err(Error::UnexpectedSystemUser {
                    system_user: system_user.clone(),
                });
            }
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2Admin => {
            if let Some(system_user) = mapping_system_user_id {
                return Err(Error::UnexpectedSystemUser {
                    system_user: system_user.clone(),
                });
            }
        }
        BackendMappingKind::NethsmBackup
        | BackendMappingKind::NethsmHermeticMetrics
        | BackendMappingKind::NethsmMetrics
        | BackendMappingKind::NethsmSigning => {
            if mapping_system_user_id.is_none() {
                return Err(Error::MissingSystemUser);
            }
        }
        #[cfg(feature = "yubihsm2")]
        BackendMappingKind::Yubihsm2AuditLog
        | BackendMappingKind::Yubihsm2Backup
        | BackendMappingKind::Yubihsm2HermeticAuditLog
        | BackendMappingKind::Yubihsm2Signing => {
            if mapping_system_user_id.is_none() {
                return Err(Error::MissingSystemUser);
            }
        }
    }

    // Check if the system user should exist as Unix user.
    if cli.exists {
        debug!("Check whether the Unix user should exist for system user {system_user:?}");

        check_unix_user_requirement(
            &cli.backend_mapping_kind,
            system_user.as_ref(),
            mapping.system_user_id_as_existing_unix_user()?,
        )?;
    }

    // Check if the system user should be the currently calling Unix user.
    if cli.current_user {
        debug!(
            "Check whether the currently calling Unix user matches the system user {system_user:?}"
        );

        check_unix_user_requirement(
            &cli.backend_mapping_kind,
            system_user.as_ref(),
            mapping.system_user_id_as_current_unix_user()?,
        )?;
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
