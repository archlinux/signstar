//! The "nethsm" command line interface.

use std::fs::{File, read, read_to_string};
use std::io::{Write, stdout};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use chrono::Utc;
use clap::Parser;
use nethsm::{
    Deserializable as _,
    DistinguishedName,
    Error,
    KeyFormat,
    KeyMechanism,
    NetworkConfigInput,
    OpenPgpKeyUsageFlags,
    Passphrase,
    PrivateKeyImport,
    SignedSecretKey,
    SignstarCryptoError,
    SignstarCryptoSignerError,
    SystemState,
    Timestamp,
    UserId,
    UserRole,
    backup::validate_backup,
    cli::{
        Cli,
        Command,
        Config,
        ConfigCommand,
        ConfigCredentials,
        ConfigGetCommand,
        ConfigInteractivity,
        ConfigSetCommand,
        ConfigSettings,
        EnvAddCommand,
        EnvCommand,
        EnvDeleteCommand,
        Error as CliError,
        HealthCommand,
        KeyCertCommand,
        KeyCommand,
        NamespaceCommand,
        OpenPgpCommand,
        PassphrasePrompt,
        SystemCommand,
        UserCommand,
    },
};
use signstar_request_signature::{Request, Sha512};

struct FileOrStdout {
    output: Box<dyn Write + Send + Sync>,
}

impl FileOrStdout {
    pub fn new(file: Option<&Path>, force: bool) -> Result<Self, crate::Error> {
        if let Some(file) = file {
            if file.exists() && !force {
                return Err(CliError::OutputFileExists(file.to_path_buf()).into());
            }

            Ok(Self {
                output: Box::new(
                    File::create(file).map_err(|_| CliError::OutputFileOpen(file.to_path_buf()))?,
                ),
            })
        } else {
            Ok(Self {
                output: Box::new(stdout()),
            })
        }
    }

    pub fn output(self) -> Box<dyn Write + Send + Sync> {
        self.output
    }
}

fn run_command(cli: Cli) -> Result<(), Error> {
    let config = Config::new(
        ConfigSettings::new("nethsm".to_string(), ConfigInteractivity::Interactive, None),
        cli.config.as_deref(),
    )?;
    let auth_passphrases: Vec<Passphrase> = cli
        .auth_passphrase_file
        .iter()
        .map(|x| x.passphrase.clone())
        .collect();

    match cli.command {
        Command::Config(command) => match command {
            ConfigCommand::Get(command) => match command {
                ConfigGetCommand::BootMode(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    println!("{:?}", nethsm.get_boot_mode()?);
                }
                ConfigGetCommand::Logging(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    println!("{:?}", nethsm.get_logging()?);
                }
                ConfigGetCommand::Network(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    println!("{:?}", nethsm.get_network()?);
                }
                ConfigGetCommand::Time(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    println!("{}", nethsm.get_time()?);
                }
                ConfigGetCommand::TlsCertificate(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output
                        .output()
                        .write_all(nethsm.get_tls_cert()?.as_bytes())
                        .map_err(CliError::Io)?;
                }
                ConfigGetCommand::TlsCsr(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    // WARNING: Upstream has decided to set all models non-exhaustive.
                    //
                    // On each update to nethsm-sdk-rs, check whether DistinguishedName has gained
                    // further fields.
                    let distinguished_name = {
                        let mut distinguished_name = DistinguishedName::new(command.common_name);
                        distinguished_name.country_name = command.country;
                        distinguished_name.state_or_province_name = command.state;
                        distinguished_name.locality_name = command.locality;
                        distinguished_name.organization_name = command.org_name;
                        distinguished_name.organizational_unit_name = command.org_unit;
                        distinguished_name.email_address = command.email;
                        distinguished_name.subject_alt_names = command.subject_alt_names;
                        distinguished_name
                    };

                    output
                        .output()
                        .write_all(nethsm.get_tls_csr(distinguished_name)?.as_bytes())
                        .map_err(CliError::Io)?;
                }
                ConfigGetCommand::TlsPublicKey(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output
                        .output()
                        .write_all(nethsm.get_tls_public_key()?.as_bytes())
                        .map_err(CliError::Io)?;
                }
            },
            ConfigCommand::Set(command) => match command {
                ConfigSetCommand::BackupPassphrase(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;
                    let current_passphrase =
                        if let Some(passphrase_file) = command.old_passphrase_file {
                            passphrase_file.passphrase
                        } else {
                            PassphrasePrompt::CurrentBackup
                                .prompt()
                                .map_err(|source| CliError::Config(source.into()))?
                        };
                    let new_passphrase = if let Some(passphrase_file) = command.new_passphrase_file
                    {
                        passphrase_file.passphrase
                    } else {
                        PassphrasePrompt::NewBackup
                            .prompt()
                            .map_err(|source| CliError::Config(source.into()))?
                    };

                    nethsm.set_backup_passphrase(current_passphrase, new_passphrase)?;
                }
                ConfigSetCommand::BootMode(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm.set_boot_mode(command.boot_mode)?;
                }
                ConfigSetCommand::Logging(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm.set_logging(
                        command.ip_address,
                        command.port,
                        command.log_level.unwrap_or_default(),
                    )?;
                }
                ConfigSetCommand::Network(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    // WARNING: Upstream has decided to set all models non-exhaustive.
                    //
                    // On each update to nethsm-sdk-rs, check whether NetworkConfigInput has gained
                    // further fields.
                    let network_config_input = {
                        let mut network_config_input = NetworkConfigInput::new(
                            command.ip_address.to_string(),
                            command.netmask,
                        );
                        network_config_input.gateway = Some(command.gateway.to_string());
                        network_config_input
                    };

                    nethsm.set_network(network_config_input)?;
                }
                ConfigSetCommand::Time(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm.set_time(command.system_time.unwrap_or_else(Utc::now))?;
                }
                ConfigSetCommand::TlsCertificate(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm
                        .set_tls_cert(&read_to_string(command.tls_cert).map_err(CliError::Io)?)?;
                }
                ConfigSetCommand::TlsGenerate(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm.generate_tls_cert(
                        command.tls_key_type.unwrap_or_default(),
                        command.tls_key_length,
                    )?;
                }
                ConfigSetCommand::UnlockPassphrase(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;
                    let current_passphrase =
                        if let Some(passphrase_file) = command.old_passphrase_file {
                            passphrase_file.passphrase
                        } else {
                            PassphrasePrompt::CurrentUnlock
                                .prompt()
                                .map_err(|source| CliError::Config(source.into()))?
                        };
                    let new_passphrase = if let Some(passphrase_file) = command.new_passphrase_file
                    {
                        passphrase_file.passphrase
                    } else {
                        PassphrasePrompt::NewUnlock
                            .prompt()
                            .map_err(|source| CliError::Config(source.into()))?
                    };

                    nethsm.set_unlock_passphrase(current_passphrase, new_passphrase)?;
                }
            },
        },
        Command::Env(command) => match command {
            EnvCommand::Add(command) => match command {
                EnvAddCommand::Credentials(command) => {
                    let label = if let Some(label) = cli.label {
                        label
                    } else if let Ok(label) = config.get_single_device_label() {
                        label
                    } else {
                        return Err(CliError::OptionMissing("label".to_string()).into());
                    };
                    let passphrase = if command.with_passphrase {
                        if let Some(passphrase_file) = command.passphrase_file {
                            Some(passphrase_file.passphrase)
                        } else {
                            Some(
                                PassphrasePrompt::User {
                                    user_id: Some(command.name.clone()),
                                    real_name: None,
                                }
                                .prompt()
                                .map_err(|source| CliError::Config(source.into()))?,
                            )
                        }
                    } else if let Some(passphrase_file) = command.passphrase_file {
                        Some(passphrase_file.passphrase)
                    } else {
                        None
                    };

                    config.add_credentials(
                        label,
                        ConfigCredentials::new(
                            command.role.unwrap_or_default(),
                            command.name,
                            passphrase.map(|p| p.expose_owned()),
                        ),
                    )?;
                    config.store(cli.config.as_deref())?;
                }
                EnvAddCommand::Device(command) => {
                    let label = if let Some(label) = cli.label {
                        label
                    } else {
                        return Err(CliError::OptionMissing("label".to_string()).into());
                    };

                    config.add_device(label, command.url, command.tls_security)?;
                    config.store(cli.config.as_deref())?;
                }
            },
            EnvCommand::Delete(command) => match command {
                EnvDeleteCommand::Credentials(command) => {
                    let label = if let Some(label) = cli.label {
                        label
                    } else if let Ok(label) = config.get_single_device_label() {
                        label
                    } else {
                        return Err(CliError::OptionMissing("label".to_string()).into());
                    };

                    config.delete_credentials(&label, &command.name)?;
                    config.store(cli.config.as_deref())?;
                }
                EnvDeleteCommand::Device(_command) => {
                    let label = if let Some(label) = cli.label {
                        label
                    } else {
                        return Err(CliError::OptionMissing("label".to_string()).into());
                    };

                    config.delete_device(&label)?;
                    config.store(cli.config.as_deref())?;
                }
            },
            EnvCommand::List => {
                println!("{config:#?}");
            }
        },
        Command::Health(command) => match command {
            HealthCommand::Alive(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(&[], &cli.user, &auth_passphrases)?;

                nethsm.alive()?;
            }
            HealthCommand::Ready(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(&[], &cli.user, &auth_passphrases)?;

                nethsm.ready()?;
            }
            HealthCommand::State(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(&[], &cli.user, &auth_passphrases)?;

                println!("{:?}", nethsm.state()?);
            }
        },
        Command::Info(_command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[], &cli.user, &auth_passphrases)?;

            println!("{:?}", nethsm.info()?);
        }
        Command::Key(command) => match command {
            KeyCommand::Cert(command) => match command {
                KeyCertCommand::Delete(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm.delete_key_certificate(&command.key_id)?;
                }
                KeyCertCommand::Get(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Operator, UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output
                        .output()
                        .write_all(
                            nethsm
                                .get_key_certificate(&command.key_id)?
                                .unwrap_or_default()
                                .as_slice(),
                        )
                        .map_err(CliError::Io)?;
                }
                KeyCertCommand::Import(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            &cli.user,
                            &auth_passphrases,
                        )?;

                    nethsm.import_key_certificate(
                        &command.key_id,
                        read(command.cert_file).map_err(CliError::Io)?,
                    )?;
                }
            },
            KeyCommand::Csr(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                // WARNING: Upstream has decided to set all models non-exhaustive.
                //
                // On each update to nethsm-sdk-rs, check whether DistinguishedName has gained
                // further fields.
                let distinguished_name = {
                    let mut distinguished_name = DistinguishedName::new(command.common_name);
                    distinguished_name.country_name = command.country;
                    distinguished_name.state_or_province_name = command.state;
                    distinguished_name.locality_name = command.locality;
                    distinguished_name.organization_name = command.org_name;
                    distinguished_name.organizational_unit_name = command.org_unit;
                    distinguished_name.email_address = command.email;
                    distinguished_name.subject_alt_names = command.subject_alt_names;
                    distinguished_name
                };

                output
                    .output()
                    .write_all(
                        nethsm
                            .get_key_csr(&command.key_id, distinguished_name)?
                            .as_bytes(),
                    )
                    .map_err(CliError::Io)?;
            }
            KeyCommand::Decrypt(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                // NOTE: IV can not be zero length or None when decrypting
                let iv = if let Some(iv) = command.initialization_vector {
                    Some(read(iv).map_err(CliError::Io)?)
                } else {
                    Some(vec![])
                };
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output
                    .output()
                    .write_all(&nethsm.decrypt(
                        &command.key_id,
                        command.decrypt_mode.unwrap_or_default(),
                        &read(command.message).map_err(CliError::Io)?,
                        iv.as_deref(),
                    )?)
                    .map_err(CliError::Io)?;
            }
            KeyCommand::Encrypt(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                // NOTE: IV can not be zero length or None when decrypting
                let iv = if let Some(iv) = command.initialization_vector {
                    Some(read(iv).map_err(CliError::Io)?)
                } else {
                    None
                };
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output
                    .output()
                    .write_all(
                        nethsm
                            .encrypt(
                                &command.key_id,
                                command.encrypt_mode.unwrap_or_default(),
                                &read(command.message).map_err(CliError::Io)?,
                                iv.as_deref(),
                            )?
                            .as_slice(),
                    )
                    .map_err(CliError::Io)?;
            }
            KeyCommand::Generate(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                println!(
                    "{}",
                    nethsm.generate_key(
                        command.key_type.unwrap_or_default(),
                        if command.key_mechanisms.is_empty() {
                            vec![KeyMechanism::default()]
                        } else {
                            command.key_mechanisms
                        },
                        command.length,
                        command.key_id,
                        command.tags,
                        command.label,
                    )?
                );
            }
            KeyCommand::Get(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                println!("{:#?}", nethsm.get_key(&command.key_id)?);
            }
            KeyCommand::Import(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let key_data = match command.format {
                    KeyFormat::Der => PrivateKeyImport::new(
                        command.key_type,
                        &read(command.key_data).map_err(CliError::Io)?,
                    ),
                    KeyFormat::Pem => PrivateKeyImport::from_pkcs8_pem(
                        command.key_type,
                        &read_to_string(command.key_data).map_err(CliError::Io)?,
                    ),
                }
                .map_err(nethsm::Error::SignstarCrypto)?;

                println!(
                    "{}",
                    nethsm.import_key(
                        command.key_mechanisms,
                        key_data,
                        command.key_id,
                        command.tags,
                        command.label,
                    )?
                );
            }
            KeyCommand::List(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm
                    .get_keys(command.filter.as_deref(), command.label.as_deref())?
                    .iter()
                    .for_each(|key_id| println!("{key_id}"));
            }
            KeyCommand::PublicKey(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output
                    .output()
                    .write_all(nethsm.get_public_key(&command.key_id)?.as_bytes())
                    .map_err(CliError::Io)?;
            }
            KeyCommand::Remove(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.delete_key(&command.key_id)?;
            }
            KeyCommand::Sign(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output
                    .output()
                    .write_all(
                        nethsm
                            .sign(
                                &command.key_id,
                                command.signature_type,
                                &read(command.message).map_err(CliError::Io)?,
                            )?
                            .as_slice(),
                    )
                    .map_err(CliError::Io)?;
            }
            KeyCommand::Tag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.add_key_tag(&command.key_id, &command.tag)?;
            }
            KeyCommand::Untag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.delete_key_tag(&command.key_id, &command.tag)?;
            }
        },
        Command::Lock(_command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(
                    &[UserRole::Administrator],
                    &cli.user,
                    &auth_passphrases,
                )?;

            nethsm.lock()?;
        }
        Command::Metrics(_command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[UserRole::Metrics], &cli.user, &auth_passphrases)?;

            println!("{}", nethsm.metrics()?);
        }
        Command::Namespace(command) => match command {
            NamespaceCommand::Add(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                nethsm.add_namespace(&command.name)?;
            }
            NamespaceCommand::List(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                nethsm
                    .get_namespaces()?
                    .iter()
                    .for_each(|namespace_id| println!("{namespace_id}"));
            }
            NamespaceCommand::Remove(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Metrics],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                nethsm.delete_namespace(&command.name)?;
            }
        },
        Command::OpenPgp(command) => match command {
            OpenPgpCommand::Add(command) => {
                let flags = {
                    let mut flags = OpenPgpKeyUsageFlags::default();
                    if command.can_sign {
                        flags.set_sign();
                    }
                    if command.cannot_sign {
                        flags.clear_sign();
                    }
                    flags
                };

                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        &cli.user,
                        &auth_passphrases.clone(),
                    )?;

                let created_at = command.time.unwrap_or_else(Utc::now);
                let created_at: SystemTime = created_at.into();
                let created_at = Timestamp::try_from(created_at)
                    .map_err(|_| CliError::InvalidTime(command.time.unwrap_or_else(Utc::now)))?;
                let cert = nethsm.create_openpgp_cert(
                    &command.key_id,
                    flags,
                    &[command.user_id],
                    Default::default(),
                    created_at,
                    command.version.unwrap_or_default(),
                )?;

                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.import_key_certificate(&command.key_id, cert.clone())?;
            }
            OpenPgpCommand::Import(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let private_key =
                    SignedSecretKey::from_file(command.tsk_file).map_err(|source| {
                        Error::SignstarCrypto(SignstarCryptoError::Signer(
                            SignstarCryptoSignerError::Pgp(source),
                        ))
                    })?;
                let (key_data, key_mechanism) = nethsm::tsk_to_private_key_import(&private_key)?;

                let key_id = nethsm.import_key(
                    vec![key_mechanism],
                    key_data,
                    command.key_id,
                    command.tags,
                    command.label,
                )?;

                let cert = nethsm::extract_openpgp_certificate(private_key)?;

                nethsm.import_key_certificate(&key_id, cert)?;
            }
            OpenPgpCommand::Sign(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output
                    .output()
                    .write_all(
                        nethsm
                            .openpgp_sign(
                                &command.key_id,
                                &read(command.message).map_err(CliError::Io)?,
                            )?
                            .as_slice(),
                    )
                    .map_err(CliError::Io)?;
            }
            OpenPgpCommand::SignState(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                let req = Request::from_reader(File::open(command.input).map_err(CliError::Io)?)
                    .map_err(|source| CliError::Request(Box::new(source)))?;

                if !req.required.output.is_openpgp_v4() {
                    return Err(CliError::SigningRequest(
                        "The only supported signature format is OpenPGP v4.".into(),
                    )
                    .into());
                }

                if req.version.major != 1 {
                    return Err(CliError::SigningRequest(
                        "This command supports version 1 signing requests only.".into(),
                    )
                    .into());
                }

                let hasher = Sha512::try_from(req.required.input).map_err(|_| {
                    Error::Cli(CliError::SigningRequest(
                        "Creating a hasher state from the input failed".into(),
                    ))
                })?;

                output
                    .output()
                    .write_all(
                        nethsm
                            .openpgp_sign_state(&command.key_id, hasher)?
                            .as_bytes(),
                    )
                    .map_err(CliError::Io)?;
            }
        },
        Command::Provision(command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[], &cli.user, &auth_passphrases)?;
            let unlock_passphrase = if let Some(passphrase_file) = command.unlock_passphrase_file {
                passphrase_file.passphrase
            } else {
                PassphrasePrompt::Unlock
                    .prompt()
                    .map_err(|source| CliError::Config(source.into()))?
            };
            let admin_passphrase = if let Some(passphrase_file) = command.admin_passphrase_file {
                passphrase_file.passphrase
            } else {
                PassphrasePrompt::User {
                    user_id: Some(UserId::SystemWide("admin".to_string())),
                    real_name: None,
                }
                .prompt()
                .map_err(|source| CliError::Config(source.into()))?
            };

            nethsm.provision(
                unlock_passphrase,
                admin_passphrase,
                command.system_time.unwrap_or_else(Utc::now),
            )?
        }
        Command::Random(command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[UserRole::Operator], &cli.user, &auth_passphrases)?;
            let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

            output
                .output()
                .write_all(&nethsm.random(command.length)?)
                .map_err(CliError::Io)?;
        }
        Command::System(command) => match command {
            SystemCommand::Backup(command) => {
                let device_config = config.clone().get_device(cli.label.as_deref())?;
                let label = if let Some(label) = cli.label {
                    label
                } else if let Ok(label) = config.get_single_device_label() {
                    label
                } else {
                    return Err(CliError::OptionMissing("label".to_string()).into());
                };
                let nethsm = device_config.nethsm_with_matching_creds(
                    &[UserRole::Backup],
                    &cli.user,
                    &auth_passphrases,
                )?;
                let output = FileOrStdout::new(
                    Some(command.output.unwrap_or_else(|| {
                        PathBuf::from(format!(
                            "{}-{}.bkp",
                            label,
                            Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                        ))
                    }))
                    .as_deref(),
                    command.force,
                )?;

                output
                    .output()
                    .write_all(nethsm.backup()?.as_slice())
                    .map_err(CliError::Io)?;
            }
            SystemCommand::CancelUpdate(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.cancel_update()?;
            }
            SystemCommand::CommitUpdate(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.commit_update()?;
            }
            SystemCommand::FactoryReset(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.factory_reset()?;
            }
            SystemCommand::Info(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                println!("{:#?}", nethsm.system_info()?);
            }
            SystemCommand::Reboot(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.reboot()?;
            }
            SystemCommand::Restore(command) => {
                let nethsm = {
                    // first check whether we need credentials or not
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(&[], &[], &[])?;
                    // WARNING: Upstream has decided to set all models non-exhaustive.
                    //
                    // On each update to nethsm-sdk-rs, check whether SystemState has gained further
                    // fields.
                    match nethsm.state()? {
                        SystemState::Unprovisioned => nethsm,
                        // we only need credentials if the device is already provisioned and
                        // operational
                        SystemState::Operational => config
                            .get_device(cli.label.as_deref())?
                            .nethsm_with_matching_creds(
                                &[UserRole::Administrator],
                                &cli.user,
                                &auth_passphrases,
                            )?,
                        SystemState::Locked => return Err(CliError::Locked.into()),
                        SystemState::Failed => return Err(CliError::Failed.into()),
                        system_state => {
                            return Err(CliError::UnknownSystemState { system_state }.into());
                        }
                    }
                };
                let backup_passphrase =
                    if let Some(passphrase_file) = command.backup_passphrase_file {
                        passphrase_file.passphrase
                    } else {
                        PassphrasePrompt::Backup
                            .prompt()
                            .map_err(|source| CliError::Config(source.into()))?
                    };

                nethsm.restore(
                    backup_passphrase,
                    command.system_time.unwrap_or_else(Utc::now),
                    read(command.input).map_err(CliError::Io)?,
                )?;
            }
            SystemCommand::Shutdown(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.shutdown()?;
            }
            SystemCommand::UploadUpdate(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                println!(
                    "{:?}",
                    nethsm.upload_update(read(command.input).map_err(CliError::Io)?)?
                );
            }
            SystemCommand::ValidateBackup(command) => {
                validate_backup(
                    &mut File::open(command.input).map_err(CliError::Io)?,
                    command
                        .backup_passphrase_file
                        .map(|passphrase_file| passphrase_file.passphrase),
                )?;
            }
        },
        Command::Unlock(command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[], &cli.user, &auth_passphrases)?;
            let unlock_passphrase = if let Some(passphrase_file) = command.unlock_passphrase_file {
                passphrase_file.passphrase
            } else {
                PassphrasePrompt::Unlock
                    .prompt()
                    .map_err(|source| CliError::Config(source.into()))?
            };

            nethsm.unlock(unlock_passphrase)?;
        }
        Command::User(command) => match command {
            UserCommand::Add(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let passphrase = if let Some(passphrase_file) = command.passphrase_file {
                    passphrase_file.passphrase
                } else {
                    PassphrasePrompt::User {
                        user_id: command.name.clone(),
                        real_name: Some(command.real_name.clone()),
                    }
                    .prompt()
                    .map_err(|source| CliError::Config(source.into()))?
                };

                println!(
                    "{}",
                    nethsm.add_user(
                        command.real_name,
                        command.role.unwrap_or_default(),
                        passphrase,
                        command.name
                    )?
                );
            }
            UserCommand::Get(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                let user_data = nethsm.get_user(&command.name)?;
                println!("{user_data:?}");
                // only users in the Operator role can have tags
                if user_data.role == UserRole::Operator.try_into()? {
                    println!("{:?}", nethsm.get_user_tags(&command.name)?);
                }
            }
            UserCommand::List(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm
                    .get_users()?
                    .iter()
                    .for_each(|name| println!("{name}"));
            }
            UserCommand::Passphrase(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;
                let passphrase = if let Some(passphrase_file) = command.passphrase_file {
                    passphrase_file.passphrase
                } else {
                    PassphrasePrompt::NewUser(command.name.clone())
                        .prompt()
                        .map_err(|source| CliError::Config(source.into()))?
                };

                nethsm.set_user_passphrase(command.name, passphrase)?;
            }
            UserCommand::Remove(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.delete_user(&command.name)?;
            }
            UserCommand::Tag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.add_user_tag(&command.name, &command.tag)?;
            }
            UserCommand::Untag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        &cli.user,
                        &auth_passphrases,
                    )?;

                nethsm.delete_user_tag(&command.name, &command.tag)?;
            }
        },
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = run_command(cli);

    if let Err(error) = result {
        eprintln!("{error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
