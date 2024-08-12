use std::fs::{read, read_to_string, File};
use std::io::{stdout, Write};
use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::Parser;

mod config;
use cli::{KeyCertCommand, KeyCommand, SystemCommand};
use config::Config;

mod cli;
use cli::{
    Cli,
    Command,
    ConfigCommand,
    ConfigGetCommand,
    ConfigSetCommand,
    EnvAddCommand,
    EnvDeleteCommand,
    HealthCommand,
    UserCommand,
};
mod passphrase_file;
mod prompt;
use nethsm::{DistinguishedName, KeyFormat, NetworkConfig, PrivateKeyImport, UserRole};
use prompt::PassphrasePrompt;

use crate::cli::EnvCommand;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A config error
    #[error("Configuration issue: {0}")]
    Config(#[from] config::Error),

    /// A NetHsm error
    #[error("NetHsm error: {0}")]
    NetHsm(#[from] nethsm::Error),

    /// A prompt error
    #[error("Prompt error: {0}")]
    Prompt(#[from] prompt::Error),

    /// An I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A CLI error
    #[error("CLI error: {0}")]
    Cli(#[from] cli::Error),

    /// A passphrase file error
    #[error("Passphrase file error: {0}")]
    PassphraseFile(#[from] passphrase_file::Error),

    /// Unable to open output file
    #[error("Failed to open output file: {0}")]
    OutputFileOpen(PathBuf),

    /// Unable to open output file
    #[error("The output file exists already: {0}")]
    OutputFileExists(PathBuf),
}

struct FileOrStdout {
    output: Box<dyn Write + Send + Sync>,
}

impl FileOrStdout {
    pub fn new(file: Option<&Path>, force: bool) -> Result<Self, Error> {
        if let Some(file) = file {
            if file.exists() && !force {
                return Err(Error::OutputFileExists(file.to_path_buf()));
            }

            Ok(Self {
                output: Box::new(
                    File::create(file).map_err(|_| Error::OutputFileOpen(file.to_path_buf()))?,
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

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let config = Config::new(cli.config.as_deref())?;
    let auth_passphrase = if let Some(passphrase_file) = cli.auth_passphrase_file {
        Some(passphrase_file.passphrase)
    } else {
        None
    };

    match cli.command {
        Command::Config(command) => match command {
            ConfigCommand::Get(command) => match command {
                ConfigGetCommand::BootMode(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    println!("{:?}", nethsm.get_boot_mode()?);
                }
                ConfigGetCommand::Logging(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    println!("{:?}", nethsm.get_logging()?);
                }
                ConfigGetCommand::Network(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    println!("{:?}", nethsm.get_network()?);
                }
                ConfigGetCommand::Time(_command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    println!("{}", nethsm.get_time()?);
                }
                ConfigGetCommand::TlsCertificate(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output
                        .output()
                        .write_all(nethsm.get_tls_cert()?.as_bytes())?;
                }
                ConfigGetCommand::TlsCsr(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output.output().write_all(
                        nethsm
                            .get_tls_csr(DistinguishedName {
                                country_name: command.country,
                                state_or_province_name: command.state,
                                locality_name: command.locality,
                                organization_name: command.org_name,
                                organizational_unit_name: command.org_unit,
                                common_name: command.common_name,
                                email_address: command.email,
                            })?
                            .as_bytes(),
                    )?;
                }
                ConfigGetCommand::TlsPublicKey(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output
                        .output()
                        .write_all(nethsm.get_tls_public_key()?.as_bytes())?;
                }
            },
            ConfigCommand::Set(command) => match command {
                ConfigSetCommand::BackupPassphrase(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;
                    let current_passphrase =
                        if let Some(passphrase_file) = command.old_passphrase_file {
                            passphrase_file.passphrase
                        } else {
                            PassphrasePrompt::CurrentBackup.prompt()?
                        };
                    let new_passphrase = if let Some(passphrase_file) = command.new_passphrase_file
                    {
                        passphrase_file.passphrase
                    } else {
                        PassphrasePrompt::NewBackup.prompt()?
                    };

                    nethsm.set_backup_passphrase(current_passphrase, new_passphrase)?;
                }
                ConfigSetCommand::BootMode(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    nethsm.set_boot_mode(command.boot_mode)?;
                }
                ConfigSetCommand::Logging(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
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
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    nethsm.set_network(NetworkConfig {
                        ip_address: command.ip_address.to_string(),
                        netmask: command.netmask,
                        gateway: command.gateway.to_string(),
                    })?;
                }
                ConfigSetCommand::Time(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    nethsm.set_time(command.system_time.unwrap_or_else(Utc::now))?;
                }
                ConfigSetCommand::TlsCertificate(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    nethsm.set_tls_cert(&read_to_string(command.tls_cert)?)?;
                }
                ConfigSetCommand::TlsGenerate(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
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
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;
                    let current_passphrase =
                        if let Some(passphrase_file) = command.old_passphrase_file {
                            passphrase_file.passphrase
                        } else {
                            PassphrasePrompt::CurrentUnlock.prompt()?
                        };
                    let new_passphrase = if let Some(passphrase_file) = command.new_passphrase_file
                    {
                        passphrase_file.passphrase
                    } else {
                        PassphrasePrompt::NewUnlock.prompt()?
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
                        return Err(cli::Error::OptionMissing("label".to_string()).into());
                    };
                    let passphrase = if command.with_passphrase {
                        if let Some(passphrase_file) = command.passphrase_file {
                            Some(passphrase_file.passphrase)
                        } else {
                            Some(PassphrasePrompt::User(command.name.clone()).prompt()?)
                        }
                    } else if let Some(passphrase_file) = command.passphrase_file {
                        Some(passphrase_file.passphrase)
                    } else {
                        None
                    };

                    config.add_credentials(
                        label,
                        command.role.unwrap_or_default(),
                        command.name,
                        passphrase.map(|p| p.expose_owned()),
                    )?;
                    config.store(cli.config.as_deref())?;
                }
                EnvAddCommand::Device(command) => {
                    let label = if let Some(label) = cli.label {
                        label
                    } else {
                        return Err(cli::Error::OptionMissing("label".to_string()).into());
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
                        return Err(cli::Error::OptionMissing("label".to_string()).into());
                    };

                    config.delete_credentials(label, command.name)?;
                    config.store(cli.config.as_deref())?;
                }
                EnvDeleteCommand::Device(_command) => {
                    let label = if let Some(label) = cli.label {
                        label
                    } else {
                        return Err(cli::Error::OptionMissing("label".to_string()).into());
                    };

                    config.delete_device(&label)?;
                    config.store(cli.config.as_deref())?;
                }
            },
            EnvCommand::List => {
                let config = Config::new(cli.config.as_deref())?;

                println!("{:#?}", config);
            }
        },
        Command::Health(command) => match command {
            HealthCommand::Alive(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(&[], cli.user.as_deref(), auth_passphrase)?;

                nethsm.alive()?;
            }
            HealthCommand::Ready(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(&[], cli.user.as_deref(), auth_passphrase)?;

                nethsm.ready()?;
            }
            HealthCommand::State(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(&[], cli.user.as_deref(), auth_passphrase)?;

                println!("{:?}", nethsm.state()?);
            }
        },
        Command::Info(_command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[], cli.user.as_deref(), auth_passphrase)?;

            println!("{:?}", nethsm.info()?);
        }
        Command::Key(command) => match command {
            KeyCommand::Cert(command) => match command {
                KeyCertCommand::Delete(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    nethsm.delete_key_certificate(&command.key_id)?;
                }
                KeyCertCommand::Get(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Operator, UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;
                    let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                    output
                        .output()
                        .write_all(nethsm.get_key_certificate(&command.key_id)?.as_slice())?;
                }
                KeyCertCommand::Import(command) => {
                    let nethsm = config
                        .get_device(cli.label.as_deref())?
                        .nethsm_with_matching_creds(
                            &[UserRole::Administrator],
                            cli.user.as_deref(),
                            auth_passphrase,
                        )?;

                    nethsm.import_key_certificate(&command.key_id, read(command.cert_file)?)?;
                }
            },
            KeyCommand::Csr(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output.output().write_all(
                    nethsm
                        .get_key_csr(
                            &command.key_id,
                            DistinguishedName {
                                country_name: command.country,
                                state_or_province_name: command.state,
                                locality_name: command.locality,
                                organization_name: command.org_name,
                                organizational_unit_name: command.org_unit,
                                common_name: command.common_name,
                                email_address: command.email,
                            },
                        )?
                        .as_bytes(),
                )?;
            }
            KeyCommand::Decrypt(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                // NOTE: IV can not be zero length or None when decrypting
                let iv = if let Some(iv) = command.initialization_vector {
                    Some(read(iv)?)
                } else {
                    Some(vec![])
                };
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output.output().write_all(&nethsm.decrypt(
                    &command.key_id,
                    command.decrypt_mode.unwrap_or_default(),
                    &read(command.message)?,
                    iv.as_deref(),
                )?)?;
            }
            KeyCommand::Encrypt(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                // NOTE: IV can not be zero length or None when decrypting
                let iv = if let Some(iv) = command.initialization_vector {
                    Some(read(iv)?)
                } else {
                    None
                };
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output.output().write_all(
                    nethsm
                        .encrypt(
                            &command.key_id,
                            command.encrypt_mode.unwrap_or_default(),
                            &read(command.message)?,
                            iv.as_deref(),
                        )?
                        .as_slice(),
                )?;
            }
            KeyCommand::Generate(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                println!(
                    "{}",
                    nethsm.generate_key(
                        command.key_type.unwrap_or_default(),
                        command.key_mechanisms,
                        command.length,
                        command.key_id,
                        command.tags,
                    )?
                );
            }
            KeyCommand::Get(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                println!("{:#?}", nethsm.get_key(&command.key_id)?);
            }
            KeyCommand::Import(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let key_data = match command.format {
                    KeyFormat::Der => {
                        PrivateKeyImport::new(command.key_type, &read(command.key_data)?)
                    }
                    KeyFormat::Pem => PrivateKeyImport::from_pkcs8_pem(
                        command.key_type,
                        &read_to_string(command.key_data)?,
                    ),
                }
                .map_err(nethsm::Error::Key)?;

                println!(
                    "{}",
                    nethsm.import_key(
                        command.key_mechanisms,
                        key_data,
                        command.key_id,
                        command.tags,
                    )?
                );
            }
            KeyCommand::List(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm
                    .get_keys(command.filter.as_deref())?
                    .iter()
                    .for_each(|key_id| println!("{key_id}"));
            }
            KeyCommand::PublicKey(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator, UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output
                    .output()
                    .write_all(nethsm.get_public_key(&command.key_id)?.as_bytes())?;
            }
            KeyCommand::Remove(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.delete_key(&command.key_id)?;
            }
            KeyCommand::Sign(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output.output().write_all(
                    nethsm
                        .sign(
                            &command.key_id,
                            command.signature_type,
                            &read(command.message)?,
                        )?
                        .as_slice(),
                )?;
            }
            KeyCommand::Tag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.add_key_tag(&command.key_id, &command.tag)?;
            }
            KeyCommand::Untag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.delete_key_tag(&command.key_id, &command.tag)?;
            }
        },
        Command::Lock(_command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(
                    &[UserRole::Administrator],
                    cli.user.as_deref(),
                    auth_passphrase,
                )?;

            nethsm.lock()?;
        }
        Command::Metrics(_command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(
                    &[UserRole::Metrics],
                    cli.user.as_deref(),
                    auth_passphrase,
                )?;

            println!("{}", nethsm.metrics()?);
        }
        Command::OpenPgp(command) => match command {
            cli::OpenPgpCommand::Add(command) => {
                let flags = {
                    let mut flags = nethsm::OpenPgpKeyUsageFlags::default();
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
                        cli.user.as_deref(),
                        auth_passphrase.clone(),
                    )?;

                let cert = nethsm.add_openpgp_cert(
                    &command.key_id,
                    flags,
                    &command.user_id,
                    command.time.unwrap_or_else(Utc::now),
                )?;

                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.import_key_certificate(&command.key_id, cert.clone())?;
            }
            cli::OpenPgpCommand::Sign(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Operator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

                output.output().write_all(
                    nethsm
                        .openpgp_sign(&command.key_id, &read(command.message)?)?
                        .as_slice(),
                )?;
            }
        },
        Command::Provision(command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[], cli.user.as_deref(), auth_passphrase)?;
            let unlock_passphrase = if let Some(passphrase_file) = command.unlock_passphrase_file {
                passphrase_file.passphrase
            } else {
                PassphrasePrompt::Unlock.prompt()?
            };
            let admin_passphrase = if let Some(passphrase_file) = command.admin_passphrase_file {
                passphrase_file.passphrase
            } else {
                PassphrasePrompt::User("admin".to_string()).prompt()?
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
                .nethsm_with_matching_creds(
                    &[UserRole::Operator],
                    cli.user.as_deref(),
                    auth_passphrase,
                )?;
            let output = FileOrStdout::new(command.output.as_deref(), command.force)?;

            output.output().write_all(&nethsm.random(command.length)?)?;
        }
        Command::System(command) => match command {
            SystemCommand::Backup(command) => {
                let device_config = config.clone().get_device(cli.label.as_deref())?;
                let label = if let Some(label) = cli.label {
                    label
                } else if let Ok(label) = config.get_single_device_label() {
                    label
                } else {
                    return Err(cli::Error::OptionMissing("label".to_string()).into());
                };
                let nethsm = device_config.nethsm_with_matching_creds(
                    &[UserRole::Backup],
                    cli.user.as_deref(),
                    auth_passphrase,
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

                output.output().write_all(nethsm.backup()?.as_slice())?;
            }
            SystemCommand::CancelUpdate(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.cancel_update()?;
            }
            SystemCommand::CommitUpdate(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.commit_update()?;
            }
            SystemCommand::FactoryReset(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.factory_reset()?;
            }
            SystemCommand::Info(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                println!("{:#?}", nethsm.system_info()?);
            }
            SystemCommand::Reboot(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.reboot()?;
            }
            SystemCommand::Restore(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let backup_passphrase =
                    if let Some(passphrase_file) = command.backup_passphrase_file {
                        passphrase_file.passphrase
                    } else {
                        PassphrasePrompt::Backup.prompt()?
                    };

                nethsm.restore(
                    backup_passphrase,
                    command.system_time.unwrap_or_else(Utc::now),
                    read(command.input)?,
                )?;
            }
            SystemCommand::Shutdown(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.shutdown()?;
            }
            SystemCommand::UploadUpdate(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                println!("{:?}", nethsm.upload_update(read(command.input)?)?);
            }
        },
        Command::Unlock(command) => {
            let nethsm = config
                .get_device(cli.label.as_deref())?
                .nethsm_with_matching_creds(&[], cli.user.as_deref(), auth_passphrase)?;
            let unlock_passphrase = if let Some(passphrase_file) = command.unlock_passphrase_file {
                passphrase_file.passphrase
            } else {
                PassphrasePrompt::Unlock.prompt()?
            };

            nethsm.unlock(unlock_passphrase)?;
        }
        Command::User(command) => match command {
            UserCommand::Add(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let passphrase = if let Some(passphrase_file) = command.passphrase_file {
                    passphrase_file.passphrase
                } else {
                    PassphrasePrompt::User(if let Some(name) = command.name.as_ref() {
                        format!("{} ({})", command.real_name, name)
                    } else {
                        command.real_name.clone()
                    })
                    .prompt()?
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
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                let user_data = nethsm.get_user(&command.name)?;
                println!("{:?}", user_data);
                // only users in the Operator role can have tags
                if user_data.role == UserRole::Operator.into() {
                    println!("{:?}", nethsm.get_user_tags(&command.name));
                }
            }
            UserCommand::List(_command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
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
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;
                let passphrase = if let Some(passphrase_file) = command.passphrase_file {
                    passphrase_file.passphrase
                } else {
                    PassphrasePrompt::NewUser(command.name.clone()).prompt()?
                };

                nethsm.set_user_passphrase(&command.name, passphrase)?;
            }
            UserCommand::Remove(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.delete_user(&command.name)?;
            }
            UserCommand::Tag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.add_user_tag(&command.name, &command.tag)?;
            }
            UserCommand::Untag(command) => {
                let nethsm = config
                    .get_device(cli.label.as_deref())?
                    .nethsm_with_matching_creds(
                        &[UserRole::Administrator],
                        cli.user.as_deref(),
                        auth_passphrase,
                    )?;

                nethsm.delete_user_tag(&command.name, &command.tag)?;
            }
        },
    }

    Ok(())
}
