//! cli

use std::{path::PathBuf, str::FromStr as _, time::Duration};

use clap::Parser;
use testresult::TestResult;
use yubihsm::{
    AuditOption,
    Capability,
    Credentials,
    Domain,
    authentication,
    client::Client,
    command::Code,
    object,
    wrap::{self, Message},
};

#[derive(Debug, Parser)]
struct Cli {
    scenario: PathBuf,

    #[clap(env = "SIGNSTAR_YUBIHSM_SN")]
    serial_number: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
enum Command {
    Info,
    Reset,
    GetLog,
    Auth {
        user: u16,
        key_file: PathBuf,
    },
    ForceAudit(String),
    #[allow(clippy::enum_variant_names)]
    CommandAudit {
        command: Code,
        setting: String,
    },
    PutAuthKey {
        key_id: u16,
        label: Option<String>,
        domain: usize,
        caps: Vec<String>,
        delegated_caps: Vec<String>,
        key_file: PathBuf,
    },
    GenerateKey {
        key_id: u16,
        label: Option<String>,
        domain: usize,
        caps: Vec<String>,
    },
    SignEd25519 {
        key_id: u16,
        data: Vec<u8>,
    },
    PutWrapKey {
        key_id: u16,
        label: Option<String>,
        domain: usize,
        caps: Vec<String>,
        delegated_caps: Vec<String>,
        key_file: PathBuf,
    },
    ExportWrapped {
        wrap_key_id: u16,
        object_type: String,
        object_id: u16,
        wrapped_file: PathBuf,
    },
    ImportWrapped {
        wrap_key_id: u16,
        wrapped_file: PathBuf,
    },
    Delete {
        object_id: u16,
        object_type: String,
    },
    GetInfo {
        object_id: u16,
        object_type: String,
    },
}

fn main() -> TestResult {
    env_logger::init();
    let cli = Cli::parse();

    let connector = if let Some(sn) = cli.serial_number {
        yubihsm::Connector::usb(&yubihsm::UsbConfig {
            serial: Some(sn.parse()?),
            timeout_ms: yubihsm::UsbConfig::DEFAULT_TIMEOUT_MILLIS,
        })
    } else {
        yubihsm::Connector::mockhsm()
    };

    let mut steps: Vec<Command> = serde_json::from_reader(std::fs::File::open(cli.scenario)?)?;
    let Command::Auth { user, key_file } = steps.remove(0) else {
        panic!("First command must be auth");
    };

    let credentials = Credentials::new(
        user,
        authentication::Key::new(
            std::fs::read(key_file)?
                .try_into()
                .expect("key file to have 32 bytes"),
        ),
    );
    let mut client = Client::open(connector, credentials, true)?;

    for command in steps {
        log::info!("Executing {command:?}");
        match command {
            Command::Info => {
                serde_json::to_writer(std::io::stdout(), &client.device_info()?)?;
                println!();
            }
            Command::Reset => {
                client.reset_device_and_reconnect(Duration::from_secs(2))?;
            }
            Command::PutAuthKey {
                key_id,
                label,
                domain,
                caps,
                delegated_caps,
                key_file,
            } => {
                let capabilities = caps
                    .into_iter()
                    .map(|c| Capability::from_str(&c))
                    .try_fold(Capability::empty(), |acc, c| Ok::<_, ()>(acc | c?))
                    .expect("conversion to succeed");
                let delegated_capabilities = delegated_caps
                    .into_iter()
                    .map(|c| Capability::from_str(&c))
                    .try_fold(Capability::empty(), |acc, c| Ok::<_, ()>(acc | c?))
                    .expect("conversion to succeed");
                let key = std::fs::read(key_file)?;
                let key: &[u8; 32] = &key[..].try_into()?;
                client.put_authentication_key(
                    key_id,
                    label.map(|s| Into::into(&*s)).unwrap_or_default(),
                    Domain::at(domain)?,
                    capabilities,
                    delegated_capabilities,
                    Default::default(),
                    *key,
                )?;
            }
            Command::GenerateKey {
                key_id,
                label,
                domain,
                caps,
            } => {
                let capabilities = caps
                    .into_iter()
                    .map(|c| Capability::from_str(&c))
                    .try_fold(Capability::empty(), |acc, c| Ok::<_, ()>(acc | c?))
                    .expect("conversion to succeed");
                client.generate_asymmetric_key(
                    key_id,
                    label.map(|s| Into::into(&*s)).unwrap_or_default(),
                    Domain::at(domain)?,
                    capabilities,
                    yubihsm::asymmetric::Algorithm::Ed25519,
                )?;
            }
            Command::SignEd25519 { key_id, data } => {
                #[derive(Debug, serde::Serialize)]
                struct Ed25519Signature {
                    r: Vec<u8>,
                    s: Vec<u8>,
                }

                let sig = client.sign_ed25519(key_id, data)?;
                serde_json::to_writer(
                    std::io::stdout(),
                    &Ed25519Signature {
                        r: sig.r_bytes().to_vec(),
                        s: sig.s_bytes().to_vec(),
                    },
                )?;
                println!();
            }
            Command::PutWrapKey {
                key_id,
                label,
                domain,
                caps,
                delegated_caps,
                key_file,
            } => {
                let capabilities = caps
                    .into_iter()
                    .map(|c| Capability::from_str(&c))
                    .try_fold(Capability::empty(), |acc, c| Ok::<_, ()>(acc | c?))
                    .expect("conversion to succeed");
                let delegated_capabilities = delegated_caps
                    .into_iter()
                    .map(|c| Capability::from_str(&c))
                    .try_fold(Capability::empty(), |acc, c| Ok::<_, ()>(acc | c?))
                    .expect("conversion to succeed");
                let key = std::fs::read(key_file)?;
                client.put_wrap_key(
                    key_id,
                    label.map(|s| Into::into(&*s)).unwrap_or_default(),
                    Domain::at(domain)?,
                    capabilities,
                    delegated_capabilities,
                    wrap::Algorithm::Aes128Ccm,
                    key,
                )?;
            }
            Command::ExportWrapped {
                wrap_key_id,
                object_type,
                object_id,
                wrapped_file,
            } => {
                let wrapped = client.export_wrapped(
                    wrap_key_id,
                    object::Type::from_str(&object_type).expect("type to be correct"),
                    object_id,
                )?;
                serde_json::to_writer(std::io::stdout(), &wrapped)?;
                std::fs::write(wrapped_file, wrapped.into_vec())?;
                println!();
            }
            Command::ImportWrapped {
                wrap_key_id,
                wrapped_file,
            } => {
                let wrapped = Message::from_vec(std::fs::read(wrapped_file)?)?;
                let imported = client.import_wrapped(wrap_key_id, wrapped)?;

                #[derive(Debug, serde::Serialize)]
                struct Imported {
                    id: u16,
                    r#type: String,
                }
                serde_json::to_writer(
                    std::io::stdout(),
                    &Imported {
                        id: imported.object_id,
                        r#type: imported.object_type.to_string(),
                    },
                )?;
                println!();
            }
            Command::Auth { user, key_file } => {
                let credentials = Credentials::new(
                    user,
                    authentication::Key::new(
                        std::fs::read(key_file)?
                            .try_into()
                            .expect("key file to have 32 bytes"),
                    ),
                );

                client = Client::open(client.connector().clone(), credentials, true)?;
            }
            Command::Delete {
                object_id,
                object_type,
            } => {
                client.delete_object(
                    object_id,
                    object::Type::from_str(&object_type).expect("type to be correct"),
                )?;
            }
            Command::GetInfo {
                object_id,
                object_type,
            } => {
                let info = client.get_object_info(
                    object_id,
                    object::Type::from_str(&object_type).expect("type to be correct"),
                )?;
                serde_json::to_writer(std::io::stdout(), &info)?;
                println!();
            }
            Command::ForceAudit(setting) => {
                let value = match &setting[..] {
                    "on" => AuditOption::On,
                    "off" => AuditOption::Off,
                    "fix" => AuditOption::Fix,
                    _ => panic!("Unknown audit setting: {setting}"),
                };
                client.set_force_audit_option(value)?;
            }
            Command::CommandAudit { command, setting } => {
                let value = match &setting[..] {
                    "on" => AuditOption::On,
                    "off" => AuditOption::Off,
                    "fix" => AuditOption::Fix,
                    _ => panic!("Unknown audit setting: {setting}"),
                };
                client.set_command_audit_option(command, value)?;
            }
            Command::GetLog => {
                let log = client.get_log_entries()?;

                serde_json::to_writer(std::io::stdout(), &log)?;
                println!();
            }
        }
    }

    Ok(())
}
