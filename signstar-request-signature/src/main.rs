use std::{path::PathBuf, time::SystemTime};

use clap::Parser;
use rand::Rng;
use serde_json::Value;
use sha2::Digest;
use signstar_request_signature::{
    Request,
    Required,
    Response,
    SignatureRequestOutput,
    cli::{Cli, SendCommand},
    ssh::client::{ConnectOptions, connect},
};

fn prepare_signing_request(
    input: PathBuf,
) -> Result<Request, Box<dyn std::error::Error + Send + Sync>> {
    let hasher = {
        let mut hasher = sha2::Sha512::new();
        std::io::copy(&mut std::fs::File::open(&input)?, &mut hasher)?;
        hasher
    };
    let required = Required {
        input: hasher.into(),
        output: SignatureRequestOutput::new_openpgp_v4(),
    };

    // Add "grease" so that the server can handle any optional data
    // See: https://lobste.rs/s/utmsph/age_plugins#c_i76hkd
    // See: https://community.letsencrypt.org/t/adding-random-entries-to-the-directory/33417
    let grease: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(7)
        .map(char::from)
        .collect();

    Ok(Request {
        version: semver::Version::new(1, 0, 0),
        required,
        optional: vec![
            (
                grease,
                Value::String(
                    "https://gitlab.archlinux.org/archlinux/signstar/-/merge_requests/43"
                        .to_string(),
                ),
            ),
            (
                "request-time".into(),
                Value::Number(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)?
                        .as_secs()
                        .into(),
                ),
            ),
            (
                "file-name".into(),
                input
                    .file_name()
                    .and_then(|s| s.to_str())
                    .map(Into::into)
                    .unwrap_or(Value::Null),
            ),
        ]
        .into_iter()
        .collect(),
    })
    //Ok(())
}

async fn send_request_via_ssh(
    send_command: SendCommand,
) -> Result<Response, Box<dyn std::error::Error + Send + Sync>> {
    let options = ConnectOptions::target(send_command.host, send_command.port)
        .append_known_hosts_from_file(send_command.known_hosts)
        .client_auth_agent_sock(send_command.agent_socket)
        .client_auth_public_key(send_command.user_public_key)
        .user(send_command.user);
    let mut session = connect(options).await?;
    let response: Response = session
        .send(&prepare_signing_request(send_command.input)?)
        .await?;
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Cli::parse();

    match args {
        Cli::Prepare(prepare) => {
            prepare_signing_request(prepare.input)?.to_writer(std::io::stdout())?;
        }
        Cli::Send(send_command) => {
            send_request_via_ssh(send_command)
                .await?
                .to_writer(std::io::stdout())?;
        }
    }
    Ok(())
}
