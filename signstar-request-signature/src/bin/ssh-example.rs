///
/// Run this example with:
/// cargo run --example client_exec_simple -- -k <private key path> <host> <command>
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use log::info;
use russh::*;
use ssh_key::HashAlg;
use tokio::net::ToSocketAddrs;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    // CLI options are defined later in this file
    let cli = Cli::parse();

    info!("Connecting to {}:{}", cli.host, cli.port);
    info!("Key path: {:?}", cli.private_key);

    // Session is a wrapper around a russh client, defined down below
    let mut ssh = Session::connect(
        cli.private_key,
        cli.username.unwrap_or("root".to_string()),
        (cli.host, cli.port),
    )
    .await?;
    info!("Connected");

    let code = ssh
        .call(
            &cli.command
                .into_iter()
                .map(|x| shell_escape::escape(x.into())) // arguments are escaped manually since the SSH protocol doesn't support quoting
                .collect::<Vec<_>>()
                .join(" "),
        )
        .await?;

    println!("Exitcode: {:?}", code);
    println!("STDOUT: <{}>", String::from_utf8_lossy(&ssh.stdout));
    ssh.close().await?;
    Ok(())
}

struct Client {}

// More SSH event handlers
// can be defined in this trait
// In this example, we're only using Channel, so these aren't needed.
#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = "SHA256:".to_string() + &server_public_key.fingerprint();
        let kh = ssh_key::KnownHosts::read_file("/home/wiktor/.ssh/known_hosts").unwrap();
        Ok(kh
            .iter()
            .any(|e| e.public_key().fingerprint(HashAlg::Sha256).to_string() == fingerprint))
    }
}

/// This struct is a convenience wrapper
/// around a russh client
pub struct Session {
    session: client::Handle<Client>,
    stdout: Vec<u8>,
}

impl Session {
    async fn connect<P: AsRef<Path>, A: ToSocketAddrs>(
        _key_path: P,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        //let key_pair = load_secret_key(key_path, None)?;
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..<_>::default()
        };

        let config = Arc::new(config);
        let sh = Client {};

        use base64::prelude::*;

        let pubkey = russh::keys::key::PublicKey::parse(b"ssh-rsa",
&BASE64_STANDARD.decode(
                                                        b"AAAAB3NzaC1yc2EAAAADAQABAAABAQDQv2RJtGurpNLWyiGz9sSuX8agzV98gHW2ZG/7vFkIQrPlaYsd/OH1z7BZNeCHs5vcoq6c2Eh5s6a0vcH4n181TKfjgpbq4t7OFNygWBJplXIZvIlsY//UCxfp5ZdKWJfrYUu/0HeEv5r/7ZcpwF/omC97aM0ipmAeQ8QEGLfgGW427ATa/r2SFwK/4h0C+BTUnMj/YC/4KI/MPWA6x7RdAw+RbVjZd4kT2ZPXcUdruSqDQ4vSP/b8gERv1IjWUn+HHteRJgR2SwNmsuuT/Ko3FRFfXxXPV2yMEvUY2+DoU781VhZJl0aqpW5bIhlK5VE5rGvmMuE5S7XwYDM9V0Wl").unwrap())?;

        let stream = tokio::net::UnixStream::connect("/run/user/1000/ssh-agent.sock").await?;
        let future = russh::keys::agent::client::AgentClient::connect(stream);

        let mut session = client::connect(config, addrs, sh).await?;
        let auth_res = session.authenticate_future(user, pubkey, future).await.1?;

        if !auth_res {
            anyhow::bail!("Authentication failed");
        }

        Ok(Self {
            session,
            stdout: Vec::new(),
        })
    }

    async fn call(&mut self, command: &str) -> Result<u32> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;

        let mut code = None;
        //let mut stdout = tokio::io::stdout();

        loop {
            // There's an event available on the session channel
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                // Write data to the terminal
                ChannelMsg::Data { ref data } => {
                    //stdout.write_all(data).await?;
                    //stdout.flush().await?;
                    self.stdout.extend(data.iter());
                }
                // The command has returned an exit code
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }
        Ok(code.expect("program did not exit cleanly"))
    }

    async fn close(&mut self) -> Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "English")
            .await?;
        Ok(())
    }
}

#[derive(clap::Parser)]
#[clap(trailing_var_arg = true)]
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: Option<String>,

    #[clap(long, short = 'k')]
    private_key: PathBuf,

    #[clap(index = 2, required = true)]
    command: Vec<String>,
}
