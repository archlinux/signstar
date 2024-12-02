use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use clap::Parser;
use log::info;
use russh::keys::agent::client::AgentClient;
use russh::keys::key::parse_public_key;
use russh::{client, ChannelMsg, Disconnect};
use ssh_key::HashAlg;
use tokio::net::{ToSocketAddrs, UnixStream};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();

    let cli = Cli::parse();

    info!("Connecting to {}:{}", cli.host, cli.port);

    let mut ssh = Session::connect(
        cli.known_hosts_file.clone(),
        cli.agent_sock.as_ref(),
        &cli.pubkey,
        cli.username,
        (cli.host, cli.port),
    )
    .await?;
    info!("Connected");

    let code = ssh.call(&cli.command).await?;

    println!("Exitcode: {:?}", code);
    println!("STDOUT: <{}>", String::from_utf8_lossy(&ssh.stdout));
    ssh.close().await?;
    Ok(())
}

struct Client {
    known_hosts_file: PathBuf,
}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = "SHA256:".to_string() + &server_public_key.fingerprint();
        let kh = ssh_key::KnownHosts::read_file(&self.known_hosts_file).unwrap();
        Ok(kh
            .iter()
            .any(|e| e.public_key().fingerprint(HashAlg::Sha256).to_string() == fingerprint))
    }
}

pub struct Session {
    session: client::Handle<Client>,
    stdout: Vec<u8>,
}

impl Session {
    async fn connect<A: ToSocketAddrs>(
        known_hosts_file: PathBuf,
        agent_sock: &Path,
        pubkey: &str,
        user: impl Into<String>,
        addrs: A,
    ) -> Result<Self> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };

        let config = Arc::new(config);
        let sh = Client { known_hosts_file };

        use base64::prelude::*;

        let pubkey =
            parse_public_key(&BASE64_STANDARD.decode(pubkey.as_bytes()).unwrap(), None).unwrap();

        let stream = UnixStream::connect(&agent_sock).await?;
        let future = AgentClient::connect(stream);

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

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    self.stdout.extend(data.iter());
                }
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
pub struct Cli {
    #[clap(index = 1)]
    host: String,

    #[clap(long, short, default_value_t = 22)]
    port: u16,

    #[clap(long, short)]
    username: String,

    #[clap(long)]
    pubkey: String,

    #[clap(long)]
    known_hosts_file: PathBuf,

    #[clap(long)]
    agent_sock: PathBuf,

    #[clap(index = 2, required = true)]
    command: String,
}
