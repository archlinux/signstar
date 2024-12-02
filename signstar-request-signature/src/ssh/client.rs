//! fixme

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use russh::keys::agent::client::AgentClient;
use russh::keys::key::parse_public_key;
use russh::{client, ChannelMsg, Disconnect};
use ssh_key::HashAlg;
use tokio::net::{ToSocketAddrs, UnixStream};

/// fixme
#[derive(Debug)]
pub struct Client {
    known_hosts_file: PathBuf,
}

#[async_trait]
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::public::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256);
        let kh = ssh_key::KnownHosts::read_file(&self.known_hosts_file).unwrap();
        Ok(kh
            .iter()
            .any(|e| e.public_key().fingerprint(HashAlg::Sha256) == fingerprint))
    }
}

/// fixme
pub struct Session {
    session: client::Handle<Client>,
    /// fixme
    pub stdout: Vec<u8>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl Session {
    /// fixme
    pub async fn connect<A: ToSocketAddrs>(
        known_hosts_file: PathBuf,
        agent_sock: &Path,
        pubkey: &str,
        user: impl Into<String>,
        addrs: A,
    ) -> anyhow::Result<Self> {
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        };

        let config = Arc::new(config);
        let sh = Client { known_hosts_file };

        use base64::prelude::*;

        let pubkey = parse_public_key(&BASE64_STANDARD.decode(pubkey.as_bytes()).unwrap()).unwrap();
        //pubkey.as_bytes()).unwrap();

        let stream = UnixStream::connect(&agent_sock).await?;
        let mut future = AgentClient::connect(stream);

        let mut session = client::connect(config, addrs, sh).await?;
        let auth_res = session
            .authenticate_publickey_with(user, pubkey, &mut future)
            .await?;

        if !auth_res {
            anyhow::bail!("Authentication failed");
        }

        Ok(Self {
            session,
            stdout: Vec::new(),
        })
    }

    /// fixme
    pub async fn call(&mut self, command: &str, data: &[u8]) -> anyhow::Result<u32> {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, command).await?;
        channel.data(data).await?;
        channel.eof().await?;

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

    /// fixme
    pub async fn close(&mut self) -> anyhow::Result<()> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}
