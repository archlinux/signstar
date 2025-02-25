#![expect(missing_docs)]

use std::{path::PathBuf, sync::Arc, time::Duration};

use base64::prelude::*;
use russh::keys::ssh_key::known_hosts::Entry;
use russh::keys::ssh_key::{HashAlg, KnownHosts, PublicKey};
use russh::keys::{agent::client::AgentClient, key::parse_public_key};
use russh::{ChannelMsg, Disconnect, client};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;

#[derive(Debug, Default)]
pub struct ConnectOptions {
    known_hosts: Vec<Entry>,

    client_auth_agent_sock: PathBuf,

    client_auth_public_key: String,

    user: String,

    hostname: String,

    port: u16,
}

impl ConnectOptions {
    pub fn append_known_hosts_from_file(mut self, known_hosts_file: PathBuf) -> Self {
        let kh = KnownHosts::read_file(&known_hosts_file).unwrap();
        self.known_hosts.extend(kh);
        self
    }

    pub fn client_auth_agent_sock(mut self, agent_sock: impl Into<PathBuf>) -> Self {
        self.client_auth_agent_sock = agent_sock.into();
        self
    }

    pub fn client_auth_public_key(mut self, public_key: impl Into<String>) -> Self {
        self.client_auth_public_key = public_key.into();
        self
    }

    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    pub fn target(hostname: String, port: u16) -> Self {
        Self {
            hostname,
            port,
            known_hosts: Default::default(),
            client_auth_agent_sock: Default::default(),
            client_auth_public_key: Default::default(),
            user: Default::default(),
        }
    }
}

pub async fn connect(options: ConnectOptions) -> Result<Session, Error> {
    let config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(5)),
        ..Default::default()
    };

    let config = Arc::new(config);

    let pubkey = parse_public_key(
        &BASE64_STANDARD
            .decode(options.client_auth_public_key.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let stream = UnixStream::connect(&options.client_auth_agent_sock).await?;
    let mut future = AgentClient::connect(stream);
    let mut session = client::connect(
        config,
        (options.hostname.clone(), options.port),
        KeyValidator(options.hostname, options.port, options.known_hosts),
    )
    .await?;
    let auth_res = session
        .authenticate_publickey_with(options.user, pubkey, Some(HashAlg::Sha512), &mut future)
        .await?;

    if !auth_res.success() {
        return Err(Error::AuthFailed);
    }

    Ok(Session { session })
}

struct KeyValidator(String, u16, Vec<Entry>);

impl client::Handler for KeyValidator {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(crate::ssh::known_hosts::is_server_known(
            self.2.iter(),
            &self.0,
            self.1,
            server_public_key,
        ))
    }
}

pub struct Session {
    session: client::Handle<KeyValidator>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, _f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Authentication failed")]
    AuthFailed,

    #[error("I/O error")]
    Io(#[from] std::io::Error),

    #[error("Program did not exit cleanly")]
    UncleanExit,

    #[error("Non zero exit code: {0}")]
    NonZeroExit(u32),

    #[error("SSH protocol error: {0}")]
    Ssh(#[from] russh::Error),

    #[error("SSH agent error: {0}")]
    Agent(#[from] russh::AgentAuthError),

    #[error("Serde serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl Session {
    pub async fn send<T, S>(&mut self, data: &T) -> Result<S, Error>
    where
        T: Serialize,
        S: DeserializeOwned,
    {
        let mut channel = self.session.channel_open_session().await?;
        channel.exec(true, b"").await?;
        let data = serde_json::to_vec(&data)?;
        channel.data(data.as_ref()).await?;
        channel.eof().await?;

        let mut code = None;
        let mut stdout = vec![];

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.extend(data.iter());
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    code = Some(exit_status);
                    // cannot leave the loop immediately, there might still be more data to receive
                }
                _ => {}
            }
        }

        if let Some(code) = code {
            if code != 0 {
                Err(Error::NonZeroExit(code))
            } else {
                Ok(serde_json::from_slice(&stdout[..])?)
            }
        } else {
            Err(Error::UncleanExit)
        }
    }

    pub async fn close(&mut self) -> Result<(), Error> {
        self.session
            .disconnect(Disconnect::ByApplication, "", "en")
            .await?;
        Ok(())
    }
}
