//! Test SSH connectivity using dummy SSH server and a dummy SSH agent.
//!
//! This test checks if the SSH client features are working properly.
//! For that the following procedure is executed:
//!   - a set of fresh, ed25519 server keys is generated,
//!   - these keys are stored additionally in a `known_hosts` formatted file for the client,
//!   - the SSH server is started on an unoccupied local port, it replies with a static content
//!   - a set of client keys are generated and stored in a new SSH agent, the agent is listening on
//!     a Unix socket,
//!   - the generated parameters are packed in a [`ConnectOptions`] structure and a connection
//!     attempt is made,
//!   - the test signing request is sent and a signing response is retrieved, the result is compared
//!     with static data.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::{debug, info};
use russh::keys::ssh_encoding::Encode;
use russh::keys::ssh_key::{PrivateKey, PublicKey, private::Ed25519Keypair};
use russh::server::{self, Msg, Server as _, Session as ServerSession};
use russh::{Channel, ChannelId};
use signstar_request_signature::Request;
use signstar_request_signature::ssh::client::ConnectOptions;
use testresult::TestResult;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

mod agent;

struct SshSetup {
    server_host: (String, u16),
    public_key: String,
    agent_socket: PathBuf,
    close: oneshot::Sender<&'static str>,
}

async fn start(temp_dir: impl AsRef<std::path::Path>) -> TestResult<SshSetup> {
    let (tx1, mut rx1) = oneshot::channel();

    let m = move |vec: &[u8]| {
        info!(
            "Received and exchanged: {vec:?}: <{}>",
            String::from_utf8_lossy(vec)
        );
        assert!(!vec.is_empty());
        r#"{"version":"0.0.3","signature":"aaa"}"#.into()
    };

    let mut sh = Server {
        f: m,
        received: vec![],
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let key_pair: PrivateKey = Ed25519Keypair::random(&mut rand::thread_rng()).into();
    let public_key = key_pair.public_key().to_string();

    let agent_socket_path = temp_dir.as_ref().join("agent.sock");
    let asp = agent_socket_path.clone();

    tokio::spawn(async move {
        info!("Starting server on {addr}; agent on {agent_socket_path:?}");
        tokio::select! {
            _ = sh.listen(key_pair, &listener) => {

            }
            _ = agent::listen_on_socket(agent_socket_path) => {
                info!("Stopping the agent");
            }
            _ = &mut rx1 => {
                info!("Stopping the server");
            }
        }
    });
    // run the spawned task before we return from this function
    // see: https://docs.rs/tokio/latest/tokio/task/index.html#yield_now
    tokio::task::yield_now().await;

    Ok(SshSetup {
        server_host: (addr.ip().to_string(), addr.port()),
        public_key,
        agent_socket: asp,
        close: tx1,
    })
}

#[tokio::test]
async fn ssh_roundtrip() -> TestResult {
    env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .init();

    let temp_dir = tempfile::tempdir()?;
    let setup = start(&temp_dir).await?;

    info!("Connecting to {:?}", setup.server_host);

    let known_hosts = {
        let path = testdir::testdir!().join("known_hosts");
        let mut known_hosts = std::fs::File::create(&path)?;
        known_hosts
            .write_all(format!("{} {}", setup.server_host.0, setup.public_key).as_bytes())?;
        path
    };

    info!("Known hosts file: {known_hosts:?}");

    let mut session =
        ssh_agent_lib::client::connect(UnixStream::connect(&setup.agent_socket)?.into())?;
    let ids = session.request_identities().await?;
    assert_eq!(ids.len(), 1);
    let mut agent_key = ids[0].pubkey.algorithm().to_string().as_bytes().to_vec();
    agent_key.push(b' ');
    let mut key = vec![];
    ids[0].pubkey.encode(&mut key)?;
    agent_key.extend(BASE64_STANDARD.encode(&key).as_bytes());
    let agent_key = String::from_utf8_lossy(&agent_key);

    info!("Client's public key: {agent_key}");

    let options = ConnectOptions::target(setup.server_host.0, setup.server_host.1)
        .append_known_hosts_from_file(known_hosts)?
        .client_auth_agent_sock(setup.agent_socket)
        .client_auth_public_key(agent_key)?
        .user("test");

    let mut ssh = options.connect().await?;
    info!("Connected");

    // send the first request
    let stdout = ssh
        .send(&Request::from_reader(std::fs::File::open(
            "tests/sample-request.json",
        )?)?)
        .await?;

    debug!("STDOUT: <{stdout:?}>");
    let mut output = Vec::new();
    stdout.signature_to_writer(std::io::Cursor::new(&mut output))?;
    assert_eq!(output, b"aaa");

    // send the second request
    let stdout = ssh
        .send(&Request::from_reader(std::fs::File::open(
            "tests/sample-request.json",
        )?)?)
        .await?;

    debug!("STDOUT: <{stdout:?}>");
    let mut output = Vec::new();
    stdout.signature_to_writer(std::io::Cursor::new(&mut output))?;
    assert_eq!(output, b"aaa");

    ssh.close().await?;
    setup.close.send("")?;
    Ok(())
}

#[derive(Clone)]
struct Server<F>
where
    F: Fn(&[u8]) -> Vec<u8> + Send + Clone,
{
    f: F,
    received: Vec<u8>,
}

impl<F: Fn(&[u8]) -> Vec<u8> + Send + Clone + 'static> Server<F> {
    pub async fn listen(
        &mut self,
        key_pair: PrivateKey,
        listener: &TcpListener,
    ) -> Result<(), std::io::Error> {
        let config = russh::server::Config {
            keys: vec![key_pair],
            ..Default::default()
        };
        self.run_on_socket(Arc::new(config), listener).await
    }
}

impl<F: Fn(&[u8]) -> Vec<u8> + Send + Clone + 'static> server::Server for Server<F> {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl<F: Fn(&[u8]) -> Vec<u8> + Send + Clone> server::Handler for Server<F> {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut ServerSession,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        self.received.extend(data);
        Ok(())
    }

    #[allow(unused_variables)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        info!("Exec requested: {}", String::from_utf8_lossy(data));
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        let response = (self.f)(&self.received);

        session.data(channel, response.into())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
