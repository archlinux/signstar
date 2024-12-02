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
use signstar_request_signature::ssh::client::{ConnectOptions, connect};
use testresult::TestResult;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

mod agent {
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use rsa::pkcs1v15::SigningKey;
    use rsa::sha2::{Sha256, Sha512};
    use rsa::signature::{RandomizedSigner, SignatureEncoding};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use ssh_agent_lib::agent::{Session as AgentSession, listen};
    use ssh_agent_lib::error::AgentError;
    use ssh_agent_lib::proto::{Identity, SignRequest, signature};
    use ssh_agent_lib::ssh_key::HashAlg;
    use ssh_agent_lib::ssh_key::public::KeyData;
    use ssh_agent_lib::ssh_key::{Algorithm, Signature};
    use tokio::net::UnixListener;

    #[derive(Clone)]
    struct RandomKey {
        private_key: Arc<Mutex<RsaPrivateKey>>,
    }

    impl RandomKey {
        pub fn new() -> Result<Self, AgentError> {
            let private_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048)
                .map_err(AgentError::other)?;
            Ok(Self {
                private_key: Arc::new(Mutex::new(private_key)),
            })
        }
    }

    #[ssh_agent_lib::async_trait]
    impl AgentSession for RandomKey {
        async fn sign(&mut self, sign_request: SignRequest) -> Result<Signature, AgentError> {
            let private_key = self.private_key.lock().unwrap();
            let mut rng = rand::thread_rng();
            let data = &sign_request.data;

            Ok(if sign_request.flags & signature::RSA_SHA2_512 != 0 {
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha512),
                    },
                    SigningKey::<Sha512>::new(private_key.clone())
                        .sign_with_rng(&mut rng, data)
                        .to_bytes(),
                )
            } else if sign_request.flags & signature::RSA_SHA2_256 != 0 {
                Signature::new(
                    Algorithm::Rsa {
                        hash: Some(HashAlg::Sha256),
                    },
                    SigningKey::<Sha256>::new(private_key.clone())
                        .sign_with_rng(&mut rng, data)
                        .to_bytes(),
                )
            } else {
                Err(std::io::Error::other("Signature for signature type not implemented").into())
            }
            .map_err(AgentError::other)?)
        }

        async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
            use ssh_agent_lib::ssh_key::public::RsaPublicKey as SshPK;
            let identity = self.private_key.lock().unwrap();
            Ok(vec![Identity {
                pubkey: KeyData::from(SshPK::try_from(RsaPublicKey::from(&*identity)).unwrap()),
                comment: "randomly generated RSA key".into(),
            }])
        }
    }

    pub async fn listen_on_socket(socket: impl AsRef<Path>) -> Result<(), AgentError> {
        listen(UnixListener::bind(socket)?, RandomKey::new()?).await?;
        Ok(())
    }
}

struct SshSetup {
    server_host: (String, u16),
    public_key: String,
    agent_socket: PathBuf,
    close: oneshot::Sender<()>,
}

async fn start() -> TestResult<SshSetup> {
    let (tx1, mut rx1) = oneshot::channel();

    let m = move |vec: &[u8]| {
        info!(
            "Received and exchanged: {vec:?}: <{}>",
            String::from_utf8_lossy(vec)
        );
        assert!(!vec.is_empty());
        r#"{"f":1,"s":"aaa"}"#.into()
    };

    let mut sh = Server {
        f: m,
        received: vec![],
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let key_pair: PrivateKey = Ed25519Keypair::random(&mut rand::thread_rng()).into();
    let public_key = key_pair.public_key().to_string();

    let agent_socket_path = testdir::testdir!().join("agent.sock");
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

    let setup = start().await?;

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
    let mut agent_key = vec![];
    ids[0].pubkey.encode(&mut agent_key)?;

    let options = ConnectOptions::target(setup.server_host.0, setup.server_host.1)
        .append_known_hosts_from_file(known_hosts)
        .client_auth_agent_sock(setup.agent_socket)
        .client_auth_public_key(BASE64_STANDARD.encode(&agent_key))
        .user("test");

    let mut ssh = connect(options).await?;
    info!("Connected");

    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct SampleStruct {
        f: u32,
        s: String,
    }

    let s = SampleStruct {
        f: 3,
        s: "test".into(),
    };

    let stdout: SampleStruct = ssh.send(&s).await?;

    debug!("STDOUT: <{stdout:?}>");
    assert_eq!(
        stdout,
        SampleStruct {
            f: 1,
            s: "aaa".into()
        }
    );

    let stdout: SampleStruct = ssh.send(&s).await?;

    debug!("STDOUT: <{stdout:?}>");
    assert_eq!(
        stdout,
        SampleStruct {
            f: 1,
            s: "aaa".into()
        }
    );
    ssh.close().await?;
    setup.close.send(()).unwrap();
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

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        log::error!("Session error: {:#?}", error);
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
