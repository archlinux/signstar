use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use log::info;
use russh::server::{Msg, Server as _, Session};
use russh::*;
use ssh_key::private::Ed25519Keypair;
use ssh_key::PrivateKey;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

async fn start() -> (oneshot::Sender<()>, SocketAddr, String) {
    let (tx1, mut rx1) = oneshot::channel();

    let m = move |vec: &[u8]| {
        info!("Received and exchanged: {vec:?}");
        assert!(!vec.is_empty());
        format!("test, you sent me {} bytes", vec.len())
            .as_bytes()
            .into()
    };

    let mut sh = Server {
        f: m,
        received: vec![],
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().expect("port");
    let key_pair: PrivateKey = Ed25519Keypair::random(&mut rand::thread_rng()).into();
    //let fingerprint = key_pair.fingerprint(HashAlg::Sha256).to_string();
    let public_key = key_pair.public_key().to_string();

    tokio::spawn(async move {
        info!("Listening");
        tokio::select! {
            _ = sh.listen(key_pair, &listener) => {

            }
            _ = &mut rx1 => {
                info!("Stopping");
            }
        }
    });
    (tx1, addr, public_key)
}

#[tokio::test]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .init();
    let (tx, addr, public_key) = start().await;
    let port = addr.port();
    let host = addr.ip();

    info!("Connecting to {}:{}", host, port);

    let mut known_hosts = std::fs::File::create("/tmp/known_hosts")?;
    known_hosts.write_all(format!("{host} {public_key}").as_bytes())?;

    let pb: PathBuf = "/run/user/1000/ssh-agent.sock".into();

    let mut ssh = signstar_request_signature::ssh::client::Session::connect(
        "/tmp/known_hosts".into(),
        &pb, "AAAAB3NzaC1yc2EAAAADAQABAAABAQDQv2RJtGurpNLWyiGz9sSuX8agzV98gHW2ZG/7vFkIQrPlaYsd/OH1z7BZNeCHs5vcoq6c2Eh5s6a0vcH4n181TKfjgpbq4t7OFNygWBJplXIZvIlsY//UCxfp5ZdKWJfrYUu/0HeEv5r/7ZcpwF/omC97aM0ipmAeQ8QEGLfgGW427ATa/r2SFwK/4h0C+BTUnMj/YC/4KI/MPWA6x7RdAw+RbVjZd4kT2ZPXcUdruSqDQ4vSP/b8gERv1IjWUn+HHteRJgR2SwNmsuuT/Ko3FRFfXxXPV2yMEvUY2+DoU781VhZJl0aqpW5bIhlK5VE5rGvmMuE5S7XwYDM9V0Wl",
        "test",
        (host, port),
    )
    .await?;
    info!("Connected");

    let code = ssh.call("test this thing", b"this is cool").await?;

    println!("Exitcode: {:?}", code);
    println!("STDOUT: <{}>", String::from_utf8_lossy(&ssh.stdout));
    ssh.close().await?;

    tx.send(()).unwrap();
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
            inactivity_timeout: Some(Duration::from_secs(3600)),
            auth_rejection_time: Duration::from_secs(3),
            auth_rejection_time_initial: Some(Duration::from_secs(0)),
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
        eprintln!("Session error: {:#?}", error);
    }
}

#[async_trait]
impl<F: Fn(&[u8]) -> Vec<u8> + Send + Clone> server::Handler for Server<F> {
    type Error = russh::Error;

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: &ssh_key::public::PublicKey,
    ) -> Result<server::Auth, Self::Error> {
        Ok(server::Auth::Accept)
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.received.extend(data);
        Ok(())
    }

    #[allow(unused_variables)]
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Exec requested: {}", String::from_utf8_lossy(data));
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let response = (self.f)(&self.received);

        session.data(channel, response.into())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}
