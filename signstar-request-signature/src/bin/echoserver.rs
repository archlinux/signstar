use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::server::{Msg, Server as _, Session};
use russh::*;
use russh_keys::key::KeyPair;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let intro = format!("hello {}", std::env::var("USER").unwrap());

    let m = move |vec: &[u8]| {
        assert!(!vec.is_empty());
        format!("{}, you sent me {} bytes", intro, vec.len())
            .as_bytes()
            .into()
    };

    let mut sh = Server {
        f: m,
        received: vec![],
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().expect("port").port();
    eprintln!("Listening on {port}");
    let key_pair = KeyPair::generate_ed25519();
    let fingerprint = key_pair.clone_public_key().unwrap().fingerprint();
    eprintln!("Fingerprint: SHA256:{fingerprint}");
    let handle = tokio::spawn(async move { sh.listen(key_pair, &listener).await });
    tokio::time::sleep(Duration::from_secs(10)).await;
    eprintln!("dropping");
    drop(handle);
    tokio::time::sleep(Duration::from_secs(100)).await;

    eprintln!("Done");
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
        key_pair: KeyPair,
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
        _key: &russh_keys::key::PublicKey,
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

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let response = (self.f)(&self.received);

        session.data(channel, response.into());
        session.eof(channel);
        session.exit_status_request(channel, 0);
        session.close(channel);
        Ok(())
    }
}
