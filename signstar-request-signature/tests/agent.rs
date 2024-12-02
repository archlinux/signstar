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
        let private_key =
            rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).map_err(AgentError::other)?;
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
